//! Repository update via RRDP.
//!
//! This module implements fetching and updating of RPKI repository
//! publication points via RRDP as defined by [RFC 8182].
//!
//! Use of RRDP is triggered by including a *rpkiNotify* Subject Information
//! Access URI in a CA certificate for that particular CA. This URI points to
//! a notification document which in turn points to a snapshot and a series
//! of deltas. The deltas are based around the concept of a publication
//! sequence identified by a serial number. If the announced serial number
//! changes, the data needs to be re-downloaded in full.
//!
//! The data published is still a number of files. These are mapped to the
//! files that can be acquired via rsync through the rsync URI. However, since
//! there is no limitation on which files a particular RRDP server is allowed
//! to publish, it is possible that it attempts to overide files that it isn’t
//! actually responsible for. To avoid this, each RRDP server (identified by a
//! *rpkiNotify* URI) is quarantined into its own area.
//!
//! Since we can’t use URIs as directory names, we keep a list of known
//! servers. Each server’s files are kept in a directory of their own. In
//! addition we start a new directory once the serial number changes.
//! Directory names are random `u32`s so that we can keep them in the same
//! directory as the rsync modules whose directory names are host names (which
//! can’t be just one number). We store the list of known servers, their
//! serial numbers, directory names, and additional state in a file called
//! `rrdp.state.json`.
//!
//! [`Repository`] represents this information and provides means to access
//! objects and update servers. Different servers are identified through a
//! short [`ServerId`] which can be looked up from the rpkiNotify URI through
//! the repository.
//!
//! Note that the implementation here doesn’t cope very well with concurrent
//! updates of the local repository cache. For the moment, we consider it an
//! operational responsibility that there isn’t two Routinators doing that at
//! the same time.
//!
//! Additionally, due to limitations of the XML library we use, all of the
//! operations are synchronous and blocking. Given the limited number of
//! RRDP servers that need to be updated right now, this is fine and a thread
//! pool will do.
//!
//! [RFC 8182]: https://tools.ietf.org/html/rfc8182
//! [`Repository`]: struct.Repository.html
//! [`ServerId`]: struct.ServerId.html

use std::{fs, io, str};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use rand::random;
use ring::digest;
use ring::constant_time::verify_slices_are_equal;
use rpki::rrdp::{NotificationFile, ProcessSnapshot, UriAndHash};
use rpki::uri;
use rpki::xml::decode as xml;
use uuid::Uuid;
use crate::config::Config;
use crate::operation::Error;


//------------ ServerId -----------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServerId {
    /// The epoch value of the repository for this server ID.
    epoch: usize,

    /// The index in the repository’s server list.
    index: usize,
}

impl ServerId {
    /// Creates a new ID from its components.
    fn new(epoch: usize, index: usize) -> Self {
        ServerId { epoch, index }
    }
}


//------------ Repository ----------------------------------------------------

/// Access to all RPKI data accessed via RRDP.
#[derive(Clone, Debug)]
pub struct Repository {
    /// The epoch of this repository.
    ///
    /// This value is changed every time the repository is refreshed. This
    /// is a measure to block reuse of server IDs beyond refreshs.
    epoch: usize,

    /// The servers we know of.
    ///
    /// The index portion of server ID refers to indexes in this vector.
    servers: Vec<Server>,

    /// The rsyncNotify URIs of the servers.
    ///
    /// This is only here to speed up those lookups.
    uris: HashMap<uri::Https, ServerId>,

    /// The path to the cache directory.
    cache_dir: PathBuf,

    /// A HTTP client.
    http: HttpClient,
}

impl Repository {
    /// Creates a new repository using the provided configuration.
    ///
    /// Prints any error messages to stderr.
    pub fn new(config: &Config) -> Result<Self, Error> {
        unimplemented!()
    }

    /// Refreshes the server list.
    ///
    /// After this, all previous server IDs are invalid.
    ///
    /// Logs any error messages.
    pub fn refresh(&mut self) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn get_server_id(&mut self, uri: &uri::Https) -> ServerId {
        if let Some(id) = self.uris.get(uri) {
            return *id
        }
        let id = ServerId::new(self.epoch, self.servers.len());
        self.servers.push(
            Server::new(&self.cache_dir, uri.clone(), &self.http)
        );
        self.uris.insert(uri.clone(), id);
        id
    }

    /*
    pub fn update(&self) -> impl Future<Item=(), Error=Error> {
    }

    pub fn load_object(
        &mut self,
        server: ServerId,
        uri: &uri::Rsync
    ) -> impl Future<Item=Option<Bytes>, Error=Error> {
        unimplemented!()
    }
    */
}


//------------ Server --------------------------------------------------------

/// An RRDP server.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Server {
    /// The notification URI of the server.
    notify_uri: uri::Https,

    /// State of the server.
    ///
    /// If the server was requested but never actually succeeded updating,
    /// this is `None`.
    state: Option<ServerState>,
}

#[derive(Clone, Debug)]
struct ServerState {
    /// The UUID of the current session of this server.
    session: Uuid,

    /// The serial number representing the current state of the server.
    serial: usize,

    /// The identifier for the local representation of that state.
    home: SessionHome,
}

impl Server {
    /// Creates a new server.
    pub fn new(
        cache_dir: &PathBuf,
        notify_uri: uri::Https,
        http: &HttpClient,
    ) -> Self {
        let (home, path) = match SessionHome::create(cache_dir) {
            Ok(some) => some,
            Err(_) => return Self::failed(notify_uri)
        };

        let notify = match http.notification_file(&notify_uri) {
            Ok(some) => some,
            Err(_) => return Self::failed(notify_uri)
        };
        
        let state = ServerState {
            session: notify.session_id().clone(), // XXX Don’t clone here.
            serial: notify.serial(),
            home
        };

        if let Err(_) = http.snapshot(&notify.snapshot(), path.as_ref(),
                                      &state) {
            return Self::failed(notify_uri)
        }

        Self {
            notify_uri,
            state: Some(state)
        }
    }

    fn failed(notify_uri: uri::Https) -> Self {
        Self {
            notify_uri,
            state: None
        }
    }
}


//------------ SessionHome ---------------------------------------------------

/// Identifier for a session in the local repository.
///
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct SessionHome([u8; 10]);

impl SessionHome {
    /// Creates a new, random value and a directory for it.
    ///
    /// This creates the new session home inside `dir`.
    ///
    /// Logs errors.
    pub fn create(dir: &PathBuf) -> Result<(Self, PathBuf), Error> {
        for _ in 0..100 {
            let res = Self::random();
            let path = dir.join(res.as_str());
            match fs::create_dir(&dir) {
                Ok(()) => { }
                Err(err) => {
                    if err.kind() == io::ErrorKind::AlreadyExists {
                        continue;
                    }
                    error!(
                        "Cannot create RRDP server directory: {}",
                        err
                    );
                    return Err(Error)
                }
            }
            return Ok((res, path))
        }
        error!(
            "Cannot create RRDP server directory: \
             failed to create random directory in 100 tries."
        );
        Err(Error)
    }

    fn random() -> Self {
        let mut value = random::<u32>();
        let mut res = SessionHome([0;10]);
        // Yeah, it’s backwards. Anyone cares?
        for i in 0..10 {
            res.0[i] = (value % 10) as u8 + b'0';
            value /= value
        }
        res
    }

    pub fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(self.0.as_ref()) }
    }
}


//------------ HttpClient ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct HttpClient(reqwest::Client);

impl HttpClient {
    pub fn new(_config: &Config) -> Result<Self, Error> {
        let builder = reqwest::Client::builder();
        match builder.build() {
            Ok(client) => Ok(Self(client)),
            Err(err) => {
                error!("Failed to initialize HTTP client: {}.", err);
                error!("No RRDP, falling to rsync only.");
                Err(Error)
            }
        }
    }

    fn notification_file(
        &self,
        uri: &uri::Https
    ) -> Result<NotificationFile, Error> {
        match NotificationFile::parse(io::BufReader::new(self.response(uri)?)) {
            Ok(res) => Ok(res),
            Err(err) => {
                error!("{}: {}", uri, err);
                Err(Error)
            }
        }
    }

    fn snapshot(
        &self,
        uri: &UriAndHash,
        base_dir: &Path,
        server: &ServerState,
    ) -> Result<(), Error> {
        let mut processor = SnapshotProcessor {
            base_dir,
            server
        };
        let mut reader = io::BufReader::new(DigestRead::sha256(
                self.response(uri.uri())?
        ));
        if let Err(err) = processor.process(&mut reader) {
            error!("{}: {}", uri.uri(), err);
            return Err(Error)
        }
        let digest = reader.into_inner().into_digest();
        if let Err(_) = verify_slices_are_equal(digest.as_ref(),
                                                uri.hash().as_ref()) {
            error!("{}: hash value mismatch.", uri.uri());
            return Err(Error)
        }
        Ok(())
    }

    fn response(&self, uri: &uri::Https) -> Result<reqwest::Response, Error> {
        match self.0.get(uri.as_str()).send() {
            Ok(response) => Ok(response),
            Err(err) => {
                error!("{}: {}", uri, err);
                Err(Error)
            }
        }
    }
}


//------------ DigestRead ----------------------------------------------------

pub struct DigestRead<R> {
    reader: R,
    context: digest::Context,
}

impl<R> DigestRead<R> {
    pub fn sha256(reader: R) -> Self {
        DigestRead {
            reader,
            context: digest::Context::new(&digest::SHA384)
        }
    }

    pub fn into_digest(self) -> digest::Digest {
        self.context.finish()
    }
}


impl<R: io::Read> io::Read for DigestRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let res = self.reader.read(buf)?;
        self.context.update(&buf[..res]);
        Ok(res)
    }
}


//------------ SnapshotProcessor ---------------------------------------------

pub struct SnapshotProcessor<'a> {
    base_dir: &'a Path,
    server: &'a ServerState,
}

impl<'a> ProcessSnapshot for SnapshotProcessor<'a> {
    type Err = SnapshotError;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: usize
    ) -> Result<(), Self::Err> {
        if session_id != self.server.session {
            return Err(SnapshotError::SessionMismatch {
                expected: self.server.session.clone(),
                received: session_id
            })
        }
        if serial != self.server.serial {
            return Err(SnapshotError::SerialMismatch {
                expected: self.server.serial,
                received: serial
            })
        }
        Ok(())
    }

    fn publish(
        &mut self,
        uri: uri::Rsync,
        data: Vec<u8>,
    ) -> Result<(), Self::Err> {
        let path = self.base_dir
            .join(uri.module().authority())
            .join(uri.module().module())
            .join(uri.path());

        if let Err(err) = fs::create_dir_all(unwrap!(path.parent())) {
            return Err(SnapshotError::Io(
                unwrap!(path.parent()).to_string_lossy().into(),
                err
            ))
        }

        let mut file = match fs::File::create(&path) {
            Ok(file) => file,
            Err(err) => {
                return Err(SnapshotError::Io(
                    path.to_string_lossy().into(),
                    err
                ))
            }
        };

        if let Err(err) = file.write_all(data.as_ref()) {
            return Err(SnapshotError::Io(
                path.to_string_lossy().into(),
                err
            ))
        }
        Ok(())
    }
}




//============ Errors ========================================================

#[derive(Debug, Display, From)]
pub enum RrdpError {
    #[display(fmt="{}", _0)]
    Http(reqwest::Error),

    #[display(fmt="{}", _0)]
    Xml(xml::Error),
    
    #[display(fmt="{}", _0)]
    Io(io::Error),
}

#[derive(Debug, Display, From)]
pub enum SnapshotError {
    #[display(fmt="{}", _0)]
    Xml(xml::Error),

    #[display(
        fmt="session ID mismatch (notification_file: {}, \
             snapshot file: {}",
        expected, received
    )]
    SessionMismatch {
        expected: Uuid,
        received: Uuid
    },

    #[display(
        fmt="serial number mismatch (notification_file: {}, \
             snapshot file: {}",
        expected, received
    )]
    SerialMismatch {
        expected: usize,
        received: usize 
    },

    #[display(fmt="{}: {}", _0, _1)]
    Io(String, io::Error),
}

