use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use openssh_sftp_client::{Sftp, SftpOptions};
use russh::{
    Disconnect, client,
    keys::{
        self, PublicKey, PublicKeyOrCertificate,
        agent::{
            AgentIdentity,
            client::{AgentClient, AgentStream},
        },
        key::PrivateKeyWithHashAlg,
    },
};
use serde_json::{Value, json};
use sha1::Sha1;
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

use crate::config::{Config, Resolved, validate_target};

pub struct Session {
    pub id: String,
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: u16,
    pub home: String,
    pub handle: Arc<client::Handle<HostVerifier>>,
    pub sftp: Arc<Sftp>,
    pub mutation_lock: Mutex<()>,
    pub command_slots: Arc<Semaphore>,
    jumps: Vec<Arc<client::Handle<HostVerifier>>>,
}

impl Session {
    pub fn info(&self) -> Value {
        json!({"session_id":self.id,"alias":self.alias,"hostname":self.hostname,"user":self.user,"port":self.port,"home":self.home,"connected":!self.handle.is_closed()})
    }

    async fn close(&self) {
        self.command_slots.close();
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            self.handle
                .disconnect(Disconnect::ByApplication, "Client disconnected", "en"),
        )
        .await;
        for jump in self.jumps.iter().rev() {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                jump.disconnect(Disconnect::ByApplication, "Client disconnected", "en"),
            )
            .await;
        }
    }
}

pub struct ConnectionManager {
    config: Config,
    sessions: Mutex<BTreeMap<String, Arc<Session>>>,
    connect_gate: Mutex<()>,
    stopping: AtomicBool,
}

impl ConnectionManager {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            sessions: Mutex::new(BTreeMap::new()),
            connect_gate: Mutex::new(()),
            stopping: AtomicBool::new(false),
        }
    }

    pub async fn list_hosts(&self) -> Result<Value> {
        let aliases = self.config.aliases()?;
        let sessions = self.sessions.lock().await;
        Ok(json!({"hosts": aliases.into_iter().map(|alias| {
            let session = sessions.values().find(|session| session.alias == alias && !session.handle.is_closed());
            json!({"alias":alias,"connected":session.is_some(),"session_id":session.map(|session|&session.id)})
        }).collect::<Vec<_>>()}))
    }

    pub async fn connect(&self, alias: &str) -> Result<Arc<Session>> {
        validate_target(alias)?;
        ensure!(
            self.config
                .aliases()?
                .iter()
                .any(|candidate| candidate == alias),
            "Unknown SSH alias; choose an alias returned by list_hosts"
        );
        // Serialize creation separately so existing sessions stay usable during a slow connection.
        let _connecting = self.connect_gate.lock().await;
        ensure!(
            !self.stopping.load(Ordering::Acquire),
            "Server is shutting down"
        );
        let stale = {
            let mut sessions = self.sessions.lock().await;
            if let Some(session) = sessions
                .values()
                .find(|session| session.alias == alias && !session.handle.is_closed())
            {
                return Ok(session.clone());
            }
            let ids = sessions
                .values()
                .filter(|session| session.alias == alias)
                .map(|session| session.id.clone())
                .collect::<Vec<_>>();
            ids.into_iter()
                .filter_map(|id| sessions.remove(&id))
                .collect::<Vec<_>>()
        };
        for session in stale {
            session.close().await;
        }
        let resolved = self.config.resolve(alias, None, None).await?;
        let route = expand_route(&self.config, resolved.clone(), BTreeSet::new()).await?;
        ensure!(route.len() <= 8, "SSH jump chain exceeds eight connections");
        let mut handles: Vec<Arc<client::Handle<HostVerifier>>> = Vec::new();
        let result: Result<(Arc<Sftp>, String)> = async {
            for target in &route {
                let verifier = HostVerifier::load(target)?;
                let mut config = client::Config {
                    keepalive_interval: Some(Duration::from_secs(15)),
                    keepalive_max: 3,
                    nodelay: true,
                    ..Default::default()
                };
                config.preferred.key = Cow::Owned(
                    config
                        .preferred
                        .key
                        .iter()
                        .filter(|algorithm| {
                            verifier.allowed.iter().any(|key| {
                                key.algorithm() == **algorithm
                                    || matches!(
                                        (key.algorithm(), *algorithm),
                                        (keys::Algorithm::Rsa { .. }, keys::Algorithm::Rsa { .. })
                                    )
                            })
                        })
                        .cloned()
                        .collect(),
                );
                config.preferred.host_key_certificates = Cow::Borrowed(&[]);
                ensure!(
                    !config.preferred.key.is_empty(),
                    "No supported algorithm matches this host's trusted keys"
                );
                let config = Arc::new(config);
                let connection = async {
                    let mut handle = if let Some(previous) = handles.last() {
                        let channel = previous
                            .channel_open_direct_tcpip(
                                &target.hostname,
                                u32::from(target.port),
                                "127.0.0.1",
                                0,
                            )
                            .await?;
                        client::connect_stream(config, channel.into_stream(), verifier).await?
                    } else {
                        client::connect(config, (target.hostname.as_str(), target.port), verifier)
                            .await?
                    };
                    authenticate(&mut handle, target).await?;
                    Ok::<_, anyhow::Error>(handle)
                };
                let handle = tokio::time::timeout(target.connect_timeout, connection)
                    .await
                    .context("SSH connection or authentication timed out")??;
                handles.push(Arc::new(handle));
            }
            let handle = handles.last().context("Empty SSH route")?;
            let sftp = tokio::time::timeout(Duration::from_secs(15), async {
                let channel = handle.channel_open_session().await?;
                channel.request_subsystem(true, "sftp").await?;
                let (reader, writer) = tokio::io::split(channel.into_stream());
                Ok::<_, anyhow::Error>(Sftp::new(writer, reader, SftpOptions::default()).await?)
            })
            .await
            .context("SFTP initialization timed out")??;
            let home = tokio::time::timeout(Duration::from_secs(15), sftp.fs().canonicalize("."))
                .await
                .context("Remote home discovery timed out")??;
            let home = home
                .to_str()
                .context("Remote home path is not UTF-8")?
                .to_owned();
            ensure!(
                home.starts_with('/'),
                "The remote server must use Unix absolute paths"
            );
            Ok((Arc::new(sftp), home))
        }
        .await;
        let (sftp, home) = match result {
            Ok(result) => result,
            Err(error) => {
                for handle in handles.iter().rev() {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        handle.disconnect(
                            Disconnect::ByApplication,
                            "Connection setup failed",
                            "en",
                        ),
                    )
                    .await;
                }
                return Err(error);
            }
        };
        let handle = handles.pop().context("Empty SSH route")?;
        let session = Arc::new(Session {
            id: Uuid::new_v4().to_string(),
            alias: alias.into(),
            hostname: resolved.hostname,
            user: resolved.user,
            port: resolved.port,
            home,
            handle,
            sftp,
            mutation_lock: Mutex::new(()),
            command_slots: Arc::new(Semaphore::new(8)),
            jumps: handles,
        });
        let mut sessions = self.sessions.lock().await;
        if self.stopping.load(Ordering::Acquire) {
            drop(sessions);
            session.close().await;
            bail!("Server is shutting down");
        }
        sessions.insert(session.id.clone(), session.clone());
        Ok(session)
    }

    pub async fn get(&self, id: &str) -> Result<Arc<Session>> {
        let session = self
            .sessions
            .lock()
            .await
            .get(id)
            .cloned()
            .context("Unknown session_id; call connect first")?;
        ensure!(
            !session.handle.is_closed(),
            "SSH connection was lost; call connect explicitly to reconnect. Interrupted operations may have an unknown outcome"
        );
        Ok(session)
    }

    pub async fn list_sessions(&self) -> Value {
        json!({"sessions": self.sessions.lock().await.values().map(|session|session.info()).collect::<Vec<_>>()})
    }

    pub async fn disconnect(&self, id: &str) -> Result<()> {
        let session = self
            .sessions
            .lock()
            .await
            .remove(id)
            .context("Unknown session_id")?;
        session.close().await;
        Ok(())
    }

    pub async fn stop_commands(&self, id: &str) -> Result<()> {
        let sessions = self.sessions.lock().await;
        let session = sessions.get(id).context("Unknown session_id")?;
        session.command_slots.close();
        Ok(())
    }

    pub async fn shutdown(&self) {
        self.stopping.store(true, Ordering::Release);
        let sessions = std::mem::take(&mut *self.sessions.lock().await);
        for session in sessions.values() {
            session.close().await;
        }
    }
}

fn expand_route<'a>(
    config: &'a Config,
    target: Resolved,
    mut seen: BTreeSet<String>,
) -> Pin<Box<dyn Future<Output = Result<Vec<Resolved>>> + Send + 'a>> {
    Box::pin(async move {
        let key = format!("{}@{}:{}", target.user, target.alias, target.port);
        ensure!(
            seen.len() < 8 && seen.insert(key),
            "SSH ProxyJump cycle or chain exceeding eight connections"
        );
        let mut route = Vec::new();
        if let Some(jumps) = &target.proxy_jump {
            for (index, jump) in jumps.split(',').enumerate() {
                let (alias, user, port) = jump_parts(jump)?;
                let resolved = config.resolve(&alias, user.as_deref(), port).await?;
                if index == 0 {
                    route.extend(expand_route(config, resolved, seen.clone()).await?);
                } else {
                    let key = format!("{}@{}:{}", resolved.user, resolved.alias, resolved.port);
                    ensure!(seen.insert(key), "SSH ProxyJump cycle");
                    route.push(resolved);
                }
            }
        }
        route.push(target);
        ensure!(route.len() <= 8, "SSH jump chain exceeds eight connections");
        Ok(route)
    })
}

fn jump_parts(value: &str) -> Result<(String, Option<String>, Option<u16>)> {
    let (user, host) = match value.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()), host),
        None => (None, value),
    };
    let (host, port) = if let Some(rest) = host.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .context("Invalid IPv6 ProxyJump target")?;
        let port = if tail.is_empty() {
            None
        } else {
            Some(
                tail.strip_prefix(':')
                    .context("Invalid ProxyJump port")?
                    .parse()?,
            )
        };
        (host, port)
    } else if host.matches(':').count() == 1 {
        let (host, port) = host.rsplit_once(':').unwrap();
        (host, Some(port.parse()?))
    } else {
        (host, None)
    };
    validate_target(host)?;
    ensure!(
        user.as_ref()
            .is_none_or(|user| !user.is_empty()
                && !user.chars().any(|c| c.is_control() || c.is_whitespace())),
        "Invalid ProxyJump user"
    );
    ensure!(port != Some(0), "Invalid ProxyJump port");
    Ok((host.into(), user, port))
}

type LocalAgent = AgentClient<Box<dyn AgentStream + Send + Unpin>>;

async fn local_agent(configured: Option<&str>) -> Result<LocalAgent> {
    ensure!(configured != Some("none"), "SSH agent is disabled");
    #[cfg(unix)]
    {
        let path = configured
            .filter(|value| *value != "SSH_AUTH_SOCK")
            .map(str::to_string)
            .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
            .context("No SSH agent is configured")?;
        Ok(AgentClient::connect_uds(path).await?.dynamic())
    }
    #[cfg(windows)]
    {
        let path = configured
            .filter(|value| *value != "SSH_AUTH_SOCK")
            .map(str::to_string)
            .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
            .unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".into());
        Ok(AgentClient::connect_named_pipe(path).await?.dynamic())
    }
}

async fn authenticate(handle: &mut client::Handle<HostVerifier>, target: &Resolved) -> Result<()> {
    let mut public_keys = Vec::new();
    let mut private_keys = Vec::new();
    for path in &target.identities {
        if let Ok(key) = keys::load_secret_key(path, None) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    std::fs::metadata(path)?.permissions().mode() & 0o077 == 0,
                    "Private identity file has group/other permissions; restrict it to its owner"
                );
            }
            public_keys.push(key.public_key().clone());
            private_keys.push(Arc::new(key));
        } else {
            let mut path_with_suffix = path.as_os_str().to_os_string();
            path_with_suffix.push(".pub");
            if let Ok(key) = keys::load_public_key(Path::new(&path_with_suffix))
                .or_else(|_| keys::load_public_key(path))
            {
                public_keys.push(key);
            }
        }
    }
    let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
    let agent_setup = async {
        let mut agent = local_agent(target.identity_agent.as_deref()).await?;
        if let Some(binding) = handle.agent_session_binding() {
            // Old agents may not implement binding. Destination-constrained agents enforce it themselves.
            let _ = agent.bind_session(binding, false).await;
        }
        let identities = agent.request_identities().await?;
        Ok::<_, anyhow::Error>((agent, identities))
    };
    let mut agent = match tokio::time::timeout(Duration::from_secs(10), agent_setup).await {
        Ok(Ok(agent)) => Some(agent),
        _ => None,
    };
    // Configured identities precede unrelated agent keys, avoiding sshd's authentication-attempt limit.
    if let Some((agent, identities)) = agent.as_mut() {
        for identity in identities.iter() {
            let AgentIdentity::PublicKey { key, .. } = identity else {
                continue;
            };
            if public_keys
                .iter()
                .any(|allowed| allowed.key_data() == key.key_data())
                && handle
                    .authenticate_publickey_with(&target.user, key.clone(), rsa_hash, agent)
                    .await
                    .is_ok_and(|result| result.success())
            {
                return Ok(());
            }
        }
    }
    for key in private_keys {
        if handle
            .authenticate_publickey(&target.user, PrivateKeyWithHashAlg::new(key, rsa_hash))
            .await?
            .success()
        {
            return Ok(());
        }
    }
    if !target.identities_only
        && let Some((agent, identities)) = agent.as_mut()
    {
        for identity in identities.iter() {
            let AgentIdentity::PublicKey { key, .. } = identity else {
                continue;
            };
            if !public_keys
                .iter()
                .any(|allowed| allowed.key_data() == key.key_data())
                && handle
                    .authenticate_publickey_with(&target.user, key.clone(), rsa_hash, agent)
                    .await
                    .is_ok_and(|result| result.success())
            {
                return Ok(());
            }
        }
    }
    bail!(
        "Public-key authentication failed; unlock encrypted keys in your local SSH agent or configure an unencrypted IdentityFile. Passwords, MFA, and user certificates are unsupported"
    )
}

pub struct HostVerifier {
    hostname: String,
    allowed: Vec<PublicKey>,
    revoked: Vec<PublicKey>,
}

impl HostVerifier {
    fn load(target: &Resolved) -> Result<Self> {
        let hostname = target.host_key_alias.clone().unwrap_or_else(|| {
            if target.port == 22 {
                target.hostname.to_lowercase()
            } else {
                format!("[{}]:{}", target.hostname.to_lowercase(), target.port)
            }
        });
        let mut verifier = Self {
            hostname,
            allowed: Vec::new(),
            revoked: Vec::new(),
        };
        for path in &target.known_hosts {
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("Cannot read known_hosts {}", path.display()));
                }
            };
            verifier.read(&text)?;
        }
        ensure!(
            !verifier.allowed.is_empty(),
            "Host {} has no trusted public key; verify and register it using normal SSH first",
            verifier.hostname
        );
        Ok(verifier)
    }

    fn read(&mut self, text: &str) -> Result<()> {
        for line in text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let mut fields = line.split_whitespace();
            let first = fields.next().context("Invalid known_hosts entry")?;
            let (marker, patterns) = if first.starts_with('@') {
                (
                    Some(first),
                    fields.next().context("Invalid known_hosts marker entry")?,
                )
            } else {
                (None, first)
            };
            if !host_matches(&self.hostname, patterns)? {
                continue;
            }
            let algorithm = fields.next().context("Invalid known_hosts key")?;
            let encoded = fields.next().context("Invalid known_hosts key")?;
            let key = PublicKey::from_openssh(&format!("{algorithm} {encoded}"))
                .context("Invalid matching known_hosts public key")?;
            match marker {
                None => self.allowed.push(key),
                Some("@revoked") => self.revoked.push(key),
                Some("@cert-authority") => {}
                Some(other) => bail!("Unsupported matching known_hosts marker {other}"),
            }
        }
        Ok(())
    }

    fn verify(&self, key: &PublicKey) -> Result<bool> {
        ensure!(
            !self
                .revoked
                .iter()
                .any(|known| known.key_data() == key.key_data()),
            "Host key is revoked for {}",
            self.hostname
        );
        ensure!(
            self.allowed
                .iter()
                .any(|known| known.key_data() == key.key_data()),
            "Host key is unknown or changed for {}; verify it using normal SSH",
            self.hostname
        );
        Ok(true)
    }
}

impl client::Handler for HostVerifier {
    type Error = anyhow::Error;
    async fn check_server_key(&mut self, offered: &PublicKeyOrCertificate) -> Result<bool> {
        match offered {
            PublicKeyOrCertificate::PublicKey { key, .. } => self.verify(key),
            PublicKeyOrCertificate::Certificate(_) => {
                bail!("Certificate-based host trust is unsupported")
            }
        }
    }
}

fn host_matches(host: &str, patterns: &str) -> Result<bool> {
    let mut matched = false;
    for pattern in patterns.split(',') {
        let (negative, pattern) = pattern
            .strip_prefix('!')
            .map(|p| (true, p))
            .unwrap_or((false, pattern));
        let found = if let Some(hash) = pattern.strip_prefix("|1|") {
            let (salt, hash) = hash
                .split_once('|')
                .context("Invalid hashed known_hosts entry")?;
            let salt = STANDARD.decode(salt).context("Invalid known_hosts salt")?;
            let hash = STANDARD.decode(hash).context("Invalid known_hosts hash")?;
            let mut hmac =
                Hmac::<Sha1>::new_from_slice(&salt).context("Invalid known_hosts salt")?;
            hmac.update(host.as_bytes());
            hmac.verify_slice(&hash).is_ok()
        } else {
            wildcard_matches(&host.to_ascii_lowercase(), &pattern.to_ascii_lowercase())
        };
        if negative && found {
            return Ok(false);
        }
        matched |= found;
    }
    Ok(matched)
}

fn wildcard_matches(value: &str, pattern: &str) -> bool {
    let (value, pattern) = (value.as_bytes(), pattern.as_bytes());
    let (mut i, mut j, mut star, mut restart) = (0, 0, None, 0);
    while i < value.len() {
        if j < pattern.len() && (pattern[j] == b'?' || pattern[j] == value[i]) {
            i += 1;
            j += 1;
        } else if j < pattern.len() && pattern[j] == b'*' {
            star = Some(j);
            j += 1;
            restart = i;
        } else if let Some(index) = star {
            restart += 1;
            i = restart;
            j = index + 1;
        } else {
            return false;
        }
    }
    while j < pattern.len() && pattern[j] == b'*' {
        j += 1;
    }
    j == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";

    #[test]
    fn strict_trust_and_revocation() -> Result<()> {
        let key = PublicKey::from_openssh(KEY)?;
        let mut verifier = HostVerifier {
            hostname: "[remote]:2222".into(),
            allowed: Vec::new(),
            revoked: Vec::new(),
        };
        verifier.read(&format!("[remote]:2222 {KEY}\n"))?;
        assert!(verifier.verify(&key)?);
        verifier.read(&format!("@revoked [remote]:2222 {KEY}\n"))?;
        assert!(verifier.verify(&key).is_err());
        Ok(())
    }

    #[test]
    fn hashed_patterns_and_negations() -> Result<()> {
        let mut hmac = Hmac::<Sha1>::new_from_slice(b"test salt")?;
        hmac.update(b"remote");
        let hashed = format!(
            "|1|{}|{}",
            STANDARD.encode(b"test salt"),
            STANDARD.encode(hmac.finalize().into_bytes())
        );
        assert!(host_matches("remote", &hashed)?);
        assert!(!host_matches("other", &hashed)?);
        assert!(host_matches("[remote]:2222", "[remote]:2222")?);
        assert!(host_matches("prod.example", "*.example,!dev.example")?);
        assert!(!host_matches("dev.example", "*.example,!dev.example")?);
        Ok(())
    }

    #[test]
    fn jump_syntax() -> Result<()> {
        assert_eq!(
            jump_parts("alice@[::1]:2222")?,
            ("::1".into(), Some("alice".into()), Some(2222))
        );
        assert_eq!(jump_parts("gateway")?, ("gateway".into(), None, None));
        assert!(jump_parts("gateway:0").is_err());
        Ok(())
    }
}
