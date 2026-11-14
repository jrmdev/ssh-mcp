use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::process::Command;

#[derive(Clone)]
pub struct Config {
    pub path: PathBuf,
    pub ssh_path: PathBuf,
    explicit_path: bool,
    home: PathBuf,
}

#[derive(Clone, Debug)]
pub struct Resolved {
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: u16,
    pub identities: Vec<PathBuf>,
    pub identity_agent: Option<String>,
    pub identities_only: bool,
    pub known_hosts: Vec<PathBuf>,
    pub host_key_alias: Option<String>,
    pub proxy_jump: Option<String>,
    pub connect_timeout: Duration,
}

impl Config {
    pub fn new(config_path: Option<PathBuf>, ssh_path: PathBuf) -> Result<Self> {
        let home = std::env::home_dir().context("Cannot determine the user's home directory")?;
        let explicit_path = config_path.is_some();
        Ok(Self {
            path: config_path.unwrap_or_else(|| home.join(".ssh/config")),
            ssh_path,
            explicit_path,
            home,
        })
    }

    pub fn aliases(&self) -> Result<Vec<String>> {
        let mut aliases = BTreeSet::new();
        discover(
            &self.path,
            &self.home.join(".ssh"),
            &self.home,
            &mut BTreeSet::new(),
            &mut aliases,
            0,
        )?;
        Ok(aliases.into_iter().collect())
    }

    pub async fn resolve(
        &self,
        alias: &str,
        user: Option<&str>,
        port: Option<u16>,
    ) -> Result<Resolved> {
        validate_target(alias)?;
        let mut command = Command::new(&self.ssh_path);
        command.kill_on_drop(true).arg("-G");
        if self.explicit_path {
            command.arg("-F").arg(&self.path);
        }
        if let Some(user) = user {
            command.arg("-l").arg(user);
        }
        if let Some(port) = port {
            command.arg("-p").arg(port.to_string());
        }
        command.arg("--").arg(alias);
        let output = tokio::time::timeout(Duration::from_secs(10), command.output())
            .await
            .context("SSH configuration resolution timed out")?
            .context("Could not run ssh -G; install OpenSSH or set --ssh")?;
        ensure!(
            output.status.success(),
            "ssh -G could not resolve this target ({}); inspect the SSH configuration locally",
            output.status
        );
        let text = String::from_utf8(output.stdout).context("ssh -G produced invalid UTF-8")?;
        parse_resolved(alias, &text, &self.home)
    }
}

pub fn validate_target(target: &str) -> Result<()> {
    ensure!(
        !target.is_empty()
            && !target.starts_with('-')
            && !target.chars().any(|c| c.is_control() || c.is_whitespace()),
        "Invalid SSH target"
    );
    Ok(())
}

fn parse_resolved(alias: &str, text: &str, home: &Path) -> Result<Resolved> {
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(char::is_whitespace) {
            values
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_string());
        }
    }
    let first = |name: &str| values.get(name).and_then(|v| v.first()).map(String::as_str);
    let hostname = first("hostname")
        .context("ssh -G omitted hostname")?
        .to_string();
    let user = first("user").context("ssh -G omitted user")?.to_string();
    let port: u16 = first("port")
        .context("ssh -G omitted port")?
        .parse()
        .context("Invalid SSH port")?;
    ensure!(port != 0, "SSH port cannot be zero");
    for field in [
        "proxycommand",
        "certificatefile",
        "pkcs11provider",
        "revokedhostkeys",
    ] {
        if first(field).is_some_and(|v| !matches!(v, "none" | "(none)")) {
            bail!("SSH option {field} is unsupported");
        }
    }
    ensure!(
        !matches!(first("pubkeyauthentication"), Some("no" | "false")),
        "Public-key authentication is disabled for this target"
    );
    if let Some(methods) = first("preferredauthentications") {
        ensure!(
            methods.split(',').any(|method| method == "publickey"),
            "This target does not permit public-key authentication"
        );
    }
    let expand = |value: &str| -> Result<PathBuf> {
        let local_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_default();
        let local_host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_default();
        let mut result = String::new();
        let mut chars = value.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                result.push(c);
                continue;
            }
            match chars.next().context("Incomplete SSH path token")? {
                '%' => result.push('%'),
                'd' => result.push_str(&home.to_string_lossy()),
                'h' => result.push_str(&hostname),
                'n' => result.push_str(alias),
                'r' => result.push_str(&user),
                'p' => result.push_str(&port.to_string()),
                'u' => result.push_str(&local_user),
                'l' => result.push_str(&local_host),
                other => bail!("Unsupported SSH path token %{other}"),
            }
        }
        ensure!(
            !result.contains("${"),
            "Environment substitutions in SSH identity/trust paths are unsupported"
        );
        expand_home(&result, home)
    };
    let identities = values
        .get("identityfile")
        .into_iter()
        .flatten()
        .filter(|p| p.as_str() != "none")
        .map(|p| expand(p))
        .collect::<Result<Vec<_>>>()?;
    let mut known_hosts = Vec::new();
    for field in ["userknownhostsfile", "globalknownhostsfile"] {
        for paths in values.get(field).into_iter().flatten() {
            for path in resolved_paths(paths)? {
                if path != "none" {
                    known_hosts.push(expand(&path)?);
                }
            }
        }
    }
    ensure!(
        !known_hosts.is_empty(),
        "No known_hosts files are configured; existing host trust is required"
    );
    let identity_agent = first("identityagent")
        .map(|value| -> Result<String> {
            if matches!(value, "none" | "SSH_AUTH_SOCK") {
                Ok(value.into())
            } else {
                Ok(expand(value)?.to_string_lossy().into_owned())
            }
        })
        .transpose()?;
    let timeout = first("connecttimeout")
        .filter(|v| *v != "none")
        .map(str::parse::<u64>)
        .transpose()
        .context("Invalid ConnectTimeout")?
        .unwrap_or(30)
        .clamp(1, 120);
    Ok(Resolved {
        alias: alias.into(),
        hostname,
        user,
        port,
        identities,
        identity_agent,
        identities_only: first("identitiesonly") == Some("yes"),
        known_hosts,
        host_key_alias: first("hostkeyalias")
            .filter(|v| *v != "none")
            .map(str::to_string),
        proxy_jump: first("proxyjump")
            .filter(|v| *v != "none")
            .map(str::to_string),
        connect_timeout: Duration::from_secs(timeout),
    })
}

fn expand_home(value: &str, home: &Path) -> Result<PathBuf> {
    if value == "~" {
        Ok(home.into())
    } else if value.starts_with("~/") || value.starts_with("~\\") {
        Ok(home.join(&value[2..]))
    } else {
        ensure!(
            !value.starts_with('~'),
            "Other users' home paths are unsupported"
        );
        Ok(value.into())
    }
}

fn resolved_paths(value: &str) -> Result<Vec<String>> {
    let words = words(value)?;
    let absolute = |s: &str| {
        s.starts_with('/')
            || s.starts_with("~/")
            || s.starts_with("~\\")
            || (s.len() >= 3 && s.as_bytes()[1] == b':' && matches!(s.as_bytes()[2], b'/' | b'\\'))
    };
    if !words.first().is_some_and(|word| absolute(word)) {
        return Ok(words);
    }
    // ssh -G omits quoting around paths with spaces. Absolute path starts delimit its path list.
    let mut paths: Vec<String> = Vec::new();
    for word in words {
        if absolute(&word) || paths.is_empty() {
            paths.push(word);
        } else {
            let path = paths.last_mut().unwrap();
            path.push(' ');
            path.push_str(&word);
        }
    }
    Ok(paths)
}

fn discover(
    path: &Path,
    base: &Path,
    home: &Path,
    seen: &mut BTreeSet<PathBuf>,
    aliases: &mut BTreeSet<String>,
    depth: usize,
) -> Result<()> {
    ensure!(depth <= 32, "SSH Include nesting exceeds 32 levels");
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).with_context(|| format!("Cannot read SSH config {}", path.display()));
        }
    };
    if !seen.insert(canonical.clone()) {
        return Ok(());
    }
    let text = std::fs::read_to_string(&canonical)
        .with_context(|| format!("Cannot read SSH config {}", path.display()))?;
    for line in text.lines() {
        let line = line.trim();
        let line = if let Some((key, rest)) = line.split_once('=') {
            if !key.contains(char::is_whitespace) {
                format!("{key} {rest}")
            } else {
                line.to_string()
            }
        } else {
            line.to_string()
        };
        let tokens = words(&line)?;
        let Some(keyword) = tokens.first() else {
            continue;
        };
        if keyword.eq_ignore_ascii_case("host") {
            for alias in &tokens[1..] {
                if !alias.contains(['*', '?', '!']) && validate_target(alias).is_ok() {
                    aliases.insert(alias.clone());
                }
            }
        } else if keyword.eq_ignore_ascii_case("include") {
            for pattern in &tokens[1..] {
                let expanded = expand_home(pattern, home)?;
                let expanded = if expanded.is_absolute() {
                    expanded
                } else {
                    base.join(expanded)
                };
                for entry in glob::glob(&expanded.to_string_lossy())
                    .context("Invalid SSH Include pattern")?
                {
                    discover(&entry?, base, home, seen, aliases, depth + 1)?;
                }
            }
        }
    }
    Ok(())
}

// SSH config tokenization, preserving literal backslashes in Windows paths.
fn words(line: &str) -> Result<Vec<String>> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if chars
                .peek()
                .is_some_and(|next| next.is_whitespace() || matches!(next, '\\' | '"' | '\'' | '#'))
            {
                current.push(chars.next().unwrap());
            } else {
                current.push(c);
            }
            started = true;
        } else if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                current.push(c);
            }
        } else if matches!(c, '\'' | '"') {
            quote = Some(c);
            started = true;
        } else if c == '#' {
            break;
        } else if c.is_whitespace() {
            if started {
                result.push(std::mem::take(&mut current));
                started = false;
            }
        } else {
            current.push(c);
            started = true;
        }
    }
    ensure!(quote.is_none(), "Unterminated quote in SSH configuration");
    if started {
        result.push(current);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_handles_includes_aliases_and_cycles() -> Result<()> {
        let temp = tempfile::tempdir()?;
        std::fs::write(
            temp.path().join("config"),
            "Host alpha beta *.example !excluded\nInclude \"extra file\"\nHost=gamma # comment\n",
        )?;
        std::fs::write(
            temp.path().join("extra file"),
            "Host beta delta\nInclude config\n",
        )?;
        let mut aliases = BTreeSet::new();
        discover(
            &temp.path().join("config"),
            temp.path(),
            temp.path(),
            &mut BTreeSet::new(),
            &mut aliases,
            0,
        )?;
        assert_eq!(
            aliases.into_iter().collect::<Vec<_>>(),
            ["alpha", "beta", "delta", "gamma"]
        );
        Ok(())
    }

    #[test]
    fn config_tokens_and_resolved_options() -> Result<()> {
        assert_eq!(
            words(r#"IdentityFile "C:\Users\me\my key" # comment"#)?,
            ["IdentityFile", r"C:\Users\me\my key"]
        );
        let text = "hostname remote.example\nuser test\nport 2222\nidentityfile ~/.ssh/key\nuserknownhostsfile ~/.ssh/known_hosts\nidentitiesonly yes\nproxyjump gateway\n";
        let resolved = parse_resolved("work", text, Path::new("/home/me"))?;
        assert_eq!(resolved.identities, [PathBuf::from("/home/me/.ssh/key")]);
        assert!(resolved.identities_only);
        assert_eq!(resolved.proxy_jump.as_deref(), Some("gateway"));
        assert!(
            parse_resolved(
                "work",
                &format!("{text}proxycommand cloudflared\n"),
                Path::new("/home/me")
            )
            .is_err()
        );
        assert!(validate_target("-oProxyCommand=bad").is_err());
        assert_eq!(
            resolved_paths(
                r"C:\Users\Test User\.ssh\known_hosts C:\Users\Test User\.ssh\known_hosts2"
            )?,
            [
                r"C:\Users\Test User\.ssh\known_hosts",
                r"C:\Users\Test User\.ssh\known_hosts2"
            ]
        );
        assert!(
            parse_resolved(
                "work",
                &format!("{text}pubkeyauthentication false\n"),
                Path::new("/home/me")
            )
            .is_err()
        );
        Ok(())
    }
}
