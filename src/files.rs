//! SFTP file tools. Hash preconditions detect stale reads, but are not a
//! transaction against writers outside this server.

use std::{io::SeekFrom, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssh_sftp_client::{
    Sftp,
    error::{Error as SftpError, SftpErrorKind},
    file::File as RemoteFile,
    metadata::{MetaData, Permissions},
};
use rmcp::schemars::{self, JsonSchema};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

use crate::ssh::Session;

pub const INLINE_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadFile {
    pub session_id: String,
    pub path: String,
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_read_length")]
    pub length: usize,
    #[serde(default)]
    pub encoding: Encoding,
}

fn default_read_length() -> usize {
    64 * 1024
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteFile {
    pub session_id: String,
    pub path: String,
    pub content: String,
    #[serde(default)]
    pub encoding: Encoding,
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EditFile {
    pub session_id: String,
    pub path: String,
    pub old_text: String,
    pub new_text: String,
    #[serde(default)]
    pub replace_all: bool,
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UploadFile {
    pub session_id: String,
    pub local_path: String,
    pub remote_path: String,
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DownloadFile {
    pub session_id: String,
    pub remote_path: String,
    pub local_path: String,
    #[serde(default)]
    pub overwrite: bool,
}

fn validate_path(path: &str) -> Result<()> {
    ensure!(!path.is_empty(), "path must not be empty");
    ensure!(!path.contains('\0'), "path must not contain NUL");
    Ok(())
}

/// Remote paths always use Unix separators, even on a Windows client.
pub fn remote_path(home: &str, path: &str) -> Result<String> {
    validate_path(path)?;
    if path.starts_with('/') {
        Ok(path.to_owned())
    } else {
        Ok(format!("{}/{path}", home.trim_end_matches('/')))
    }
}

fn remote_parent(path: &str) -> Result<(&str, &str)> {
    let (parent, filename) = path
        .rsplit_once('/')
        .context("expected absolute remote path")?;
    ensure!(
        !filename.is_empty() && filename != "." && filename != "..",
        "path must name a regular file"
    );
    Ok((if parent.is_empty() { "/" } else { parent }, filename))
}

fn no_such_file(error: &SftpError) -> bool {
    matches!(error, SftpError::SftpError(SftpErrorKind::NoSuchFile, _))
}

fn regular_file(metadata: &MetaData) -> Result<()> {
    ensure!(
        metadata.file_type().is_some_and(|kind| kind.is_file()),
        "path must refer to a regular file"
    );
    Ok(())
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn check_expected(expected: Option<&str>, actual: &str) -> Result<()> {
    if let Some(expected) = expected {
        ensure!(
            expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
            "expected_sha256 must contain 64 hexadecimal characters"
        );
        ensure!(
            expected.eq_ignore_ascii_case(actual),
            "content conflict: remote SHA-256 does not match expected_sha256"
        );
    }
    Ok(())
}

fn decode(content: &str, encoding: &Encoding) -> Result<Vec<u8>> {
    let data = match encoding {
        Encoding::Utf8 => {
            ensure!(
                content.len() <= INLINE_LIMIT,
                "inline content exceeds 1 MiB; use upload_file"
            );
            content.as_bytes().to_vec()
        }
        Encoding::Base64 => {
            ensure!(
                content.len() <= INLINE_LIMIT.div_ceil(3) * 4,
                "inline content exceeds 1 MiB; use upload_file"
            );
            STANDARD.decode(content).context("invalid base64 content")?
        }
    };
    ensure!(
        data.len() <= INLINE_LIMIT,
        "inline content exceeds 1 MiB; use upload_file"
    );
    Ok(data)
}

async fn read_chunk(file: &mut RemoteFile, length: u32) -> Result<Option<Vec<u8>>> {
    let offset = file.offset();
    let Some(bytes) = file.read(length, Default::default()).await? else {
        return Ok(None);
    };
    ensure!(
        !bytes.is_empty(),
        "SFTP server returned an empty non-EOF read"
    );
    // The crate advances by the requested size; short reads must advance by
    // the actual response size instead, or the next request skips file data.
    file.seek(SeekFrom::Start(
        offset
            .checked_add(bytes.len() as u64)
            .context("offset overflow")?,
    ))
    .await?;
    Ok(Some(bytes.to_vec()))
}

async fn read_bounded(
    session: &Session,
    path: &str,
    offset: u64,
    length: usize,
) -> Result<(Vec<u8>, bool)> {
    let mut file = session.sftp.open(path).await?;
    regular_file(&file.metadata().await?)?;
    file.seek(SeekFrom::Start(offset)).await?;
    let mut bytes = Vec::with_capacity(length + 1);
    while bytes.len() < length + 1 {
        let remaining = (length + 1 - bytes.len()).min(64 * 1024) as u32;
        let Some(chunk) = read_chunk(&mut file, remaining).await? else {
            break;
        };
        bytes.extend_from_slice(&chunk);
    }
    let eof = bytes.len() <= length;
    bytes.truncate(length);
    file.close().await?;
    Ok((bytes, eof))
}

pub async fn read_file(session: &Session, request: ReadFile) -> Result<Value> {
    ensure!(
        (1..=INLINE_LIMIT).contains(&request.length),
        "length must be between 1 and 1048576 bytes"
    );
    let path = remote_path(&session.home, &request.path)?;
    let (bytes, eof) = read_bounded(session, &path, request.offset, request.length).await?;
    let content = match request.encoding {
        Encoding::Utf8 => String::from_utf8(bytes.clone()).context("content is not UTF-8 or a page splits a UTF-8 character; use base64 or align byte offsets")?,
        Encoding::Base64 => STANDARD.encode(&bytes),
    };
    Ok(json!({
        "path": path,
        "content": content,
        "encoding": match request.encoding { Encoding::Utf8 => "utf8", Encoding::Base64 => "base64" },
        "bytes_read": bytes.len(),
        "next_offset": request.offset.checked_add(bytes.len() as u64).context("offset overflow")?,
        "eof": eof,
        "sha256": if request.offset == 0 && eof { Some(hash(&bytes)) } else { None },
    }))
}

struct Destination {
    path: String,
    metadata: Option<MetaData>,
}

async fn destination(session: &Session, input: &str) -> Result<Destination> {
    let path = remote_path(&session.home, input)?;
    let mut fs = session.sftp.fs();
    match fs.symlink_metadata(&path).await {
        Ok(_) => {
            // Resolve existing links before replacing, preserving the link itself.
            let path = fs
                .canonicalize(&path)
                .await?
                .to_str()
                .context("remote path is not UTF-8")?
                .to_owned();
            let metadata = fs.metadata(&path).await?;
            regular_file(&metadata)?;
            Ok(Destination {
                path,
                metadata: Some(metadata),
            })
        }
        Err(error) if no_such_file(&error) => {
            let (parent, filename) = remote_parent(&path)?;
            let parent = fs.canonicalize(parent).await?;
            let parent = parent.to_str().context("remote parent path is not UTF-8")?;
            Ok(Destination {
                path: format!("{}/{filename}", parent.trim_end_matches('/')),
                metadata: None,
            })
        }
        Err(error) => Err(error.into()),
    }
}

struct RemoteStage {
    sftp: Arc<Sftp>,
    path: String,
    armed: bool,
}

impl Drop for RemoteStage {
    fn drop(&mut self) {
        if self.armed
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let sftp = self.sftp.clone();
            let path = self.path.clone();
            runtime.spawn(async move {
                let _ = sftp.fs().remove_file(path).await;
            });
        }
    }
}

impl RemoteStage {
    fn new(session: &Session, target: &str) -> Result<Self> {
        let (parent, _) = remote_parent(target)?;
        Ok(Self {
            sftp: session.sftp.clone(),
            path: format!(
                "{}/.ssh-mcp-{}.tmp",
                parent.trim_end_matches('/'),
                Uuid::new_v4()
            ),
            armed: true,
        })
    }

    async fn cleanup(&mut self) -> Result<()> {
        self.sftp.fs().remove_file(&self.path).await?;
        self.armed = false;
        Ok(())
    }
}

async fn remote_hash(session: &Session, path: &str) -> Result<String> {
    let mut file = session.sftp.open(path).await?;
    regular_file(&file.metadata().await?)?;
    let mut digest = Sha256::new();
    while let Some(bytes) = read_chunk(&mut file, 64 * 1024).await? {
        digest.update(&bytes);
    }
    file.close().await?;
    Ok(format!("{:x}", digest.finalize()))
}

async fn verify_remote_hash(session: &Session, path: &str, expected: Option<&str>) -> Result<()> {
    if expected.is_some() {
        let actual = remote_hash(session, path)
            .await
            .context("cannot check expected_sha256 against destination")?;
        check_expected(expected, &actual)?;
    }
    Ok(())
}

fn check_commit_support(session: &Session, overwrite: bool) -> Result<()> {
    if overwrite {
        ensure!(
            session.sftp.support_posix_rename(),
            "atomic replacement requires the SFTP posix-rename extension"
        );
    } else {
        ensure!(
            session.sftp.support_hardlink(),
            "atomic no-overwrite creation requires the SFTP hardlink extension"
        );
    }
    Ok(())
}

async fn stage_file(
    session: &Session,
    stage: &RemoteStage,
) -> Result<openssh_sftp_client::file::File> {
    let mut options = session.sftp.options();
    let mut file = options
        .write(true)
        .create_new(true)
        .open(&stage.path)
        .await?;
    file.set_permissions(Permissions::from(0o600)).await?;
    Ok(file)
}

async fn commit_remote(
    session: &Session,
    stage: &mut RemoteStage,
    target: &Destination,
    overwrite: bool,
) -> Result<()> {
    if overwrite {
        session
            .sftp
            .fs()
            .rename(&stage.path, &target.path)
            .await
            .context(
                "atomic rename failed; transport failures may leave the remote outcome unknown",
            )?;
        stage.armed = false;
    } else {
        // POSIX rename overwrites. Linking instead gives atomic create-if-absent.
        session
            .sftp
            .fs()
            .hard_link(&stage.path, &target.path)
            .await
            .context("create-if-absent failed; destination may already exist")?;
        stage
            .cleanup()
            .await
            .context("destination committed, but staging-file cleanup failed")?;
    }
    Ok(())
}

async fn write_bytes(
    session: &Session,
    target: &Destination,
    bytes: &[u8],
    expected: Option<&str>,
) -> Result<()> {
    check_commit_support(session, true)?;
    verify_remote_hash(session, &target.path, expected).await?;
    let mut stage = RemoteStage::new(session, &target.path)?;
    let result = async {
        let mut file = stage_file(session, &stage).await?;
        file.write_all(bytes).await?;
        if let Some(permissions) = target.metadata.as_ref().and_then(MetaData::permissions) {
            file.set_permissions(permissions).await?;
        }
        if session.sftp.support_fsync() {
            file.sync_all().await?;
        }
        file.close().await?;
        verify_remote_hash(session, &target.path, expected).await?;
        commit_remote(session, &mut stage, target, true).await
    }
    .await;
    if result.is_err() {
        let _ = stage.cleanup().await;
    }
    result
}

pub async fn write_file(session: &Session, request: WriteFile) -> Result<Value> {
    let bytes = decode(&request.content, &request.encoding)?;
    let _guard = session.mutation_lock.lock().await;
    let target = destination(session, &request.path).await?;
    write_bytes(session, &target, &bytes, request.expected_sha256.as_deref()).await?;
    Ok(json!({"path": target.path, "bytes_written": bytes.len(), "sha256": hash(&bytes)}))
}

fn replace_text(content: &str, old: &str, new: &str, all: bool) -> Result<(String, usize)> {
    ensure!(!old.is_empty(), "old_text must not be empty");
    ensure!(
        old.len() <= INLINE_LIMIT && new.len() <= INLINE_LIMIT,
        "edit input exceeds 1 MiB"
    );
    let count = content.matches(old).count();
    ensure!(count > 0, "old_text was not found");
    ensure!(
        all || count == 1,
        "old_text is ambiguous ({count} matches); use replace_all or a more specific search"
    );
    let removed = old.len().checked_mul(count).context("edit size overflow")?;
    let inserted = new.len().checked_mul(count).context("edit size overflow")?;
    let length = content
        .len()
        .checked_sub(removed)
        .and_then(|n| n.checked_add(inserted))
        .context("edit size overflow")?;
    ensure!(
        length <= INLINE_LIMIT,
        "edited content exceeds 1 MiB; use upload_file"
    );
    Ok((content.replace(old, new), count))
}

pub async fn edit_file(session: &Session, request: EditFile) -> Result<Value> {
    let _guard = session.mutation_lock.lock().await;
    let target = destination(session, &request.path).await?;
    ensure!(target.metadata.is_some(), "cannot edit a missing file");
    let (bytes, eof) = read_bounded(session, &target.path, 0, INLINE_LIMIT).await?;
    ensure!(eof, "file exceeds 1 MiB; use download_file and upload_file");
    let before = hash(&bytes);
    check_expected(request.expected_sha256.as_deref(), &before)?;
    let content = std::str::from_utf8(&bytes).context("edit_file requires UTF-8 text")?;
    let (content, replacements) = replace_text(
        content,
        &request.old_text,
        &request.new_text,
        request.replace_all,
    )?;
    write_bytes(session, &target, content.as_bytes(), Some(&before)).await?;
    Ok(
        json!({"path": target.path, "replacements": replacements, "bytes_written": content.len(), "sha256": hash(content.as_bytes())}),
    )
}

pub async fn upload_file(session: &Session, request: UploadFile) -> Result<Value> {
    validate_path(&request.local_path)?;
    let mut source = tokio::fs::File::open(&request.local_path)
        .await
        .context("open local source")?;
    ensure!(
        source.metadata().await?.is_file(),
        "local source must be a regular file"
    );
    let _guard = session.mutation_lock.lock().await;
    let target = destination(session, &request.remote_path).await?;
    ensure!(
        request.overwrite || target.metadata.is_none(),
        "remote destination exists; set overwrite=true to replace it"
    );
    check_commit_support(session, request.overwrite)?;
    let mut stage = RemoteStage::new(session, &target.path)?;
    let result = async {
        let mut file = stage_file(session, &stage).await?;
        let mut buffer = vec![0; 64 * 1024];
        let mut digest = Sha256::new();
        let mut size = 0u64;
        loop {
            let count = source.read(&mut buffer).await?;
            if count == 0 { break; }
            file.write_all(&buffer[..count]).await?;
            digest.update(&buffer[..count]);
            size = size.checked_add(count as u64).context("transfer size overflow")?;
        }
        if let Some(permissions) = target.metadata.as_ref().and_then(MetaData::permissions) {
            file.set_permissions(permissions).await?;
        }
        if session.sftp.support_fsync() { file.sync_all().await?; }
        file.close().await?;
        commit_remote(session, &mut stage, &target, request.overwrite).await?;
        Ok(json!({"remote_path": target.path, "local_path": request.local_path, "bytes_written": size, "sha256": format!("{:x}", digest.finalize())}))
    }.await;
    if result.is_err() {
        let _ = stage.cleanup().await;
    }
    result
}

struct LocalStage {
    path: PathBuf,
    armed: bool,
}

impl Drop for LocalStage {
    fn drop(&mut self) {
        if self.armed
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let path = self.path.clone();
            runtime.spawn(async move {
                let _ = tokio::fs::remove_file(path).await;
            });
        }
    }
}

pub async fn download_file(session: &Session, request: DownloadFile) -> Result<Value> {
    validate_path(&request.local_path)?;
    let path = remote_path(&session.home, &request.remote_path)?;
    let mut remote = session.sftp.open(&path).await?;
    regular_file(&remote.metadata().await?)?;
    let local = std::path::absolute(&request.local_path)?;
    let metadata = match tokio::fs::symlink_metadata(&local).await {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    ensure!(
        request.overwrite || metadata.is_none(),
        "local destination exists; set overwrite=true to replace it"
    );
    if let Some(metadata) = &metadata {
        ensure!(
            metadata.is_file(),
            "local destination must be a regular file; local symlinks are not replaced"
        );
    }
    let parent = local
        .parent()
        .context("local destination must name a file")?;
    ensure!(
        local.file_name().is_some(),
        "local destination must name a file"
    );
    let mut stage = LocalStage {
        path: parent.join(format!(".ssh-mcp-{}.tmp", Uuid::new_v4())),
        armed: true,
    };
    let result = async {
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&stage.path).await?;
        let mut digest = Sha256::new();
        let mut size = 0u64;
        while let Some(bytes) = read_chunk(&mut remote, 64 * 1024).await? {
            file.write_all(&bytes).await?;
            digest.update(&bytes);
            size = size.checked_add(bytes.len() as u64).context("transfer size overflow")?;
        }
        remote.close().await?;
        if let Some(metadata) = &metadata { file.set_permissions(metadata.permissions()).await?; }
        file.sync_all().await?;
        drop(file);
        if request.overwrite {
            tokio::fs::rename(&stage.path, &local).await?;
            stage.armed = false;
        } else {
            tokio::fs::hard_link(&stage.path, &local).await.context("create-if-absent failed; destination may already exist or filesystem may not support hard links")?;
            tokio::fs::remove_file(&stage.path).await.context("destination committed, but staging-file cleanup failed")?;
            stage.armed = false;
        }
        Ok(json!({"remote_path": path, "local_path": local, "bytes_written": size, "sha256": format!("{:x}", digest.finalize())}))
    }.await;
    if result.is_err() && tokio::fs::remove_file(&stage.path).await.is_ok() {
        stage.armed = false;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_paths_do_not_use_client_path_rules() {
        assert_eq!(remote_path("/home/u", "a\\b").unwrap(), "/home/u/a\\b");
        assert_eq!(remote_path("/home/u", "/tmp/a").unwrap(), "/tmp/a");
        assert_eq!(remote_path("/", "a").unwrap(), "/a");
        assert_eq!(remote_parent("/a").unwrap(), ("/", "a"));
        assert!(remote_path("/home/u", "bad\0path").is_err());
        assert!(remote_parent("/tmp/").is_err());
    }

    #[test]
    fn edit_requires_an_unambiguous_match_and_preserves_newlines() {
        assert!(replace_text("a a", "a", "b", false).is_err());
        assert!(replace_text("abc", "", "b", true).is_err());
        assert!(replace_text("abc", "d", "b", true).is_err());
        assert_eq!(
            replace_text("a\r\na\n", "a", "β", true).unwrap(),
            ("β\r\nβ\n".to_string(), 2)
        );
        assert!(replace_text(&"a".repeat(INLINE_LIMIT), "a", "aa", true).is_err());
    }

    #[test]
    fn binary_encoding_and_hash_preconditions() {
        assert_eq!(decode("AP8=", &Encoding::Base64).unwrap(), vec![0, 255]);
        assert!(decode("%", &Encoding::Base64).is_err());
        assert!(decode(&"a".repeat(INLINE_LIMIT + 1), &Encoding::Utf8).is_err());
        let digest = hash(b"hello");
        assert!(check_expected(Some(&digest.to_uppercase()), &digest).is_ok());
        assert!(check_expected(Some("bad"), &digest).is_err());
        assert!(check_expected(Some(&"0".repeat(64)), &digest).is_err());
    }
}
