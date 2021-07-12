use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use uuid::Uuid;

use alphonse_api as api;
use api::session::Session;
use api::utils::serde::get_ser_json_size;

#[derive(Clone, Debug, Default)]
pub struct OutputPath {
    /// The actual output path
    pub path: PathBuf,
    /// Temporary output path
    pub tmp_path: PathBuf,
}

impl<P: Into<PathBuf>> From<P> for OutputPath {
    fn from(dir: P) -> Self {
        let path = dir.into().clone();
        let tmp_path = path.join("tmp");
        Self { path, tmp_path }
    }
}

trait DebugWrite: Write + std::fmt::Debug {}
impl DebugWrite for File {}

#[derive(Debug, Default)]
pub struct Writer {
    /// alphonse output directory
    pub output_dir: OutputPath,
    /// Current opened json file path and its final location
    fpath: OutputPath,
    /// Current opened json file handle
    file: Option<Box<dyn DebugWrite>>,
    pub max_file_size: usize,
    written_size: usize,
    sessions: Vec<Box<Session>>,
}

unsafe impl Send for Writer {}
unsafe impl Sync for Writer {}

impl Writer {
    pub fn write(&mut self, ses: &Box<Session>) -> Result<()> {
        let size = get_ser_json_size(ses)?;
        if self.written_size + size >= self.max_file_size || self.file.is_none() {
            // If current size is huger than max file size or current file is a new opend file
            let fpath = generate_fpath(&self.output_dir);
            self.fpath = fpath;
            let mut file = File::create(&self.fpath.tmp_path)?;
            let size = file.write(serde_json::to_string(ses)?.as_bytes())?;
            self.written_size += size;
            self.file = Some(Box::new(file));
        } else {
            match &mut self.file {
                None => unreachable!("this should never happen"),
                Some(file) => {
                    file.write(serde_json::to_string(ses)?.as_bytes())?;
                }
            }
        }

        Ok(())
    }
}

/// Generate a random json file name
fn generate_fpath(dir: &OutputPath) -> OutputPath {
    let fname = PathBuf::from(format!("{}.json", Uuid::new_v4()));
    OutputPath {
        tmp_path: dir.tmp_path.join(fname.clone()),
        path: dir.path.join(fname),
    }
}
