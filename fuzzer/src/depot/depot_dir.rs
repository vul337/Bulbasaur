use bulbasaur_common::defs;
use std::{
    fs,
    path::{Path, PathBuf},
};

/// `DepotDir` contains all dir paths needed.
#[derive(Debug)]
pub struct DepotDir {
    pub inputs_dir: PathBuf,   // Directory path where inputs are stored.
    pub hangs_dir: PathBuf,    // Directory path for hangs.
    pub crashes_dir: PathBuf,  // Directory path for crashes.
    pub seeds_dir: PathBuf,    // Directory path for initial corpus (seeds).
}

impl DepotDir {
    pub fn new(seeds_dir: PathBuf, out_dir: &Path) -> Self {
        let inputs_dir = out_dir.join(defs::INPUTS_DIR);
        let hangs_dir = out_dir.join(defs::HANGS_DIR);
        let crashes_dir = out_dir.join(defs::CRASHES_DIR);

        fs::create_dir(&crashes_dir).unwrap();
        fs::create_dir(&hangs_dir).unwrap();
        fs::create_dir(&inputs_dir).unwrap();

        Self {
            inputs_dir,
            hangs_dir,
            crashes_dir,
            seeds_dir,
        }
    }
}
