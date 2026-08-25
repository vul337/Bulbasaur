use std::{
    fs,
    io::prelude::*,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

pub fn get_file_name(dir: &Path, id: usize) -> PathBuf {
    let file_name = format!("id:{:06}", id);
    dir.join(file_name)
}

pub fn read_from_file(path: &Path) -> Vec<u8> {
    let mut file;
    let mut i = 0;
    /*
        In rare corner cases, a thread might fail to read a file written by another thread immediately.
        To handle this, we retry reading the file in a loop.
     */
    loop {
        match fs::File::open(path) {
            Ok(f) => {
                file = f;
                break;
            },
            Err(e) => {
                error!("fail to read from file : ({:?}) -- {:?}", path, e);
                thread::sleep(Duration::from_millis(100)); // sleep 0.1 seconds
            },
        };
        i += 1;
        if i == 10 {
            panic!("Failed to open {:?} after 10 retries", path);
        }
    }

    let mut buf = Vec::new();

    match file.read_to_end(&mut buf) {
        Ok(_) => (),
        _ => panic!("Failed to read to end on file {:?}", path),
    };

    buf
}
