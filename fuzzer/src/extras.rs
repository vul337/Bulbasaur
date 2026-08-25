use std::fs::{File, read_dir};
use std::io::Read;
use std::path::Path;
use std::io::BufReader;
use std::io::BufRead;
use std::cmp::{min, max};

const MAX_DICT_FILE: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraData {
    pub data: Vec<u8>,
    pub len: usize,
}

impl Ord for ExtraData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.len.cmp(&other.len)
    }
}

impl PartialOrd for ExtraData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn dms(size: usize) -> String {
    if size >= 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else {
        format!("{} B", size)
    }
}

pub fn load_extras(paths: Vec<&str>) -> Vec<ExtraData> {
    let mut extras = Vec::<ExtraData>::new();
    let mut min_len = MAX_DICT_FILE;
    let mut max_len = 0;

    for dir_str in paths {
        let mut dict_level = 0;

        // Deal with "@level"
        let mut path_str = dir_str.to_string();
        if let Some(at_pos) = path_str.find('@') {
            dict_level = path_str[at_pos + 1..].parse::<u32>().unwrap_or(0);
            path_str.truncate(at_pos);
        }

        let path = Path::new(&path_str);

        info!(
            "[*] Loading extra dictionary from '{}' (level {})...",
            path.display(),
            dict_level
        );

        if path.is_file() {
            load_extras_file(&mut extras, path, &mut min_len, &mut max_len, dict_level);
        } else if path.is_dir() {
            if dir_str.contains('@') {
                panic!("Dictionary levels not supported for directories.");
            }

            let entries = read_dir(path).unwrap_or_else(|e| {
                panic!("Unable to open '{}': {}", path.display(), e);
            });

            for entry in entries {
                let entry = entry.unwrap();
                let file_path = entry.path();
                let metadata = entry.metadata().unwrap();

                if !metadata.is_file() || metadata.len() == 0 {
                    continue;
                }

                let size = metadata.len() as usize;
                if size > MAX_DICT_FILE {
                    warn!(
                        "Extra '{}' is too big ({} > {})",
                        file_path.display(),
                        dms(size),
                        dms(MAX_DICT_FILE)
                    );
                    continue;
                }

                min_len = min_len.min(size);
                max_len = max_len.max(size);

                let mut data = vec![0u8; size];
                let mut file = File::open(&file_path)
                    .unwrap_or_else(|_| panic!("Unable to open '{}'", file_path.display()));
                file.read_exact(&mut data)
                    .unwrap_or_else(|_| panic!("Failed to read '{}'", file_path.display()));

                assert!(data.len() == size);
                extras.push(ExtraData {
                    data,
                    len: size,
                });
            }
        } else {
            panic!("Unable to open '{}': Not a file or directory", path.display());
        }
    }

    if extras.is_empty() {
        return extras
    }

    extras.sort();

    info!(
        "Loaded {} extra tokens, size range {} to {}.",
        extras.len(),
        dms(min_len),
        dms(max_len)
    );

    if max_len > 32 {
        warn!(
            "Some tokens are relatively large ({}) - consider trimming.",
            dms(max_len)
        );
    }

    deunicode_extras(&mut extras);
    dedup_extras(&mut extras);

    info!("Loaded a total of {} extras.", extras.len());

    extras
}


fn load_extras_file<P: AsRef<Path>>(
    extras: &mut Vec<ExtraData>,
    fname: P,
    min_len: &mut usize,
    max_len: &mut usize,
    dict_level: u32,
) {
    let file = File::open(&fname).unwrap_or_else(|_| panic!("Unable to open '{}'.", fname.as_ref().display()));
    let reader = BufReader::new(file);

    for (cur_line, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        let mut lptr = line.trim().to_string();

        if lptr.is_empty() || lptr.starts_with('#') {
            continue;
        }

        if !lptr.ends_with('"') {
            warn!("[WARN] Malformed name=\"value\" pair in line {}", cur_line + 1);
            continue;
        }

        lptr.pop(); // Remove the ending '"'

        // Skip label (alnum, _, etc)
        let pos = lptr.find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(lptr.len());

        lptr = lptr[pos..].to_string();
        let mut lptr = lptr.trim_start();

        if let Some(rest) = lptr.strip_prefix('@') {
            let mut num_str = String::new();
            for c in rest.chars() {
                if c.is_ascii_digit() {
                    num_str.push(c);
                } else {
                    break;
                }
            }
            if num_str.parse::<u32>().unwrap_or(0) > dict_level {
                continue;
            }
            lptr = &rest[num_str.len()..];
        }

        if let Some(rest) = lptr.strip_prefix('[') {
            if let Some(end_bracket) = rest.find(']') {
                lptr = &rest[end_bracket + 1..];
            }
        }

        lptr = lptr.trim_start_matches(|c: char| c.is_whitespace() || c == '=');

        if !lptr.starts_with('"') {
            warn!("[WARN] Malformed name=\"keyword\" pair in line {}", cur_line + 1);
            continue;
        }

        lptr = &lptr[1..]; // Skip opening quote

        if lptr.is_empty() {
            warn!("[WARN] Empty keyword in line {}.", cur_line + 1);
            continue;
        }

        let mut data = Vec::with_capacity(lptr.len());
        let mut chars = lptr.chars().peekable();
        let mut klen = 0;

        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some('\\') => { data.push(b'\\'); klen += 1; },
                    Some('"') => { data.push(b'"'); klen += 1; },
                    Some('x') => {
                        let h1 = chars.next();
                        let h2 = chars.next();
                        if let (Some(h1), Some(h2)) = (h1, h2) {
                            if let (Some(v1), Some(v2)) = (h1.to_digit(16), h2.to_digit(16)) {
                                data.push(((v1 << 4) | v2) as u8);
                                klen += 1;
                            } else {
                                warn!("[WARN] Invalid escaping (not \\xNN) in line {}", cur_line + 1);
                                continue;
                            }
                        }
                    }
                    _ => {
                        warn!("[WARN] Invalid escape in line {}", cur_line + 1);
                        continue;
                    }
                },
                c if (c as u8) < 32 || (c as u8) > 127 => {
                    warn!("[WARN] Non-printable character in line {}.", cur_line + 1);
                    continue;
                },
                _ => {
                    data.push(c as u8);
                    klen += 1;
                }
            }
        }

        if klen > MAX_DICT_FILE {
            warn!(
                "[WARN] Keyword too big in line {} ({} bytes, limit is {})",
                cur_line + 1,
                dms(klen),
                dms(MAX_DICT_FILE)
            );
            continue;
        }

        *min_len = min(*min_len, klen);
        *max_len = max(*max_len, klen);

        assert!(data.len() == klen);

        extras.push(ExtraData { data, len: klen });
    }
}

/* Sometimes strings in input is transformed to unicode internally, so for
   fuzzing we should attempt to de-unicode if it looks like simple unicode */
pub fn deunicode_extras(extras: &mut Vec<ExtraData>) {

    if extras.is_empty() {
        return
    }

    let orig_cnt = extras.len();
    let mut new_extras = Vec::new();
    let mut buf = [0u8; 64];

    for i in 0..orig_cnt {
        let extra = &extras[i];

        if extra.len < 6 || extra.len > 64 || extra.len % 2 != 0 {
            continue;
        }

        let mut z1 = 0;
        let mut z2 = 0;
        let mut z3 = 0;
        let mut z4 = 0;
        let half = extra.len / 2;
        let quarter = half / 2;

        for (j, &byte) in extra.data.iter().enumerate() {
            match j % 4 {
                2 => {
                    if byte == 0 { z3 += 1; }
                    if byte == 0 { z1 += 1; }
                }
                0 => {
                    if byte == 0 { z1 += 1; }
                }
                3 => {
                    if byte == 0 { z4 += 1; }
                    if byte == 0 { z2 += 1; }
                }
                1 => {
                    if byte == 0 { z2 += 1; }
                }
                _ => {}
            }
        }

        if (z1 < half && z2 < half) || (z1 + z2 == extra.len) {
            continue;
        }

        if extra.len % 4 == 0 && extra.len >= 12 &&
            (z3 == quarter || z4 == quarter) &&
            (z1 + z2 == quarter * 3) {

            let mut k = 0;
            for (j, &byte) in extra.data.iter().enumerate() {
                if z4 < quarter {
                    if j % 4 == 3 { buf[k] = byte; k += 1; }
                } else if z3 < quarter {
                    if j % 4 == 2 { buf[k] = byte; k += 1; }
                } else if z2 < half {
                    if j % 4 == 1 { buf[k] = byte; k += 1; }
                } else {
                    if j % 4 == 0 { buf[k] = byte; k += 1; }
                }
            }

            new_extras.push(ExtraData {
                data: buf[..k].to_vec(),
                len: k,
            });
        }

        let mut k = 0;
        for (j, &byte) in extra.data.iter().enumerate() {
            if z1 < half {
                if j % 2 == 0 { buf[k] = byte; k += 1; }
            } else {
                if j % 2 == 1 { buf[k] = byte; k += 1; }
            }
        }

        new_extras.push(ExtraData {
            data: buf[..k].to_vec(),
            len: k,
        });
    }

    extras.extend(new_extras);
    extras.sort();
}

pub fn dedup_extras(extras: &mut Vec<ExtraData>){
    if extras.len() < 2 {
        return;
    }

    let mut i = 0;
    while i < extras.len() - 1 {
        let mut j = i + 1;
        while j < extras.len() {
            if extras[i].len != extras[j].len {
                j += 1;
                continue;
            }

            if extras[i].data == extras[j].data {
                extras.remove(j);
                continue;
            }

            j += 1;
        }

        i += 1;
    }
}