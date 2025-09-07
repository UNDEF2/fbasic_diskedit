use std::env;
use std::error::Error;
use std::fs;

enum DiskType {
    T2D,
    T2DD,
    T2HD
}

struct Sector {
    c: u8,
    h: u8,
    r: u8,
    n: u8,
    density: u8,
    deleted: u8,
    status: u8,
    data: Vec<u8>
}

impl Sector {
    fn new() -> Sector {
        Sector {
            c: 0,
            h: 0,
            r: 0,
            n: 0,
            density: 0,
            deleted: 0,
            status: 0,
            data: Vec::new()
        }
    }
}

struct D77 {
    name: [u8; 17],
    raw_mode: bool,
    write_protected: bool,
    disk_type: DiskType,
    disk_size: u32,
    tracks: [Vec<Sector>; 164]
}

impl D77 {
    fn from_raw(img: &[u8]) -> Result<D77, Box<dyn Error>> {
        if img.len() < 0x2b0 {
            return Err("Image too short".into());
        }
        let mut d77 = D77 {
            name: [0;17],
            raw_mode: false,
            write_protected: false,
            disk_type: DiskType::T2DD,
            disk_size: 0,
            tracks: [(); 164].map(|_| Vec::new())
        };
        let mut seen_terminator = false;
        for i in 0..d77.name.len() {
            let c = img[i];
            d77.name[i] = c;
            if c == 0 {
                seen_terminator = true;
                break;
            }
        }
        if !seen_terminator {
            return Err("Invalid image name".into());
        }

        d77.raw_mode = match img[0x11] {
            0x00 => false,
            0x10 => return Err("Raw mode unsupported".into()),
            _ => return Err("Invalid raw mode flag".into())
        };

        d77.write_protected = match img[0x1a] {
            0x00 => false,
            0x10 => true,
            _ => return Err("Invalid write protect flag".into())
        };

        d77.disk_type = match img[0x1b] {
            0x00 => DiskType::T2D,
            0x10 => DiskType::T2DD,
            0x20 => DiskType::T2HD,
            _ => return Err("Invalid disk type".into())
        };

        d77.disk_size = u32::from_le_bytes(img[0x1c..0x20].try_into().unwrap());

        if d77.disk_size as usize != img.len() {
            return Err("Image size inconsistent. \
                        Multidisk images unsupported".into());
        }

        for (i, t) in d77.tracks.iter_mut().enumerate() {
            let base = 0x20 + 4*i;
            let mut ptr = u32::from_le_bytes(img[base..base+4].try_into()
                                             .unwrap()) as usize;
            // pointer 0 means track is unused
            if ptr == 0 {
                continue;
            }

            if ptr + 0x6 > d77.disk_size as usize {
                return Err("Track pointer out of bounds".into());
            }
            // get number of sectors in track for later consistency checks
            let nsec = u16::from_le_bytes(img[ptr+0x4..ptr+0x6].try_into()
                                          .unwrap());

            for j in 0..nsec {
                if ptr + 0x10 > d77.disk_size as usize {
                    return Err(
                        format!("Track {i} sector {j} header out of bounds")
                            .into());
                }
                let mut s = Sector::new();
                s.c = img[ptr+0x0];
                s.h = img[ptr+0x1];
                s.r = img[ptr+0x2];
                s.n = img[ptr+0x3];
                // println!("C:{} H:{} R:{} N:{}", s.c, s.h, s.r, s.n);
                if s.n >= 4 {
                    return Err(format!("Bad sector N value {}", s.n).into());
                }

                let ns = u16::from_le_bytes(img[ptr+0x4..ptr+0x6].try_into()
                                            .unwrap());
                if ns != nsec {
                    return Err(format!(
                        "Track {i} inconsistent number of sectors").into());
                }

                // TODO: sanity check
                s.density = img[ptr+0x6];
                s.deleted = img[ptr+0x7];
                s.status = img[ptr+0x8];
                let size = u16::from_le_bytes(img[ptr+0xe..ptr+0x10].try_into()
                                              .unwrap()) as usize;
                if size != 128 << s.n {
                    println!("Warning: Sector {i} size inconsistent");
                }

                if ptr + 0x10 + size > img.len() as usize {
                    return Err(format!("C:{} H:{} R:{} N:{} \
                                        data runs off end of disk",
                                       s.c, s.h, s.r, s.n).into());
                }
                s.data = img[ptr+0x10..ptr+0x10+size].to_vec();
                t.push(s);
                ptr += size + 0x10;
            }
        }
        Ok(d77)
    }

    fn find_sector(&self, c: u8, h: u8, r: u8) -> Option<&Sector> {
        assert!(h < 2);
        assert!(c < 40);
        // TODO: assumes linear track layout
        for s in &self.tracks[(c*2 + h) as usize] {
            if s.c == c && s.h == h && s.r == r {
                return Some(&s);
            }
        }
        None
    }
}

struct FBasicFS {
    // cluster_chains[];
}

fn parse_fs(img: &D77) -> Result<FBasicFS, Box<dyn Error>> {
    // FAT is always side 0, track 1, sector 1
    /*
    for s in &img.tracks[1] {
        if s.h == 0 && s.c == 1 && s.r == 1 {
            if s.n < 1 {
                return Err("FAT sector too small".into());
            }
            let mut fs = FBasicFS{};
            return Ok(fs);
        }
    }
    Err("Could not locate FAT".into())
     */
    for i in 3..32 {
        let c = 1;
        let h = i/16;
        let s = i%16 + 1;
        let Some(s) = img.find_sector(c, h, s) else {
            return Err("Incomplete directory".into());
        };
        if s.n != 1 {
            return Err("Incorrect directory sector N".into());
        }
        for j in (0..256).step_by(32) {
            if s.data[j] == 0xFF {
                continue;
            }
            let print_name = match str::from_utf8(&s.data[j..j+8]) {
                Ok(s) => s,
                _ => "[unprintable]"
            };
            let filetype = s.data[j + 0x0B];
            let mode = match s.data[j + 0x0C] {
                0x00 => 'B',
                0xFF => 'A',
                _ => return Err("Unrecognized file mode".into())
            };
            // TODO: speculative
            let access = match s.data[j + 0x0D] {
                0x00 => 'S',
                0xFF => 'R',
                _ => return Err("Unrecognized file access mode".into())

            };
            println!("{print_name} {filetype} {mode} {access}");
        }
    }
    todo!()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err("Must supply exactly one argument: input file name".into());
    }
    let raw = fs::read(&args[1])?;
    let img = D77::from_raw(&raw)?;
    parse_fs(&img);
    Ok(())
}
