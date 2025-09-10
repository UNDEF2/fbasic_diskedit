// Filesystem info based on YS-DOS source.

use std::path::PathBuf;
use std::error::Error;
use std::fmt;
use std::fs;

use clap::{Parser, Subcommand};


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
        if img.len() < 0x2B0 {
            return Err("Image too short".into());
        }

        let name = &img[0..17];
        if !name.contains(&0) {
            return Err("Invalid image name".into());
        }

        let mut d77 = D77 {
            name: name.try_into().unwrap(),
            raw_mode: false,
            write_protected: false,
            disk_type: DiskType::T2DD,
            disk_size: 0,
            tracks: [(); 164].map(|_| Vec::new())
        };

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

    fn find_sector_mut(&mut self, c: u8, h: u8, r: u8) -> Option<&mut Sector> {
        assert!(h < 2);
        assert!(c < 40);
        // TODO: assumes linear track layout
        for (i, s) in self.tracks[(c*2 + h) as usize].iter().enumerate() {
            if s.c == c && s.h == h && s.r == r {
                return Some(&mut self.tracks[(c*2 + h) as usize][i]);
            }
        }
        None
    }

    fn write(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        // re-serialize the D77
        let mut image = vec![0x0; 0x2B0];
        image[0..0x11].copy_from_slice(&self.name);
        image[0x11] = if self.raw_mode { 0x10 } else { 0x00 };
        image[0x1A] = if self.write_protected { 0x10 } else { 0x00 };
        image[0x1B] = match &self.disk_type {
            DiskType::T2D => 0x00,
            DiskType::T2DD => 0x10,
            DiskType::T2HD => 0x20
        };
        image[0x1C..0x20].copy_from_slice(&self.disk_size.to_le_bytes());
        for (i, t) in self.tracks.iter().enumerate() {
            // don't write a pointer for empty tracks
            if t.is_empty() {
                continue;
            }
            // current length of image is the offset for the track data
            let o = image.len() as u32;
            let b = 0x20 + 4*i;
            image[b..b+4].copy_from_slice(&o.to_le_bytes());
            let num_sectors = (t.len() as u16).to_le_bytes();
            for s in t {
                let size = s.data.len();
                let b = image.len();
                image.resize(b + size + 0x10, 0);
                image[b + 0x0] = s.c;
                image[b + 0x1] = s.h;
                image[b + 0x2] = s.r;
                image[b + 0x3] = s.n;
                image[b+0x4..b+0x6].copy_from_slice(&num_sectors);
                image[b + 0x7] = s.deleted;
                image[b + 0x8] = s.status;
                let size_bytes = (size as u16).to_le_bytes();
                image[b+0xe..b+0x10].copy_from_slice(&size_bytes);
                image[b+0x10..b+0x10+size].copy_from_slice(&s.data);
            }
        }
        Ok(image)
    }
}

struct File {
    name: [u8; 8],
    filetype: u8,
    mode: u8,
    access: u8,
    cluster: u8,
    dirty: bool
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Directory is terminated by first unused entry
        if self.name[0] == 0xFF {
            return write!(f, "[unused]");
        }
        // Deleted entries are ignored but do not terminate the listing
        if self.name[0] == 0x00 {
            return write!(f, "[deleted]");
        }
        let hexname: String;
        let print_name = match str::from_utf8(&self.name) {
            Ok(x) => x,
            _ => {
                hexname = format!("{:X?}", self.name);
                &hexname
            }
        };
        let filetype = self.filetype;
        let mode = match self.mode {
            0x00 => "B",
            0xFF => "A",
            _ => &format!("[{:02X}]", self.mode)
        };
        // TODO: speculative, though it seems correct
        let access = match self.access {
            0x00 => "S",
            0xFF => "R",
            _ => &format!("[{:02X}]", self.access)
        };
        write!(f, "{print_name} {filetype} {mode} {access}")
    }
}

struct FBasicFS {
    fat: [u8; 152],
    files: Vec<File>
}

impl FBasicFS {
    fn cluster_to_chs(cluster: u8) -> (u8, u8, u8) {
        let c = 2 + cluster/4;
        let h = (cluster/2)%2;
        let s = 1 + 8*(cluster%2);
        (c, h, s)
    }

    fn dir_index_to_pos(idx: u8) -> (u8, u8, u8, u8) {
        // make the math easier by adding dummy values for the first 3 sectors
        // of side 0 and all of track 0
        let idx_w = (idx as u16) + (32 + 3)*8;
        let sec_base = (idx_w/8) as u8;
        // skip track 0
        let c = sec_base/32;
        let h = (sec_base/16)%2;
        let s = 1 + sec_base%16;
        let i = ((idx_w%8)*32) as u8;
        (c, h, s, i)
    }

    fn parse_fs(img: &D77) -> Result<FBasicFS, Box<dyn Error>> {
        // FAT is always side 0, track 1, sector 1
        let Some(s) = img.find_sector(1, 0, 1) else {
            return Err("Could not locate FAT".into());
        };
        if s.n != 1 {
            return Err("Incorrect FAT sector N".into());
        }
        let mut fs = FBasicFS {
            fat: s.data[5..157].try_into().unwrap(),
            files: Vec::new()
        };
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
            for j in (0..0x100).step_by(0x20) {
                fs.files.push(File {
                    name: s.data[j..j+0x08].try_into().unwrap(),
                    filetype: s.data[j + 0x0B],
                    mode: s.data[j + 0x0C],
                    access: s.data[j + 0x0D],
                    cluster: s.data[j + 0x0E],
                    dirty: false
                });
            }
        }
        Ok(fs)
    }

    fn get_chain_size(&self, head: u8) -> u8 {
        let mut cluster = head;
        let mut size = 0;
        while cluster < 0xC0 {
            cluster = self.fat[cluster as usize];
            size += 1;
        }
        size
    }

    fn files(&self) {
        for f in &self.files {
            // Directory is terminated by first unused entry
            if f.name[0] == 0xFF {
                break;
            }
            // Deleted entries are ignored but do not terminate the listing
            if f.name[0] == 0x00 {
                continue;
            }
            let size = self.get_chain_size(f.cluster);
            println!("{f} {size}");
        }
        let free = self.fat.iter().filter(|&n| *n == 0xFF).count();
        println!("{free} Clusters Free");
    }

    fn read(&self, d77: &D77, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let Some(f) = self.files.iter()
            .find(|x| x.name.trim_ascii_end() == name.as_bytes()) else {
                return Err("File not found".into());
            };
        let mut cluster = f.cluster;
        let mut out: Vec<u8> = Vec::new();
        while cluster < 0xC0 {
            let (c, h, s) = Self::cluster_to_chs(cluster);
            cluster = self.fat[cluster as usize];
            let limit = if cluster >= 0xC0 { (cluster&0x07) + 1} else { 8 };
            for i in 0..limit {
                let Some(s) = d77.find_sector(c, h, s+i) else {
                    return Err(
                        "Sector {c:02X} {h:02X} {s:02X} could not be found"
                            .into());
                };
                out.extend(&s.data);
            }
        };
        // If the output is ASCII BASIC, truncate it to the 0x1A marker
        if f.filetype == 0 && f.mode == 0xFF {
            if let Some(i) = out.iter().position(|&x| x == 0x1A) {
                out.truncate(i);
            } else {
                println!("Warning: ASCII file did not contain SUB terminator");
            }
        }
        Ok(out)
    }

    // Return a directory handle in case we want to replace in-place
    fn kill(&mut self, d77: &mut D77, name: &str)
            -> Result<Option<u8>, Box<dyn Error>> {
        let Some((i, f)) = self.files.iter().enumerate()
            .find(|(_, x)| x.name.trim_ascii_end() == name.as_bytes()) else {
                return Ok(None);
            };
        let mut cluster = f.cluster;
        while cluster < 0xC0 {
            let new_cluster = self.fat[cluster as usize];
            self.fat[cluster as usize] = 0xFF;
            cluster = new_cluster;
        }
        // erase directory entry
        let f = &mut self.files[i];
        f.name[0] = 0;
        f.dirty = true;
        self.write_fs(d77);
        Ok(Some(i as u8))
    }

    fn alloc_dir(&mut self) -> Result<u8, Box<dyn Error>> {
        // look for a directory entry that is either deleted or unused
        let Some((i, _)) = self.files.iter().enumerate()
            .find(|(_, x)| x.name[0] == 0 || x.name[0] == 0xFF) else {
                return Err("No free directory entries".into());
            };
        Ok(i as u8)
    }

    fn alloc_chain(&mut self, sectors: usize) -> Result<u8, Box<dyn Error>> {
        let clusters = (sectors+7)/8;
        let free = self.fat.iter().filter(|&n| *n == 0xFF).count();
        if free < clusters {
            return Err("Insufficient space".into());
        }

        let mut head = 0xFF;
        let mut tail = 0xFF;
        let mut remaining = clusters;
        for i in 0..self.fat.len() {
            if remaining == 0 {
                break;
            }
            if self.fat[i] == 0xFF {
                if head == 0xFF {
                    head = i;
                } else {
                    self.fat[tail] = i as u8;
                }
                tail = i;
                remaining -= 1;
            }
        }

        assert!(remaining == 0);
        // terminate the list
        if sectors == 0 {
            head = 0xC0;
        } else {
            let rem = (sectors&0x07) as u8;
            // want 0 (meaning 8) to wrap to 7
            let used_in_last = rem.wrapping_sub(1) & 0x07;
            self.fat[tail] = 0xC0 | used_in_last;
        }

        Ok(head as u8)
    }

    fn write(&mut self, d77: &mut D77, name: &str, mut data: Vec<u8>,
             filetype: u8, mode: char, access: char)
             -> Result <(), Box<dyn Error>> {
        if name.len() > 8 {
            return Err("Filenames are limited to 8 characters".into());
        }
        if !name.is_ascii() || name.contains('\0') {
            return Err("Filename contains illegal character".into());
        }

        let mode = match mode {
            'B' => 0x00,
            'A' => {
                if filetype == 0 {
                    if let Some(x) = data.iter().position(|&x| x == 0x1A) {
                        println!("Warning: ASCII-mode file contains SUB. \
                                  Truncating");
                        data.truncate(x);
                    }
                    // now add our SUB terminator
                    data.push(0x1A);
                }
                0xFF
            },
            _ => return Err("Invalid mode".into()),
        };

        // pad to nearest 16B boundary with 0, then 0xFF the rest of the way.
        // this seems to be what the real F-BASIC does
        let align_16 = (data.len() + 0xF) & !0xF;
        data.resize(align_16, 0);
        // TODO: define elsewhere
        const SECTOR_SIZE: usize = 256;
        const CLUSTER_SIZE: usize = SECTOR_SIZE*8;
        let align_sector = (data.len() + SECTOR_SIZE-1) & !(SECTOR_SIZE-1);
        data.resize(align_sector, 0xFF);

        // data size is now sector-aligned
        assert!(data.len()%SECTOR_SIZE == 0);
        let num_sectors = data.len()/SECTOR_SIZE;

        // since we'll just bail without writing if there isn't enough
        // space, it's safe to delete the existing file first if it
        // already exists, giving us the best chance of success
        let dir = match self.kill(d77, &name)? {
            Some(x) => x,
            None => self.alloc_dir()?
        };

        let chain = self.alloc_chain(num_sectors)?;
        let f = &mut self.files[dir as usize];
        f.name.copy_from_slice(format!("{name:<8}").as_bytes());
        f.filetype = match filetype {
            x if x <= 2 => x,
            _ => return Err("Invalid type".into()),
        };
        f.mode = mode;
        f.access = match access {
            'S' => 0x00,
            'R' => 0xFF,
            _ => return Err("Invalid mode".into()),
        };
        f.cluster = chain;
        f.dirty = true;

        let mut cluster = chain;
        let mut i = 0;
        while i < data.len() {
            let (c, h, s) = Self::cluster_to_chs(cluster);
            let sec_in_cluster = s + ((i/SECTOR_SIZE)%8) as u8;
            let sector = d77.find_sector_mut(c, h, sec_in_cluster).unwrap();
            sector.data.copy_from_slice(&data[i..i+SECTOR_SIZE]);
            i += SECTOR_SIZE;
            if i%CLUSTER_SIZE == 0 {
                cluster = self.fat[cluster as usize];
            }
        }
        self.write_fs(d77);
        Ok(())
    }

    fn write_fs(&self, d77: &mut D77) {
        let s = d77.find_sector_mut(1, 0, 1).unwrap();
        s.data[5..157].copy_from_slice(&self.fat);
        for (idx, f) in self.files.iter().enumerate() {
            if f.dirty {
                let (c, h, r, i) = Self::dir_index_to_pos(idx as u8);
                let s = d77.find_sector_mut(c, h, r).unwrap();
                let idx = i as usize;
                // if deleted, just clear the first byte of the name and move on
                if f.name[0] == 0x00 {
                    s.data[idx] = 0;
                } else {
                    s.data[idx..idx+0x8].copy_from_slice(&f.name);
                    // zero out flags, then write the relevant fields
                    s.data[idx+0x8..idx+0x20].copy_from_slice(&[0; 0x18]);
                    s.data[idx + 0xB] = f.filetype;
                    s.data[idx + 0xC] = f.mode;
                    s.data[idx + 0xD] = f.access;
                    s.data[idx + 0xE] = f.cluster;
                }
            }
        }
    }
}

#[derive(Parser)]
struct Opts {
    image: PathBuf,
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    Files,
    Read {
        name: String,
        out_dir: PathBuf,
    },
    Write {
        in_dir: PathBuf,
        name: String,
        #[arg(short='t', default_value_t = 1)]
        filetype: u8,
        #[arg(short, default_value_t = 'B')]
        mode: char,
        #[arg(short, default_value_t = 'S')]
        access: char
    },
    Kill {
        name: String
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts = Opts::parse();
    let raw = fs::read(&opts.image)?;
    let mut d77 = D77::from_raw(&raw)?;
    let mut fbfs = FBasicFS::parse_fs(&d77)?;
    match opts.command {
        Commands::Files => fbfs.files(),
        Commands::Read{name, out_dir} => {
            let data = fbfs.read(&d77, &name)?;
            fs::write(out_dir, data)?;
        },
        Commands::Write{in_dir, name, filetype, mode, access} => {
            let data = fs::read(in_dir)?;
            fbfs.write(&mut d77, &name, data, filetype, mode, access)?;
            let img = d77.write()?;
            fs::write(&opts.image, img)?;
        },
        Commands::Kill{name} => {
            fbfs.kill(&mut d77, &name)?;
            let img = d77.write()?;
            fs::write(&opts.image, img)?;
        }
    }
    Ok(())
}
