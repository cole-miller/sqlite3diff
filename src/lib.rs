use rand::prelude::*;
use std::fs::File;
use std::io::prelude::*;
use std::os::fd::*;

pub const PAGE_SIZE: usize = 4096;
pub const CKSUM_SIZE: usize = 32;

fn sendfile(
    output: BorrowedFd<'_>,
    input: &File,
    start: u64,
    len: u64,
) -> Result<(), std::io::Error> {
    let mut off: libc::off_t = start.try_into().unwrap();
    let mut count: libc::size_t = len.try_into().unwrap();
    while count > 0 {
        let n = unsafe { libc::sendfile(output.as_raw_fd(), input.as_raw_fd(), &mut off, count) };
        if n == -1 {
            return Err(std::io::Error::last_os_error());
        }
        count -= n as libc::size_t;
    }
    Ok(())
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Cksum(pub [u8; CKSUM_SIZE]);

impl std::hash::Hash for Cksum {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        hasher.write_u64(u64::from_ne_bytes(self.0[..8].try_into().unwrap()));
    }
}

impl nohash::IsEnabled for Cksum {}

pub type Lookup = indexmap::IndexMap<Cksum, u64, nohash::BuildNoHashHasher<Cksum>>;

#[derive(Clone, Copy, Debug)]
pub enum Del {
    Reuse { start: u64, len: u64 },
    Transfer { start: u64, len: u64 },
}

#[derive(Debug)]
pub struct Delta {
    pos: u64,
    wip: Del,
    pages_transferred: u64,
    pages_reused: u64,
}

impl Delta {
    fn new() -> Self {
        Self {
            pos: 0,
            wip: Del::Reuse { start: 0, len: 0 },
            pages_transferred: 0,
            pages_reused: 0,
        }
    }

    fn feed(&mut self, off: Option<u64>) -> Option<Del> {
        let del = match (self.wip, off) {
            (Del::Reuse { start, ref mut len }, Some(off)) if start + *len == off => {
                *len += PAGE_SIZE as u64;
                self.pages_reused += 1;
                None
            }
            (Del::Transfer { ref mut len, .. }, None) => {
                *len += PAGE_SIZE as u64;
                self.pages_transferred += 1;
                None
            }
            (del, Some(off)) => {
                self.wip = Del::Reuse {
                    start: off,
                    len: PAGE_SIZE as u64,
                };
                self.pages_reused += 1;
                Some(del)
            }
            (reuse @ Del::Reuse { len, .. }, None) => {
                self.wip = Del::Transfer {
                    start: self.pos,
                    len: PAGE_SIZE as u64,
                };
                self.pages_transferred += 1;
                (len > 0).then(|| reuse)
            }
        };
        self.pos += PAGE_SIZE as u64;
        del
    }
}

fn stream_del(del: Del, input: &File, output: &mut (impl Write + AsFd)) -> Result<(), std::io::Error> {
    match del {
        Del::Transfer { start, len } => {
                // TODO TCP_CORK?
                let mut hdr = [0; 9];
                hdr[0] = 0x44;
                hdr[1..].copy_from_slice(&u64::to_be_bytes(len));
                output.write_all(&hdr)?;
                sendfile(output.as_fd(), input, start, len)?;
        }
        Del::Reuse { start, len } => {
                let mut hdr = [0; 17];
                hdr[0] = 0x54;
                hdr[1..9].copy_from_slice(&u64::to_be_bytes(start));
                hdr[9..].copy_from_slice(&u64::to_be_bytes(len));
                output.write_all(&hdr)?;
        }
    }
    Ok(())
}

pub fn stream_delta(
    input: &File,
    cksums: impl Iterator<Item = Option<Cksum>>,
    lookup: &Lookup,
    output: &mut (impl Write + AsFd),
) -> Result<(), std::io::Error> {
    let mut delta = Delta::new();
    let (mut hit_count, mut miss_count, mut unavailable_count) = (0, 0, 0);
    for cksum in cksums {
        let off = match cksum {
            None => {
                unavailable_count += 1;
                None
            }
            Some(cksum) => {
                match lookup.get(&cksum) {
                    None => {
                        miss_count += 1;
                        None
                    }
                    Some(&off) => {
                        hit_count += 1;
                        Some(off)
                    }
                }
            }
        };
        if let Some(del) = delta.feed(off) {
            stream_del(del, input, output)?;
        }
    }
    // flush
    stream_del(delta.wip, input, output)?;
    output.write_all(&[0])?;
    dbg!(hit_count);
    dbg!(miss_count);
    dbg!(unavailable_count);
    println!("Delta stats: {delta:?}");
    Ok(())
}

pub fn build_lookup(n: u64) -> Lookup {
    let mut rng = SmallRng::from_entropy();
    (0..n)
        .map(|i| (Cksum(rng.gen()), i * PAGE_SIZE as u64))
        .collect()
}

struct Lcg {
    state: u64,
}

impl RngCore for Lcg {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    
    fn next_u64(&mut self) -> u64 {
        self.state *= 0x7c3c3267d015ceb5;
        self.state += 0x24bd2d95276253a9;
        self.state
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= dest.len() {
            dest[i..i + 8].copy_from_slice(&u64::to_ne_bytes(self.next_u64()));
            i += 8;
        }
        let k = dest.len() - i;
        dest[i..].copy_from_slice(&u64::to_ne_bytes(self.next_u64())[..k]);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

pub fn make_leader_checksums(
    num_pages: u64,
    matching_count: u64,
    non_matching_count: u64,
    lookup: &Lookup,
) -> impl '_ + Iterator<Item = Option<Cksum>> {
    struct MakeChecksums<'a> {
        matching_count: u64,
        non_matching_count: u64,
        non_cached_count: u64,
        lookup: &'a Lookup,
        rng: Lcg,
    }

    impl<'a> Iterator for MakeChecksums<'a> {
        type Item = Option<Cksum>;

        fn next(&mut self) -> Option<Self::Item> {
            let slice = self.lookup.as_slice();
            let x = self.rng.gen_range(0..slice.len() as u64);
            let matching = *slice.get_index(x as usize).unwrap().0;
            // gin up a checksum that's unlikely to be in the table
            let mut non_matching = [0; CKSUM_SIZE];
            non_matching[..8].copy_from_slice(&u64::to_be_bytes(x)[..]);
            let non_matching = Cksum(non_matching);
            let mut pairs = [(Some(matching), &mut self.matching_count), (Some(non_matching), &mut self.non_matching_count), (None, &mut self.non_cached_count)];
            let pair = pairs.choose_weighted_mut(&mut self.rng, |it| *it.1).unwrap();
            *pair.1 -= 1;
            Some(pair.0)
        }
    }

    let non_cached_count = num_pages - matching_count - non_matching_count;
    (MakeChecksums {
        matching_count: dbg!(matching_count),
        non_matching_count: dbg!(non_matching_count),
        non_cached_count: dbg!(non_cached_count),
        lookup,
        rng: Lcg { state: 17 },
    }).take(num_pages as usize)
}
