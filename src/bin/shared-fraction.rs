use blake2::*;
use clap::Parser;
use sqlite3diff::*;
use std::fs::File;
use std::io::prelude::*;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    follower_file: PathBuf,
    leader_file: PathBuf,
}

fn main() {
    let args = Args::parse();
    let mut follower_db = File::open(args.follower_file).unwrap();
    let mut leader_db = File::open(args.leader_file).unwrap();
    let mut follower_page_size = [0; 2];
    follower_db
        .read_exact_at(&mut follower_page_size[..], 16)
        .unwrap();
    let mut leader_page_size = [0; 2];
    leader_db
        .read_exact_at(&mut leader_page_size[..], 16)
        .unwrap();
    assert!(u16::from_be_bytes(follower_page_size) == u16::from_be_bytes(leader_page_size));
    let page_size = u16::from_be_bytes(follower_page_size);
    let mut buf = vec![0; page_size as usize].into_boxed_slice();
    let mut lookup = nohash::IntSet::default();
    loop {
        match follower_db.read_exact(&mut buf[..]) {
            Ok(()) => {
                let mut hasher = Blake2s256::new();
                hasher.update(&buf[..]);
                lookup.insert(Cksum(hasher.finalize().into()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("{e}"),
        }
    }
    let mut hits = 0;
    loop {
        match leader_db.read_exact(&mut buf[..]) {
            Ok(()) => {
                let mut hasher = Blake2s256::new();
                hasher.update(&buf[..]);
                if lookup.contains(&Cksum(hasher.finalize().into())) {
                    hits += 1;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("{e}"),
        }
    }
    let follower_pages = lookup.len();
    let frac = hits as f64 / follower_pages as f64;
    println!("{hits} pages of {follower_pages} on the follower matched with a page on the leader ({frac})");
}
