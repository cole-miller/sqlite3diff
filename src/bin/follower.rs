use clap::Parser;
use blake2::{Blake2sVar, digest::*};
use std::io::prelude::*;
use sqlite3diff::*;
use std::net::{TcpStream, Shutdown};
use anyhow::bail;
use std::fs::File;
use std::path::PathBuf;
use sqlite3diff::PAGE_SIZE;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    addr: String,
    #[arg(long)]
    from_file: Option<PathBuf>,
    #[arg(long, value_parser = cksum_len_parser)]
    cksum_len: CksumLen,
}

fn main() -> anyhow::Result<()> {
    let Args { addr, from_file: Some(path), cksum_len } = Args::parse() else {
        bail!("--from-file is required")
    };
    let cksum_len = cksum_len as usize;
    let mut db = File::open(&path)?;
    let mut devnull = File::open("/dev/null")?;
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(&[0])?;
    let multiplier = 200;
    let mut buf = vec![0; PAGE_SIZE * multiplier];
    let mut cksum_buf = vec![0; cksum_len * multiplier];
    loop {
        let off = db.read(&mut buf[..])?;
        assert!(off % PAGE_SIZE == 0);
        for (i, pg) in buf.chunks_exact(PAGE_SIZE).take(off / PAGE_SIZE).enumerate() {
            let mut hasher = Blake2sVar::new(cksum_len).unwrap();
            hasher.update(pg);
            hasher.finalize_variable(&mut cksum_buf[i * cksum_len..(i + 1) * cksum_len]).unwrap();
        }
        stream.write_all(&cksum_buf[..(off / PAGE_SIZE) * cksum_len])?;
        if off < buf.len() { break }
    }
    stream.shutdown(Shutdown::Write)?;
    std::io::copy(&mut stream, &mut devnull)?;
    Ok(())
}
