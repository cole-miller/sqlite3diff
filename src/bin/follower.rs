use anyhow::bail;
use blake2::{digest::*, Blake2sVar};
use byteorder::*;
use clap::Parser;
use nix::fcntl::copy_file_range;
use sqlite3diff::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::net::{Shutdown, TcpStream};
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    addr: String,
    #[arg(long)]
    from_file: Option<PathBuf>,
    #[arg(long, value_parser = cksum_len_parser)]
    cksum_len: CksumLen,
}

fn process_cmd(sock: &mut impl Read, base: &File, mut out: &File) -> anyhow::Result<Option<()>> {
    let x = match sock.read_u8()? {
        RS_OP_LITERAL_N8 => {
            let len = sock.read_u64::<BE>()?;
            std::io::copy(&mut sock.take(len), &mut out)?;
            Some(())
        }
        RS_OP_COPY_N8_N8 => {
            let start = sock.read_u64::<BE>()?;
            let len = sock.read_u64::<BE>()?;
            copy_file_range(base, Some(&mut (start as i64)), out, None, len as usize)?;
            Some(())
        }
        OP_LITERAL_AT_N8_N8 => {
            let start = sock.read_u64::<BE>()?;
            let len = sock.read_u64::<BE>()?;
            out.seek(SeekFrom::Start(start))?;
            std::io::copy(&mut sock.take(len), &mut out)?;
            Some(())
        }
        RS_OP_END => None,
        OP_DELTA_FAILED => bail!("delta installation was aborted by the leader"),
        _ => bail!("invalid command byte"),
    };
    Ok(x)
}

fn main() -> anyhow::Result<()> {
    let Args {
        addr,
        from_file: Some(path),
        cksum_len,
    } = Args::parse()
    else {
        bail!("--from-file is required")
    };
    let cksum_len = cksum_len as usize;
    let mut db = File::open(&path)?;
    let devnull = File::open("/dev/null")?;
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(&[0])?;
    let multiplier = 200;
    let mut buf = vec![0; PAGE_SIZE * multiplier];
    let mut cksum_buf = vec![0; cksum_len * multiplier];
    loop {
        let off = db.read(&mut buf[..])?;
        assert!(off % PAGE_SIZE == 0);
        for (i, pg) in buf
            .chunks_exact(PAGE_SIZE)
            .take(off / PAGE_SIZE)
            .enumerate()
        {
            let mut hasher = Blake2sVar::new(cksum_len).unwrap();
            hasher.update(pg);
            hasher
                .finalize_variable(&mut cksum_buf[i * cksum_len..(i + 1) * cksum_len])
                .unwrap();
        }
        stream.write_all(&cksum_buf[..(off / PAGE_SIZE) * cksum_len])?;
        if off < buf.len() {
            break;
        }
    }
    stream.shutdown(Shutdown::Write)?;
    while let Some(()) = process_cmd(&mut stream, &db, &devnull)? {}
    Ok(())
}
