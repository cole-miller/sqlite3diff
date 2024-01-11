use bus::*;
use clap::{Parser, ValueEnum};
use indexmap::IndexMap;
use rusqlite::ffi::*;
use signal_hook::consts::SIGUSR1;
use sqlite3diff::{sendfile, write_del, Cksum, Delta, PageNumber, CKSUM_SIZE, PAGE_SIZE};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::net::ToSocketAddrs;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::*;
use std::sync::Arc;
use std::time::Duration;
use zstr::zstr;

#[derive(Clone, Copy)]
enum Message {
    WalWrite(PageNumber, Cksum),
    DbWrite(PageNumber),
}

type CksumCache = BTreeMap<PageNumber, Cksum>;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CheckpointPolicy {
    Bail,
    Persist,
}

fn follower_comms_work(
    db: File,
    mut stream: mio::net::TcpStream,
    cache: Arc<CksumCache>,
    mut rx: BusReader<Message>,
    policy: CheckpointPolicy,
) -> anyhow::Result<BusReader<Message>> {
    let mut buf = vec![Cksum([0; CKSUM_SIZE]); 5000].into_boxed_slice();
    let mut lookup = IndexMap::<_, _, nohash::BuildNoHashHasher<Cksum>>::default();
    let mut pgnos = 0u32..;
    let mut off = 0;
    loop {
        let n = {
            let bytes: &mut [u8] = unsafe {
                std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast(), buf.len() * CKSUM_SIZE)
            };
            let bytes = &mut bytes[off..];
            stream.read(bytes)?
        };
        if n == 0 {
            break;
        }
        off += n;
        if off % CKSUM_SIZE == 0 {
            lookup.extend(buf.iter().copied().take(off / CKSUM_SIZE).zip(&mut pgnos));
            off = 0;
        }
    }
    let size = db.metadata()?.len();
    assert!(size % PAGE_SIZE as u64 == 0);
    let page_count = (size / PAGE_SIZE as u64) as u32;
    let mut delta = Delta::new();
    let mut mark = u32::MAX;
    for (&pgno, &cksum) in &*cache {
        for _ in mark..pgno {
            if let Some(del) = delta.feed(None) {
                write_del(del, &db, &mut stream)?;
            }
        }
        if let Some(del) = delta.feed(lookup.get(&cksum).copied()) {
            write_del(del, &db, &mut stream)?;
        }
        mark = pgno + 1;
    }
    for _ in mark..page_count {
        if let Some(del) = delta.feed(None) {
            write_del(del, &db, &mut stream)?;
        }
    }
    // flush
    write_del(delta.wip, &db, &mut stream)?;

    loop {
        let mut updated = vec![];
        while let Ok(msg) = rx.try_recv() {
            if let Message::DbWrite(pgno) = msg {
                updated.push(pgno);
            }
        }
        if updated.len() == 0 {
            break;
        }
        match policy {
            CheckpointPolicy::Bail => {
                stream.write_all(&[0xff])?;
            }
            CheckpointPolicy::Persist => {
                for pgno in updated {
                    let mut hdr = [0; 17];
                    hdr[0] = 0xfe;
                    let start = pgno as u64 & PAGE_SIZE as u64;
                    hdr[1..9].copy_from_slice(&u64::to_be_bytes(start));
                    hdr[9..].copy_from_slice(&u64::to_be_bytes(PAGE_SIZE as u64));
                    sendfile(stream.as_raw_fd(), &db, start, PAGE_SIZE as u64)?;
                }
            }
        }
    }
    // then loop checking for checkpoint notifications until there are none, handling them by
    // sending pages (need to extend the wire format to support this)
    stream.write_all(&[0])?;
    Ok(rx)
}

enum Status {
    Available(BusReader<Message>),
    Busy(std::thread::JoinHandle<anyhow::Result<BusReader<Message>>>),
}

#[derive(Parser)]
struct Args {
    addr: String,
    db_name: PathBuf,
    checkpoint_policy: CheckpointPolicy,
}

fn main() -> anyhow::Result<()> {
    let checkpoint_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGUSR1, Arc::clone(&checkpoint_flag))?;

    let args = Args::parse();
    let mut bus = Bus::new(1000);
    let mut my_rx = bus.add_rx();
    let snapshot_rx = bus.add_rx();
    let vfs = vfs::make(zstr!("unix-excl"), bus);
    unsafe {
        sqlite3_vfs_register(vfs, 1 /* make default */);
    }
    let conn = rusqlite::Connection::open(&args.db_name)?;
    conn.execute("PRAGMA journal_mode=WAL", ())?;
    // XXX
    conn.execute("PRAGMA wal_autocheckpoint=0", ())?;
    let addr = args.addr.to_socket_addrs()?.nth(0).unwrap();
    let mut listener = mio::net::TcpListener::bind(addr)?;
    let mut status = Status::Available(snapshot_rx);
    let mut cache = Arc::new(BTreeMap::new());
    let mut k = mio::Poll::new()?;
    k.registry()
        .register(&mut listener, mio::Token(17), mio::Interest::READABLE)?;
    let mut events = mio::Events::with_capacity(100);
    loop {
        // handle any new client or follower
        k.poll(&mut events, Some(Duration::from_millis(10)))?;
        if events.iter().count() > 0 {
            let (mut stream, _) = listener.accept()?;
            let mut b = 0;
            let n = stream.peek(std::slice::from_mut(&mut b))?;
            if n == 0 {
                continue;
            }
            if b == b'\0' {
                let Status::Available(rx) = status else {
                    continue;
                };
                let db = File::open(&args.db_name)?;
                let cache = Arc::clone(&cache);
                let policy = args.checkpoint_policy;
                status = Status::Busy(std::thread::spawn(move || {
                    follower_comms_work(db, stream, cache, rx, policy)
                }));
            } else {
                let mut sql = Vec::new();
                stream.read_to_end(&mut sql)?;
                let sql = String::from_utf8(sql)?;
                conn.execute(&sql, ())?;
            }
        }
        // handle any follower that's finished getting up to date
        if let Status::Busy(ref handle) = status {
            if handle.is_finished() {
                let Status::Busy(handle) = status else {
                    unreachable!()
                };
                status = match handle.join() {
                    Ok(res) => Status::Available(res?),
                    Err(e) => std::panic::resume_unwind(e),
                };
            }
        }
        // handle backlog of newly-computed checksums
        while let Ok(msg) = my_rx.try_recv() {
            if let Message::WalWrite(pgno, cksum) = msg {
                Arc::make_mut(&mut cache).insert(pgno, cksum);
            }
        }
        // trigger explicit checkpoint on SIGUSR1
        if checkpoint_flag.fetch_and(false, Ordering::SeqCst) {
            unsafe {
                sqlite3_wal_checkpoint_v2(
                    conn.handle(),
                    std::ptr::null_mut(),
                    SQLITE_CHECKPOINT_PASSIVE,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
            }
        }
    }
}

mod vfs;
