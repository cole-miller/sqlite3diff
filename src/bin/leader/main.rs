//! This file implements a dqlite-like server that can execute SQL requests from clients against a
//! single on-disk database, trigger checkpoints, and stream checksum-based snapshots to
//! "followers". It does not implement any part of the Raft protocol.
//!
//! There are three threads:
//!
//! * The "database thread" (see `db_work`) is a long-lived thread that holds a SQLite database
//!   connection and executes transactions and checkpoints against that connection. It uses a
//!   custom VFS (see the `vfs` module).
//!
//! * The "snapshot thread" (see `follower_comms_work`) exists only when a pseudo-follower has connected to the server and
//!   requested to receive a snapshot, and lives just long enough to service that follower. Only
//!   one follower can be receiving a snapshot at a time. This thread sends "copy" and "move" instructions in the rdiff format
//!   to the follower based on the checksums received from the follower and on a local cache of
//!   checksums that is updated after each checkpoint by the database thread. When it has finished
//!   scanning the database file in this way, it checks whether a checkpoint occurred in the
//!   meantime. If so it either (based on the `CheckpointPolicy`) aborts the installation process
//!   (special rdiff instruction) or tries again by sending copies of just the pages affected by
//!   the checkpoint (another special rdiff instruction).
//! * The main thread handles client communications and dispatches work to the other two threads.
//!
//! SQLite's auto-checkpoint is turned off; you can trigger a checkpoint from outside by sending
//! SIGUSR1 to the server process. The server listens for both clients and followers on the same
//! address, provided on the command line.
//!
//! ## Wire protocols
//!
//! Requests from clients are simply SQL strings (not NUL-terminated). Only SQL requests that don't
//! return rows are supported.
//!
//! Requests from followers consist of a single NUL byte follower by a stream of 32-byte checksums.
//! The server responds using a variant of the rdiff delta format:
//!
//! * `RS_OP_LITERAL_N8`, `RS_OP_COPY_N8_N8`, and `RS_OP_END` are used in the conventional way.
//!   `RS_OP_END` always signals a *successful* end to the snapshot installation process.
//! * The byte `0xff` signals an *unsuccessful* end to the snapshot installation process.
//! * The byte `0xfe` introduces a special kind of literal command. It is followed by an 8-byte
//!   big-endian offset `start` nd an 8-byte big-endian length `len`, then by `len` bytes of
//!   literal data. The semantics is that the follower should write those `len` bytes to its
//!   database file beginning at `start`.

use bus::*;
use clap::{Parser, ValueEnum};
use indexmap::IndexMap;
use parking_lot::RwLock;
use rusqlite::ffi::*;
use signal_hook::consts::SIGUSR1;
use sqlite3diff::*;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::net::ToSocketAddrs;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::*;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use zstr::zstr;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Message(PageNumber, ErasedCksum);

type CksumCache<const N: usize> = BTreeMap<PageNumber, Cksum<N>>;

enum ErasedSharedCache {
    Cache16(RwLock<Arc<CksumCache<16>>>),
    Cache32(RwLock<Arc<CksumCache<32>>>),
}

impl ErasedSharedCache {
    fn new(cksum_len: CksumLen) -> Self {
        match cksum_len {
            CksumLen::Len16 => Self::Cache16(RwLock::new(Arc::new(BTreeMap::new()))),
            CksumLen::Len32 => Self::Cache32(RwLock::new(Arc::new(BTreeMap::new()))),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CheckpointPolicy {
    Bail,
    Persist,
}

fn follower_comms_work<const N: usize>(
    db: File,
    mut stream: mio::net::TcpStream,
    cache: &RwLock<Arc<CksumCache<N>>>,
    mut rx: BusReader<Message>,
    policy: CheckpointPolicy,
) -> anyhow::Result<BusReader<Message>> {
    let mut buf = vec![Cksum([0; N]); 5000].into_boxed_slice();
    let mut lookup = IndexMap::<_, _, nohash::BuildNoHashHasher<Cksum<N>>>::default();
    let mut pgnos = 0u32..;
    let mut off = 0;
    loop {
        let n = {
            let bytes: &mut [u8] = unsafe {
                std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast(), buf.len() * N)
            };
            let bytes = &mut bytes[off..];
            stream.read(bytes)?
        };
        if n == 0 {
            break;
        }
        off += n;
        if off % N == 0 {
            lookup.extend(buf.iter().copied().take(off / N).zip(&mut pgnos));
            off = 0;
        }
    }
    let size = db.metadata()?.len();
    assert!(size % PAGE_SIZE as u64 == 0);
    let page_count = (size / PAGE_SIZE as u64) as u32;
    let mut delta = Delta::new();
    let mut mark = u32::MAX;
    let guard = cache.read();
    for (&pgno, &cksum) in &**guard {
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
    drop(guard);
    for _ in mark..page_count {
        if let Some(del) = delta.feed(None) {
            write_del(del, &db, &mut stream)?;
        }
    }
    // flush
    write_del(delta.wip, &db, &mut stream)?;

    loop {
        let mut updated = vec![];
        while let Ok(Message(pgno, _)) = rx.try_recv() {
            updated.push(pgno);
        }
        if updated.len() == 0 {
            break;
        }
        match policy {
            CheckpointPolicy::Bail => {
                stream.write_all(&[0xff])?;
                return Ok(rx);
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
    stream.write_all(&[0])?;
    Ok(rx)
}

fn erased_follower_comms_work(
    db: File,
    stream: mio::net::TcpStream,
    cache: &ErasedSharedCache,
    rx: BusReader<Message>,
    policy: CheckpointPolicy,
) -> anyhow::Result<BusReader<Message>> {
    match *cache {
        ErasedSharedCache::Cache16(ref cache) => follower_comms_work(db, stream, cache, rx, policy),
        ErasedSharedCache::Cache32(ref cache) => follower_comms_work(db, stream, cache, rx, policy),
    }
}

enum DbReq {
    Exec(String),
    Checkpoint,
}

fn db_work<const N: usize>(
    db_name: &Path,
    mut bus: Bus<Message>,
    rx: mpsc::Receiver<DbReq>,
    cache: &RwLock<Arc<CksumCache<N>>>,
) -> anyhow::Result<()> {
    let mut bus_rx = bus.add_rx();
    let vfs = vfs::make(zstr!("unix-excl"), bus, N);
    unsafe {
        sqlite3_vfs_register(vfs, 1 /* make default */)
    };
    let conn = rusqlite::Connection::open(&db_name)?;
    conn.query_row("PRAGMA journal_mode=WAL", (), |_| Ok(()))?;
    // XXX
    conn.query_row("PRAGMA wal_autocheckpoint=0", (), |_| Ok(()))?;
    for req in rx {
        match req {
            DbReq::Exec(sql) => {
                conn.execute(&sql, ())?;
            }
            DbReq::Checkpoint => {
                unsafe {
                    sqlite3_wal_checkpoint_v2(
                        conn.handle(),
                        std::ptr::null_mut(),
                        SQLITE_CHECKPOINT_PASSIVE,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );
                }
                // update checksum cache
                while let Ok(Message(pgno, cksum)) = bus_rx.try_recv() {
                    Arc::make_mut(&mut *cache.write()).insert(pgno, cksum.recover());
                }
            }
        }
    }
    Ok(())
}

fn erased_db_work(
    db_name: &Path,
    bus: Bus<Message>,
    rx: mpsc::Receiver<DbReq>,
    cache: &ErasedSharedCache,
) -> anyhow::Result<()> {
    match *cache {
        ErasedSharedCache::Cache16(ref cache) => db_work(db_name, bus, rx, cache),
        ErasedSharedCache::Cache32(ref cache) => db_work(db_name, bus, rx, cache),
    }
}

enum Status<'a> {
    Available(BusReader<Message>),
    Busy(std::thread::ScopedJoinHandle<'a, anyhow::Result<BusReader<Message>>>),
}

#[derive(Clone, Copy, ValueEnum)]
enum CksumLen {
    Len16 = 16,
    Len32 = 32,
}

fn cksum_len_parser(s: &str) -> Result<CksumLen, Box<dyn std::error::Error + Send + Sync>> {
    match s.parse()? {
        16 => Ok(CksumLen::Len16),
        32 => Ok(CksumLen::Len32),
        _ => Err(WrongCksumSize.into()),
    }
}

#[derive(Parser)]
struct Args {
    db_name: PathBuf,
    #[arg(long)]
    addr: String,
    #[arg(long)]
    checkpoint_policy: CheckpointPolicy,
    #[arg(long, value_parser = cksum_len_parser)]
    cksum_len: CksumLen,
}

fn main() -> anyhow::Result<()> {
    let checkpoint_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGUSR1, Arc::clone(&checkpoint_flag))?;

    let Args {
        addr,
        db_name,
        checkpoint_policy,
        cksum_len,
    } = Args::parse();
    let mut bus = Bus::new(1000);
    let snapshot_rx = bus.add_rx();
    let addr = addr.to_socket_addrs()?.nth(0).unwrap();
    let mut listener = mio::net::TcpListener::bind(addr)?;
    let mut k = mio::Poll::new()?;
    let (db_tx, db_rx) = mpsc::channel();
    k.registry()
        .register(&mut listener, mio::Token(17), mio::Interest::READABLE)?;
    let mut events = mio::Events::with_capacity(100);
    let cache = ErasedSharedCache::new(cksum_len);
    std::thread::scope(|scope| {
        let _db_thread = scope.spawn(|| erased_db_work(&db_name, bus, db_rx, &cache));
        let mut status = Status::Available(snapshot_rx);
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
                    stream.read_exact(std::slice::from_mut(&mut b))?;
                    let db = File::open(&db_name)?;
                    status =
                        Status::Busy(scope.spawn(|| erased_follower_comms_work(db, stream, &cache, rx, checkpoint_policy)));
                } else {
                    let mut sql = Vec::new();
                    stream.read_to_end(&mut sql)?;
                    let sql = String::from_utf8(sql)?;
                    let _ = db_tx.send(DbReq::Exec(sql));
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
            // trigger explicit checkpoint on SIGUSR1
            if checkpoint_flag.fetch_and(false, Ordering::SeqCst) {
                let _ = db_tx.send(DbReq::Checkpoint);
            }
        }
    })
}

mod vfs;
