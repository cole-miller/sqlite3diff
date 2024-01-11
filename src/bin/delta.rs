use clap::Parser;
use sqlite3diff::*;
use std::fs::File;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    db_file: PathBuf,
    delta_file: PathBuf,
    /// Number of checksums in the follower's signature.
    #[arg(long, short = 'f')]
    follower_checksum_count: u32,
    /// Number of matching checksums between the follower and the leader.
    #[arg(long, short = 'm')]
    matching_count: u32,
    /// Number of pages on the leader with cached checksums that don't match with the follower.
    #[arg(long, short = 's')]
    leader_addl_cached_count: u32,
}

fn main() {
    let args = Args::parse();
    let db = File::open(args.db_file).unwrap();
    let db_size = db.metadata().unwrap().len();
    assert!(db_size % PAGE_SIZE as u64 == 0);
    let page_count = (db_size / PAGE_SIZE as u64) as u32;
    assert!(args.matching_count <= args.follower_checksum_count);
    assert!(args.matching_count + args.leader_addl_cached_count <= page_count);
    let lookup = build_lookup(args.follower_checksum_count);

    let cksums = make_leader_checksums(
        page_count,
        args.matching_count,
        args.leader_addl_cached_count,
        &lookup,
    );
    let expected_delta_pages = page_count - args.matching_count;
    let expected_delta_bytes = expected_delta_pages as u64 * PAGE_SIZE as u64;
    println!(
        "Expected delta size: about {expected_delta_pages} pages, {expected_delta_bytes} bytes"
    );
    let mut delta = File::create(args.delta_file).unwrap();
    let begin = std::time::Instant::now();
    stream_delta(&db, cksums, &lookup, &mut delta).unwrap();
    dbg!(begin.elapsed());
}
