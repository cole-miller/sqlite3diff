use crate::{Message, PageNumber};
use blake2::{digest::*, Blake2sVar};
use bus::Bus;
use rusqlite::ffi::*;
use sqlite3diff::{ErasedCksum, MAX_CKSUM_SIZE, PAGE_SIZE};
use std::cell::{Cell, RefCell};
use std::ffi::*;
use std::mem::ManuallyDrop;
use zstr::zstr;

fn vtable() -> &'static sqlite3_io_methods {
    macro_rules! forward_to_orig {
        ( $name:ident (*mut sqlite3_file $(,)? $($a:ident: $t:ty),* $(,)?) $(-> $rt:ty)?) => { {
            #[allow(non_snake_case)]
            unsafe extern "C" fn $name(f: *mut sqlite3_file, $($a: $t),*) $(-> $rt)? {
                let orig = unsafe { f.cast::<File>().read().orig };
                let orig_method = unsafe { (*orig).pMethods.read().$name.unwrap() };
                unsafe { orig_method(orig, $($a),*) }
            }
            Some($name)
        } }
    }

    #[allow(non_snake_case)]
    unsafe extern "C" fn xClose(f: *mut sqlite3_file) -> c_int {
        let orig = unsafe { f.cast::<File>().read().orig };
        let orig_method = unsafe { (*orig).pMethods.read().xClose.unwrap() };
        let e = unsafe { orig_method(orig) };
        unsafe {
            sqlite3_free(orig.cast());
        }
        e
    }

    #[allow(non_snake_case)]
    unsafe extern "C" fn xWrite(
        f: *mut sqlite3_file,
        p: *const c_void,
        len: c_int,
        off: i64,
    ) -> c_int {
        match write_impl(
            unsafe { f.cast::<File>().as_ref().unwrap() },
            unsafe { std::slice::from_raw_parts(p.cast::<u8>(), len as usize) },
            off,
        ) {
            Ok(()) => SQLITE_OK,
            Err(e) => e,
        }
    }

    &sqlite3_io_methods {
        iVersion: 3,
        xCheckReservedLock: forward_to_orig!(xCheckReservedLock(*mut sqlite3_file, p: *mut c_int) -> c_int),
        xClose: Some(xClose),
        xDeviceCharacteristics: forward_to_orig!(
            xDeviceCharacteristics(*mut sqlite3_file) -> c_int
        ),
        xFetch: forward_to_orig!(xFetch(*mut sqlite3_file, o: i64, n: c_int, p: *mut *mut c_void) -> c_int),
        xFileControl: forward_to_orig!(xFileControl(*mut sqlite3_file, op: c_int, p: *mut c_void) -> c_int),
        xFileSize: forward_to_orig!(xFileSize(*mut sqlite3_file, z: *mut i64)-> c_int),
        xLock: forward_to_orig!(xLock(*mut sqlite3_file, n: c_int) -> c_int),
        xRead: forward_to_orig!(xRead(*mut sqlite3_file, p: *mut c_void, n: c_int, o: i64) -> c_int),
        xSectorSize: forward_to_orig!(xSectorSize(*mut sqlite3_file) -> c_int),
        xShmBarrier: forward_to_orig!(xShmBarrier(*mut sqlite3_file)),
        xShmLock: forward_to_orig!(xShmLock(*mut sqlite3_file, o: c_int, n: c_int, f: c_int) -> c_int),
        xShmMap: forward_to_orig!(xShmMap(*mut sqlite3_file, g: c_int, z: c_int, n: c_int, p: *mut *mut c_void) -> c_int),
        xShmUnmap: forward_to_orig!(xShmUnmap(*mut sqlite3_file, d: c_int) -> c_int),
        xSync: forward_to_orig!(xSync(*mut sqlite3_file, f: c_int) -> c_int),
        xTruncate: forward_to_orig!(xTruncate(*mut sqlite3_file, z: i64) -> c_int),
        xUnfetch: forward_to_orig!(xUnfetch(*mut sqlite3_file, o: i64, p: *mut c_void) -> c_int),
        xUnlock: forward_to_orig!(xUnlock(*mut sqlite3_file, n: c_int) -> c_int),
        xWrite: Some(xWrite),
    }
}

fn open_impl(data: &Data, name: &CStr, flags: c_int) -> Result<(File, c_int), c_int> {
    let orig = unsafe { *data.orig };
    let buf = unsafe { sqlite3_malloc(orig.szOsFile).cast::<sqlite3_file>() };
    if buf.is_null() {
        return Err(SQLITE_NOMEM);
    }
    let mut flags_out = 0;
    let e = unsafe { orig.xOpen.unwrap()(data.orig, name.as_ptr(), buf, flags, &mut flags_out) };
    if e != SQLITE_OK {
        return Err(e);
    }
    Ok((
        File {
            base: sqlite3_file { pMethods: vtable() },
            flags,
            tx: &data.tx,
            orig: buf,
            cksum_len: data.cksum_len,
            pending_pgno: Cell::new(None),
        },
        flags_out,
    ))
}

fn write_impl(file: &File, data: &[u8], offset: i64) -> Result<(), c_int> {
    let orig = unsafe { file.orig.read().pMethods.read().xWrite.unwrap() };
    let e = unsafe { orig(file.orig, data.as_ptr().cast(), data.len() as _, offset) };
    if e != SQLITE_OK {
        return Err(e);
    }
    let tx = unsafe { &file.tx.as_ref().unwrap() };
    if file.flags & SQLITE_OPEN_MAIN_DB != 0 && data.len() == PAGE_SIZE {
        let pgno = offset / PAGE_SIZE as i64;
        let mut hasher = Blake2sVar::new(file.cksum_len).unwrap();
        hasher.update(data);
        let mut buf = [0; MAX_CKSUM_SIZE];
        hasher
            .finalize_variable(&mut buf[..file.cksum_len])
            .unwrap();
        tx.borrow_mut()
            .broadcast(Message(pgno as u32, ErasedCksum(buf)));
    }
    Ok(())
}

pub fn make(orig: &CStr, tx: Bus<Message>, cksum_len: usize) -> *mut sqlite3_vfs {
    macro_rules! forward_to_base {
        ( $name:ident ( *mut sqlite3_vfs, $($a:ident: $t:ty),* ) $(-> $rt:ty)?) => { {
            #[allow(non_snake_case)]
            unsafe extern "C" fn $name(vfs: *mut sqlite3_vfs, $($a: $t),*) $(-> $rt)? {
                let orig: *mut sqlite3_vfs = unsafe { (*vfs).pAppData.cast::<Data>().read().orig };
                let orig_method = unsafe { (*orig).$name.unwrap() };
                unsafe { orig_method(orig, $($a),*) }
            }
            Some($name)
        } }
    }

    #[allow(non_snake_case)]
    unsafe extern "C" fn xOpen(
        vfs: *mut sqlite3_vfs,
        n: *const c_char,
        f: *mut sqlite3_file,
        flags: c_int,
        flags_out: *mut c_int,
    ) -> c_int {
        let data = unsafe { (*vfs).pAppData.cast::<Data>().as_ref().unwrap() };
        match open_impl(data, unsafe { CStr::from_ptr(n) }, flags) {
            Ok((file, o)) => {
                unsafe {
                    f.cast::<File>().write(file);
                    if !flags_out.is_null() {
                        flags_out.write(o);
                    }
                }
                SQLITE_OK
            }
            Err(e) => e,
        }
    }

    let orig = unsafe { sqlite3_vfs_find(orig.as_ptr()) };
    Box::into_raw(Box::new(sqlite3_vfs {
        iVersion: 3,
        zName: zstr!("diff").as_ptr(),
        mxPathname: unsafe { (*orig).mxPathname },
        pAppData: Box::into_raw(Box::new(Data {
            orig,
            tx: ManuallyDrop::new(RefCell::new(tx)),
            cksum_len,
        }))
        .cast(),
        pNext: std::ptr::null_mut(),
        szOsFile: std::mem::size_of::<File>() as c_int,
        xAccess: forward_to_base!(xAccess(*mut sqlite3_vfs, name: *const c_char, flags: c_int, flags_out: *mut c_int) -> c_int),
        xCurrentTime: forward_to_base!(xCurrentTime(*mut sqlite3_vfs, x: *mut f64) -> c_int),
        xCurrentTimeInt64: forward_to_base!(xCurrentTimeInt64(*mut sqlite3_vfs, x: *mut i64) -> c_int),
        xDelete: forward_to_base!(xDelete(*mut sqlite3_vfs, n: *const c_char, f: c_int) -> c_int),
        xDlClose: forward_to_base!(xDlClose(*mut sqlite3_vfs, x: *mut c_void)),
        xDlError: forward_to_base!(xDlError(*mut sqlite3_vfs, n: c_int, m: *mut c_char)),
        xDlOpen: forward_to_base!(xDlOpen(*mut sqlite3_vfs, f: *const c_char) -> *mut c_void),
        // XXX
        xDlSym: forward_to_base!(xDlSym(*mut sqlite3_vfs, x: *mut c_void, s: *const c_char) -> Option<unsafe extern "C" fn(*mut sqlite3_vfs, *mut c_void, *const c_char)>),
        xFullPathname: forward_to_base!(xFullPathname(*mut sqlite3_vfs, s: *const c_char, n: c_int, o: *mut c_char) -> c_int),
        xGetLastError: forward_to_base!(xGetLastError(*mut sqlite3_vfs, x: c_int, s: *mut c_char) -> c_int),
        xGetSystemCall: forward_to_base!(xGetSystemCall(*mut sqlite3_vfs, n: *const c_char) -> sqlite3_syscall_ptr),
        xNextSystemCall: forward_to_base!(xNextSystemCall(*mut sqlite3_vfs, n: *const c_char) -> *const c_char),
        xOpen: Some(xOpen),
        xRandomness: forward_to_base!(xRandomness(*mut sqlite3_vfs, n: c_int, o: *mut c_char) -> c_int),
        xSetSystemCall: forward_to_base!(xSetSystemCall(*mut sqlite3_vfs, s: *const c_char, p: sqlite3_syscall_ptr) -> c_int),
        xSleep: forward_to_base!(xSleep(*mut sqlite3_vfs, u: c_int) -> c_int),
    }))
}

struct Data {
    orig: *mut sqlite3_vfs,
    tx: ManuallyDrop<RefCell<Bus<Message>>>,
    cksum_len: usize,
}

#[repr(C)]
struct File {
    base: sqlite3_file,
    orig: *mut sqlite3_file,
    tx: *const ManuallyDrop<RefCell<Bus<Message>>>,
    flags: c_int,
    cksum_len: usize,
    pending_pgno: Cell<Option<PageNumber>>,
}
