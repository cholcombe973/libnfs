//! LIBNFS is a client library for accessing NFS shares over a network
//! NFSv3 is the default but NFSv4 can be selected either by using the URL argument
//! version=4 or programatically calling nfs_set_version(nfs, NFS_V4) before
//! connecting to the server/share.
//!
use futures::future::Future;
use futures::unsync::oneshot;
use libnfs_sys::*;
use log::error;
use mio::event::Evented;
use mio::unix::EventedFd;
use nix::fcntl::OFlag;
use nix::poll::poll;
use nix::poll::{EventFlags, PollFd};
use nix::sys::stat::Mode;
use tokio::prelude::*;

use std::ffi::{c_void, CStr, CString};
use std::io::{Error, ErrorKind, Result};
use std::mem::{transmute, zeroed};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::rc::Rc;

#[derive(Clone, Debug)]
struct NfsPtr(*mut nfs_context);

impl Drop for NfsPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                nfs_destroy_context(self.0);
            }
        }
    }
}

fn check_mut_ptr<T>(ptr: *mut T) -> Result<*mut T> {
    if ptr.is_null() {
        Err(Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

fn check_retcode(ctx: *mut nfs_context, code: i32) -> Result<()> {
    if code < 0 {
        unsafe {
            let err_str = nfs_get_error(ctx);
            let e = CStr::from_ptr(err_str).to_string_lossy().into_owned();
            Err(Error::new(ErrorKind::Other, e))
        }
    } else {
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn nfs_mount_callback(
    result: i32,
    context: *mut nfs_context,
    // Data is null for mount
    _data: *mut c_void,
    private_data: *mut c_void,
) {
    println!("Callback called");
    unsafe {
        // box the callback function
        let callback: Box<fn(Result<()>) -> Result<()>> =
            Box::from_raw(private_data as *mut fn(Result<()>) -> Result<()>);
        // Check the async result from libnfs
        let result: Result<()> = if result < 0 {
            let err_str = nfs_get_error(context);
            let e = CStr::from_ptr(err_str).to_string_lossy().into_owned();
            Err(Error::new(ErrorKind::Other, e))
        } else {
            Ok(())
        };
        if let Err(e) = callback(result) {
            error!("nfs_mount callback error: {:?}", e);
        };
    }
}

#[no_mangle]
pub extern "C" fn nfs_open_callback(
    result: i32,
    context: *mut nfs_context,
    // data is an *mut nfsfh
    data: *mut c_void,
    private_data: *mut c_void,
) {
    println!("open callback called");
    unsafe {
        // box the callback function
        let callback: Box<fn(Result<NfsFile>) -> Result<NfsFile>> =
            Box::from_raw(private_data as *mut fn(Result<NfsFile>) -> Result<NfsFile>);
        // Check the async result from libnfs
        let result: Result<NfsFile> = if result < 0 {
            let err_str = nfs_get_error(context);
            let e = CStr::from_ptr(err_str).to_string_lossy().into_owned();
            Err(Error::new(ErrorKind::Other, e))
        } else {
            let nfsfh = NfsFile {
                nfs: Rc::new(NfsPtr(context)),
                handle: data as *mut nfsfh,
            };
            Ok(nfsfh)
        };
        if let Err(e) = callback(result) {
            error!("nfs_mount callback error: {:?}", e);
        };
    }
}

#[no_mangle]
pub extern "C" fn stat64_callback(
    result: i32,
    context: *mut nfs_context,
    // data is an *mut nfs_stat_64
    data: *mut c_void,
    private_data: *mut c_void,
) {
    unsafe {
        // box the callback function
        println!("callback called with private_data: {:p}", &private_data);
        let callback: &mut Box<FnMut(Result<*mut nfs_stat_64>) -> Result<()>> = transmute(private_data);
        println!("boxed callback: {:p}", &callback);
        // Check the async result from libnfs
        let result: Result<*mut nfs_stat_64> = if result < 0 {
            let err_str = nfs_get_error(context);
            let e = CStr::from_ptr(err_str).to_string_lossy().into_owned();
            Err(Error::new(ErrorKind::Other, e))
        } else {
            let stat = data as *mut nfs_stat_64;
            Ok(stat)
        };
        println!("Calling user callback with: {:?}", result);
        if let Err(e) = callback(result) {
            error!("nfs_mount callback error: {:?}", e);
        };
        println!("Done");
    }
}

#[derive(Clone, Debug)]
pub struct Nfs {
    context: Rc<NfsPtr>,
}

#[derive(Clone, Debug)]
pub enum EntryType {
    Block,
    Character,
    Directory,
    File,
    NamedPipe,
    Symlink,
    Socket,
}

impl EntryType {
    fn from(t: ftype3) -> Result<EntryType> {
        match t {
            ftype3_NF3BLK => Ok(EntryType::Block),
            ftype3_NF3CHR => Ok(EntryType::Character),
            ftype3_NF3DIR => Ok(EntryType::Directory),
            ftype3_NF3REG => Ok(EntryType::File),
            ftype3_NF3FIFO => Ok(EntryType::NamedPipe),
            ftype3_NF3LNK => Ok(EntryType::Symlink),
            ftype3_NF3SOCK => Ok(EntryType::Socket),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unknown file type: {}", t),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub path: PathBuf,
    pub inode: u64,
    pub d_type: EntryType,
    pub mode: Mode,
    pub size: u64,
    pub atime: timeval,
    pub mtime: timeval,
    pub ctime: timeval,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub dev: u64,
    pub rdev: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub used: u64,
    pub atime_nsec: u32,
    pub mtime_nsec: u32,
    pub ctime_nsec: u32,
}

#[derive(Clone, Debug)]
pub struct NfsDirectory {
    nfs: Rc<NfsPtr>,
    handle: *mut nfsdir,
}

impl Drop for NfsDirectory {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                nfs_closedir(self.nfs.0, self.handle);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct NfsFile {
    nfs: Rc<NfsPtr>,
    handle: *mut nfsfh,
}

impl Drop for NfsFile {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                nfs_close(self.nfs.0, self.handle);
            }
        }
    }
}

/*
pub struct NfsUrl<'a> {
    nfs: &'a mut Nfs,
    url: *mut nfs_url,
}

impl<'a> Drop for NfsUrl<'a> {
    fn drop(&mut self) {
        if !self.url.is_null() {
            unsafe {
                nfs_destroy_url(self.url);
            }
        }
    }
}
*/

impl Nfs {
    pub fn new() -> Result<Self> {
        unsafe {
            let ctx = check_mut_ptr(nfs_init_context())?;
            Ok(Nfs {
                context: Rc::new(NfsPtr(ctx)),
            })
        }
    }

    pub fn access(&self, path: &Path, mode: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                self.context.0,
                nfs_access(self.context.0, path.as_ptr(), mode),
            )?;
            Ok(())
        }
    }

    pub fn access2(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self.context.0, nfs_access2(self.context.0, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn chdir(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self.context.0, nfs_chdir(self.context.0, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn chown(&self, path: &Path, uid: i32, gid: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                self.context.0,
                nfs_chown(self.context.0, path.as_ptr(), uid, gid),
            )?;
            Ok(())
        }
    }

    /// Supported flags:
    /// O_APPEND
    /// O_SYNC
    /// O_EXCL
    /// O_TRUNC
    pub fn create(&mut self, path: &Path, flags: OFlag, mode: Mode) -> Result<NfsFile> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let mut file_handle: *mut nfsfh = ptr::null_mut();
            check_retcode(
                self.context.0,
                nfs_create(
                    self.context.0,
                    path.as_ptr(),
                    flags.bits(),
                    mode.bits() as i32,
                    &mut file_handle,
                ),
            )?;
            Ok(NfsFile {
                nfs: Rc::clone(&self.context),
                handle: file_handle,
            })
        }
    }

    pub fn getcwd(&self) -> Result<PathBuf> {
        let mut cwd = ptr::null();
        unsafe {
            nfs_getcwd(self.context.0, &mut cwd);
            let path_tmp = CStr::from_ptr(cwd).to_string_lossy().into_owned();

            Ok(PathBuf::from(path_tmp))
        }
    }

    /// Get the maximum supported READ3 size by the server
    pub fn get_readmax(&self) -> Result<u64> {
        unsafe {
            let max = nfs_get_readmax(self.context.0);
            Ok(max)
        }
    }

    /// Get the maximum supported WRITE3 size by the server
    pub fn get_writemax(&self) -> Result<u64> {
        unsafe {
            let max = nfs_get_writemax(self.context.0);
            Ok(max)
        }
    }

    pub fn lchmod(&self, path: &Path, mode: Mode) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                self.context.0,
                nfs_lchmod(self.context.0, path.as_ptr(), mode.bits() as i32),
            )?;
            Ok(())
        }
    }

    pub fn lchown(&self, path: &Path, uid: i32, gid: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                self.context.0,
                nfs_lchown(self.context.0, path.as_ptr(), uid, gid),
            )?;
            Ok(())
        }
    }

    pub fn link(&self, oldpath: &Path, newpath: &Path) -> Result<()> {
        let old_path = CString::new(oldpath.as_os_str().as_bytes())?;
        let new_path = CString::new(newpath.as_os_str().as_bytes())?;

        unsafe {
            check_retcode(
                self.context.0,
                nfs_link(self.context.0, old_path.as_ptr(), new_path.as_ptr()),
            )?;
            Ok(())
        }
    }

    pub fn lstat64(&self, path: &Path) -> Result<nfs_stat_64> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let mut stat_buf: nfs_stat_64 = zeroed();
            check_retcode(
                self.context.0,
                nfs_lstat64(self.context.0, path.as_ptr(), &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn mkdir(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self.context.0, nfs_mkdir(self.context.0, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn mknod(&self, path: &Path, mode: i32, dev: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                self.context.0,
                nfs_mknod(self.context.0, path.as_ptr(), mode, dev),
            )?;
            Ok(())
        }
    }

    pub fn mount(&self, server: &str, export_name: &str) -> Result<()> {
        let server = CString::new(server.as_bytes())?;
        let export = CString::new(export_name.as_bytes())?;
        unsafe {
            check_retcode(
                self.context.0,
                nfs_mount(self.context.0, server.as_ptr(), export.as_ptr()),
            )?;
            Ok(())
        }
    }

    /// Accepts an optional callback function pointer
    pub fn mount_async<F>(&self, server: &str, export_name: &str, callback: F) -> Result<()>
    where
        F: FnOnce(Result<()>) -> Result<()> + 'static,
        // This should accept a Nfs and return a Future
        // how does the async chain get created?
        // mount -> stat -> open -> etc etc etc all needs to be chained
    {
        let server = CString::new(server.as_bytes()).unwrap();
        let export = CString::new(export_name.as_bytes()).unwrap();
        let callback_ptr = Box::into_raw(Box::new(callback));
        unsafe {
            check_retcode(
                self.context.0,
                nfs_mount_async(
                    self.context.0,
                    server.as_ptr(),
                    export.as_ptr(),
                    Some(nfs_mount_callback),
                    callback_ptr as *mut c_void,
                ),
            )?;
        }
        Ok(())
    }

    /// Supported flags are
    /// O_APPEND
    /// O_RDONLY
    /// O_WRONLY
    /// O_RDWR
    /// O_SYNC
    /// O_TRUNC (Only valid with O_RDWR or O_WRONLY. Ignored otherwise.)
    pub fn open(&mut self, path: &Path, flags: OFlag) -> Result<NfsFile> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let mut file_handle: *mut nfsfh = ptr::null_mut();
            check_retcode(
                self.context.0,
                nfs_open(
                    self.context.0,
                    path.as_ptr(),
                    flags.bits(),
                    &mut file_handle,
                ),
            )?;
            Ok(NfsFile {
                nfs: Rc::clone(&self.context),
                handle: file_handle,
            })
        }
    }

    /// Accepts an optional callback function pointer
    pub fn open_async<F>(&self, path: &Path, flags: OFlag, callback: F) -> Result<()>
    where
        F: FnOnce(Result<NfsFile>) -> Result<NfsFile> + 'static,
        // This should accept a Nfs and return a Future
        // how does the async chain get created?
        // mount -> stat -> open -> etc etc etc all needs to be chained
    {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let callback_ptr = Box::into_raw(Box::new(callback));
        unsafe {
            check_retcode(
                self.context.0,
                nfs_open_async(
                    self.context.0,
                    path.as_ptr(),
                    flags.bits(),
                    Some(nfs_open_callback),
                    callback_ptr as *mut c_void,
                ),
            )?;
        }
        Ok(())
    }

    pub fn opendir(&mut self, path: &Path) -> Result<NfsDirectory> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let mut dir_handle: *mut nfsdir = ptr::null_mut();
            check_retcode(
                self.context.0,
                nfs_opendir(self.context.0, path.as_ptr(), &mut dir_handle),
            )?;
            Ok(NfsDirectory {
                nfs: Rc::clone(&self.context),
                handle: dir_handle,
            })
        }
    }

    /*
    /// Parse an NFS URL, but do not split path and file. File
    /// in the resulting struct remains NULL.
    pub fn parse_url_dir(&mut self, url: &str) -> Result<NfsUrl> {
        let url = CString::new(url.as_bytes())?;
        unsafe {
            let nfs_url = check_mut_ptr(nfs_parse_url_dir(self.context.0, url.as_ptr()))?;
            Ok(NfsUrl {
                nfs: self,
                url: nfs_url,
            })
        }
    }

    /// Parse an NFS URL, but do not fail if file, path or even server is missing.
    /// Check elements of the resulting struct for NULL.
    pub fn parse_url_incomplete(&mut self, url: &str) -> Result<NfsUrl> {
        let url = CString::new(url.as_bytes())?;
        unsafe {
            let nfs_url = check_mut_ptr(nfs_parse_url_incomplete(self.context.0, url.as_ptr()))?;
            Ok(NfsUrl {
                nfs: self,
                url: nfs_url,
            })
        }
    }

    /// URL parsing functions.
    /// These functions all parse a URL of the form
    /// nfs://server/path/file?argv=val[&arg=val]*
    /// and returns a nfs_url.
    ///
    /// Apart from parsing the URL the functions will also update
    /// the nfs context to reflect settings controlled via url arguments.
    ///
    /// Current URL arguments are :
    /// tcp-syncnt=<int>  : Number of SYNs to send during the seccion establish
    ///                     before failing settin up the tcp connection to the
    ///                     server.
    /// uid=<int>         : UID value to use when talking to the server.
    ///                     default it 65534 on Windows and getuid() on unixen.
    /// gid=<int>         : GID value to use when talking to the server.
    ///                     default it 65534 on Windows and getgid() on unixen.
    /// readahead=<int>   : Enable readahead for files and set the maximum amount
    ///                     of readahead to <int>.
    ///
    /// Parse a complete NFS URL including, server, path and
    /// filename. Fail if any component is missing.
    pub fn parse_url_full(&mut self, url: &str) -> Result<NfsUrl> {
        let url = CString::new(url.as_bytes())?;
        unsafe {
            let nfs_url = check_mut_ptr(nfs_parse_url_full(self.context.0, url.as_ptr()))?;
            Ok(NfsUrl {
                nfs: self,
                url: nfs_url,
            })
        }
    }
    */

    /*fn convert_cb(
        &self,
        f: &extern "C" fn(c_int, *mut nfs_context, *mut c_void, *mut c_void) -> (),
    ) -> unsafe extern "C" fn(c_int, *mut nfs_context, *mut c_void, *mut c_void) {
        *f
    }*/

    pub fn readlink(&self, path: &Path, buf: &mut [u8]) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;

        unsafe {
            check_retcode(
                self.context.0,
                nfs_readlink(
                    self.context.0,
                    path.as_ptr(),
                    buf.as_mut_ptr() as *mut i8,
                    buf.len() as i32,
                ),
            )?;
            Ok(())
        }
    }

    pub fn rename(&self, oldpath: &Path, newpath: &Path) -> Result<()> {
        let old_path = CString::new(oldpath.as_os_str().as_bytes())?;
        let new_path = CString::new(newpath.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                self.context.0,
                nfs_rename(self.context.0, old_path.as_ptr(), new_path.as_ptr()),
            )?;
            Ok(())
        }
    }

    pub fn rmdir(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self.context.0, nfs_rmdir(self.context.0, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn set_auth(&self, auth: &mut AUTH) -> Result<()> {
        unsafe {
            nfs_set_auth(self.context.0, auth);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_tcp_syncnt(&self, syncnt: i32) -> Result<()> {
        unsafe {
            nfs_set_tcp_syncnt(self.context.0, syncnt);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_uid(&self, uid: i32) -> Result<()> {
        unsafe {
            nfs_set_uid(self.context.0, uid);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_gid(&self, gid: i32) -> Result<()> {
        unsafe {
            nfs_set_gid(self.context.0, gid);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_readahead(&self, size: u32) -> Result<()> {
        unsafe {
            nfs_set_readahead(self.context.0, size);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_debug(&self, level: i32) -> Result<()> {
        unsafe {
            nfs_set_debug(self.context.0, level);
        }
        Ok(())
    }

    pub fn run_async(&mut self) -> Result<()> {
        loop {
            let mut file_desc: Vec<PollFd> = Vec::new();
            let fd = unsafe { nfs_get_fd(self.context.0) };
            let events_needed = unsafe { nfs_which_events(self.context.0) };
            println!("events_needed: {:?}", events_needed);
            let nfs_fd = PollFd::new(fd, EventFlags::from_bits_truncate(events_needed as i16));
            file_desc.push(nfs_fd);
            if poll(&mut file_desc, -1).expect("poll failed") < 0 {
                println!("poll failed");
                break;
            } else {
                println!("polled.  Got revents: {:?}", file_desc[0].revents());
                if unsafe {
                    nfs_service(
                        self.context.0,
                        file_desc[0].revents().expect("nfs_service failed").bits() as i32,
                    ) < 0
                } {
                    println!("nfs_service failed");
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn setup_async(&mut self) -> Result<()> {
        let register = tokio::reactor::Registration::new();
        let fd = unsafe { nfs_get_fd(self.context.0) };
        let events_needed = unsafe { nfs_which_events(self.context.0) };
        println!("nsf_get_fd: {}", fd);
        println!("nfs_which_events: {}", events_needed);
        let registered = register.register(&EventedFd(&fd))?;
        if registered {
            println!("registered");
            register.poll_read_ready()?;
            println!("read ready");
            if unsafe { nfs_service(self.context.0, events_needed) } < 0 {
                println!("nfs_service failed");
            }
        } else {
            // I/O resource has been previously registered

        }

        Ok(())
    }

    pub fn stat64(&self, path: &Path) -> Result<nfs_stat_64> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let mut stat_buf: nfs_stat_64 = zeroed();
            check_retcode(
                self.context.0,
                nfs_stat64(self.context.0, path.as_ptr(), &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn stat64_async<F>(&self, path: &Path, callback: F) -> Result<()>
    where
        F: FnMut(Result<NfsFile>) -> Result<NfsFile>, F: 'static,
    {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let cb: Box<Box<FnMut(Result<NfsFile>) -> Result<NfsFile>>> = Box::new(Box::new(callback));
        println!("stat64_async callback_ptr: {:p}", &cb);
        unsafe {
            check_retcode(
                self.context.0,
                nfs_stat64_async(
                    self.context.0,
                    path.as_ptr(),
                    Some(stat64_callback),
                    Box::into_raw(cb) as _
                ),
            )?;
            Ok(())
        }
    }

    pub fn statvfs(&self, path: &Path) -> Result<statvfs> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let mut stat_buf: statvfs = zeroed();
            check_retcode(
                self.context.0,
                nfs_statvfs(self.context.0, path.as_ptr(), &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn symlink(&self, oldpath: &Path, newpath: &Path) -> Result<()> {
        let old_path = CString::new(oldpath.as_os_str().as_bytes())?;
        let new_path = CString::new(newpath.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                self.context.0,
                nfs_symlink(self.context.0, old_path.as_ptr(), new_path.as_ptr()),
            )?;
            Ok(())
        }
    }

    pub fn truncate(&self, path: &Path, len: u64) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                self.context.0,
                nfs_truncate(self.context.0, path.as_ptr(), len),
            )?;
            Ok(())
        }
    }

    pub fn umask(&self, mask: u16) -> Result<u16> {
        unsafe {
            let mask = nfs_umask(self.context.0, mask);
            Ok(mask)
        }
    }

    pub fn unlink(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self.context.0, nfs_unlink(self.context.0, path.as_ptr()))?;
            Ok(())
        }
    }

    // Set the access and modified times
    pub fn utimes(&self, path: &Path, times: &mut [timeval; 2]) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                self.context.0,
                nfs_utimes(self.context.0, path.as_ptr(), times.as_mut_ptr()),
            )?;
            Ok(())
        }
    }
}

impl NfsFile {
    pub fn fchmod(&self, mode: i32) -> Result<()> {
        unsafe {
            check_retcode(self.nfs.0, nfs_fchmod(self.nfs.0, self.handle, mode))?;

            Ok(())
        }
    }

    pub fn fchown(&self, uid: i32, gid: i32) -> Result<()> {
        unsafe {
            check_retcode(self.nfs.0, nfs_fchown(self.nfs.0, self.handle, uid, gid))?;
            Ok(())
        }
    }

    pub fn ftruncate(&self, len: u64) -> Result<()> {
        unsafe {
            check_retcode(self.nfs.0, nfs_ftruncate(self.nfs.0, self.handle, len))?;
            Ok(())
        }
    }

    /// 64 bit version of fstat. All fields are always 64bit.
    pub fn fstat64(&self) -> Result<nfs_stat_64> {
        unsafe {
            let mut stat_buf: nfs_stat_64 = zeroed();
            check_retcode(
                self.nfs.0,
                nfs_fstat64(self.nfs.0, self.handle, &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn fsync(&self) -> Result<()> {
        unsafe {
            check_retcode(self.nfs.0, nfs_fsync(self.nfs.0, self.handle))?;
            Ok(())
        }
    }

    pub fn pread(&self, count: u64, offset: u64) -> Result<Vec<u8>> {
        let mut buffer: Vec<u8> = Vec::with_capacity(count as usize);
        unsafe {
            let read_size = nfs_pread(
                self.nfs.0,
                self.handle,
                offset,
                count,
                buffer.as_mut_ptr() as *mut _,
            );
            check_retcode(self.nfs.0, read_size)?;
            buffer.set_len(read_size as usize);
            Ok(buffer)
        }
    }

    pub fn pwrite(&self, buffer: &[u8], offset: u64) -> Result<i32> {
        unsafe {
            let write_size = nfs_pwrite(
                self.nfs.0,
                self.handle,
                offset,
                buffer.len() as u64,
                buffer.as_ptr() as *mut _,
            );
            check_retcode(self.nfs.0, write_size)?;
            Ok(write_size)
        }
    }

    pub fn read(&self, count: u64) -> Result<Vec<u8>> {
        self.pread(count, 0)
    }

    pub fn write(&self, buffer: &[u8]) -> Result<i32> {
        self.pwrite(buffer, 0)
    }

    /*
    pub fn lseek(&self, offset: i64, whence: i32, current_offset: u64) -> Result<()> {
        unsafe {
            check_retcode(self.context.0.nfs, nfs_lseek(*self.nfs.context, self.handle, offset, whence, current_offset))?;
            Ok(())
        }
    }
    */
}

impl Iterator for NfsDirectory {
    type Item = Result<DirEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let dirent = nfs_readdir(self.nfs.0, self.handle);
            if dirent.is_null() {
                return None;
            }

            let file_name = CStr::from_ptr((*dirent).name);
            let d_type = match EntryType::from((*dirent).type_) {
                Ok(ty) => ty,
                Err(e) => {
                    return Some(Err(e));
                }
            };
            let mode = Mode::from_bits_truncate((*dirent).mode);
            Some(Ok(DirEntry {
                path: PathBuf::from(file_name.to_string_lossy().into_owned()),
                inode: (*dirent).inode,
                d_type,
                mode,
                size: (*dirent).size,
                atime: (*dirent).atime,
                mtime: (*dirent).mtime,
                ctime: (*dirent).ctime,
                uid: (*dirent).uid,
                gid: (*dirent).gid,
                nlink: (*dirent).nlink,
                dev: (*dirent).dev,
                rdev: (*dirent).rdev,
                blksize: (*dirent).blksize,
                blocks: (*dirent).blocks,
                used: (*dirent).used,
                atime_nsec: (*dirent).atime_nsec,
                mtime_nsec: (*dirent).mtime_nsec,
                ctime_nsec: (*dirent).ctime_nsec,
            }))
        }
    }
}
