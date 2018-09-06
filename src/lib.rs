//! LIBNFS is a client library for accessing NFS shares over a network
//! NFSv3 is the default but NFSv4 can be selected either by using the URL argument
//! version=4 or programatically calling nfs_set_version(nfs, NFS_V4) before
//! connecting to the server/share.
//!
extern crate libc;
extern crate libnfs_sys;
extern crate nix;

use libnfs_sys::*;
use nix::{fcntl::OFlag, sys::stat::Mode};

use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Result};
use std::mem::zeroed;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

fn check_mut_ptr<T>(ptr: *mut T) -> Result<*mut T> {
    if ptr.is_null() {
        Err(Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

fn check_retcode(n: &Nfs, code: i32) -> Result<()> {
    if code < 0 {
        Err(Error::new(ErrorKind::Other, n.get_nfs_error()?))
    } else {
        Ok(())
    }
}

pub struct Nfs {
    context: *mut nfs_context,
}

impl Drop for Nfs {
    fn drop(&mut self) {
        if !self.context.is_null() {
            unsafe {
                nfs_destroy_context(self.context);
            }
        }
    }
}

#[derive(Debug)]
pub struct DirEntry {
    pub path: PathBuf,
    pub inode: u64,
    pub type_: u32,
    pub mode: u32,
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

pub struct NfsDirectory<'a> {
    nfs: &'a mut Nfs,
    handle: *mut nfsdir,
}

impl<'a> Drop for NfsDirectory<'a> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                nfs_closedir(self.nfs.context, self.handle);
            }
        }
    }
}

pub struct NfsFile<'a> {
    nfs: &'a mut Nfs,
    handle: *mut nfsfh,
}

impl<'a> Drop for NfsFile<'a> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                nfs_close(self.nfs.context, self.handle);
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
            Ok(Nfs { context: ctx })
        }
    }

    pub fn access(&self, path: &Path, mode: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self, nfs_access(self.context, path.as_ptr(), mode))?;
            Ok(())
        }
    }

    pub fn access2(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self, nfs_access2(self.context, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn chdir(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(&self, nfs_chdir(self.context, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn chown(&self, path: &Path, uid: i32, gid: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(&self, nfs_chown(self.context, path.as_ptr(), uid, gid))?;
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
                &self,
                nfs_create(
                    self.context,
                    path.as_ptr(),
                    flags.bits(),
                    mode.bits() as i32,
                    &mut file_handle,
                ),
            )?;
            Ok(NfsFile {
                nfs: self,
                handle: file_handle,
            })
        }
    }

    pub fn getcwd(&self) -> Result<PathBuf> {
        let mut cwd_val_buff: Vec<u8> = Vec::with_capacity(2048);
        unsafe {
            nfs_getcwd(self.context, cwd_val_buff.as_mut_ptr() as *mut *const i8);

            Ok(PathBuf::from(
                String::from_utf8_lossy(&cwd_val_buff).into_owned(),
            ))
        }
    }

    /// Get the maximum supported READ3 size by the server
    pub fn get_readmax(&self) -> Result<u64> {
        unsafe {
            let max = nfs_get_readmax(self.context);
            Ok(max)
        }
    }

    /// Get the maximum supported WRITE3 size by the server
    pub fn get_writemax(&self) -> Result<u64> {
        unsafe {
            let max = nfs_get_writemax(self.context);
            Ok(max)
        }
    }

    fn get_nfs_error(&self) -> Result<String> {
        unsafe {
            let err_str = nfs_get_error(self.context);

            Ok(CStr::from_ptr(err_str).to_string_lossy().into_owned())
        }
    }

    pub fn lchmod(&self, path: &Path, mode: Mode) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                &self,
                nfs_lchmod(self.context, path.as_ptr(), mode.bits() as i32),
            )?;
            Ok(())
        }
    }

    pub fn lchown(&self, path: &Path, uid: i32, gid: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(&self, nfs_lchown(self.context, path.as_ptr(), uid, gid))?;
            Ok(())
        }
    }

    pub fn link(&self, oldpath: &Path, newpath: &Path) -> Result<()> {
        let old_path = CString::new(oldpath.as_os_str().as_bytes())?;
        let new_path = CString::new(newpath.as_os_str().as_bytes())?;

        unsafe {
            check_retcode(
                &self,
                nfs_link(self.context, old_path.as_ptr(), new_path.as_ptr()),
            )?;
            Ok(())
        }
    }

    pub fn lstat64(&self, path: &Path) -> Result<nfs_stat_64> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let mut stat_buf: nfs_stat_64 = zeroed();
            check_retcode(
                self,
                nfs_lstat64(self.context, path.as_ptr(), &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn mkdir(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self, nfs_mkdir(self.context, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn mknod(&self, path: &Path, mode: i32, dev: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self, nfs_mknod(self.context, path.as_ptr(), mode, dev))?;
            Ok(())
        }
    }

    pub fn mount(&self, server: &str, export_name: &str) -> Result<()> {
        let server = CString::new(server.as_bytes())?;
        let export = CString::new(export_name.as_bytes())?;
        unsafe {
            check_retcode(
                self,
                nfs_mount(self.context, server.as_ptr(), export.as_ptr()),
            )?;
            Ok(())
        }
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
                self,
                nfs_open(self.context, path.as_ptr(), flags.bits(), &mut file_handle),
            )?;
            Ok(NfsFile {
                nfs: self,
                handle: file_handle,
            })
        }
    }

    pub fn opendir(&mut self, path: &Path) -> Result<NfsDirectory> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let mut dir_handle: *mut nfsdir = ptr::null_mut();
            check_retcode(
                &self,
                nfs_opendir(self.context, path.as_ptr(), &mut dir_handle),
            )?;
            Ok(NfsDirectory {
                nfs: self,
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
            let nfs_url = check_mut_ptr(nfs_parse_url_dir(self.context, url.as_ptr()))?;
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
            let nfs_url = check_mut_ptr(nfs_parse_url_incomplete(self.context, url.as_ptr()))?;
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
            let nfs_url = check_mut_ptr(nfs_parse_url_full(self.context, url.as_ptr()))?;
            Ok(NfsUrl {
                nfs: self,
                url: nfs_url,
            })
        }
    }
    */

    pub fn readlink(&self, path: &Path, buf: &mut [u8]) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;

        unsafe {
            check_retcode(
                &self,
                nfs_readlink(
                    self.context,
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
                &self,
                nfs_rename(self.context, old_path.as_ptr(), new_path.as_ptr()),
            )?;
            Ok(())
        }
    }

    pub fn rmdir(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self, nfs_rmdir(self.context, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn set_auth(&self, auth: &mut AUTH) -> Result<()> {
        unsafe {
            nfs_set_auth(self.context, auth);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_tcp_syncnt(&self, syncnt: i32) -> Result<()> {
        unsafe {
            nfs_set_tcp_syncnt(self.context, syncnt);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_uid(&self, uid: i32) -> Result<()> {
        unsafe {
            nfs_set_uid(self.context, uid);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_gid(&self, gid: i32) -> Result<()> {
        unsafe {
            nfs_set_gid(self.context, gid);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_readahead(&self, size: u32) -> Result<()> {
        unsafe {
            nfs_set_readahead(self.context, size);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_debug(&self, level: i32) -> Result<()> {
        unsafe {
            nfs_set_debug(self.context, level);
        }
        Ok(())
    }

    pub fn stat64(&self, path: &Path) -> Result<nfs_stat_64> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let mut stat_buf: nfs_stat_64 = zeroed();
            check_retcode(self, nfs_stat64(self.context, path.as_ptr(), &mut stat_buf))?;
            Ok(stat_buf)
        }
    }

    pub fn statvfs(&self, path: &Path) -> Result<statvfs> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let mut stat_buf: statvfs = zeroed();
            check_retcode(
                self,
                nfs_statvfs(self.context, path.as_ptr(), &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn symlink(&self, oldpath: &Path, newpath: &Path) -> Result<()> {
        let old_path = CString::new(oldpath.as_os_str().as_bytes())?;
        let new_path = CString::new(newpath.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(
                self,
                nfs_symlink(self.context, old_path.as_ptr(), new_path.as_ptr()),
            )?;
            Ok(())
        }
    }

    pub fn truncate(&self, path: &Path, len: u64) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self, nfs_truncate(self.context, path.as_ptr(), len))?;
            Ok(())
        }
    }

    pub fn umask(&self, mask: u16) -> Result<u16> {
        unsafe {
            let mask = nfs_umask(self.context, mask);
            Ok(mask)
        }
    }

    pub fn unlink(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            check_retcode(self, nfs_unlink(self.context, path.as_ptr()))?;
            Ok(())
        }
    }

    /*
    pub fn utime(&self, path: &Path) -> Result<utimbuf> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let mut times = utimbuf {
            actime: 0,
            modtime: 0,
        };
        unsafe {
            check_retcode(self, nfs_utime(self.context, path.as_ptr(), times as *mut libnfs_sys::utimbuf))?;
            Ok(times)
        }
    }
    */
}

impl<'a> NfsFile<'a> {
    pub fn fchmod(&self, mode: i32) -> Result<()> {
        unsafe {
            check_retcode(self.nfs, nfs_fchmod(self.nfs.context, self.handle, mode))?;

            Ok(())
        }
    }

    pub fn fchown(&self, uid: i32, gid: i32) -> Result<()> {
        unsafe {
            check_retcode(
                self.nfs,
                nfs_fchown(self.nfs.context, self.handle, uid, gid),
            )?;
            Ok(())
        }
    }

    pub fn ftruncate(&self, len: u64) -> Result<()> {
        unsafe {
            check_retcode(self.nfs, nfs_ftruncate(self.nfs.context, self.handle, len))?;
            Ok(())
        }
    }

    /// 64 bit version of fstat. All fields are always 64bit.
    pub fn fstat64(&self) -> Result<nfs_stat_64> {
        unsafe {
            let mut stat_buf: nfs_stat_64 = zeroed();
            check_retcode(
                self.nfs,
                nfs_fstat64(self.nfs.context, self.handle, &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn fsync(&self) -> Result<()> {
        unsafe {
            check_retcode(self.nfs, nfs_fsync(self.nfs.context, self.handle))?;
            Ok(())
        }
    }

    pub fn pread(&self, buffer: &mut Vec<u8>, count: u64, offset: u64) -> Result<i32> {
        unsafe {
            let read_size = nfs_pread(
                self.nfs.context,
                self.handle,
                offset,
                count,
                buffer.as_mut_ptr() as *mut i8,
            );
            if read_size < 0 {
                return Err(Error::new(ErrorKind::Other, self.nfs.get_nfs_error()?));
            }
            buffer.set_len(read_size as usize);
            Ok(read_size)
        }
    }

    pub fn pwrite(&self, buffer: &mut [u8], count: u64, offset: u64) -> Result<i32> {
        unsafe {
            let write_size = nfs_pwrite(
                self.nfs.context,
                self.handle,
                offset,
                count,
                buffer.as_mut_ptr() as *mut i8,
            );
            if write_size < 0 {
                return Err(Error::new(ErrorKind::Other, self.nfs.get_nfs_error()?));
            }
            Ok(write_size)
        }
    }

    pub fn read(&self, fill_buffer: &mut Vec<u8>, count: u64) -> Result<i32> {
        self.pread(fill_buffer, count, 0)
    }

    pub fn write(&self, buffer: &mut [u8]) -> Result<i32> {
        let len = buffer.len();
        self.pwrite(buffer, len as u64, 0)
    }

    /*
    pub fn lseek(&self, offset: i64, whence: i32, current_offset: u64) -> Result<()> {
        unsafe {
            check_retcode(self.nfs, nfs_lseek(self.nfs.context, self.handle, offset, whence, current_offset))?;
            Ok(())
        }
    }
    */
}

impl<'a> Iterator for NfsDirectory<'a> {
    type Item = DirEntry;
    fn next(&mut self) -> Option<DirEntry> {
        unsafe {
            let dirent = nfs_readdir(self.nfs.context, self.handle);
            if dirent.is_null() {
                return None;
            }

            let file_name = CStr::from_ptr((*dirent).name);
            return Some(DirEntry {
                path: PathBuf::from(file_name.to_string_lossy().into_owned()),
                inode: (*dirent).inode,
                type_: (*dirent).type_,
                mode: (*dirent).mode,
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
            });
        }
    }
}
