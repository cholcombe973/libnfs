extern crate libnfs;
extern crate nix;

use libnfs::*;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use std::path::Path;

fn main() -> Result<(), String> {
    let mut nfs = Nfs::new().map_err(|e| e.to_string())?;
    nfs.set_uid(1000).map_err(|e| e.to_string())?;
    nfs.set_gid(1000).map_err(|e| e.to_string())?;
    nfs.set_debug(9).map_err(|e| e.to_string())?;
    nfs.mount("0.0.0.0", "/srv/nfs")
        .map_err(|e| e.to_string())?;

    let dir = nfs.opendir(&Path::new("/")).map_err(|e| e.to_string())?;
    for f in dir {
        println!("dir: {:?}", f);
    }

    println!("creating file");
    let file = nfs
        .create(&Path::new("/rust"), OFlag::O_SYNC, Mode::S_IRWXU)
        .map_err(|e| e.to_string())?;
    let mut contents = String::from("Hello from rust").into_bytes();
    file.write(&mut contents).map_err(|e| e.to_string())?;

    println!("reading file");
    let file = nfs
        .open(&Path::new("/rust"), OFlag::O_RDONLY)
        .map_err(|e| e.to_string())?;
    let buff = file.read(1024).map_err(|e| e.to_string())?;
    println!("read file: {}", String::from_utf8_lossy(&buff));
    Ok(())
}
