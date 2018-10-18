extern crate libnfs;
extern crate nix;

use std::io::Result;
use std::path::Path;

use libnfs::*;
use nix::fcntl::OFlag;

fn main() -> Result<()> {
    let mut nfs = Nfs::new()?;
    nfs.set_uid(1000)?;
    nfs.set_gid(1000)?;
    nfs.set_debug(9)?;
    nfs.mount("0.0.0.0", "/srv/nfs")?;

    let dir = nfs.opendir(&Path::new("/"))?;
    for f in dir {
        println!("dir: {:?}", f);
    }

    println!("creating file");
    let file = nfs.create(
        &Path::new("/rust"),
        OFlag::O_SYNC,
        Mode::S_IROTH | Mode::S_IWOTH,
    )?;
    let mut contents = String::from("Hello from rust").into_bytes();
    file.write(&mut contents)?;

    println!("reading file");
    let file = nfs.open(&Path::new("/rust"), OFlag::O_RDONLY)?;
    let buff = file.read(1024)?;
    println!("read file: {}", String::from_utf8_lossy(&buff));
    Ok(())
}
