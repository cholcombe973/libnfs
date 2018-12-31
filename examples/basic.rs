use std::io::Result;
use std::path::Path;

use libnfs::*;
use nix::{fcntl::OFlag, sys::stat::Mode};

fn main() -> Result<()> {
    let mut nfs = Nfs::new()?;
    //nfs.set_uid(0)?;
    //nfs.set_gid(0)?;
    nfs.set_debug(9)?;
    println!("mounting");
    nfs.mount("192.168.122.78", "/var/nfs")?;
    nfs.stat64_async(&Path::new("foo"), |result|{
        println!("async stat result: {:?}", result);

        // Pass it on
        result
    })?;
    nfs.run_async()?;
    /*

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
    */
    Ok(())
}
