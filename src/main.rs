use std::env::args;

use anyhow::Result;

use cilium_map_dump::dump;

fn main() -> Result<()> {
    dump(&args().skip(1).next().unwrap())?;
    Ok(())
}
