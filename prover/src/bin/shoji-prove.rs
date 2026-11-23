//! Command-line front end, for checking the library on a PC:
//!   shoji-prove <circuit.json> <inputs.json> <srs g1.dat> <vk> <output dir>
//! Writes `proof` and `public_inputs` in the layout `bb verify` reads.

use std::{env, fs, path::Path, process::exit, time::Instant};

fn main() {
    let a: Vec<String> = env::args().collect();
    if a.len() != 6 {
        eprintln!("usage: shoji-prove <circuit.json> <inputs.json> <srs g1.dat> <vk> <output dir>");
        exit(2);
    }
    let read = |p: &str| fs::read(p).unwrap_or_else(|e| { eprintln!("{p}: {e}"); exit(1) });
    let circuit = String::from_utf8(read(&a[1])).expect("circuit is UTF-8");
    let inputs = String::from_utf8(read(&a[2])).expect("inputs are UTF-8");
    let srs = read(&a[3]);
    let vk = read(&a[4]);

    let start = Instant::now();
    match shoji_prover::prove(&circuit, &inputs, &srs, &vk) {
        Ok(out) => {
            let dir = Path::new(&a[5]);
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join("proof"), &out.proof).unwrap();
            fs::write(dir.join("public_inputs"), &out.public_inputs).unwrap();
            println!(
                "proved in {:.2}s: proof {} bytes, public inputs {} bytes",
                start.elapsed().as_secs_f64(), out.proof.len(), out.public_inputs.len()
            );
        }
        Err(e) => { eprintln!("failed: {e}"); exit(1) }
    }
}
