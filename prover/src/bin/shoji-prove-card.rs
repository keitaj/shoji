//! Command-line front end for the card path, for rehearsing on a PC what the
//! phone does:
//!   shoji-prove-card <circuit.json> <cert.der> <ca.der> <nonce_sig.bin> <request.json> <srs g1.dat> <vk> <output dir>
//! Writes `proof` and `public_inputs`.

use std::{env, fs, path::Path, process::exit};

fn main() {
    let a: Vec<String> = env::args().collect();
    if a.len() != 9 {
        eprintln!("usage: shoji-prove-card <circuit.json> <cert.der> <ca.der> <nonce_sig.bin> <request.json> <srs g1.dat> <vk> <output dir>");
        exit(2);
    }
    let read = |p: &str| fs::read(p).unwrap_or_else(|e| { eprintln!("{p}: {e}"); exit(1) });
    let circuit = String::from_utf8(read(&a[1])).expect("circuit is UTF-8");
    let request = String::from_utf8(read(&a[5])).expect("request is UTF-8");
    match shoji_prover::prove_card(&circuit, &read(&a[2]), &read(&a[3]), &read(&a[4]), &request, &read(&a[6]), &read(&a[7])) {
        Ok(out) => {
            let dir = Path::new(&a[8]);
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join("proof"), &out.proof).unwrap();
            fs::write(dir.join("public_inputs"), &out.public_inputs).unwrap();
            println!("proved: proof {} bytes", out.proof.len());
        }
        Err(e) => { eprintln!("failed: {e}"); exit(1) }
    }
}
