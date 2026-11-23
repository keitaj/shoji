//! In-process proof generation for shoji.
//!
//! This is the phone-side equivalent of running `noir-execute` followed by
//! `bb prove -t noir-recursive`: it executes the compiled circuit to obtain the
//! witness and asks Barretenberg for an UltraHonk proof with the Poseidon2
//! transcript and zero-knowledge enabled. The proof is verified by the same
//! `bb verify` and verification key the server already uses.
//!
//! Nothing here talks to the network or writes files: the circuit, the inputs,
//! the structured reference string and the verification key are passed in.

mod ffi;
pub mod inputs;

use std::io::Read;

use acvm::acir::circuit::Program;
use acvm::acir::native_types::WitnessStack;
use acvm::FieldElement;
use barretenberg_rs::backends::FfiBackend;
use barretenberg_rs::generated_types::{CircuitInput, ProofSystemSettings};
use barretenberg_rs::BarretenbergApi;
use base64::Engine;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use nargo::foreign_calls::default::DefaultForeignCallBuilder;
use noirc_abi::input_parser::Format;
use noirc_abi::Abi;

/// Size of one G1 point of the structured reference string, in bytes.
const G1_POINT_BYTES: usize = 64;

/// The G2 point of the BN254 structured reference string
/// (https://crs.aztec.network/g2.dat, the same for every circuit size).
const SRS_G2: [u8; 128] = [
    0x01, 0x18, 0xc4, 0xd5, 0xb8, 0x37, 0xbc, 0xc2, 0xbc, 0x89, 0xb5, 0xb3, 0x98, 0xb5, 0x97, 0x4e, 0x9f, 0x59, 0x44, 0x07, 0x3b, 0x32, 0x07, 0x8b, 0x7e, 0x23, 0x1f, 0xec, 0x93, 0x88, 0x83, 0xb0, 0x26, 0x0e, 0x01, 0xb2, 0x51, 0xf6, 0xf1, 0xc7, 0xe7, 0xff, 0x4e, 0x58, 0x07, 0x91, 0xde, 0xe8, 0xea, 0x51, 0xd8, 0x7a, 0x35, 0x8e, 0x03, 0x8b, 0x4e, 0xfe, 0x30, 0xfa, 0xc0, 0x93, 0x83, 0xc1, 0x22, 0xfe, 0xbd, 0xa3, 0xc0, 0xc0, 0x63, 0x2a, 0x56, 0x47, 0x5b, 0x42, 0x14, 0xe5, 0x61, 0x5e, 0x11, 0xe6, 0xdd, 0x3f, 0x96, 0xe6, 0xce, 0xa2, 0x85, 0x4a, 0x87, 0xd4, 0xda, 0xcc, 0x5e, 0x55, 0x04, 0xfc, 0x63, 0x69, 0xf7, 0x11, 0x0f, 0xe3, 0xd2, 0x51, 0x56, 0xc1, 0xbb, 0x9a, 0x72, 0x85, 0x9c, 0xf2, 0xa0, 0x46, 0x41, 0xf9, 0x9b, 0xa4, 0xee, 0x41, 0x3c, 0x80, 0xda, 0x6a, 0x5f, 0xe4, 
];

/// A proof and the public inputs it was made for, both as concatenated 32-byte
/// big-endian field elements (the layout of bb's `proof` and `public_inputs` files).
pub struct ProofOutput {
    pub public_inputs: Vec<u8>,
    pub proof: Vec<u8>,
}

/// The settings behind `bb prove -t noir-recursive`. Zero-knowledge must stay on:
/// without it the proof would leak information about the certificate.
fn settings() -> ProofSystemSettings {
    ProofSystemSettings {
        ipa_accumulation: false,
        oracle_hash_type: "poseidon2".to_string(),
        disable_zk: false,
        optimized_solidity_verifier: false,
    }
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| format!("gunzip: {e}"))?;
    Ok(out)
}

/// Generates a proof.
///
/// * `circuit_json`: the compiled circuit (`circuits/target/shoji.json`)
/// * `inputs_json`: the inputs of `main`, keyed by parameter name
/// * `srs_g1`: uncompressed BN254 G1 points of the structured reference string
/// * `verification_key`: the circuit's verification key as written by `bb write_vk`
///
/// Error messages never contain input values.
pub fn prove(
    circuit_json: &str,
    inputs_json: &str,
    srs_g1: &[u8],
    verification_key: &[u8],
) -> Result<ProofOutput, String> {
    // --- Circuit artifact ---
    let artifact: serde_json::Value =
        serde_json::from_str(circuit_json).map_err(|_| "circuit: not valid JSON".to_string())?;
    let abi: Abi = serde_json::from_value(artifact["abi"].clone())
        .map_err(|_| "circuit: unreadable ABI".to_string())?;
    let bytecode = artifact["bytecode"]
        .as_str()
        .ok_or_else(|| "circuit: missing bytecode".to_string())?;
    let acir_gz = base64::engine::general_purpose::STANDARD
        .decode(bytecode)
        .map_err(|_| "circuit: bytecode is not base64".to_string())?;
    let program: Program<FieldElement> = Program::deserialize_program(&acir_gz)
        .map_err(|_| "circuit: unreadable bytecode".to_string())?;

    // --- Witness generation (what noir-execute does) ---
    let input_map = Format::Json
        .parse(inputs_json, &abi)
        .map_err(|_| "inputs: do not match the circuit's parameters".to_string())?;
    let initial_witness = abi
        .encode(&input_map, None)
        .map_err(|_| "inputs: could not be encoded".to_string())?;
    let solver = Bn254BlackBoxSolver::default();
    let mut foreign_calls = DefaultForeignCallBuilder::default().build();
    let witness_stack: WitnessStack<FieldElement> =
        nargo::ops::execute_program(&program, initial_witness, &solver, &mut foreign_calls)
            .map_err(|_| "inputs do not satisfy the circuit".to_string())?;

    // Barretenberg takes both buffers uncompressed.
    let witness = gunzip(
        &witness_stack
            .serialize()
            .map_err(|_| "witness: could not be serialized".to_string())?,
    )?;
    let acir = gunzip(&Program::serialize_program(&program))?;

    // --- Proving (what bb prove does) ---
    if srs_g1.is_empty() || srs_g1.len() % G1_POINT_BYTES != 0 {
        return Err("srs: length is not a multiple of the point size".to_string());
    }
    let backend = FfiBackend::new().map_err(|e| format!("barretenberg: {e}"))?;
    let mut api = BarretenbergApi::new(backend);
    api.srs_init_srs(srs_g1, (srs_g1.len() / G1_POINT_BYTES) as u32, &SRS_G2)
        .map_err(|e| format!("srs: {e}"))?;
    let response = api
        .circuit_prove(
            CircuitInput {
                name: "shoji".to_string(),
                bytecode: acir,
                verification_key: verification_key.to_vec(),
            },
            &witness,
            settings(),
        )
        .map_err(|e| format!("prove: {e}"))?;

    Ok(ProofOutput {
        public_inputs: response.public_inputs.concat(),
        proof: response.proof.concat(),
    })
}

/// Generates a proof directly from what a phone holds after talking to the card,
/// so that the certificate never has to leave this process.
///
/// * `certificate_der` / `ca_certificate_der`: as read from the card
/// * `nonce_signature`: the card's signature over the request's nonce message
/// * `request_json`: the verifier's request (see `inputs::Request`)
pub fn prove_card(
    circuit_json: &str,
    certificate_der: &[u8],
    ca_certificate_der: &[u8],
    nonce_signature: &[u8],
    request_json: &str,
    srs_g1: &[u8],
    verification_key: &[u8],
) -> Result<ProofOutput, String> {
    let request = inputs::Request::parse(request_json)?;
    let inputs_json = inputs::build_inputs(certificate_der, ca_certificate_der, nonce_signature, &request)?;
    prove(circuit_json, &inputs_json, srs_g1, verification_key)
}
