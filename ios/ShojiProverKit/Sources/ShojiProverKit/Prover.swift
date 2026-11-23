import Foundation
import ShojiProverFFI

/// Generates shoji proofs in-process, on the device.
///
/// Thin wrapper over the Rust library in `prover/`, which runs Noir witness
/// generation and Barretenberg proving (UltraHonk, Poseidon2 transcript,
/// zero-knowledge) and uses neither the network nor the file system.
public enum Prover {
    public struct Proof: Equatable, Sendable {
        /// The proof, as `bb verify` reads it.
        public let proof: Data
        /// The public inputs and outputs, 32 bytes each, in circuit order:
        /// ca_pubkey_hash, nonce, app_id, current_date, age_threshold, nullifier, is_over_threshold.
        public let publicInputs: Data

        /// Public value number `index` (0-based).
        public func publicValue(_ index: Int) -> Data? {
            let start = index * 32
            guard index >= 0, start + 32 <= publicInputs.count else { return nil }
            return publicInputs.subdata(in: (publicInputs.startIndex + start)..<(publicInputs.startIndex + start + 32))
        }
    }

    public struct ProverError: Error, Equatable, CustomStringConvertible {
        /// A message from the prover. It never contains input values.
        public let description: String

        public init(description: String) {
            self.description = description
        }
    }

    /// - Parameters:
    ///   - circuit: the compiled circuit (`shoji.json`)
    ///   - inputs: the inputs of `main` as JSON, keyed by parameter name
    ///   - srs: uncompressed BN254 G1 points of the structured reference string
    ///   - verificationKey: the circuit's verification key
    ///
    /// Blocks for the duration of proving; call it off the main thread.
    public static func prove(circuit: Data, inputs: Data, srs: Data, verificationKey: Data) throws -> Proof {
        let result = circuit.withUnsafeBytes { c in
            inputs.withUnsafeBytes { i in
                srs.withUnsafeBytes { s in
                    verificationKey.withUnsafeBytes { v in
                        shoji_prove(
                            c.bindMemory(to: UInt8.self).baseAddress, c.count,
                            i.bindMemory(to: UInt8.self).baseAddress, i.count,
                            s.bindMemory(to: UInt8.self).baseAddress, s.count,
                            v.bindMemory(to: UInt8.self).baseAddress, v.count)
                    }
                }
            }
        }
        return try unwrap(result)
    }

    /// Proves directly from what the phone holds after talking to the card. The
    /// certificate is only passed into the prover; nothing derived from it is
    /// returned except the proof and the public values.
    ///
    /// - Parameters:
    ///   - certificate: the holder's signing certificate (DER), as read from the card
    ///   - caCertificate: the signing CA certificate (DER), as read from the card
    ///   - signature: the card's signature over the request's nonce message
    ///   - request: the verifier's request JSON (challenge, current_date, age_threshold, ca_pubkey_hash)
    public static func prove(
        circuit: Data, certificate: Data, caCertificate: Data, signature: Data, request: Data,
        srs: Data, verificationKey: Data
    ) throws -> Proof {
        func bytes(_ d: Data, _ body: (UnsafePointer<UInt8>?, Int) -> ShojiProveResult) -> ShojiProveResult {
            d.withUnsafeBytes { body($0.bindMemory(to: UInt8.self).baseAddress, $0.count) }
        }
        let result = bytes(circuit) { c, cn in
            bytes(certificate) { ce, cen in
                bytes(caCertificate) { ca, can in
                    bytes(signature) { sg, sgn in
                        bytes(request) { rq, rqn in
                            bytes(srs) { sr, srn in
                                bytes(verificationKey) { vk, vkn in
                                    shoji_prove_card(c, cn, ce, cen, ca, can, sg, sgn, rq, rqn, sr, srn, vk, vkn)
                                }
                            }
                        }
                    }
                }
            }
        }
        return try unwrap(result)
    }

    private static func unwrap(_ result: ShojiProveResult) throws -> Proof {
        defer { shoji_result_free(result) }
        if let error = result.error {
            throw ProverError(description: String(cString: error))
        }
        guard let proof = result.proof, let publicInputs = result.public_inputs else {
            throw ProverError(description: "prover returned no result")
        }
        return Proof(
            proof: Data(bytes: proof, count: result.proof_len),
            publicInputs: Data(bytes: publicInputs, count: result.public_inputs_len))
    }
}
