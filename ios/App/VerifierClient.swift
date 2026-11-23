import Foundation
import ShojiCardKit

/// The only network code in the app: two requests to the verifier a link named.
/// What is sent is the session, and later the proof with its public values.
/// Nothing from the certificate is ever sent.
struct VerifierClient {
    let link: VerificationLink

    struct ChallengeResponse: Decodable {
        let nonce: String
        let app_id: String
        let current_date: Int
        let age_threshold: Int
        let trusted_ca_hashes: [String]
    }

    struct VerifyResponse: Decodable {
        let ok: Bool
        let nullifier: String
        let new: Bool
    }

    enum ClientError: Error {
        /// The server answered with an error; `message` is its short reason.
        case rejected(status: Int, message: String)
        case unreachable
        case malformedResponse
    }

    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral  // no cookies, no cache, nothing stored
        config.timeoutIntervalForRequest = 30
        return URLSession(configuration: config)
    }()

    private func post<T: Decodable>(_ path: String, _ body: [String: String]) async throws -> T {
        guard let url = URL(string: link.origin + path) else { throw ClientError.malformedResponse }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await Self.session.data(for: request)
        } catch {
            throw ClientError.unreachable
        }
        guard let http = response as? HTTPURLResponse else { throw ClientError.malformedResponse }
        guard http.statusCode == 200 else {
            let message = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw ClientError.rejected(status: http.statusCode, message: message ?? "")
        }
        guard let decoded = try? JSONDecoder().decode(T.self, from: data) else { throw ClientError.malformedResponse }
        return decoded
    }

    func challenge() async throws -> ChallengeResponse {
        try await post("/challenge", ["app": link.origin, "session": link.session])
    }

    func verify(nonce: String, caPubkeyHash: String, nullifier: String, proof: Data) async throws -> VerifyResponse {
        try await post(
            "/verify",
            ["nonce": nonce, "ca_pubkey_hash": caPubkeyHash, "nullifier": nullifier, "proof": proof.base64EncodedString()])
    }
}
