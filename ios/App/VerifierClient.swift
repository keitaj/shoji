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
        /// No answer from the server. `reason` is the system's error domain and
        /// code (for example "NSURLErrorDomain -1009"), never a URL or a body.
        case unreachable(reason: String)
        case malformedResponse
    }

    /// A session per request, so each request opens its own connection. Entering
    /// the PIN, tapping the card and proving take long enough for the server to
    /// close an idle connection; reusing it fails with "connection lost" (-1005),
    /// and the proof must not be sent twice.
    private static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral  // no cookies, no cache, nothing stored
        config.timeoutIntervalForRequest = 30
        return URLSession(configuration: config)
    }

    private func post<T: Decodable>(_ path: String, _ body: [String: String]) async throws -> T {
        guard let url = URL(string: link.origin + path) else { throw ClientError.malformedResponse }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let data: Data
        let response: URLResponse
        let session = Self.makeSession()
        defer { session.finishTasksAndInvalidate() }
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            let e = error as NSError
            throw ClientError.unreachable(reason: "\(e.domain) \(e.code)")
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
