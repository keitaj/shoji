// C interface of the shoji prover library (see prover/src/ffi.rs).
#ifndef SHOJI_PROVER_H
#define SHOJI_PROVER_H

#include <stddef.h>
#include <stdint.h>

// Exactly one of (proof, public_inputs) or error is set.
// Release with shoji_result_free.
typedef struct {
    uint8_t *proof;
    size_t proof_len;
    uint8_t *public_inputs;
    size_t public_inputs_len;
    char *error; // NUL-terminated, or NULL on success
} ShojiProveResult;

ShojiProveResult shoji_prove(const uint8_t *circuit_json, size_t circuit_json_len,
                             const uint8_t *inputs_json, size_t inputs_json_len,
                             const uint8_t *srs_g1, size_t srs_g1_len,
                             const uint8_t *verification_key, size_t verification_key_len);

// Proves directly from the card material; the certificate stays in this process.
ShojiProveResult shoji_prove_card(const uint8_t *circuit_json, size_t circuit_json_len,
                                  const uint8_t *certificate, size_t certificate_len,
                                  const uint8_t *ca_certificate, size_t ca_certificate_len,
                                  const uint8_t *nonce_signature, size_t nonce_signature_len,
                                  const uint8_t *request_json, size_t request_json_len,
                                  const uint8_t *srs_g1, size_t srs_g1_len,
                                  const uint8_t *verification_key, size_t verification_key_len);

void shoji_result_free(ShojiProveResult result);

#endif
