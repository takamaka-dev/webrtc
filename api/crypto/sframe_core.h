/*
 * Takamaka E2EE calls (C182 / DR-055) — RFC 9605 SFrame primitives, cipher
 * suite 5 (AES_256_GCM_SHA512), on BoringSSL only. No key bytes are ever logged
 * by this code.
 *
 * Spec: rschat-docs/security/E2EE_CALLS_PROTOCOL_SPEC_v1.md §9.2 (draft 0.2)
 *   unit = clear codec prefix ‖ SFrame header ‖ ciphertext ‖ tag
 *   AAD  = SFrame header ‖ clear prefix            (RFC 9605 §4.4.3: aad =
 * header + metadata) KID  = the integer leg_index · 2^16 + (epoch mod 2^16),
 * RFC 9605 §4.3 minimal encoding CTR  = per-key counter from 0; nonce = salt
 * XOR BE96(CTR)
 *
 * The references this file must match byte for byte: the Java reference
 * (Messages io.takamaka.messages.call.sframe.*) and the web worker
 * (chat-web-gui static/js/call/sframe-core.js), through the vectors
 * group6_sframe of security/vectors/call_vectors_v1.json.
 */

#ifndef API_CRYPTO_SFRAME_CORE_H_
#define API_CRYPTO_SFRAME_CORE_H_

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "rtc_base/system/rtc_export.h"

namespace webrtc {
namespace sframe {

inline constexpr uint16_t kCipherSuite =
    0x0005;                                // AES_256_GCM_SHA512 (RFC 9605 §8.1)
inline constexpr size_t kKeySize = 32;     // Nk
inline constexpr size_t kNonceSize = 12;   // Nn
inline constexpr size_t kTagSize = 16;     // Nt (full tag)
inline constexpr size_t kSecretSize = 64;  // SHA-512 output
inline constexpr size_t kBaseKeySize =
    32;  // spec §6.1: sender_base_e is 32 bytes
inline constexpr size_t kMaxHeaderSize = 1 + 8 + 8;
// CTR values at or above this need a new epoch. Same limit as the web worker
// (6-byte CTR field, JS safe integers); unreachable in practice (2^48 frames).
inline constexpr uint64_t kCtrLimit = uint64_t{1} << 48;
inline constexpr size_t kReplayWindow =
    128;  // spec §9.2: 128 frames on CTR, per sender key

// ---- KID convention (spec §9.2)
// ---------------------------------------------------------------------------------

// KID = leg_index · 2^16 + (epoch mod 2^16). leg_index is 16-bit; leg_index 0
// is reserved (never assigned: the relay's blank VP8 frame parses as KID 0).
// Returns nullopt when leg_index does not fit 16 bits.
RTC_EXPORT std::optional<uint64_t> MakeKid(uint32_t leg_index, uint64_t epoch);
inline uint32_t LegIndexOf(uint64_t kid) {
  return static_cast<uint32_t>(kid >> 16);
}
inline uint32_t EpochOf(uint64_t kid) {
  return static_cast<uint32_t>(kid & 0xFFFF);
}
// A KID this implementation accepts for a key: leg_index 1..65535 (so 2^16 <=
// kid < 2^32).
inline bool IsAssignableKid(uint64_t kid) {
  return kid >= (uint64_t{1} << 16) && kid < (uint64_t{1} << 32);
}

// ---- header (RFC 9605 §4.3)
// -------------------------------------------------------------------------------------
//   config byte X(1) K(3) Y(1) C(3); values 0..7 inline, otherwise the MINIMUM
//   number of big-endian bytes.

struct Header {
  uint64_t kid = 0;
  uint64_t ctr = 0;
  size_t length = 0;  // header bytes
};

RTC_EXPORT std::vector<uint8_t> EncodeHeader(uint64_t kid, uint64_t ctr);
// Parses a header at the start of `data`. nullopt on truncation or on a
// non-minimal encoding (a decoder MUST reject those, RFC 9605 §4.3 / spec
// §9.2).
RTC_EXPORT std::optional<Header> ParseHeader(std::span<const uint8_t> data);

// ---- key schedule (RFC 9605 §4.4.2)
// -----------------------------------------------------------------------------
//   sframe_secret = HKDF-Extract("", base_key) (SHA-512) sframe_key    =
//   HKDF-Expand(secret, "SFrame 1.0 Secret key "  ‖ BE64(KID) ‖ BE16(suite),
//   32) sframe_salt   = HKDF-Expand(secret, "SFrame 1.0 Secret salt " ‖
//   BE64(KID) ‖ BE16(suite), 12)

struct KeyMaterial {
  std::array<uint8_t, kKeySize> key{};
  std::array<uint8_t, kNonceSize> salt{};
  ~KeyMaterial();  // wipes
};

RTC_EXPORT std::vector<uint8_t> KeyLabel(uint64_t kid);
RTC_EXPORT std::vector<uint8_t> SaltLabel(uint64_t kid);
// Any base key length is accepted here (the RFC vector uses 16 bytes); the key
// store enforces kBaseKeySize. `secret_out` (optional) receives sframe_secret —
// for the vectors only.
RTC_EXPORT bool DeriveKeyMaterial(
    uint64_t kid,
    std::span<const uint8_t> base_key,
    KeyMaterial* out,
    std::array<uint8_t, kSecretSize>* secret_out = nullptr);

RTC_EXPORT std::array<uint8_t, kNonceSize> MakeNonce(
    std::span<const uint8_t, kNonceSize> salt,
    uint64_t ctr);

// ---- AEAD (RFC 9605 §4.4.3, §4.4.4)
// -----------------------------------------------------------------------------

// One initialised AES-256-GCM context for one (KID, key, salt). Not copyable.
class RTC_EXPORT SealingKey {
 public:
  // nullptr on a BoringSSL failure.
  static std::unique_ptr<SealingKey> Create(uint64_t kid,
                                            const KeyMaterial& material);
  ~SealingKey();
  SealingKey(const SealingKey&) = delete;
  SealingKey& operator=(const SealingKey&) = delete;

  uint64_t kid() const { return kid_; }
  // Constant-time comparison with other key material (no-op detection of
  // SetKey).
  bool SameMaterial(const KeyMaterial& other) const;

  // Appends ciphertext ‖ tag of `plaintext` to `out`. AAD = header ‖ metadata.
  bool Seal(uint64_t ctr,
            std::span<const uint8_t> header,
            std::span<const uint8_t> metadata,
            std::span<const uint8_t> plaintext,
            std::vector<uint8_t>* out) const;
  // Appends the plaintext of `ct_and_tag` to `out`; false on a bad tag (out
  // unchanged).
  bool Open(uint64_t ctr,
            std::span<const uint8_t> header,
            std::span<const uint8_t> metadata,
            std::span<const uint8_t> ct_and_tag,
            std::vector<uint8_t>* out) const;

 private:
  SealingKey();
  struct Impl;
  uint64_t kid_ = 0;
  std::array<uint8_t, kKeySize> key_{};
  std::array<uint8_t, kNonceSize> salt_{};
  std::unique_ptr<Impl> impl_;
};

// RFC form: header ‖ AEAD(key, nonce, header ‖ metadata, plaintext).
RTC_EXPORT std::vector<uint8_t> Encrypt(const SealingKey& key,
                                        uint64_t ctr,
                                        std::span<const uint8_t> metadata,
                                        std::span<const uint8_t> plaintext);
// RFC form decryption; nullopt on a header error, a KID that is not the key's,
// or a bad tag.
RTC_EXPORT std::optional<std::vector<uint8_t>> Decrypt(
    const SealingKey& key,
    std::span<const uint8_t> metadata,
    std::span<const uint8_t> sframe_ciphertext);

// ---- replay window (spec §9.2: 128 frames on CTR, per sender key)
// ------------------------------------------------
//   Check() before decrypting; Commit() only after the tag verified, so forged
//   frames cannot move the window.

class RTC_EXPORT ReplayWindow {
 public:
  enum class Verdict { kOk, kReplay, kTooOld };
  Verdict Check(uint64_t ctr) const;
  void Commit(uint64_t ctr);

 private:
  bool any_ = false;
  uint64_t highest_ = 0;
  std::bitset<kReplayWindow> seen_;
};

// ---- H.264 (spec §9.2 [0.2] fallback rule)
// -----------------------------------------------------------------------
//   SPS/PPS/SEI/AUD in clear; each slice NAL unit (types 1 and 5) = its own
//   SFrame unit behind a clear prefix = the 1-byte NAL header + the
//   slice-header bytes up to and including pic_parameter_set_id; consecutive
//   CTR values within a frame; everything after the clear prefix (SFrame header
//   ‖ ciphertext ‖ tag) emulation-prevention escaped. See EscapeRegion for the
//   exact escaping rule (proposed for the spec, OPEN H-2 of the M1 report).

// Length, in bytes of `nal` (escaped form, NAL header included), of the clear
// prefix of a slice NAL; nullopt if the three ue(v) fields cannot be read.
RTC_EXPORT std::optional<size_t> H264SliceClearPrefixLength(
    std::span<const uint8_t> nal);

// Number of trailing 0x00 bytes of `prefix`, capped at 2: the escaping context
// of the region that follows it.
RTC_EXPORT int TrailingZeros(std::span<const uint8_t> prefix);

// Emulation-prevention escaping of `in`, appended to `out`, as if `in` followed
// `leading_zeros` zero bytes: 0x03 is inserted after two zeros when the next
// byte is <= 0x03; then, if the escaped region is non-empty and ends in 0x00 or
// 0x03, one final 0x03 is appended. The final byte makes the rule reversible
// and keeps a NAL unit from ending in 0x00 (which an Annex-B reader would take
// as part of the next start code).
RTC_EXPORT void EscapeRegion(int leading_zeros,
                             std::span<const uint8_t> in,
                             std::vector<uint8_t>* out);
// Inverse of EscapeRegion. nullopt on input that EscapeRegion cannot produce (a
// forbidden 00 00 0x sequence).
RTC_EXPORT std::optional<std::vector<uint8_t>> UnescapeRegion(
    int leading_zeros,
    std::span<const uint8_t> in);

}  // namespace sframe
}  // namespace webrtc

#endif  // API_CRYPTO_SFRAME_CORE_H_
