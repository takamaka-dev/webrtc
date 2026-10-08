/*
 * Takamaka E2EE calls (C182 / DR-055) — RFC 9605 SFrame primitives, cipher
 * suite 5. See sframe_core.h.
 */

#include "api/crypto/sframe_core.h"

#include <openssl/aead.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <openssl/mem.h>

#include <algorithm>
#include <cstring>
#include <string_view>

#include "rtc_base/bitstream_reader.h"

namespace webrtc {
namespace sframe {

namespace {

// Minimal big-endian length of v (>= 1 byte).
size_t MinLen(uint64_t v) {
  size_t n = 1;
  while (n < 8 && v >= (uint64_t{1} << (8 * n))) {
    ++n;
  }
  return n;
}

void AppendBe(uint64_t v, size_t n, std::vector<uint8_t>* out) {
  for (size_t i = n; i-- > 0;) {
    out->push_back(static_cast<uint8_t>(v >> (8 * i)));
  }
}

uint64_t ReadBe(std::span<const uint8_t> b, size_t pos, size_t n) {
  uint64_t v = 0;
  for (size_t i = 0; i < n; ++i) {
    v = (v << 8) | b[pos + i];
  }
  return v;
}

std::vector<uint8_t> Label(std::string_view prefix, uint64_t kid) {
  std::vector<uint8_t> out(prefix.begin(), prefix.end());
  AppendBe(kid, 8, &out);
  AppendBe(kCipherSuite, 2, &out);
  return out;
}

}  // namespace

// ---- KID
// ----------------------------------------------------------------------------------------------------------

std::optional<uint64_t> MakeKid(uint32_t leg_index, uint64_t epoch) {
  if (leg_index > 0xFFFF) {
    return std::nullopt;
  }
  return (uint64_t{leg_index} << 16) | (epoch & 0xFFFF);
}

// ---- header
// -------------------------------------------------------------------------------------------------------

std::vector<uint8_t> EncodeHeader(uint64_t kid, uint64_t ctr) {
  std::vector<uint8_t> out;
  out.reserve(kMaxHeaderSize);
  out.push_back(0);
  uint8_t config = 0;
  if (kid < 8) {
    config |= static_cast<uint8_t>(kid << 4);
  } else {
    size_t n = MinLen(kid);
    config |= 0x80 | static_cast<uint8_t>((n - 1) << 4);
    AppendBe(kid, n, &out);
  }
  if (ctr < 8) {
    config |= static_cast<uint8_t>(ctr);
  } else {
    size_t n = MinLen(ctr);
    config |= 0x08 | static_cast<uint8_t>(n - 1);
    AppendBe(ctr, n, &out);
  }
  out[0] = config;
  return out;
}

std::optional<Header> ParseHeader(std::span<const uint8_t> data) {
  if (data.empty()) {
    return std::nullopt;
  }
  const uint8_t config = data[0];
  size_t pos = 1;
  Header h;
  if (config & 0x80) {
    size_t n = ((config >> 4) & 0x07) + 1;
    if (pos + n > data.size()) {
      return std::nullopt;  // truncated KID
    }
    h.kid = ReadBe(data, pos, n);
    pos += n;
    if (h.kid < 8 || MinLen(h.kid) != n) {
      return std::nullopt;  // non-minimal KID
    }
  } else {
    h.kid = (config >> 4) & 0x07;
  }
  if (config & 0x08) {
    size_t n = (config & 0x07) + 1;
    if (pos + n > data.size()) {
      return std::nullopt;  // truncated CTR
    }
    h.ctr = ReadBe(data, pos, n);
    pos += n;
    if (h.ctr < 8 || MinLen(h.ctr) != n) {
      return std::nullopt;  // non-minimal CTR
    }
  } else {
    h.ctr = config & 0x07;
  }
  h.length = pos;
  return h;
}

// ---- key schedule
// -------------------------------------------------------------------------------------------------

KeyMaterial::~KeyMaterial() {
  OPENSSL_cleanse(key.data(), key.size());
  OPENSSL_cleanse(salt.data(), salt.size());
}

std::vector<uint8_t> KeyLabel(uint64_t kid) {
  return Label("SFrame 1.0 Secret key ", kid);
}

std::vector<uint8_t> SaltLabel(uint64_t kid) {
  return Label("SFrame 1.0 Secret salt ", kid);
}

bool DeriveKeyMaterial(uint64_t kid,
                       std::span<const uint8_t> base_key,
                       KeyMaterial* out,
                       std::array<uint8_t, kSecretSize>* secret_out) {
  if (base_key.empty() || out == nullptr) {
    return false;
  }
  std::array<uint8_t, kSecretSize> secret{};
  size_t secret_len = 0;
  // HKDF-Extract with an empty salt (RFC 5869: HashLen zeros, which HMAC pads
  // an empty key to anyway).
  bool ok = HKDF_extract(secret.data(), &secret_len, EVP_sha512(),
                         base_key.data(), base_key.size(), nullptr, 0) == 1 &&
            secret_len == kSecretSize;
  const std::vector<uint8_t> key_label = KeyLabel(kid);
  const std::vector<uint8_t> salt_label = SaltLabel(kid);
  ok =
      ok &&
      HKDF_expand(out->key.data(), out->key.size(), EVP_sha512(), secret.data(),
                  secret.size(), key_label.data(), key_label.size()) == 1 &&
      HKDF_expand(out->salt.data(), out->salt.size(), EVP_sha512(),
                  secret.data(), secret.size(), salt_label.data(),
                  salt_label.size()) == 1;
  if (ok && secret_out != nullptr) {
    *secret_out = secret;
  }
  OPENSSL_cleanse(secret.data(), secret.size());
  return ok;
}

std::array<uint8_t, kNonceSize> MakeNonce(
    std::span<const uint8_t, kNonceSize> salt,
    uint64_t ctr) {
  std::array<uint8_t, kNonceSize> n{};
  std::copy(salt.begin(), salt.end(), n.begin());
  for (size_t i = 0; i < 8; ++i) {
    n[kNonceSize - 1 - i] ^= static_cast<uint8_t>(ctr >> (8 * i));
  }
  return n;
}

// ---- AEAD
// ---------------------------------------------------------------------------------------------------------

struct SealingKey::Impl {
  bssl::ScopedEVP_AEAD_CTX ctx;
};

SealingKey::SealingKey() : impl_(std::make_unique<Impl>()) {}

SealingKey::~SealingKey() {
  OPENSSL_cleanse(key_.data(), key_.size());
  OPENSSL_cleanse(salt_.data(), salt_.size());
}

std::unique_ptr<SealingKey> SealingKey::Create(uint64_t kid,
                                               const KeyMaterial& material) {
  std::unique_ptr<SealingKey> k(new SealingKey());
  k->kid_ = kid;
  k->key_ = material.key;
  k->salt_ = material.salt;
  if (EVP_AEAD_CTX_init(k->impl_->ctx.get(), EVP_aead_aes_256_gcm(),
                        k->key_.data(), k->key_.size(), kTagSize,
                        nullptr) != 1) {
    return nullptr;
  }
  return k;
}

bool SealingKey::SameMaterial(const KeyMaterial& other) const {
  return CRYPTO_memcmp(key_.data(), other.key.data(), kKeySize) == 0 &&
         CRYPTO_memcmp(salt_.data(), other.salt.data(), kNonceSize) == 0;
}

bool SealingKey::Seal(uint64_t ctr,
                      std::span<const uint8_t> header,
                      std::span<const uint8_t> metadata,
                      std::span<const uint8_t> plaintext,
                      std::vector<uint8_t>* out) const {
  std::vector<uint8_t> aad(header.begin(), header.end());
  aad.insert(aad.end(), metadata.begin(), metadata.end());
  const std::array<uint8_t, kNonceSize> nonce =
      MakeNonce(std::span<const uint8_t, kNonceSize>(salt_), ctr);
  const size_t old = out->size();
  out->resize(old + plaintext.size() + kTagSize);
  size_t written = 0;
  const std::span<uint8_t> dst = std::span<uint8_t>(*out).subspan(old);
  if (EVP_AEAD_CTX_seal(impl_->ctx.get(), dst.data(), &written, dst.size(),
                        nonce.data(), nonce.size(), plaintext.data(),
                        plaintext.size(), aad.data(), aad.size()) != 1 ||
      written != plaintext.size() + kTagSize) {
    out->resize(old);
    return false;
  }
  return true;
}

bool SealingKey::Open(uint64_t ctr,
                      std::span<const uint8_t> header,
                      std::span<const uint8_t> metadata,
                      std::span<const uint8_t> ct_and_tag,
                      std::vector<uint8_t>* out) const {
  if (ct_and_tag.size() < kTagSize) {
    return false;
  }
  std::vector<uint8_t> aad(header.begin(), header.end());
  aad.insert(aad.end(), metadata.begin(), metadata.end());
  const std::array<uint8_t, kNonceSize> nonce =
      MakeNonce(std::span<const uint8_t, kNonceSize>(salt_), ctr);
  const size_t old = out->size();
  out->resize(old + ct_and_tag.size());
  size_t written = 0;
  const std::span<uint8_t> dst = std::span<uint8_t>(*out).subspan(old);
  if (EVP_AEAD_CTX_open(impl_->ctx.get(), dst.data(), &written, dst.size(),
                        nonce.data(), nonce.size(), ct_and_tag.data(),
                        ct_and_tag.size(), aad.data(), aad.size()) != 1) {
    out->resize(old);
    return false;
  }
  out->resize(old + written);
  return true;
}

std::vector<uint8_t> Encrypt(const SealingKey& key,
                             uint64_t ctr,
                             std::span<const uint8_t> metadata,
                             std::span<const uint8_t> plaintext) {
  std::vector<uint8_t> out = EncodeHeader(key.kid(), ctr);
  const std::vector<uint8_t> header = out;
  if (!key.Seal(ctr, header, metadata, plaintext, &out)) {
    return {};
  }
  return out;
}

std::optional<std::vector<uint8_t>> Decrypt(
    const SealingKey& key,
    std::span<const uint8_t> metadata,
    std::span<const uint8_t> sframe_ciphertext) {
  std::optional<Header> h = ParseHeader(sframe_ciphertext);
  if (!h || h->kid != key.kid()) {
    return std::nullopt;
  }
  std::vector<uint8_t> out;
  if (!key.Open(h->ctr, sframe_ciphertext.first(h->length), metadata,
                sframe_ciphertext.subspan(h->length), &out)) {
    return std::nullopt;
  }
  return out;
}

// ---- replay window
// ------------------------------------------------------------------------------------------------

ReplayWindow::Verdict ReplayWindow::Check(uint64_t ctr) const {
  if (!any_ || ctr > highest_) {
    return Verdict::kOk;
  }
  if (highest_ - ctr >= kReplayWindow) {
    return Verdict::kTooOld;
  }
  return seen_[ctr % kReplayWindow] ? Verdict::kReplay : Verdict::kOk;
}

void ReplayWindow::Commit(uint64_t ctr) {
  if (!any_) {
    any_ = true;
    seen_.reset();
    highest_ = ctr;
  } else if (ctr > highest_) {
    const uint64_t gap = std::min<uint64_t>(ctr - highest_, kReplayWindow);
    for (uint64_t i = 1; i <= gap; ++i) {
      seen_[(highest_ + i) % kReplayWindow] =
          false;  // slide: clear the new slots
    }
    highest_ = ctr;
  }
  seen_[ctr % kReplayWindow] = true;
}

// ---- H.264
// --------------------------------------------------------------------------------------------------------

std::optional<size_t> H264SliceClearPrefixLength(std::span<const uint8_t> nal) {
  if (nal.size() < 2) {
    return std::nullopt;
  }
  // Unescape up to 32 RBSP bytes after the NAL header; end_pos[i] = index in
  // `nal` just past RBSP byte i.
  constexpr size_t kMaxRbsp = 32;
  std::array<uint8_t, kMaxRbsp> rbsp{};
  std::array<size_t, kMaxRbsp> end_pos{};
  size_t n = 0;
  int zeros = 0;
  for (size_t i = 1; i < nal.size() && n < kMaxRbsp; ++i) {
    const uint8_t b = nal[i];
    if (zeros >= 2 && b == 0x03) {
      zeros = 0;  // emulation prevention byte
      continue;
    }
    rbsp[n] = b;
    end_pos[n] = i + 1;
    ++n;
    zeros = (b == 0) ? zeros + 1 : 0;
  }
  BitstreamReader reader(std::span<const uint8_t>(rbsp.data(), n));
  reader.ReadExponentialGolomb();  // first_mb_in_slice
  reader.ReadExponentialGolomb();  // slice_type
  reader.ReadExponentialGolomb();  // pic_parameter_set_id
  if (!reader.Ok()) {
    return std::nullopt;
  }
  const size_t bits = n * 8 - static_cast<size_t>(reader.RemainingBitCount());
  const size_t bytes = (bits + 7) / 8;
  if (bytes == 0 || bytes > n) {
    return std::nullopt;
  }
  return end_pos[bytes - 1];
}

int TrailingZeros(std::span<const uint8_t> prefix) {
  int z = 0;
  for (size_t i = prefix.size(); i-- > 0 && z < 2;) {
    if (prefix[i] != 0) {
      break;
    }
    ++z;
  }
  return z;
}

void EscapeRegion(int leading_zeros,
                  std::span<const uint8_t> in,
                  std::vector<uint8_t>* out) {
  int zeros = std::min(leading_zeros, 2);
  const size_t start = out->size();
  for (uint8_t b : in) {
    if (zeros >= 2 && b <= 0x03) {
      out->push_back(0x03);
      zeros = 0;
    }
    out->push_back(b);
    zeros = (b == 0) ? zeros + 1 : 0;
  }
  if (out->size() > start && (out->back() == 0x00 || out->back() == 0x03)) {
    out->push_back(0x03);
  }
}

std::optional<std::vector<uint8_t>> UnescapeRegion(
    int leading_zeros,
    std::span<const uint8_t> in) {
  if (in.empty()) {
    return std::vector<uint8_t>();
  }
  std::span<const uint8_t> body = in;
  if (body.back() == 0x03) {
    body = body.first(body.size() - 1);  // the final byte EscapeRegion appended
  }
  std::vector<uint8_t> out;
  out.reserve(body.size());
  int zeros = std::min(leading_zeros, 2);
  for (uint8_t b : body) {
    if (zeros >= 2 && b <= 0x03) {
      if (b == 0x03) {
        zeros = 0;  // emulation prevention byte
        continue;
      }
      return std::nullopt;  // 00 00 00/01/02: a start code or forbidden
                            // sequence, never EscapeRegion's output
    }
    out.push_back(b);
    zeros = (b == 0) ? zeros + 1 : 0;
  }
  // Canonical form only: the input must be exactly what EscapeRegion produces
  // for `out`.
  std::vector<uint8_t> again;
  again.reserve(in.size());
  EscapeRegion(leading_zeros, out, &again);
  if (again.size() != in.size() ||
      !std::equal(again.begin(), again.end(), in.begin())) {
    return std::nullopt;
  }
  return out;
}

}  // namespace sframe
}  // namespace webrtc
