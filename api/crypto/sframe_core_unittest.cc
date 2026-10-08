/*
 * C182 / DR-055 — RFC 9605 SFrame primitives against the RFC vectors and our
 * Java reference vectors (group6_sframe of
 * rschat-docs/security/vectors/call_vectors_v1.json), byte for byte.
 */

#include "api/crypto/sframe_core.h"

#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "test/gtest.h"

namespace webrtc {
namespace sframe {
namespace {

#include "api/crypto/sframe_test_vectors.inc"

std::vector<uint8_t> Unhex(const std::string& s) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < s.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
  }
  return out;
}

std::string Hex(std::span<const uint8_t> b) {
  static constexpr std::string_view d = "0123456789abcdef";
  std::string s;
  for (uint8_t x : b) {
    s += d[x >> 4];
    s += d[x & 15];
  }
  return s;
}

std::vector<uint8_t> Cat(std::span<const uint8_t> a,
                         std::span<const uint8_t> b) {
  std::vector<uint8_t> out(a.begin(), a.end());
  out.insert(out.end(), b.begin(), b.end());
  return out;
}

// ---- RFC 9605 Appendix C.1: all 289 header encodings
// ----------------------------------------------------------

TEST(SframeCore, Rfc9605AppendixC1Headers) {
  ASSERT_EQ(std::size(kRfc9605C1), 289u);
  for (const C1Row& row : kRfc9605C1) {
    EXPECT_EQ(Hex(EncodeHeader(row.kid, row.ctr)), row.header) << row.header;
    const std::vector<uint8_t> h = Unhex(row.header);
    std::optional<Header> d = ParseHeader(h);
    ASSERT_TRUE(d) << row.header;
    EXPECT_EQ(d->kid, row.kid);
    EXPECT_EQ(d->ctr, row.ctr);
    EXPECT_EQ(d->length, h.size());
    // Every strict prefix is a truncation and must fail.
    for (size_t n = 0; n < h.size(); ++n) {
      EXPECT_FALSE(ParseHeader(std::span<const uint8_t>(h).first(n)))
          << row.header << " truncated to " << n;
    }
  }
}

TEST(SframeCore, NonMinimalHeadersRejected) {
  // The Java reference's negative cases (SframeTest.nonMinimalHeadersRejected)
  // ...
  EXPECT_FALSE(ParseHeader(Unhex("8005")));    // KID 5 in an extension byte
  EXPECT_FALSE(ParseHeader(Unhex("090001")));  // CTR 1 in 2 bytes
  EXPECT_FALSE(ParseHeader(Unhex("90000a")));  // KID 10 in 2 bytes
  EXPECT_FALSE(ParseHeader(Unhex("a001")));    // truncated
  // ... and a few more: a leading zero byte in a long field, CTR 7 extended.
  EXPECT_FALSE(ParseHeader(Unhex("a000ffff")));
  EXPECT_FALSE(ParseHeader(Unhex("0807")));
  EXPECT_TRUE(ParseHeader(Unhex("0808")));
}

TEST(SframeCore, Rfc9605AppendixC3Suite5) {
  const C3Suite5& v = kRfc9605C3Suite5;
  EXPECT_EQ(Hex(KeyLabel(v.kid)), v.key_label);
  EXPECT_EQ(Hex(SaltLabel(v.kid)), v.salt_label);
  KeyMaterial m;
  std::array<uint8_t, kSecretSize> secret{};
  ASSERT_TRUE(DeriveKeyMaterial(v.kid, Unhex(v.base_key), &m, &secret));
  EXPECT_EQ(Hex(secret), v.secret);
  EXPECT_EQ(Hex(m.key), v.key);
  EXPECT_EQ(Hex(m.salt), v.salt);
  EXPECT_EQ(Hex(MakeNonce(std::span<const uint8_t, kNonceSize>(m.salt), v.ctr)),
            v.nonce);
  std::unique_ptr<SealingKey> k = SealingKey::Create(v.kid, m);
  ASSERT_TRUE(k);
  EXPECT_EQ(Hex(Encrypt(*k, v.ctr, Unhex(v.metadata), Unhex(v.pt))), v.ct);
  std::optional<std::vector<uint8_t>> pt =
      Decrypt(*k, Unhex(v.metadata), Unhex(v.ct));
  ASSERT_TRUE(pt);
  EXPECT_EQ(Hex(*pt), v.pt);
  // The metadata is authenticated: without it the tag fails (Java: assertThrows
  // on empty metadata).
  EXPECT_FALSE(Decrypt(*k, {}, Unhex(v.ct)));
}

// ---- our units (Java reference, group6_sframe.units)
// -----------------------------------------------------------

TEST(SframeCore, OurKidMapping) {
  EXPECT_EQ(MakeKid(kUnitsLegIndex, kUnitsEpoch), kUnitsKid);
  EXPECT_EQ(MakeKid(1, 4), 0x00010004u);
  EXPECT_EQ(MakeKid(1, 65536), 0x00010000u);  // epoch taken mod 2^16
  EXPECT_EQ(MakeKid(0, 3), 3u);
  EXPECT_EQ(Hex(EncodeHeader(*MakeKid(0, 3), 0)),
            "30");  // leg 0, epoch 3: inline (why leg 0 is reserved)
  EXPECT_EQ(Hex(EncodeHeader(*MakeKid(1, 4), 0)), "a0010004");
  EXPECT_EQ(Hex(EncodeHeader(*MakeKid(0xffff, 0xffff), 0)), "b0ffffffff");
  EXPECT_FALSE(MakeKid(0x10000, 0));
  EXPECT_FALSE(IsAssignableKid(3));
  EXPECT_FALSE(IsAssignableKid(0xffff));
  EXPECT_TRUE(IsAssignableKid(0x10000));
  EXPECT_TRUE(IsAssignableKid(0xffffffff));
  EXPECT_FALSE(IsAssignableKid(0x100000000));
  EXPECT_EQ(LegIndexOf(kUnitsKid), kUnitsLegIndex);
  EXPECT_EQ(EpochOf(kUnitsKid), kUnitsEpoch);
}

TEST(SframeCore, JavaReferenceUnits) {
  KeyMaterial m;
  std::array<uint8_t, kSecretSize> secret{};
  ASSERT_TRUE(DeriveKeyMaterial(kUnitsKid, Unhex(kUnitsBaseKey), &m, &secret));
  EXPECT_EQ(Hex(secret), kUnitsSecret);
  EXPECT_EQ(Hex(m.key), kUnitsKey);
  EXPECT_EQ(Hex(m.salt), kUnitsSalt);
  std::unique_ptr<SealingKey> k = SealingKey::Create(kUnitsKid, m);
  ASSERT_TRUE(k);
  ASSERT_EQ(std::size(kUnitCases), 4u);
  for (const UnitCase& c : kUnitCases) {
    const std::vector<uint8_t> frame = Unhex(c.frame);
    const std::span<const uint8_t> prefix =
        std::span<const uint8_t>(frame).first(c.prefix_len);
    const std::vector<uint8_t> header = EncodeHeader(kUnitsKid, c.ctr);
    EXPECT_EQ(Hex(header), c.header) << c.codec << " ctr " << c.ctr;
    EXPECT_EQ(
        Hex(MakeNonce(std::span<const uint8_t, kNonceSize>(m.salt), c.ctr)),
        c.nonce);
    EXPECT_EQ(Hex(Cat(header, prefix)), c.aad);
    // unit = prefix ‖ header ‖ ct ‖ tag, AAD = header ‖ prefix
    std::vector<uint8_t> unit(prefix.begin(), prefix.end());
    unit.insert(unit.end(), header.begin(), header.end());
    ASSERT_TRUE(k->Seal(c.ctr, header, prefix,
                        std::span<const uint8_t>(frame).subspan(c.prefix_len),
                        &unit));
    EXPECT_EQ(Hex(unit), c.unit) << c.codec << " ctr " << c.ctr;
    // and back
    const std::vector<uint8_t> expected = Unhex(c.unit);
    std::optional<Header> h =
        ParseHeader(std::span<const uint8_t>(expected).subspan(c.prefix_len));
    ASSERT_TRUE(h);
    std::vector<uint8_t> opened(prefix.begin(), prefix.end());
    ASSERT_TRUE(k->Open(
        h->ctr,
        std::span<const uint8_t>(expected).subspan(c.prefix_len, h->length),
        prefix,
        std::span<const uint8_t>(expected).subspan(c.prefix_len + h->length),
        &opened));
    EXPECT_EQ(Hex(opened), c.frame);
  }
}

TEST(SframeCore, WrongKeyOrKidNeverOpens) {
  const std::vector<uint8_t> base = Unhex(kUnitsBaseKey);
  KeyMaterial right, other_kid, other_key;
  ASSERT_TRUE(DeriveKeyMaterial(kUnitsKid, base, &right));
  ASSERT_TRUE(
      DeriveKeyMaterial(kUnitsKid + 1, base, &other_kid));  // another epoch
  std::vector<uint8_t> base2 = base;
  base2[0] ^= 1;
  ASSERT_TRUE(DeriveKeyMaterial(kUnitsKid, base2,
                                &other_key));  // same KID, another base key
  auto k = SealingKey::Create(kUnitsKid, right);
  auto k2 = SealingKey::Create(kUnitsKid + 1, other_kid);
  auto k3 = SealingKey::Create(kUnitsKid, other_key);
  const std::vector<uint8_t> meta = {0x78};
  const std::vector<uint8_t> pt = Unhex(kUnitCases[0].frame);
  const std::vector<uint8_t> ct = Encrypt(*k, 9, meta, pt);
  EXPECT_TRUE(Decrypt(*k, meta, ct));
  EXPECT_FALSE(Decrypt(*k2, meta, ct));  // KID mismatch
  EXPECT_FALSE(Decrypt(*k3, meta, ct));  // bad tag
  std::vector<uint8_t> t = ct;
  t.back() ^= 1;
  EXPECT_FALSE(Decrypt(*k, meta, t));
  EXPECT_FALSE(Decrypt(*k, std::vector<uint8_t>{0x79},
                       ct));  // the clear prefix is authenticated
}

// ---- replay window
// ----------------------------------------------------------------------------------------------

TEST(SframeCore, ReplayWindow128) {
  ReplayWindow w;
  EXPECT_EQ(w.Check(0), ReplayWindow::Verdict::kOk);
  w.Commit(0);
  EXPECT_EQ(w.Check(0), ReplayWindow::Verdict::kReplay);
  w.Commit(200);
  EXPECT_EQ(w.Check(200), ReplayWindow::Verdict::kReplay);
  EXPECT_EQ(w.Check(73),
            ReplayWindow::Verdict::kOk);  // 200 - 73 = 127: inside, late,
                                          // accepted once
  w.Commit(73);
  EXPECT_EQ(w.Check(73), ReplayWindow::Verdict::kReplay);
  EXPECT_EQ(w.Check(72),
            ReplayWindow::Verdict::kTooOld);  // 200 - 72 = 128: outside
  EXPECT_EQ(w.Check(0), ReplayWindow::Verdict::kTooOld);
  EXPECT_EQ(w.Check(201), ReplayWindow::Verdict::kOk);
  // Sliding clears stale slots: 201 shares the slot of 73 (201 % 128), cleared
  // when the window moved past it.
  w.Commit(300);
  EXPECT_EQ(w.Check(201), ReplayWindow::Verdict::kOk);
  EXPECT_EQ(w.Check(200), ReplayWindow::Verdict::kReplay);  // 100 behind, seen
  EXPECT_EQ(w.Check(173), ReplayWindow::Verdict::kOk);  // 127 behind, unseen
  EXPECT_EQ(w.Check(172), ReplayWindow::Verdict::kTooOld);  // 128 behind
  EXPECT_EQ(w.Check(300), ReplayWindow::Verdict::kReplay);
  // Check() alone never moves the window (a forged frame cannot).
  ReplayWindow f;
  f.Commit(10);
  EXPECT_EQ(f.Check(1000), ReplayWindow::Verdict::kOk);
  EXPECT_EQ(f.Check(10), ReplayWindow::Verdict::kReplay);
  EXPECT_EQ(f.Check(9), ReplayWindow::Verdict::kOk);
}

// ---- H.264 helpers
// ----------------------------------------------------------------------------------------------

bool HasForbidden(std::span<const uint8_t> b, int leading_zeros) {
  int zeros = leading_zeros;
  for (uint8_t x : b) {
    if (zeros >= 2 && x <= 0x02) {
      return true;
    }
    zeros = (x == 0) ? zeros + 1 : 0;
  }
  return false;
}

TEST(SframeCore, EscapeRegionRoundTripAndNoStartCodes) {
  std::mt19937 rng(182);
  for (int lead = 0; lead <= 2; ++lead) {
    for (int iter = 0; iter < 4000; ++iter) {
      // Biased toward zeros and small bytes, where the escaping rules bite.
      const size_t n = 1 + rng() % 40;
      std::vector<uint8_t> in(n);
      for (auto& b : in) {
        const uint32_t r = rng() % 8;
        b = r < 4 ? 0
                  : (r < 7 ? static_cast<uint8_t>(rng() % 4)
                           : static_cast<uint8_t>(rng()));
      }
      std::vector<uint8_t> esc;
      EscapeRegion(lead, in, &esc);
      ASSERT_FALSE(HasForbidden(esc, lead)) << Hex(in) << " lead " << lead;
      ASSERT_NE(esc.back(), 0x00) << Hex(in);
      std::optional<std::vector<uint8_t>> back = UnescapeRegion(lead, esc);
      ASSERT_TRUE(back) << Hex(in) << " -> " << Hex(esc);
      ASSERT_EQ(*back, in) << Hex(esc);
    }
  }
}

TEST(SframeCore, EscapeRegionKnownCases) {
  auto esc = [](int lead, const std::string& h) {
    std::vector<uint8_t> o;
    EscapeRegion(lead, Unhex(h), &o);
    return Hex(o);
  };
  EXPECT_EQ(esc(0, "0000010203"),
            "00000301020303");  // 00 00 01 → 00 00 03 01; final 03 → + 03
  EXPECT_EQ(esc(0, "000004"), "000004");    // 04 after 00 00 needs nothing
  EXPECT_EQ(esc(0, "aa00"), "aa0003");      // never ends in 00
  EXPECT_EQ(esc(0, "aa0000"), "aa000003");  // the H.264 cabac_zero_word shape
  EXPECT_EQ(esc(2, "01ff"), "0301ff");  // context: the prefix ended in 00 00
  EXPECT_EQ(esc(1, "0001"), "000301");
  EXPECT_EQ(esc(0, "ff03"), "ff0303");
  // Non-canonical / forbidden inputs are rejected.
  EXPECT_FALSE(UnescapeRegion(0, Unhex("000001")));
  EXPECT_FALSE(UnescapeRegion(2, Unhex("01ff")));
  EXPECT_FALSE(
      UnescapeRegion(0, Unhex("ff00")));  // a valid escaping never ends in 00
  EXPECT_FALSE(
      UnescapeRegion(0, Unhex("0000030503")));  // a superfluous emulation byte
}

TEST(SframeCore, H264SliceClearPrefix) {
  // LiveKit's blank IDR (65 88 84 …): first_mb 0 ('1'), slice_type 7
  // ('0001000'), pps 0 ('1') → 9 bits → 2 bytes.
  EXPECT_EQ(H264SliceClearPrefixLength(Unhex("6588840af2628000a7be")), 3u);
  // P slice, first_mb 5 ('00110'), slice_type 5 ('00110'), pps 0 ('1') = 0011
  // 0001 1010 0000 → 2 bytes.
  EXPECT_EQ(H264SliceClearPrefixLength(Unhex("4131a0ffff")), 3u);
  // A huge first_mb_in_slice whose RBSP holds 00 00 01: the escaped prefix
  // counts the emulation byte. RBSP 00 00 01 00 00 01 c0: 23 zeros, then 1, 23
  // info bits (first_mb = 2^23 - 1), slice_type 1, pps 1 → 49 bits
  EXPECT_EQ(H264SliceClearPrefixLength(Unhex("45"
                                             "0000030100000301"
                                             "c0"
                                             "ab")),
            10u);
  EXPECT_FALSE(H264SliceClearPrefixLength(Unhex("65")));
  EXPECT_FALSE(
      H264SliceClearPrefixLength(Unhex("650000")));  // ue(v) never terminates
  EXPECT_EQ(TrailingZeros(Unhex("650000")), 2);
  EXPECT_EQ(TrailingZeros(Unhex("6500")), 1);
  EXPECT_EQ(TrailingZeros(Unhex("65")), 0);
}

}  // namespace
}  // namespace sframe
}  // namespace webrtc
