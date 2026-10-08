/*
 * C182 / DR-055 — the SFrame transformer: our vectors through the
 * FrameTransformerInterface, the fail-closed negative controls (CM-1, CM-2,
 * replay, wrong key, non-minimal header, KID 0, relay blank frames), the storm
 * rule with both resume paths, explicit retention, H.264 units, and round trips
 * through libwebrtc's own RTP packetizers, depacketizers and the H.264 SPS/PPS
 * tracker (the receive-path parsers that run BEFORE the transformer).
 */

#include "api/crypto/sframe_transformer.h"

#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "api/make_ref_counted.h"
#include "api/test/mock_transformable_audio_frame.h"
#include "api/test/mock_transformable_video_frame.h"
#include "api/units/time_delta.h"
#include "common_video/h264/h264_common.h"
#include "modules/rtp_rtcp/source/rtp_format.h"
#include "modules/rtp_rtcp/source/rtp_format_h264.h"
#include "modules/rtp_rtcp/source/rtp_format_vp8.h"
#include "modules/rtp_rtcp/source/rtp_packet_to_send.h"
#include "modules/rtp_rtcp/source/video_rtp_depacketizer_h264.h"
#include "modules/rtp_rtcp/source/video_rtp_depacketizer_vp8.h"
#include "modules/video_coding/h264_sps_pps_tracker.h"
#include "system_wrappers/include/clock.h"
#include "test/gmock.h"
#include "test/gtest.h"

namespace webrtc {
namespace {

#include "api/crypto/sframe_test_vectors.inc"

using ::testing::NiceMock;
using ::testing::Return;
using Direction = TransformableFrameInterface::Direction;

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

std::unique_ptr<TransformableFrameInterface> AudioFrame(
    std::vector<uint8_t> data,
    Direction dir,
    const std::string& mime = "audio/opus",
    uint32_t ssrc = 1111) {
  auto f = std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  auto bytes = std::make_shared<std::vector<uint8_t>>(std::move(data));
  ON_CALL(*f, GetData()).WillByDefault([bytes] {
    return std::span<const uint8_t>(*bytes);
  });
  ON_CALL(*f, SetData).WillByDefault([bytes](std::span<const uint8_t> d) {
    bytes->assign(d.begin(), d.end());
  });
  ON_CALL(*f, GetDirection()).WillByDefault(Return(dir));
  ON_CALL(*f, GetMimeType()).WillByDefault(Return(mime));
  ON_CALL(*f, GetSsrc()).WillByDefault(Return(ssrc));
  return f;
}

std::unique_ptr<TransformableFrameInterface> VideoFrame(
    std::vector<uint8_t> data,
    Direction dir,
    const std::string& mime = "video/VP8",
    uint32_t ssrc = 2222,
    bool key = false) {
  auto f = std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  auto bytes = std::make_shared<std::vector<uint8_t>>(std::move(data));
  ON_CALL(*f, GetData()).WillByDefault([bytes] {
    return std::span<const uint8_t>(*bytes);
  });
  ON_CALL(*f, SetData).WillByDefault([bytes](std::span<const uint8_t> d) {
    bytes->assign(d.begin(), d.end());
  });
  ON_CALL(*f, GetDirection()).WillByDefault(Return(dir));
  ON_CALL(*f, GetMimeType()).WillByDefault(Return(mime));
  ON_CALL(*f, GetSsrc()).WillByDefault(Return(ssrc));
  ON_CALL(*f, IsKeyFrame()).WillByDefault(Return(key));
  return f;
}

class Sink : public TransformedFrameCallback {
 public:
  void OnTransformedFrame(
      std::unique_ptr<TransformableFrameInterface> frame) override {
    const std::span<const uint8_t> d = frame->GetData();
    frames.emplace_back(d.begin(), d.end());
  }
  std::vector<std::vector<uint8_t>> frames;
};

class Recorder : public SframeObserver {
 public:
  void OnSframeEvent(const SframeEvent& e) override { events.push_back(e); }
  int Count(SframeEvent::Type t, const std::string& stream = "") const {
    int n = 0;
    for (const auto& e : events) {
      if (e.type == t && (stream.empty() || e.stream_id == stream)) {
        ++n;
      }
    }
    return n;
  }
  std::vector<SframeEvent> events;
};

// One leg of a call: a key store with the transformers of one track per
// direction and kind.
struct Leg {
  explicit Leg(Clock* clock = nullptr) : store(SframeKeyStore::Create(clock)) {
    recorder = make_ref_counted<Recorder>();
    store->SetObserver(recorder);
  }
  scoped_refptr<SframeTransformer> Make(SframeRole role,
                                        SframeMediaKind kind,
                                        const std::string& id) {
    auto t = SframeTransformer::Create(store, role, kind, id);
    auto s = make_ref_counted<Sink>();
    t->RegisterTransformedFrameCallback(s);
    sinks[id] = s;
    return t;
  }
  scoped_refptr<SframeKeyStore> store;
  scoped_refptr<Recorder> recorder;
  std::map<std::string, scoped_refptr<Sink>> sinks;
};

uint64_t Dropped(const SframeStreamStats& s, SframeDropReason r) {
  return s.dropped[static_cast<size_t>(r)];
}

const std::vector<uint8_t> kBase = Unhex(kUnitsBaseKey);

std::vector<uint8_t> OtherBase() {
  std::vector<uint8_t> b = kBase;
  b[31] ^= 0x5a;
  return b;
}

// ---- vectors through the transformer
// ----------------------------------------------------------------------------

TEST(SframeTransformer, JavaVectorsByteForByteThroughTheTransformer) {
  Leg alice;
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(alice.store->SetSendKid(kUnitsKid));
  auto audio =
      alice.Make(SframeRole::kSender, SframeMediaKind::kAudio, "send:audio");
  auto video =
      alice.Make(SframeRole::kSender, SframeMediaKind::kVideo, "send:video");
  // One CTR space per KID shared by audio and video (the web worker's rule):
  // cases 0, 1 (opus), 2 (vp8).
  audio->Transform(AudioFrame(Unhex(kUnitCases[0].frame), Direction::kSender));
  audio->Transform(AudioFrame(Unhex(kUnitCases[1].frame), Direction::kSender));
  video->Transform(VideoFrame(Unhex(kUnitCases[2].frame), Direction::kSender));
  // Case 3 is CTR 4660: 4657 more frames first.
  for (int i = 0; i < 4657; ++i) {
    video->Transform(VideoFrame({0x31, 0x32, 0x33}, Direction::kSender));
  }
  video->Transform(VideoFrame(Unhex(kUnitCases[3].frame), Direction::kSender));
  const auto& a = alice.sinks["send:audio"]->frames;
  const auto& v = alice.sinks["send:video"]->frames;
  ASSERT_EQ(a.size(), 2u);
  ASSERT_EQ(v.size(), 4659u);
  EXPECT_EQ(Hex(a[0]), kUnitCases[0].unit);
  EXPECT_EQ(Hex(a[1]), kUnitCases[1].unit);
  EXPECT_EQ(Hex(v[0]), kUnitCases[2].unit);
  EXPECT_EQ(Hex(v.back()), kUnitCases[3].unit);

  // Bob opens them all (his own key store, the same base key).
  Leg bob;
  ASSERT_EQ(bob.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  auto raudio =
      bob.Make(SframeRole::kReceiver, SframeMediaKind::kAudio, "recv:audio");
  auto rvideo =
      bob.Make(SframeRole::kReceiver, SframeMediaKind::kVideo, "recv:video");
  for (const UnitCase& c : kUnitCases) {
    if (std::string(c.codec) == "opus") {
      raudio->Transform(AudioFrame(Unhex(c.unit), Direction::kReceiver));
    } else {
      rvideo->Transform(VideoFrame(Unhex(c.unit), Direction::kReceiver));
    }
  }
  const auto& ra = bob.sinks["recv:audio"]->frames;
  const auto& rv = bob.sinks["recv:video"]->frames;
  ASSERT_EQ(ra.size(), 2u);
  ASSERT_EQ(rv.size(), 2u);
  EXPECT_EQ(Hex(ra[0]), kUnitCases[0].frame);
  EXPECT_EQ(Hex(ra[1]), kUnitCases[1].frame);
  EXPECT_EQ(Hex(rv[0]), kUnitCases[2].frame);
  EXPECT_EQ(Hex(rv[1]), kUnitCases[3].frame);
  EXPECT_EQ(rvideo->GetStats().passed, 2u);
  EXPECT_EQ(rvideo->GetStats().dropped_total(), 0u);
}

TEST(SframeTransformer, VectorSealAndOpenSeamsReproduceTheJavaUnits) {
  for (const UnitCase& c : kUnitCases) {
    const std::vector<uint8_t> unit = SframeKeyStore::VectorSeal(
        kBase, kUnitsKid, c.ctr, Unhex(c.frame), c.prefix_len);
    EXPECT_EQ(Hex(unit), c.unit);
    std::optional<std::vector<uint8_t>> frame = SframeKeyStore::VectorOpen(
        kBase, kUnitsKid, Unhex(c.unit), c.prefix_len);
    ASSERT_TRUE(frame);
    EXPECT_EQ(Hex(*frame), c.frame);
  }
  std::vector<uint8_t> t = Unhex(kUnitCases[0].unit);
  t.back() ^= 1;
  EXPECT_FALSE(SframeKeyStore::VectorOpen(kBase, kUnitsKid, t, 1));
  EXPECT_FALSE(SframeKeyStore::VectorOpen(OtherBase(), kUnitsKid,
                                          Unhex(kUnitCases[0].unit), 1));
  EXPECT_FALSE(SframeKeyStore::VectorOpen(kBase, kUnitsKid + 1,
                                          Unhex(kUnitCases[0].unit), 1));
  EXPECT_TRUE(SframeKeyStore::VectorSeal(kBase, kUnitsKid, 0, {}, 1).empty());
}

// ---- CM-2: nothing passes in plaintext while a key is missing
// ---------------------------------------------------

TEST(SframeTransformer, SenderWithoutSendKidDropsEverything) {
  Leg alice;
  auto audio = alice.Make(SframeRole::kSender, SframeMediaKind::kAudio, "a");
  auto video = alice.Make(SframeRole::kSender, SframeMediaKind::kVideo, "v");
  // No key at all; then a key but no send KID.
  audio->Transform(AudioFrame({0x78, 1, 2, 3}, Direction::kSender));
  video->Transform(VideoFrame({0x10, 1, 2, 3}, Direction::kSender));
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  audio->Transform(AudioFrame({0x78, 1, 2, 3}, Direction::kSender));
  EXPECT_FALSE(alice.store->SetSendKid(kUnitsKid + 1));  // no key for it
  audio->Transform(AudioFrame({0x78, 1, 2, 3}, Direction::kSender));
  EXPECT_TRUE(alice.sinks["a"]->frames.empty());
  EXPECT_TRUE(alice.sinks["v"]->frames.empty());
  EXPECT_EQ(Dropped(audio->GetStats(), SframeDropReason::kNoKey), 3u);
  EXPECT_EQ(Dropped(video->GetStats(), SframeDropReason::kNoKey), 1u);
  // Removing the send key closes the sender again.
  ASSERT_TRUE(alice.store->SetSendKid(kUnitsKid));
  audio->Transform(AudioFrame({0x78, 1, 2, 3}, Direction::kSender));
  EXPECT_EQ(alice.sinks["a"]->frames.size(), 1u);
  ASSERT_TRUE(alice.store->RemoveKey(kUnitsKid));
  EXPECT_FALSE(alice.store->send_kid());
  audio->Transform(AudioFrame({0x78, 1, 2, 3}, Direction::kSender));
  EXPECT_EQ(alice.sinks["a"]->frames.size(), 1u);
}

TEST(SframeTransformer, SenderDropsEmptyFramesAndForeignCodecs) {
  Leg alice;
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(alice.store->SetSendKid(kUnitsKid));
  auto audio = alice.Make(SframeRole::kSender, SframeMediaKind::kAudio, "a");
  auto video = alice.Make(SframeRole::kSender, SframeMediaKind::kVideo, "v");
  audio->Transform(AudioFrame({}, Direction::kSender));  // §9.1: no TOC
  audio->Transform(AudioFrame({0x78, 1, 2}, Direction::kSender,
                              "audio/red"));  // CM-5: RED off
  audio->Transform(AudioFrame({0x78, 1, 2}, Direction::kSender, "audio/PCMU"));
  video->Transform(VideoFrame({}, Direction::kSender));
  video->Transform(VideoFrame({0x10, 1, 2}, Direction::kSender, "video/VP9"));
  video->Transform(VideoFrame({0x10, 1, 2}, Direction::kSender, "video/AV1"));
  video->Transform(VideoFrame({0, 0, 0, 1, 0x65, 0x88, 0x84, 1},
                              Direction::kSender,
                              "video/H264"));  // not enabled
  video->Transform(
      VideoFrame({0x10, 1, 2}, Direction::kReceiver));  // direction mismatch
  EXPECT_TRUE(alice.sinks["a"]->frames.empty());
  EXPECT_TRUE(alice.sinks["v"]->frames.empty());
  EXPECT_EQ(Dropped(audio->GetStats(), SframeDropReason::kEmpty), 1u);
  EXPECT_EQ(Dropped(audio->GetStats(), SframeDropReason::kCodec), 2u);
  EXPECT_EQ(Dropped(video->GetStats(), SframeDropReason::kEmpty), 1u);
  EXPECT_EQ(Dropped(video->GetStats(), SframeDropReason::kCodec), 3u);
  EXPECT_EQ(Dropped(video->GetStats(), SframeDropReason::kInternal), 1u);
}

// ---- receiver negatives (CM-1, CM-4, wrong key, headers)
// -------------------------------------------------------

TEST(SframeTransformer, ReceiverFailsClosed) {
  const std::vector<uint8_t> unit =
      Unhex(kUnitCases[2].unit);  // VP8, KID 0x10004, CTR 2
  Leg bob;
  auto rv = bob.Make(SframeRole::kReceiver, SframeMediaKind::kVideo, "rv");
  auto& out = bob.sinks["rv"]->frames;

  rv->Transform(VideoFrame(unit, Direction::kReceiver));  // no key at all
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kUnknownKid), 1u);
  ASSERT_EQ(bob.store->SetKey(kUnitsKid, OtherBase()),
            SframeKeyStore::SetKeyResult::kChanged);
  rv->Transform(VideoFrame(unit, Direction::kReceiver));  // same KID, wrong key
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kBadTag), 1u);
  ASSERT_EQ(bob.store->SetKey(kUnitsKid + 1, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  EXPECT_TRUE(out.empty());  // a key of another epoch never opens it: no
                             // implicit fallback

  ASSERT_EQ(bob.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  rv->Transform(VideoFrame(unit, Direction::kReceiver));
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(Hex(out[0]), kUnitCases[2].frame);
  rv->Transform(VideoFrame(unit, Direction::kReceiver));  // replay
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kReplay), 1u);

  // Tampering with the clear prefix, the header (CTR) or the ciphertext: bad
  // tag, never played.
  std::vector<uint8_t> t = Unhex(kUnitCases[3].unit);  // CTR 4660, still unseen
  t[0] ^= 0x01;                                        // the VP8 keyframe bit
  rv->Transform(VideoFrame(t, Direction::kReceiver));
  t = Unhex(kUnitCases[3].unit);
  t[5] ^= 0x01;  // CTR 0x1234 → 0x1235
  rv->Transform(VideoFrame(t, Direction::kReceiver));
  t = Unhex(kUnitCases[3].unit);
  t[10] ^= 0x80;
  rv->Transform(VideoFrame(t, Direction::kReceiver));
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kBadTag), 4u);
  // The untampered unit still opens: forged frames did not move the window.
  rv->Transform(VideoFrame(Unhex(kUnitCases[3].unit), Direction::kReceiver));
  ASSERT_EQ(out.size(), 2u);
  // CTR 2 is now 4658 behind: too old.
  std::vector<uint8_t> again = Unhex(kUnitCases[2].unit);
  rv->Transform(VideoFrame(again, Direction::kReceiver));
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kReplay) +
                Dropped(rv->GetStats(), SframeDropReason::kTooOld),
            2u);
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kTooOld), 1u);

  // Non-minimal header: KID 0x10004 re-encoded in 4 bytes (b0 00 01 00 04
  // instead of a0 01 00 04).
  std::vector<uint8_t> nm = {0x10, 0xb2, 0x00, 0x01, 0x00, 0x04};
  nm.insert(nm.end(), unit.begin() + 5, unit.end());
  rv->Transform(VideoFrame(nm, Direction::kReceiver));
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kBadHeader), 1u);
  // Short and empty frames.
  rv->Transform(
      VideoFrame({0x10, 0xa0, 0x01, 0x00, 0x04}, Direction::kReceiver));
  rv->Transform(VideoFrame({}, Direction::kReceiver));
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kShort), 2u);
  // A codec that is not VP8 on a video receiver is never played.
  rv->Transform(
      VideoFrame(Unhex(kUnitCases[3].unit), Direction::kReceiver, "video/VP9"));
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kCodec), 1u);
  EXPECT_EQ(out.size(), 2u);
}

TEST(SframeTransformer, RelayInjectedBlankFramesAreDroppedAndCount) {
  // LiveKit's blank frames, byte for byte (pkg/sfu/downtrack.go; the stock
  // cryptor's kSif* constants).
  const std::vector<uint8_t> vp8_blank = {
      0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x08, 0x00, 0x08, 0x00, 0x00,
      0x47, 0x08, 0x85, 0x85, 0x88, 0x85, 0x84, 0x88, 0x02, 0x02, 0x00,
      0x0c, 0x0d, 0x60, 0x00, 0xfe, 0xff, 0xab, 0x50, 0x80};
  std::vector<uint8_t> opus_blank(80, 0x00);
  opus_blank[0] = 0xf8;
  opus_blank[1] = 0xff;
  opus_blank[2] = 0xfe;
  // With the "LKROCKS" trailer the stock cryptor used to pass them in clear
  // (CM-1): here nothing is special.
  std::vector<uint8_t> vp8_trailer = vp8_blank;
  for (char c : std::string("LKROCKS")) {
    vp8_trailer.push_back(static_cast<uint8_t>(c));
  }
  Leg bob;
  ASSERT_EQ(bob.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  auto rv = bob.Make(SframeRole::kReceiver, SframeMediaKind::kVideo, "rv");
  auto ra = bob.Make(SframeRole::kReceiver, SframeMediaKind::kAudio, "ra");
  rv->Transform(
      VideoFrame(vp8_blank, Direction::kReceiver, "video/VP8", 2222, true));
  rv->Transform(VideoFrame(vp8_trailer, Direction::kReceiver));
  ra->Transform(AudioFrame(opus_blank, Direction::kReceiver));
  EXPECT_TRUE(bob.sinks["rv"]->frames.empty());
  EXPECT_TRUE(bob.sinks["ra"]->frames.empty());
  // The blank VP8 frame parses as KID 0 (why leg_index 0 is reserved): unknown
  // KID, counted toward the storm.
  EXPECT_EQ(rv->GetStats().last_kid, 0u);
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kUnknownKid), 2u);
  EXPECT_EQ(rv->GetStats().consecutive, 2u);
  // The Opus silence frame has a non-minimal 8-byte CTR: bad header, counted.
  EXPECT_EQ(Dropped(ra->GetStats(), SframeDropReason::kBadHeader), 1u);
  EXPECT_EQ(ra->GetStats().consecutive, 1u);
  // KID 0 (leg_index 0) can never get a key.
  EXPECT_EQ(bob.store->SetKey(0, kBase),
            SframeKeyStore::SetKeyResult::kInvalid);
  EXPECT_EQ(bob.store->SetKey(0x2, kBase),
            SframeKeyStore::SetKeyResult::kInvalid);
}

// ---- key store rules
// ------------------------------------------------------------------------------------------

TEST(SframeTransformer, KeyStoreRules) {
  Leg l;
  const std::vector<uint8_t> short_key(16, 7);
  EXPECT_EQ(l.store->SetKey(kUnitsKid, short_key),
            SframeKeyStore::SetKeyResult::kInvalid);
  EXPECT_EQ(l.store->SetKey(uint64_t{1} << 32, kBase),
            SframeKeyStore::SetKeyResult::kInvalid);
  EXPECT_EQ(l.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  EXPECT_EQ(l.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kUnchanged);
  EXPECT_EQ(l.store->SetKey(kUnitsKid, OtherBase()),
            SframeKeyStore::SetKeyResult::kChanged);
  // Cap: a 5th epoch of leg 1 evicts the oldest-installed one (0x10004).
  const uint64_t leg1 = kUnitsKid & ~uint64_t{0xFFFF};
  for (uint64_t e = 5; e <= 8; ++e) {
    ASSERT_EQ(l.store->SetKey(leg1 + e, kBase),
              SframeKeyStore::SetKeyResult::kChanged);
  }
  EXPECT_FALSE(l.store->HasKey(kUnitsKid));
  EXPECT_EQ(l.store->kids().size(), 4u);
  EXPECT_EQ(l.recorder->Count(SframeEvent::Type::kKeyEvicted), 1);
  // Another leg is not affected by leg 1's cap.
  ASSERT_EQ(l.store->SetKey((uint64_t{2} << 16) + 1, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  EXPECT_EQ(l.store->kids().size(), 5u);
}

TEST(SframeTransformer, CtrIsNeverReusedForAKid) {
  Leg alice;
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(alice.store->SetSendKid(kUnitsKid));
  auto a = alice.Make(SframeRole::kSender, SframeMediaKind::kAudio, "a");
  a->Transform(AudioFrame({0x78, 1}, Direction::kSender));
  a->Transform(AudioFrame({0x78, 1}, Direction::kSender));
  ASSERT_TRUE(alice.store->RemoveKey(kUnitsKid));
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(alice.store->SetSendKid(kUnitsKid));
  a->Transform(AudioFrame({0x78, 1}, Direction::kSender));
  const auto& f = alice.sinks["a"]->frames;
  ASSERT_EQ(f.size(), 3u);
  for (size_t i = 0; i < 3; ++i) {
    auto h = sframe::ParseHeader(std::span<const uint8_t>(f[i]).subspan(1));
    ASSERT_TRUE(h);
    EXPECT_EQ(h->ctr, i);
  }
}

// ---- storm rule (spec §9.2 [0.2])
// -------------------------------------------------------------------------------

TEST(SframeTransformer, StormAfterNAndResumeOnKey) {
  Leg bob;
  ASSERT_EQ(bob.store->SetKey(kUnitsKid, OtherBase()),
            SframeKeyStore::SetKeyResult::kChanged);  // wrong key
  auto rv = bob.Make(SframeRole::kReceiver, SframeMediaKind::kVideo, "rv");
  const std::vector<uint8_t> unit = Unhex(kUnitCases[2].unit);
  for (int i = 0; i < 29; ++i) {
    rv->Transform(VideoFrame(unit, Direction::kReceiver));
  }
  EXPECT_FALSE(rv->GetStats().storm);
  EXPECT_EQ(bob.recorder->Count(SframeEvent::Type::kStorm), 0);
  rv->Transform(VideoFrame(unit, Direction::kReceiver));  // the 30th
  EXPECT_TRUE(rv->GetStats().storm);
  EXPECT_EQ(bob.recorder->Count(SframeEvent::Type::kStorm, "rv"), 1);
  for (int i = 0; i < 10; ++i) {
    rv->Transform(VideoFrame(unit, Direction::kReceiver));
  }
  EXPECT_EQ(bob.recorder->Count(SframeEvent::Type::kStorm), 1);  // raised once
  // Replay drops do not count toward N.
  // The right key arrives: resumed.
  ASSERT_EQ(bob.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  EXPECT_FALSE(rv->GetStats().storm);
  EXPECT_EQ(rv->GetStats().consecutive, 0u);
  EXPECT_EQ(bob.recorder->Count(SframeEvent::Type::kResumed, "rv"), 1);
  rv->Transform(VideoFrame(unit, Direction::kReceiver));
  EXPECT_EQ(bob.sinks["rv"]->frames.size(), 1u);
  rv->Transform(
      VideoFrame(unit, Direction::kReceiver));  // replay: not a storm reason
  EXPECT_EQ(rv->GetStats().consecutive, 0u);
  // A smaller N is honoured.
  bob.store->SetStormThreshold(3);
  for (int i = 0; i < 3; ++i) {
    rv->Transform(VideoFrame({0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x08, 0, 8, 0,
                              0, 0x47, 8, 0x85, 0x85, 0x88, 0x85, 0x84},
                             Direction::kReceiver));
  }
  EXPECT_EQ(rv->GetStats().storms, 2u);
}

TEST(SframeTransformer, StormResumesWhenAnotherStreamUnderTheKidAuthenticates) {
  // The sender had the wrong key (its fault): the receiver's key was right, so
  // it never gets a key event. Its paused video resumes when the same leg's
  // audio authenticates again (the GUI lab finding).
  Leg alice;
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, OtherBase()),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(alice.store->SetSendKid(kUnitsKid));
  auto sa = alice.Make(SframeRole::kSender, SframeMediaKind::kAudio, "sa");
  auto sv = alice.Make(SframeRole::kSender, SframeMediaKind::kVideo, "sv");
  Leg bob;
  ASSERT_EQ(bob.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  auto ra = bob.Make(SframeRole::kReceiver, SframeMediaKind::kAudio, "ra");
  auto rv = bob.Make(SframeRole::kReceiver, SframeMediaKind::kVideo, "rv");
  for (int i = 0; i < 30; ++i) {
    sv->Transform(
        VideoFrame({0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, Direction::kSender));
    rv->Transform(
        VideoFrame(alice.sinks["sv"]->frames.back(), Direction::kReceiver));
  }
  ASSERT_TRUE(rv->GetStats().storm);
  // The sender fixes its key; the app keeps the video subscription paused, but
  // audio flows.
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  sa->Transform(AudioFrame({0x78, 1, 2, 3}, Direction::kSender));
  ra->Transform(
      AudioFrame(alice.sinks["sa"]->frames.back(), Direction::kReceiver));
  ASSERT_EQ(bob.sinks["ra"]->frames.size(), 1u);
  EXPECT_FALSE(rv->GetStats().storm);
  EXPECT_EQ(bob.recorder->Count(SframeEvent::Type::kRecovered, "rv"), 1);
  EXPECT_EQ(bob.recorder->Count(SframeEvent::Type::kResumed), 0);
}

// ---- explicit retention
// -----------------------------------------------------------------------------------------

TEST(SframeTransformer, RetiredKeyOpensUntilRetentionThenIsGone) {
  SimulatedClock clock(Timestamp::Seconds(1000));
  Leg bob(&clock);
  ASSERT_EQ(bob.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(bob.store->SetSendKid(kUnitsKid));
  auto rv = bob.Make(SframeRole::kReceiver, SframeMediaKind::kVideo, "rv");
  auto sa = bob.Make(SframeRole::kSender, SframeMediaKind::kAudio, "sa");
  ASSERT_TRUE(bob.store->RetireKey(kUnitsKid, TimeDelta::Seconds(10)));
  clock.AdvanceTime(TimeDelta::Seconds(9));
  rv->Transform(VideoFrame(Unhex(kUnitCases[2].unit), Direction::kReceiver));
  EXPECT_EQ(bob.sinks["rv"]->frames.size(), 1u);
  clock.AdvanceTime(TimeDelta::Seconds(2));
  rv->Transform(VideoFrame(Unhex(kUnitCases[3].unit), Direction::kReceiver));
  EXPECT_EQ(bob.sinks["rv"]->frames.size(), 1u);
  EXPECT_EQ(Dropped(rv->GetStats(), SframeDropReason::kUnknownKid), 1u);
  EXPECT_EQ(bob.recorder->Count(SframeEvent::Type::kKeyExpired), 1);
  EXPECT_FALSE(bob.store->send_kid());  // an expired send key closes the sender
  sa->Transform(AudioFrame({0x78, 1}, Direction::kSender));
  EXPECT_TRUE(bob.sinks["sa"]->frames.empty());
}

// ---- sinks and engagement
// ---------------------------------------------------------------------------------------

TEST(SframeTransformer, SinksPerSsrcAndEngagementCounters) {
  Leg alice;
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(alice.store->SetSendKid(kUnitsKid));
  auto v = SframeTransformer::Create(alice.store, SframeRole::kSender,
                                     SframeMediaKind::kVideo, "simulcast");
  auto low = make_ref_counted<Sink>();
  auto high = make_ref_counted<Sink>();
  v->RegisterTransformedFrameSinkCallback(low, 1);
  v->RegisterTransformedFrameSinkCallback(high, 2);
  v->Transform(VideoFrame({0x10, 1, 2}, Direction::kSender, "video/VP8", 1));
  v->Transform(
      VideoFrame({0x10, 1, 2}, Direction::kSender, "video/VP8", 2, true));
  v->Transform(VideoFrame({0x10, 1, 2}, Direction::kSender, "video/VP8",
                          3));  // no sink: dropped, no CTR used
  v->UnregisterTransformedFrameSinkCallback(2);
  v->Transform(VideoFrame({0x10, 1, 2}, Direction::kSender, "video/VP8", 2));
  EXPECT_EQ(low->frames.size(), 1u);
  EXPECT_EQ(high->frames.size(), 1u);
  const SframeStreamStats s = v->GetStats();
  EXPECT_EQ(s.frames, 4u);
  EXPECT_EQ(s.passed, 2u);
  EXPECT_EQ(s.keyframes, 1u);
  EXPECT_EQ(Dropped(s, SframeDropReason::kNoSink), 2u);
  EXPECT_TRUE(s.first_frame_at && s.first_pass_at);
  EXPECT_EQ(alice.recorder->Count(SframeEvent::Type::kEngaged, "simulcast"), 1);
  EXPECT_EQ(alice.recorder->Count(SframeEvent::Type::kFirstPass, "simulcast"),
            1);
  auto h =
      sframe::ParseHeader(std::span<const uint8_t>(high->frames[0]).subspan(1));
  ASSERT_TRUE(h);
  EXPECT_EQ(h->ctr, 1u);
  // The store lists every live stream; a destroyed transformer leaves it.
  EXPECT_EQ(alice.store->GetAllStats().size(), 1u);
  v = nullptr;
  EXPECT_EQ(alice.store->GetAllStats().size(), 0u);
}

// ---- H.264
// ------------------------------------------------------------------------------------------------------

const std::vector<uint8_t> kSps = {
    0x67, 0x42, 0xc0, 0x1f, 0x0f, 0xd9, 0x1f, 0x88, 0x88, 0x84, 0x00, 0x00,
    0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xc8, 0x3c, 0x60, 0xc9, 0x20};
const std::vector<uint8_t> kPps = {0x68, 0x87, 0xcb, 0x83, 0xcb, 0x20};

// A slice NAL: `head` (NAL header + slice header bytes) then `n` pseudo-random
// bytes in 1..255 (no 00 00 sequence).
std::vector<uint8_t> Slice(std::vector<uint8_t> head, size_t n, uint32_t seed) {
  std::mt19937 rng(seed);
  for (size_t i = 0; i < n; ++i) {
    head.push_back(static_cast<uint8_t>(1 + rng() % 255));
  }
  return head;
}

std::vector<uint8_t> AnnexB(const std::vector<std::vector<uint8_t>>& nalus) {
  std::vector<uint8_t> out;
  for (const auto& n : nalus) {
    out.insert(out.end(), {0, 0, 0, 1});
    out.insert(out.end(), n.begin(), n.end());
  }
  return out;
}

TEST(SframeTransformer, H264DisabledByDefaultOnBothSides) {
  Leg l;
  ASSERT_EQ(l.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(l.store->SetSendKid(kUnitsKid));
  auto s = l.Make(SframeRole::kSender, SframeMediaKind::kVideo, "s");
  auto r = l.Make(SframeRole::kReceiver, SframeMediaKind::kVideo, "r");
  const std::vector<uint8_t> frame =
      AnnexB({kSps, kPps, Slice({0x65, 0x88, 0x84}, 300, 1)});
  s->Transform(VideoFrame(frame, Direction::kSender, "video/H264"));
  r->Transform(
      VideoFrame(frame, Direction::kReceiver,
                 "video/H264"));  // e.g. a clear H.264 frame from the relay
  EXPECT_TRUE(l.sinks["s"]->frames.empty());
  EXPECT_TRUE(l.sinks["r"]->frames.empty());
  EXPECT_EQ(Dropped(s->GetStats(), SframeDropReason::kCodec), 1u);
  EXPECT_EQ(Dropped(r->GetStats(), SframeDropReason::kCodec), 1u);
}

TEST(SframeTransformer, H264UnitsRoundTrip) {
  Leg alice;
  alice.store->SetH264Enabled(true);
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(alice.store->SetSendKid(kUnitsKid));
  auto s = alice.Make(SframeRole::kSender, SframeMediaKind::kVideo, "s");
  Leg bob;
  bob.store->SetH264Enabled(true);
  ASSERT_EQ(bob.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  auto r = bob.Make(SframeRole::kReceiver, SframeMediaKind::kVideo, "r");

  // Keyframe: AUD, SPS, PPS, SEI, two IDR slices (first_mb 0 and 40); then a P
  // frame.
  const std::vector<uint8_t> aud = {0x09, 0xf0};
  const std::vector<uint8_t> sei = {0x06, 0x05, 0x01, 0xaa, 0x80};
  const std::vector<uint8_t> idr0 = Slice({0x65, 0x88, 0x84}, 700, 2);
  // first_mb 40 = ue '00000101001' (11 bits), slice_type 7 '0001000', pps 0 '1'
  // → 19 bits
  const std::vector<uint8_t> idr1 = Slice({0x65, 0x05, 0x22, 0x20}, 500, 3);
  const std::vector<uint8_t> key = AnnexB({aud, kSps, kPps, sei, idr0, idr1});
  const std::vector<uint8_t> delta = AnnexB({Slice({0x41, 0x9a}, 200, 4)});
  s->Transform(VideoFrame(key, Direction::kSender, "video/H264", 2222, true));
  s->Transform(VideoFrame(delta, Direction::kSender, "video/H264"));
  const auto& sent = alice.sinks["s"]->frames;
  ASSERT_EQ(sent.size(), 2u);

  // What the relay sees: the same NAL units, AUD/SPS/PPS/SEI unchanged, slice
  // prefixes clear, no start-code emulation.
  std::vector<H264::NaluIndex> in = H264::FindNaluIndices(key);
  std::vector<H264::NaluIndex> on_wire = H264::FindNaluIndices(sent[0]);
  ASSERT_EQ(on_wire.size(), in.size());
  for (size_t i = 0; i < 4; ++i) {
    EXPECT_EQ(Hex(std::span<const uint8_t>(sent[0]).subspan(
                  on_wire[i].payload_start_offset, on_wire[i].payload_size)),
              Hex(std::span<const uint8_t>(key).subspan(
                  in[i].payload_start_offset, in[i].payload_size)));
  }
  const std::span<const uint8_t> w4 = std::span<const uint8_t>(sent[0]).subspan(
      on_wire[4].payload_start_offset);
  EXPECT_EQ(Hex(w4.first(3)), "658884");
  const std::span<const uint8_t> w5 = std::span<const uint8_t>(sent[0]).subspan(
      on_wire[5].payload_start_offset);
  EXPECT_EQ(sframe::H264SliceClearPrefixLength(idr1), 4u);
  EXPECT_EQ(Hex(w5.first(4)), "65052220");
  // Consecutive CTRs: 0, 1 in the keyframe, 2 in the P frame.
  auto ctr_of = [](std::span<const uint8_t> nal, size_t prefix) {
    auto unit = sframe::UnescapeRegion(sframe::TrailingZeros(nal.first(prefix)),
                                       nal.subspan(prefix));
    EXPECT_TRUE(unit);
    auto h = sframe::ParseHeader(*unit);
    EXPECT_TRUE(h);
    return h->ctr;
  };
  EXPECT_EQ(ctr_of(w4.first(on_wire[4].payload_size), 3), 0u);
  EXPECT_EQ(ctr_of(w5.first(on_wire[5].payload_size), 4), 1u);
  auto d = H264::FindNaluIndices(sent[1]);
  ASSERT_EQ(d.size(), 1u);
  const std::span<const uint8_t> wd = std::span<const uint8_t>(sent[1]).subspan(
      d[0].payload_start_offset, d[0].payload_size);
  EXPECT_EQ(sframe::H264SliceClearPrefixLength(wd),
            2u);  // 41 9a: first_mb 0, slice_type 5, pps 0 → 7 bits
  EXPECT_EQ(ctr_of(wd, 2), 2u);

  r->Transform(
      VideoFrame(sent[0], Direction::kReceiver, "video/H264", 2222, true));
  r->Transform(VideoFrame(sent[1], Direction::kReceiver, "video/H264"));
  const auto& got = bob.sinks["r"]->frames;
  ASSERT_EQ(got.size(), 2u);
  EXPECT_EQ(got[0], key);
  EXPECT_EQ(got[1], delta);

  // Negatives: replay of the whole frame; a flipped bit in a sealed slice; a
  // frame of clear parameter sets only; a clear (relay-injected) slice; a frame
  // without start codes on the sender.
  r->Transform(VideoFrame(sent[0], Direction::kReceiver, "video/H264"));
  EXPECT_EQ(Dropped(r->GetStats(), SframeDropReason::kReplay), 1u);
  std::vector<uint8_t> t = sent[1];
  t[t.size() - 20] ^= 0x10;
  r->Transform(VideoFrame(t, Direction::kReceiver, "video/H264"));
  r->Transform(
      VideoFrame(AnnexB({kSps, kPps}), Direction::kReceiver, "video/H264"));
  r->Transform(
      VideoFrame(AnnexB({kSps, kPps, Slice({0x65, 0x88, 0x84}, 300, 9)}),
                 Direction::kReceiver, "video/H264"));
  EXPECT_EQ(got.size(), 2u);
  const SframeStreamStats rs = r->GetStats();
  EXPECT_EQ(rs.dropped_total(), 4u);
  s->Transform(VideoFrame({0x65, 0x88, 0x84, 1, 2, 3}, Direction::kSender,
                          "video/H264"));
  s->Transform(VideoFrame(AnnexB({kSps, kPps}), Direction::kSender,
                          "video/H264"));  // no slice
  s->Transform(VideoFrame(AnnexB({{0x0c, 0xff, 0xff}}), Direction::kSender,
                          "video/H264"));  // filler NAL
  EXPECT_EQ(Dropped(s->GetStats(), SframeDropReason::kMalformed), 3u);
  EXPECT_EQ(sent.size(), 2u);
}

// ---- through libwebrtc's RTP plumbing
// ---------------------------------------------------------------------------

TEST(SframeTransformer, Vp8UnitSurvivesPacketizerAndDepacketizer) {
  Leg alice;
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(alice.store->SetSendKid(kUnitsKid));
  auto s = alice.Make(SframeRole::kSender, SframeMediaKind::kVideo, "s");
  // A VP8 keyframe shape: tag (P=0), start code 9d 01 2a, 320x180, then data.
  std::vector<uint8_t> frame = {0x50, 0x42, 0x00, 0x9d, 0x01,
                                0x2a, 0x40, 0x01, 0xb4, 0x00};
  std::mt19937 rng(7);
  for (int i = 0; i < 3000; ++i) {
    frame.push_back(static_cast<uint8_t>(rng()));
  }
  s->Transform(VideoFrame(frame, Direction::kSender, "video/VP8", 2222, true));
  ASSERT_EQ(alice.sinks["s"]->frames.size(), 1u);
  const std::vector<uint8_t> unit = alice.sinks["s"]->frames[0];

  RTPVideoHeaderVP8 vp8;
  vp8.InitRTPVideoHeaderVP8();
  vp8.pictureId = 17;
  RtpPacketizer::PayloadSizeLimits limits;
  limits.max_payload_len = 1000;
  RtpPacketizerVp8 packetizer(unit, limits, vp8);
  ASSERT_GT(packetizer.NumPackets(), 2u);
  VideoRtpDepacketizerVp8 depacketizer;
  std::vector<uint8_t> reassembled;
  bool key = false;
  RtpPacketToSend packet(/*extensions=*/nullptr);
  while (packetizer.NextPacket(&packet)) {
    std::optional<VideoRtpDepacketizer::ParsedRtpPayload> parsed =
        depacketizer.Parse(packet.PayloadBuffer());
    ASSERT_TRUE(parsed) << "the depacketizer dropped a sealed VP8 packet";
    if (parsed->video_header.is_first_packet_in_frame) {
      key = parsed->video_header.frame_type == VideoFrameType::kVideoFrameKey;
    }
    reassembled.insert(reassembled.end(), parsed->video_payload.begin(),
                       parsed->video_payload.end());
  }
  EXPECT_TRUE(key) << "the keyframe bit (clear byte 0) must survive";
  EXPECT_EQ(reassembled, unit);

  Leg bob;
  ASSERT_EQ(bob.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  auto r = bob.Make(SframeRole::kReceiver, SframeMediaKind::kVideo, "r");
  r->Transform(
      VideoFrame(reassembled, Direction::kReceiver, "video/VP8", 2222, key));
  ASSERT_EQ(bob.sinks["r"]->frames.size(), 1u);
  EXPECT_EQ(bob.sinks["r"]->frames[0], frame);
}

TEST(SframeTransformer,
     H264UnitsSurvivePacketizerDepacketizerAndSpsPpsTracker) {
  Leg alice;
  alice.store->SetH264Enabled(true);
  ASSERT_EQ(alice.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  ASSERT_TRUE(alice.store->SetSendKid(kUnitsKid));
  auto s = alice.Make(SframeRole::kSender, SframeMediaKind::kVideo, "s");
  const std::vector<uint8_t> key =
      AnnexB({kSps, kPps, Slice({0x65, 0x88, 0x84}, 2500, 11)});
  const std::vector<uint8_t> delta = AnnexB({Slice({0x41, 0x9a}, 900, 12)});
  s->Transform(VideoFrame(key, Direction::kSender, "video/H264", 2222, true));
  s->Transform(VideoFrame(delta, Direction::kSender, "video/H264"));
  ASSERT_EQ(alice.sinks["s"]->frames.size(), 2u);

  Leg bob;
  bob.store->SetH264Enabled(true);
  ASSERT_EQ(bob.store->SetKey(kUnitsKid, kBase),
            SframeKeyStore::SetKeyResult::kChanged);
  auto r = bob.Make(SframeRole::kReceiver, SframeMediaKind::kVideo, "r");

  video_coding::H264SpsPpsTracker tracker;
  VideoRtpDepacketizerH264 depacketizer;
  for (const std::vector<uint8_t>& unit : alice.sinks["s"]->frames) {
    RtpPacketizer::PayloadSizeLimits limits;
    limits.max_payload_len =
        700;  // forces FU-A fragments of the slices, STAP-A of SPS + PPS
    RtpPacketizerH264 packetizer(unit, limits,
                                 H264PacketizationMode::NonInterleaved);
    std::vector<uint8_t> assembled;
    bool first = true;
    RtpPacketToSend packet(/*extensions=*/nullptr);
    while (packetizer.NextPacket(&packet)) {
      std::optional<VideoRtpDepacketizer::ParsedRtpPayload> parsed =
          depacketizer.Parse(packet.PayloadBuffer());
      ASSERT_TRUE(parsed) << "the H.264 depacketizer dropped a packet of a "
                             "sealed frame (slice header / SPS / PPS)";
      if (first) {
        EXPECT_TRUE(parsed->video_header.is_first_packet_in_frame)
            << "first_mb_in_slice must stay readable";
        first = false;
      }
      video_coding::H264SpsPpsTracker::FixedBitstream fixed =
          tracker.CopyAndFixBitstream(parsed->video_payload,
                                      &parsed->video_header);
      ASSERT_EQ(fixed.action, video_coding::H264SpsPpsTracker::kInsert)
          << "the SPS/PPS tracker refused the packet (would request a "
             "keyframe)";
      assembled.insert(assembled.end(), fixed.bitstream.begin(),
                       fixed.bitstream.end());
    }
    const bool is_key = &unit == &alice.sinks["s"]->frames[0];
    r->Transform(VideoFrame(assembled, Direction::kReceiver, "video/H264", 2222,
                            is_key));
  }
  const auto& got = bob.sinks["r"]->frames;
  ASSERT_EQ(got.size(), 2u);
  EXPECT_EQ(got[0], key);
  EXPECT_EQ(got[1], delta);
  EXPECT_EQ(r->GetStats().dropped_total(), 0u);
}

}  // namespace
}  // namespace webrtc
