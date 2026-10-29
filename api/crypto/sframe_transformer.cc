/*
 * Takamaka E2EE calls (C182 / DR-055) — the SFrame frame transformer. See
 * sframe_transformer.h.
 */

#include "api/crypto/sframe_transformer.h"

#include <algorithm>
#include <deque>
#include <cctype>
#include <string_view>
#include <utility>

#include "api/make_ref_counted.h"
#include "common_video/h264/h264_common.h"
#include "rtc_base/checks.h"
#include "rtc_base/logging.h"
#include "system_wrappers/include/clock.h"

namespace webrtc {

namespace {

constexpr size_t kPrefix = 1;  // Opus TOC / VP8 byte 0 (spec §9.2, R31)

// H.264 NAL unit types (ITU-T H.264 Table 7-1).
constexpr uint8_t kNalSlice = 1;
constexpr uint8_t kNalIdr = 5;
constexpr uint8_t kNalSei = 6;
constexpr uint8_t kNalSps = 7;
constexpr uint8_t kNalPps = 8;
constexpr uint8_t kNalAud = 9;

enum class Codec { kOpus, kVp8, kH264, kOther };

Codec CodecOf(const TransformableFrameInterface& frame) {
  std::string mime = frame.GetMimeType();
  std::transform(mime.begin(), mime.end(), mime.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  if (mime == "audio/opus") {
    return Codec::kOpus;
  }
  if (mime == "video/vp8") {
    return Codec::kVp8;
  }
  if (mime == "video/h264") {
    return Codec::kH264;
  }
  return Codec::kOther;
}

bool CodecAllowed(Codec codec, SframeMediaKind kind, bool h264_enabled) {
  if (kind == SframeMediaKind::kAudio) {
    return codec == Codec::kOpus;
  }
  return codec == Codec::kVp8 || (codec == Codec::kH264 && h264_enabled);
}

uint8_t NalType(uint8_t header) {
  return header & 0x1F;
}

bool IsClearH264Nal(uint8_t type) {
  return type == kNalSei || type == kNalSps || type == kNalPps ||
         type == kNalAud;
}

bool IsSliceNal(uint8_t type) {
  return type == kNalSlice || type == kNalIdr;
}

// Splits an Annex-B frame. Empty when the frame does not start with a start
// code or holds an empty NAL unit.
std::vector<H264::NaluIndex> SplitAnnexB(std::span<const uint8_t> data) {
  std::vector<H264::NaluIndex> nalus = H264::FindNaluIndices(data);
  if (nalus.empty() || nalus.front().start_offset != 0) {
    return {};
  }
  for (const H264::NaluIndex& n : nalus) {
    if (n.payload_size == 0) {
      return {};
    }
  }
  return nalus;
}

}  // namespace

// ---- names
// ----------------------------------------------------------------------------------------------------------

const char* SframeDropReasonName(SframeDropReason reason) {
  switch (reason) {
    case SframeDropReason::kEmpty:
      return "empty";
    case SframeDropReason::kCodec:
      return "codec";
    case SframeDropReason::kNoKey:
      return "no-key";
    case SframeDropReason::kCtrExhausted:
      return "ctr-exhausted";
    case SframeDropReason::kShort:
      return "short";
    case SframeDropReason::kBadHeader:
      return "bad-header";
    case SframeDropReason::kUnknownKid:
      return "unknown-kid";
    case SframeDropReason::kReplay:
      return "replay";
    case SframeDropReason::kTooOld:
      return "too-old";
    case SframeDropReason::kBadTag:
      return "bad-tag";
    case SframeDropReason::kMalformed:
      return "malformed";
    case SframeDropReason::kNoSink:
      return "no-sink";
    case SframeDropReason::kInternal:
      return "internal";
    case SframeDropReason::kHeldExpired:
      return "held-expired";
    case SframeDropReason::kHeldOverflow:
      return "held-overflow";
    case SframeDropReason::kUnbound:
      return "unbound";
    case SframeDropReason::kWrongLeg:
      return "wrong-leg";
    case SframeDropReason::kCount:
      break;
  }
  return "?";
}

bool SframeDropCountsForStorm(SframeDropReason reason) {
  // The web worker's COUNTS_FOR_STORM ('bad-tag', 'unknown-kid', 'bad-header',
  // 'short') + H.264 'malformed'.
  // C-24: a held frame whose key never came (or that overflowed the hold) is
  // an unknown-kid drop that waited.
  // S-7 (ruling Q3): a frame this stream may not open (unbound, another leg's
  // KID) is undecryptable for it — it counts.
  return reason == SframeDropReason::kBadTag ||
         reason == SframeDropReason::kUnknownKid ||
         reason == SframeDropReason::kBadHeader ||
         reason == SframeDropReason::kShort ||
         reason == SframeDropReason::kMalformed ||
         reason == SframeDropReason::kHeldExpired ||
         reason == SframeDropReason::kHeldOverflow ||
         reason == SframeDropReason::kUnbound ||
         reason == SframeDropReason::kWrongLeg;
}

const char* SframeEventTypeName(SframeEvent::Type type) {
  switch (type) {
    case SframeEvent::Type::kEngaged:
      return "engaged";
    case SframeEvent::Type::kFirstPass:
      return "first-pass";
    case SframeEvent::Type::kDropping:
      return "dropping";
    case SframeEvent::Type::kStorm:
      return "storm";
    case SframeEvent::Type::kRecovered:
      return "recovered";
    case SframeEvent::Type::kResumed:
      return "resumed";
    case SframeEvent::Type::kKeyExpired:
      return "key-expired";
    case SframeEvent::Type::kKeyEvicted:
      return "key-evicted";
    case SframeEvent::Type::kHeld:
      return "held";
    case SframeEvent::Type::kReleased:
      return "released";
  }
  return "?";
}

uint64_t SframeStreamStats::dropped_total() const {
  uint64_t t = 0;
  for (uint64_t d : dropped) {
    t += d;
  }
  return t;
}

// ---- key store
// ------------------------------------------------------------------------------------------------------

scoped_refptr<SframeKeyStore> SframeKeyStore::Create(Clock* clock) {
  return make_ref_counted<SframeKeyStore>(
      clock != nullptr ? clock : Clock::GetRealTimeClock());
}

SframeKeyStore::SframeKeyStore(Clock* clock) : clock_(clock) {}

SframeKeyStore::~SframeKeyStore() = default;

SframeKeyStore::SetKeyResult SframeKeyStore::SetKey(
    uint64_t kid,
    std::span<const uint8_t> base_key) {
  if (!sframe::IsAssignableKid(kid) ||
      base_key.size() != sframe::kBaseKeySize) {
    return SetKeyResult::kInvalid;
  }
  sframe::KeyMaterial material;
  if (!sframe::DeriveKeyMaterial(kid, base_key, &material)) {
    return SetKeyResult::kInvalid;
  }
  Events events;
  std::vector<Delivery> deliveries;
  SetKeyResult result;
  {
    MutexLock lock(&mutex_);
    PurgeExpiredLocked(&events);
    auto it = keys_.find(kid);
    if (it != keys_.end() && it->second.key->SameMaterial(material)) {
      result = SetKeyResult::kUnchanged;  // same key: nothing changes (the web
                                          // worker's fingerprint rule)
    } else {
      std::unique_ptr<sframe::SealingKey> key =
          sframe::SealingKey::Create(kid, material);
      if (!key) {
        return SetKeyResult::kInvalid;
      }
      if (it == keys_.end()) {
        // Cap per leg: evict the oldest-installed key of the same leg.
        std::vector<std::pair<uint64_t, uint64_t>>
            same_leg;  // (installed_seq, kid)
        for (const auto& [k, e] : keys_) {
          if (sframe::LegIndexOf(k) == sframe::LegIndexOf(kid)) {
            same_leg.emplace_back(e.installed_seq, k);
          }
        }
        if (same_leg.size() >= kMaxKeysPerLeg) {
          const uint64_t victim =
              std::min_element(same_leg.begin(), same_leg.end())->second;
          keys_.erase(victim);
          if (send_kid_ == victim) {
            send_kid_.reset();
          }
          SframeEvent e;
          e.type = SframeEvent::Type::kKeyEvicted;
          e.kid = victim;
          events.push_back(e);
        }
      }
      KeyEntry& entry = keys_[kid];
      entry.key = std::move(key);
      entry.window = sframe::ReplayWindow();  // a different sender key starts a
                                              // fresh window
      entry.installed_seq = ++install_seq_;
      entry.expires_at.reset();
      result = SetKeyResult::kChanged;
      // spec §9.2 [0.2]: a key arriving resumes a stormed subscription; every
      // receive stream restarts its count.
      for (auto& s : streams_) {
        if (s->stats.role != SframeRole::kReceiver) {
          continue;
        }
        if (s->stats.storm) {
          SframeEvent e;
          e.type = SframeEvent::Type::kResumed;
          e.stream_id = s->stats.stream_id;
          e.role = s->stats.role;
          e.kind = s->stats.kind;
          e.kid = kid;
          events.push_back(e);
        }
        s->stats.storm = false;
        s->stats.consecutive = 0;
      }
      // C-24: the frames held for this KID open now, in order
      ReleaseHeldLocked(kid, &events, &deliveries);
    }
  }
  Dispatch(events);
  Deliver(std::move(deliveries));
  return result;
}

bool SframeKeyStore::RemoveKey(uint64_t kid) {
  MutexLock lock(&mutex_);
  if (keys_.erase(kid) == 0) {
    return false;
  }
  if (send_kid_ == kid) {
    send_kid_.reset();
  }
  return true;
}

bool SframeKeyStore::RetireKey(uint64_t kid, TimeDelta retention) {
  MutexLock lock(&mutex_);
  auto it = keys_.find(kid);
  if (it == keys_.end()) {
    return false;
  }
  it->second.expires_at =
      clock_->CurrentTime() + std::max(retention, TimeDelta::Zero());
  return true;
}

bool SframeKeyStore::SetSendKid(uint64_t kid) {
  Events events;
  bool ok;
  {
    MutexLock lock(&mutex_);
    PurgeExpiredLocked(&events);
    ok = keys_.count(kid) > 0;
    if (ok) {
      send_kid_ = kid;
    }
  }
  Dispatch(events);
  return ok;
}

void SframeKeyStore::ClearSendKid() {
  MutexLock lock(&mutex_);
  send_kid_.reset();
}

std::optional<uint64_t> SframeKeyStore::send_kid() const {
  MutexLock lock(&mutex_);
  return send_kid_;
}

std::vector<uint64_t> SframeKeyStore::kids() const {
  MutexLock lock(&mutex_);
  std::vector<uint64_t> out;
  for (const auto& [k, e] : keys_) {
    out.push_back(k);
  }
  return out;
}

bool SframeKeyStore::HasKey(uint64_t kid) const {
  MutexLock lock(&mutex_);
  return keys_.count(kid) > 0;
}

void SframeKeyStore::SetStormThreshold(int n) {
  if (n <= 0) {
    return;
  }
  MutexLock lock(&mutex_);
  storm_threshold_ = n;
}

void SframeKeyStore::SetHoldTime(TimeDelta hold) {
  Events events;
  {
    MutexLock lock(&mutex_);
    hold_time_ = std::max(hold, TimeDelta::Zero());
    if (hold_time_.IsZero()) {
      // nothing may wait any more: what is held drops now
      for (auto& s : streams_) {
        for (HeldFrame& h : s->held) {
          h.deadline = Timestamp::MinusInfinity();
        }
      }
      ExpireHeldLocked(&events);
    }
  }
  Dispatch(events);
}

void SframeKeyStore::SetObserver(scoped_refptr<SframeObserver> observer) {
  MutexLock lock(&observer_mutex_);
  observer_ = std::move(observer);
}

void SframeKeyStore::SetH264Enabled(bool enabled) {
  MutexLock lock(&mutex_);
  h264_enabled_ = enabled;
}

void SframeKeyStore::SetRequireLegBinding(bool required) {
  MutexLock lock(&mutex_);
  require_leg_binding_ = required;
}

bool SframeKeyStore::require_leg_binding() const {
  MutexLock lock(&mutex_);
  return require_leg_binding_;
}

bool SframeKeyStore::BindLeg(const std::string& stream_id,
                             std::optional<uint32_t> leg_index) {
  Events events;
  bool found = false;
  {
    MutexLock lock(&mutex_);
    for (auto& s : streams_) {
      if (s->stats.role == SframeRole::kReceiver &&
          s->stats.stream_id == stream_id) {
        if (!BindLegLocked(s.get(), leg_index, &events)) {
          return false;
        }
        found = true;
      }
    }
  }
  Dispatch(events);
  return found;
}

bool SframeKeyStore::BindStreamLeg(Stream* stream,
                                   std::optional<uint32_t> leg_index) {
  Events events;
  bool ok;
  {
    MutexLock lock(&mutex_);
    ok = BindLegLocked(stream, leg_index, &events);
  }
  Dispatch(events);
  return ok;
}

bool SframeKeyStore::BindLegLocked(Stream* stream,
                                   std::optional<uint32_t> leg_index,
                                   Events* events) {
  if (stream->stats.role != SframeRole::kReceiver ||
      (leg_index && (*leg_index == 0 || *leg_index > 0xFFFF))) {
    return false;
  }
  SframeStreamStats& st = stream->stats;
  if (st.bound_leg == leg_index) {
    return true;  // re-bound to the same leg (every roster change): no-op
  }
  st.bound_leg = leg_index;
  // Frames held under the old binding (C-24) are not known to be the new
  // leg's: they go, counted as wrong-leg (outside the storm count, which
  // restarts below).
  while (!stream->held.empty()) {
    stream->held_bytes -= stream->held.front().bytes;
    st.held_now--;
    st.dropped[static_cast<size_t>(SframeDropReason::kWrongLeg)]++;
    stream->held.pop_front();
  }
  // The drops before this binding (unbound / another leg) say nothing about
  // the new leg: a fresh storm count.
  if (st.storm) {
    SframeEvent e;
    e.type = SframeEvent::Type::kResumed;
    e.stream_id = st.stream_id;
    e.role = st.role;
    e.kind = st.kind;
    events->push_back(e);
  }
  st.storm = false;
  st.consecutive = 0;
  return true;
}

std::optional<SframeDropReason> SframeKeyStore::LegCheckLocked(
    const Stream* stream,
    uint64_t kid) const {
  const std::optional<uint32_t>& bound = stream->stats.bound_leg;
  if (!bound) {
    // S-7 / Q1: a store that requires the binding opens nothing for an
    // unbound stream (the participant is not known to be in the verified
    // roster yet, or left it).
    return require_leg_binding_ ? std::optional(SframeDropReason::kUnbound)
                                : std::nullopt;
  }
  if (sframe::LegIndexOf(kid) != *bound) {
    return SframeDropReason::kWrongLeg;
  }
  return std::nullopt;
}

std::vector<uint8_t> SframeKeyStore::VectorSeal(
    std::span<const uint8_t> base_key,
    uint64_t kid,
    uint64_t ctr,
    std::span<const uint8_t> frame,
    size_t prefix_len) {
  sframe::KeyMaterial material;
  if (prefix_len > frame.size() || base_key.empty() ||
      !sframe::DeriveKeyMaterial(kid, base_key, &material)) {
    return {};
  }
  std::unique_ptr<sframe::SealingKey> key =
      sframe::SealingKey::Create(kid, material);
  if (!key) {
    return {};
  }
  const std::span<const uint8_t> prefix = frame.first(prefix_len);
  const std::vector<uint8_t> header = sframe::EncodeHeader(kid, ctr);
  std::vector<uint8_t> out(prefix.begin(), prefix.end());
  out.insert(out.end(), header.begin(), header.end());
  if (!key->Seal(ctr, header, prefix, frame.subspan(prefix_len), &out)) {
    return {};
  }
  return out;
}

std::optional<std::vector<uint8_t>> SframeKeyStore::VectorOpen(
    std::span<const uint8_t> base_key,
    uint64_t kid,
    std::span<const uint8_t> unit,
    size_t prefix_len) {
  sframe::KeyMaterial material;
  if (prefix_len >= unit.size() || base_key.empty() ||
      !sframe::DeriveKeyMaterial(kid, base_key, &material)) {
    return std::nullopt;
  }
  std::unique_ptr<sframe::SealingKey> key =
      sframe::SealingKey::Create(kid, material);
  const std::optional<sframe::Header> h =
      sframe::ParseHeader(unit.subspan(prefix_len));
  if (!key || !h || h->kid != kid) {
    return std::nullopt;
  }
  const std::span<const uint8_t> prefix = unit.first(prefix_len);
  std::vector<uint8_t> out(prefix.begin(), prefix.end());
  if (!key->Open(h->ctr, unit.subspan(prefix_len, h->length), prefix,
                 unit.subspan(prefix_len + h->length), &out)) {
    return std::nullopt;
  }
  return out;
}

std::vector<SframeStreamStats> SframeKeyStore::GetAllStats() const {
  MutexLock lock(&mutex_);
  std::vector<SframeStreamStats> out;
  for (const auto& s : streams_) {
    out.push_back(s->stats);
  }
  return out;
}

SframeKeyStore::Stream* SframeKeyStore::RegisterStream(
    const std::string& stream_id,
    SframeRole role,
    SframeMediaKind kind,
    SframeTransformer* transformer) {
  auto s = std::make_unique<Stream>();
  s->stats.stream_id = stream_id;
  s->stats.role = role;
  s->stats.kind = kind;
  s->transformer = transformer;
  Stream* raw = s.get();
  MutexLock lock(&mutex_);
  streams_.push_back(std::move(s));
  return raw;
}

void SframeKeyStore::UnregisterStream(Stream* stream) {
  MutexLock lock(&mutex_);
  streams_.erase(std::remove_if(streams_.begin(), streams_.end(),
                                [stream](const std::unique_ptr<Stream>& s) {
                                  return s.get() == stream;
                                }),
                 streams_.end());
}

SframeStreamStats SframeKeyStore::StatsOf(const Stream* stream) const {
  MutexLock lock(&mutex_);
  return stream->stats;
}

void SframeKeyStore::Dispatch(const Events& events) {
  if (events.empty()) {
    return;
  }
  scoped_refptr<SframeObserver> observer;
  {
    MutexLock lock(&observer_mutex_);
    observer = observer_;
  }
  if (!observer) {
    return;
  }
  for (const SframeEvent& e : events) {
    observer->OnSframeEvent(e);
  }
}

void SframeKeyStore::PurgeExpiredLocked(Events* events) {
  ExpireHeldLocked(events);
  const Timestamp now = clock_->CurrentTime();
  for (auto it = keys_.begin(); it != keys_.end();) {
    if (it->second.expires_at && *it->second.expires_at <= now) {
      SframeEvent e;
      e.type = SframeEvent::Type::kKeyExpired;
      e.kid = it->first;
      events->push_back(e);
      if (send_kid_ == it->first) {
        send_kid_.reset();
      }
      it = keys_.erase(it);
    } else {
      ++it;
    }
  }
}

void SframeKeyStore::RecordNoSink(Stream* stream,
                                  size_t bytes,
                                  Events* events) {
  MutexLock lock(&mutex_);
  stream->stats.frames++;
  stream->stats.bytes_in += bytes;
  DropLocked(stream, SframeDropReason::kNoSink, events);
}

SframeKeyStore::KeyEntry* SframeKeyStore::FindKeyLocked(uint64_t kid) {
  auto it = keys_.find(kid);
  return it == keys_.end() ? nullptr : &it->second;
}

void SframeKeyStore::SampleDrop(Stream* stream,
                                SframeDropReason why,
                                std::span<const uint8_t> data) {
  // Receive side only, as the web worker: a sender's dropped frame is
  // PLAINTEXT media, which must never reach stats or logs.
  if (stream->stats.role != SframeRole::kReceiver) {
    return;
  }
  std::vector<std::string>& samples = stream->stats.drop_samples;
  const std::string name = SframeDropReasonName(why);
  size_t same = 0;
  for (const std::string& s : samples) {
    if (s.compare(0, name.size() + 1, name + " ") == 0) {
      ++same;
    }
  }
  if (same >= 3 || samples.size() >= 12) {
    return;
  }
  static constexpr std::string_view kHex = "0123456789abcdef";
  std::string hex;
  for (uint8_t b : data.first(std::min<size_t>(12, data.size()))) {
    hex += kHex[b >> 4];
    hex += kHex[b & 15];
  }
  samples.push_back(name + " len=" + std::to_string(data.size()) +
                    " first=" + hex);
}

void SframeKeyStore::DropLocked(Stream* stream,
                                SframeDropReason why,
                                Events* events) {
  SframeStreamStats& st = stream->stats;
  st.dropped[static_cast<size_t>(why)]++;
  if (stream->last_reported_drop != why) {
    stream->last_reported_drop = why;
    SframeEvent e;
    e.type = SframeEvent::Type::kDropping;
    e.stream_id = st.stream_id;
    e.role = st.role;
    e.kind = st.kind;
    e.reason = why;
    e.kid = st.last_kid;
    events->push_back(e);
  }
  if (st.role != SframeRole::kReceiver || !SframeDropCountsForStorm(why)) {
    return;
  }
  st.consecutive++;
  if (!st.storm && st.consecutive >= static_cast<uint64_t>(storm_threshold_)) {
    st.storm = true;
    st.storms++;
    SframeEvent e;
    e.type = SframeEvent::Type::kStorm;
    e.stream_id = st.stream_id;
    e.role = st.role;
    e.kind = st.kind;
    e.reason = why;
    e.kid = st.last_kid;
    e.consecutive = st.consecutive;
    events->push_back(e);
  }
}

bool SframeKeyStore::Process(Stream* stream,
                             std::unique_ptr<TransformableFrameInterface>& frame_ptr,
                             std::vector<uint8_t>* out,
                             Events* events,
                             bool* held) {
  *held = false;
  const TransformableFrameInterface& frame = *frame_ptr;
  MutexLock lock(&mutex_);
  PurgeExpiredLocked(events);
  SframeStreamStats& st = stream->stats;
  const Timestamp now = clock_->CurrentTime();
  const std::span<const uint8_t> data = frame.GetData();
  st.frames++;
  st.bytes_in += data.size();
  st.last_frame_at = now;
  if (!st.first_frame_at) {
    st.first_frame_at = now;
    SframeEvent e;
    e.type = SframeEvent::Type::kEngaged;
    e.stream_id = st.stream_id;
    e.role = st.role;
    e.kind = st.kind;
    events->push_back(e);
  }
  if (st.kind == SframeMediaKind::kVideo &&
      static_cast<const TransformableVideoFrameInterface&>(frame)
          .IsKeyFrame()) {
    st.keyframes++;
  }
  const TransformableFrameInterface::Direction expected =
      st.role == SframeRole::kSender
          ? TransformableFrameInterface::Direction::kSender
          : TransformableFrameInterface::Direction::kReceiver;
  if (frame.GetDirection() != expected) {
    DropLocked(stream, SframeDropReason::kInternal, events);
    SampleDrop(stream, SframeDropReason::kInternal, data);
    return false;
  }
  SframeDropReason why = SframeDropReason::kInternal;
  uint64_t kid = 0;
  const bool ok = st.role == SframeRole::kSender
                      ? SealLocked(stream, frame, out, &why)
                      : OpenLocked(stream, frame, out, &why, &kid);
  if (!ok) {
    out->clear();
    if (why == SframeDropReason::kUnknownKid && st.last_kid &&
        ShouldHoldLocked(stream, *st.last_kid)) {
      // C-24: the key of a known leg's next epoch has not arrived yet — wait
      // for it instead of breaking the decoder's reference chain
      HoldLocked(stream, std::move(frame_ptr), *st.last_kid, events);
      *held = true;
      return false;
    }
    DropLocked(stream, why, events);
    SampleDrop(stream, why, data);
    return false;
  }
  PassLocked(stream, kid, out->size(), events);
  return true;
}

void SframeKeyStore::PassLocked(Stream* stream,
                                uint64_t kid,
                                size_t out_bytes,
                                Events* events) {
  SframeStreamStats& st = stream->stats;
  const Timestamp now = clock_->CurrentTime();
  st.passed++;
  st.bytes_out += out_bytes;
  stream->last_reported_drop.reset();
  if (!st.first_pass_at) {
    st.first_pass_at = now;
    SframeEvent e;
    e.type = SframeEvent::Type::kFirstPass;
    e.stream_id = st.stream_id;
    e.role = st.role;
    e.kind = st.kind;
    e.kid = st.last_kid;
    events->push_back(e);
  }
  if (st.role == SframeRole::kReceiver) {
    st.consecutive = 0;
    // A KID that authenticates again proves its key works: every stormed
    // receive stream whose last frames carried that KID (e.g. the paused video
    // of a leg whose audio now opens) may resume — spec §9.2 [0.2], the web
    // worker's recovered(): the fix may have been on the sender's side, so no
    // key event ever arrives here.
    for (auto& s : streams_) {
      if (s->stats.role == SframeRole::kReceiver && s->stats.storm &&
          (s.get() == stream || s->stats.last_kid == kid)) {
        s->stats.storm = false;
        s->stats.consecutive = 0;
        SframeEvent e;
        e.type = SframeEvent::Type::kRecovered;
        e.stream_id = s->stats.stream_id;
        e.role = s->stats.role;
        e.kind = s->stats.kind;
        e.kid = kid;
        events->push_back(e);
      }
    }
  }
}

// ---- C-24 hold
// ----------------------------------------------------------------------------------------------------

bool SframeKeyStore::ShouldHoldLocked(const Stream* stream,
                                      uint64_t kid) const {
  if (hold_time_.IsZero() || stream->stats.role != SframeRole::kReceiver ||
      stream->stats.kind != SframeMediaKind::kVideo ||
      !sframe::IsAssignableKid(kid)) {
    return false;
  }
  const uint32_t leg = sframe::LegIndexOf(kid);
  // S-7: a bound stream holds only for its own leg (a frame of another leg
  // never reaches here: OpenLocked drops it wrong-leg first).
  if (stream->stats.bound_leg && *stream->stats.bound_leg != leg) {
    return false;
  }
  for (const auto& [k, e] : keys_) {
    if (sframe::LegIndexOf(k) != leg) {
      continue;
    }
    const uint32_t ahead =
        (sframe::EpochOf(kid) - sframe::EpochOf(k)) & 0xFFFF;
    if (ahead >= 1 && ahead <= kHoldEpochsAhead) {
      return true;  // a known leg, an epoch this receiver has not reached
    }
  }
  return false;
}

void SframeKeyStore::HoldLocked(Stream* stream,
                                std::unique_ptr<TransformableFrameInterface> frame,
                                uint64_t kid,
                                Events* events) {
  SframeStreamStats& st = stream->stats;
  const size_t bytes = frame->GetData().size();
  while (!stream->held.empty() &&
         (stream->held.size() >= kMaxHeldFrames ||
          stream->held_bytes + bytes > kMaxHeldBytes)) {
    HeldFrame& old = stream->held.front();
    stream->held_bytes -= old.bytes;
    st.held_now--;
    DropLocked(stream, SframeDropReason::kHeldOverflow, events);
    SampleDrop(stream, SframeDropReason::kHeldOverflow, old.frame->GetData());
    stream->held.pop_front();
  }
  const bool first = stream->held.empty();
  HeldFrame h;
  h.frame = std::move(frame);
  h.kid = kid;
  h.deadline = clock_->CurrentTime() + hold_time_;
  h.bytes = bytes;
  stream->held.push_back(std::move(h));
  stream->held_bytes += bytes;
  st.held++;
  st.held_now++;
  if (first) {
    SframeEvent e;
    e.type = SframeEvent::Type::kHeld;
    e.stream_id = st.stream_id;
    e.role = st.role;
    e.kind = st.kind;
    e.kid = kid;
    events->push_back(e);
  }
}

void SframeKeyStore::ReleaseHeldLocked(uint64_t kid,
                                       Events* events,
                                       std::vector<Delivery>* deliveries) {
  for (auto& s : streams_) {
    if (s->held.empty()) {
      continue;
    }
    std::deque<HeldFrame> keep;
    uint64_t released = 0;
    for (HeldFrame& h : s->held) {
      if (h.kid != kid) {
        keep.push_back(std::move(h));
        continue;
      }
      s->held_bytes -= h.bytes;
      s->stats.held_now--;
      std::vector<uint8_t> out;
      SframeDropReason why = SframeDropReason::kInternal;
      uint64_t opened_kid = 0;
      const bool ok = OpenLocked(s.get(), *h.frame, &out, &why, &opened_kid);
      if (!ok) {
        DropLocked(s.get(), why, events);
        SampleDrop(s.get(), why, h.frame->GetData());
        continue;
      }
      scoped_refptr<TransformedFrameCallback> sink =
          s->transformer ? s->transformer->SinkFor(h.frame->GetSsrc())
                         : nullptr;
      if (!sink) {
        DropLocked(s.get(), SframeDropReason::kNoSink, events);
        continue;
      }
      h.frame->SetData(out);
      PassLocked(s.get(), opened_kid, out.size(), events);
      s->stats.held_released++;
      released++;
      deliveries->push_back(Delivery{std::move(sink), std::move(h.frame)});
    }
    s->held = std::move(keep);
    if (released > 0) {
      SframeEvent e;
      e.type = SframeEvent::Type::kReleased;
      e.stream_id = s->stats.stream_id;
      e.role = s->stats.role;
      e.kind = s->stats.kind;
      e.kid = kid;
      e.count = released;
      events->push_back(e);
    }
  }
}

void SframeKeyStore::ExpireHeldLocked(Events* events) {
  const Timestamp now = clock_->CurrentTime();
  for (auto& s : streams_) {
    // deadlines are in insertion order (one hold time per store)
    while (!s->held.empty() && s->held.front().deadline <= now) {
      HeldFrame& h = s->held.front();
      s->held_bytes -= h.bytes;
      s->stats.held_now--;
      DropLocked(s.get(), SframeDropReason::kHeldExpired, events);
      SampleDrop(s.get(), SframeDropReason::kHeldExpired,
                 h.frame->GetData());
      s->held.pop_front();
    }
  }
}

void SframeKeyStore::Deliver(std::vector<Delivery> deliveries) {
  for (Delivery& d : deliveries) {
    d.sink->OnTransformedFrame(std::move(d.frame));
  }
}

bool SframeKeyStore::SealLocked(Stream* stream,
                                const TransformableFrameInterface& frame,
                                std::vector<uint8_t>* out,
                                SframeDropReason* why) {
  const std::span<const uint8_t> data = frame.GetData();
  if (data.empty()) {
    *why = SframeDropReason::kEmpty;  // spec §9.1 [0.2]: no TOC → drop, never
                                      // sealed or sent
    return false;
  }
  const Codec codec = CodecOf(frame);
  if (!CodecAllowed(codec, stream->stats.kind, h264_enabled_)) {
    *why = SframeDropReason::kCodec;  // never sent unsealed
    return false;
  }
  if (!send_kid_) {
    *why = SframeDropReason::kNoKey;
    return false;
  }
  const uint64_t kid = *send_kid_;
  KeyEntry* entry = FindKeyLocked(kid);
  if (entry == nullptr) {
    *why = SframeDropReason::kNoKey;
    return false;
  }
  uint64_t& next = next_ctr_[kid];

  if (codec != Codec::kH264) {
    if (next >= sframe::kCtrLimit) {
      *why = SframeDropReason::kCtrExhausted;
      return false;
    }
    const uint64_t ctr = next++;
    const std::span<const uint8_t> prefix = data.first(kPrefix);
    const std::vector<uint8_t> header = sframe::EncodeHeader(kid, ctr);
    out->clear();
    out->reserve(data.size() + header.size() + sframe::kTagSize);
    out->insert(out->end(), prefix.begin(), prefix.end());
    out->insert(out->end(), header.begin(), header.end());
    if (!entry->key->Seal(ctr, header, prefix, data.subspan(kPrefix), out)) {
      *why = SframeDropReason::kInternal;
      return false;
    }
    stream->stats.last_kid = kid;
    return true;
  }

  // H.264: validate the whole frame before consuming any CTR.
  const std::vector<H264::NaluIndex> nalus = SplitAnnexB(data);
  if (nalus.empty()) {
    *why = SframeDropReason::kMalformed;  // no start codes: never encrypt blind
                                          // (survey §6)
    return false;
  }
  std::vector<size_t> prefix_len(nalus.size(), 0);
  size_t slices = 0;
  for (size_t i = 0; i < nalus.size(); ++i) {
    const std::span<const uint8_t> nal =
        data.subspan(nalus[i].payload_start_offset, nalus[i].payload_size);
    const uint8_t type = NalType(nal[0]);
    if (IsClearH264Nal(type)) {
      continue;
    }
    if (!IsSliceNal(type)) {
      *why = SframeDropReason::kMalformed;  // OPEN H-3: other NAL types are
                                            // dropped, never sent in clear
      return false;
    }
    std::optional<size_t> len = sframe::H264SliceClearPrefixLength(nal);
    if (!len) {
      *why = SframeDropReason::kMalformed;
      return false;
    }
    prefix_len[i] = *len;
    ++slices;
  }
  if (slices == 0 || next > sframe::kCtrLimit - slices) {
    *why = slices == 0 ? SframeDropReason::kMalformed
                       : SframeDropReason::kCtrExhausted;
    return false;
  }
  out->clear();
  out->reserve(data.size() +
               slices * (sframe::kMaxHeaderSize + sframe::kTagSize + 4));
  std::vector<uint8_t> unit;
  for (size_t i = 0; i < nalus.size(); ++i) {
    const H264::NaluIndex& n = nalus[i];
    const std::span<const uint8_t> start_code =
        data.subspan(n.start_offset, n.payload_start_offset - n.start_offset);
    const std::span<const uint8_t> nal =
        data.subspan(n.payload_start_offset, n.payload_size);
    out->insert(out->end(), start_code.begin(), start_code.end());
    if (prefix_len[i] == 0) {
      out->insert(
          out->end(), nal.begin(),
          nal.end());  // SPS / PPS / SEI / AUD in clear (spec §9.2, §9.3)
      continue;
    }
    const std::span<const uint8_t> prefix = nal.first(prefix_len[i]);
    const uint64_t ctr = next++;
    unit = sframe::EncodeHeader(kid, ctr);
    const std::vector<uint8_t> header = unit;
    if (!entry->key->Seal(ctr, header, prefix, nal.subspan(prefix_len[i]),
                          &unit)) {
      *why = SframeDropReason::kInternal;
      return false;
    }
    out->insert(out->end(), prefix.begin(), prefix.end());
    sframe::EscapeRegion(sframe::TrailingZeros(prefix), unit, out);
  }
  stream->stats.last_kid = kid;
  return true;
}

bool SframeKeyStore::OpenLocked(Stream* stream,
                                const TransformableFrameInterface& frame,
                                std::vector<uint8_t>* out,
                                SframeDropReason* why,
                                uint64_t* kid_out) {
  const std::span<const uint8_t> data = frame.GetData();
  if (data.empty()) {
    // Padding-only RTP packets (bandwidth probing) reach the audio receive
    // transform as zero-length frames (audio/channel_receive.cc subtracts the
    // padding). No media, not a decryption failure: dropped as 'empty', not
    // counted toward the storm (M2 finding F-M2-1).
    *why = SframeDropReason::kEmpty;
    return false;
  }
  if (data.size() < kPrefix + 1 + sframe::kTagSize) {
    *why = SframeDropReason::kShort;
    return false;
  }
  const Codec codec = CodecOf(frame);
  if (!CodecAllowed(codec, stream->stats.kind, h264_enabled_)) {
    *why = SframeDropReason::kCodec;  // never played
    return false;
  }

  if (codec != Codec::kH264) {
    const std::optional<sframe::Header> h =
        sframe::ParseHeader(data.subspan(kPrefix));
    if (!h) {
      *why = SframeDropReason::kBadHeader;
      return false;
    }
    // S-7: the binding is checked BEFORE the key lookup and before last_kid
    // (which drives the hold and the storm recovery) is written: a frame of
    // another leg never touches a replay window, the hold or this stream's
    // KID history.
    if (const std::optional<SframeDropReason> leg =
            LegCheckLocked(stream, h->kid)) {
      *why = *leg;
      return false;
    }
    stream->stats.last_kid = h->kid;
    KeyEntry* entry = FindKeyLocked(h->kid);
    if (entry == nullptr) {
      *why = SframeDropReason::kUnknownKid;  // spec §9.2: nothing passes while
                                             // a key is missing
      return false;
    }
    switch (entry->window.Check(h->ctr)) {
      case sframe::ReplayWindow::Verdict::kOk:
        break;
      case sframe::ReplayWindow::Verdict::kReplay:
        *why = SframeDropReason::kReplay;
        return false;
      case sframe::ReplayWindow::Verdict::kTooOld:
        *why = SframeDropReason::kTooOld;
        return false;
    }
    const std::span<const uint8_t> prefix = data.first(kPrefix);
    const std::span<const uint8_t> header = data.subspan(kPrefix, h->length);
    out->clear();
    out->insert(out->end(), prefix.begin(), prefix.end());
    if (!entry->key->Open(h->ctr, header, prefix,
                          data.subspan(kPrefix + h->length), out)) {
      *why = SframeDropReason::kBadTag;
      return false;
    }
    entry->window.Commit(h->ctr);  // only after the tag verified
    *kid_out = h->kid;
    return true;
  }

  // H.264: every slice NAL must authenticate; the window moves only when the
  // whole frame did.
  const std::vector<H264::NaluIndex> nalus = SplitAnnexB(data);
  if (nalus.empty()) {
    *why = SframeDropReason::kMalformed;
    return false;
  }
  out->clear();
  out->reserve(data.size());
  std::optional<uint64_t> frame_kid;
  KeyEntry* entry = nullptr;
  std::vector<uint64_t> ctrs;
  std::vector<uint8_t> plain;
  for (const H264::NaluIndex& n : nalus) {
    const std::span<const uint8_t> start_code =
        data.subspan(n.start_offset, n.payload_start_offset - n.start_offset);
    const std::span<const uint8_t> nal =
        data.subspan(n.payload_start_offset, n.payload_size);
    const uint8_t type = NalType(nal[0]);
    out->insert(out->end(), start_code.begin(), start_code.end());
    if (IsClearH264Nal(type)) {
      out->insert(out->end(), nal.begin(), nal.end());
      continue;
    }
    if (!IsSliceNal(type)) {
      *why = SframeDropReason::kMalformed;
      return false;
    }
    const std::optional<size_t> len = sframe::H264SliceClearPrefixLength(nal);
    if (!len) {
      *why = SframeDropReason::kMalformed;
      return false;
    }
    const std::span<const uint8_t> prefix = nal.first(*len);
    const std::optional<std::vector<uint8_t>> unit = sframe::UnescapeRegion(
        sframe::TrailingZeros(prefix), nal.subspan(*len));
    if (!unit) {
      *why = SframeDropReason::kMalformed;
      return false;
    }
    const std::optional<sframe::Header> h = sframe::ParseHeader(*unit);
    if (!h || unit->size() < h->length + sframe::kTagSize) {
      *why = h ? SframeDropReason::kShort : SframeDropReason::kBadHeader;
      return false;
    }
    if (const std::optional<SframeDropReason> leg =
            LegCheckLocked(stream, h->kid)) {
      *why = *leg;  // S-7, as above
      return false;
    }
    stream->stats.last_kid = h->kid;
    if (frame_kid && *frame_kid != h->kid) {
      *why = SframeDropReason::kMalformed;  // one frame, one sender key
      return false;
    }
    if (!frame_kid) {
      frame_kid = h->kid;
      entry = FindKeyLocked(h->kid);
      if (entry == nullptr) {
        *why = SframeDropReason::kUnknownKid;
        return false;
      }
    }
    if (std::find(ctrs.begin(), ctrs.end(), h->ctr) != ctrs.end()) {
      *why = SframeDropReason::kReplay;
      return false;
    }
    switch (entry->window.Check(h->ctr)) {
      case sframe::ReplayWindow::Verdict::kOk:
        break;
      case sframe::ReplayWindow::Verdict::kReplay:
        *why = SframeDropReason::kReplay;
        return false;
      case sframe::ReplayWindow::Verdict::kTooOld:
        *why = SframeDropReason::kTooOld;
        return false;
    }
    const std::span<const uint8_t> u(*unit);
    plain.clear();
    if (!entry->key->Open(h->ctr, u.first(h->length), prefix,
                          u.subspan(h->length), &plain)) {
      *why = SframeDropReason::kBadTag;
      return false;
    }
    ctrs.push_back(h->ctr);
    out->insert(out->end(), prefix.begin(), prefix.end());
    out->insert(out->end(), plain.begin(), plain.end());
  }
  if (!frame_kid) {
    *why = SframeDropReason::kMalformed;  // a frame with no sealed slice is
                                          // never played
    return false;
  }
  for (uint64_t ctr : ctrs) {
    entry->window.Commit(ctr);
  }
  *kid_out = *frame_kid;
  return true;
}

// ---- transformer
// ----------------------------------------------------------------------------------------------------

scoped_refptr<SframeTransformer> SframeTransformer::Create(
    scoped_refptr<SframeKeyStore> store,
    SframeRole role,
    SframeMediaKind kind,
    const std::string& stream_id) {
  RTC_CHECK(store);
  return make_ref_counted<SframeTransformer>(std::move(store), role, kind,
                                             stream_id);
}

SframeTransformer::SframeTransformer(scoped_refptr<SframeKeyStore> store,
                                     SframeRole role,
                                     SframeMediaKind kind,
                                     const std::string& stream_id)
    : store_(std::move(store)),
      role_(role),
      kind_(kind),
      stream_(store_->RegisterStream(stream_id, role, kind, this)) {}

SframeTransformer::~SframeTransformer() {
  store_->UnregisterStream(stream_);
}

SframeStreamStats SframeTransformer::GetStats() const {
  return store_->StatsOf(stream_);
}

bool SframeTransformer::BindLeg(std::optional<uint32_t> leg_index) {
  return store_->BindStreamLeg(stream_, leg_index);
}

scoped_refptr<TransformedFrameCallback> SframeTransformer::SinkFor(
    uint32_t ssrc) {
  MutexLock lock(&sink_mutex_);
  auto it = sinks_.find(ssrc);
  if (it != sinks_.end()) {
    return it->second;
  }
  return sink_;
}

void SframeTransformer::Transform(
    std::unique_ptr<TransformableFrameInterface> frame) {
  if (!frame) {
    return;
  }
  scoped_refptr<TransformedFrameCallback> sink = SinkFor(frame->GetSsrc());
  SframeKeyStore::Events events;
  std::vector<uint8_t> out;
  bool ok = false;
  bool held = false;
  if (!sink) {
    store_->RecordNoSink(stream_, frame->GetData().size(), &events);
  } else {
    ok = store_->Process(stream_, frame, &out, &events, &held);
  }
  store_->Dispatch(events);
  if (held) {
    return;  // C-24: the store owns the frame until its key arrives (SetKey
             // delivers it) or the hold expires
  }
  if (!ok) {
    return;  // dropped: neither plaintext nor ciphertext goes further
  }
  frame->SetData(out);
  sink->OnTransformedFrame(std::move(frame));
}

void SframeTransformer::RegisterTransformedFrameCallback(
    scoped_refptr<TransformedFrameCallback> callback) {
  MutexLock lock(&sink_mutex_);
  sink_ = std::move(callback);
}

void SframeTransformer::RegisterTransformedFrameSinkCallback(
    scoped_refptr<TransformedFrameCallback> callback,
    uint32_t ssrc) {
  MutexLock lock(&sink_mutex_);
  sinks_[ssrc] = std::move(callback);
}

void SframeTransformer::UnregisterTransformedFrameCallback() {
  MutexLock lock(&sink_mutex_);
  sink_ = nullptr;
}

void SframeTransformer::UnregisterTransformedFrameSinkCallback(uint32_t ssrc) {
  MutexLock lock(&sink_mutex_);
  sinks_.erase(ssrc);
}

}  // namespace webrtc
