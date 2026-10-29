/*
 * Takamaka E2EE calls (C182 / DR-055) — the SFrame (RFC 9605) frame transformer
 * of the native engine.
 *
 * A FrameTransformerInterface beside the stock FrameCryptorTransformer (which
 * it shares NOTHING with): suite 5 AES_256_GCM_SHA512, KID = leg_index·2^16 +
 * (epoch mod 2^16), AAD = SFrame header ‖ clear codec prefix, replay window 128
 * per sender key, storm rule, fail closed everywhere. Same semantics as the web
 * worker (chat-web-gui static/js/call/sframe-worker.js) and the Java reference
 * (Messages call/sframe), spec §9.1–§9.3.
 *
 * Fail-closed properties (the stock cryptor's CM-1/CM-2/CM-4/CM-11 defects, by
 * construction absent here):
 *   - there is no "disabled" state and no pass-through: a sender with no send
 * KID (or no key for it) DROPS every frame; a receiver drops every frame it
 * cannot authenticate; neither ever emits a frame it did not seal/open;
 *   - no magic trailer, no byte sequence that bypasses decryption (relay blank
 * frames fail and are dropped);
 *   - no default key, no implicit key fallback, no ratchet: a frame is opened
 * only by the key of its own KID;
 *   - leg binding (S-7): a receive stream bound to a leg opens only KIDs of
 * that leg, and with require_leg_binding an unbound one opens nothing — the
 * relay cannot route one member's frames under another participant's track;
 *   - nonce = salt XOR CTR with a CTR per KID that never repeats within this
 * key store's life;
 *   - zero-length frames dropped; codecs other than Opus / VP8 (H.264 only when
 * explicitly enabled) dropped;
 *   - no key byte is ever logged.
 */

#ifndef API_CRYPTO_SFRAME_TRANSFORMER_H_
#define API_CRYPTO_SFRAME_TRANSFORMER_H_

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "api/crypto/sframe_core.h"
#include "api/frame_transformer_interface.h"
#include "api/ref_count.h"
#include "api/scoped_refptr.h"
#include "api/units/time_delta.h"
#include "api/units/timestamp.h"
#include "rtc_base/synchronization/mutex.h"
#include "rtc_base/system/rtc_export.h"
#include "rtc_base/thread_annotations.h"

namespace webrtc {

class Clock;

enum class SframeRole { kSender, kReceiver };
enum class SframeMediaKind { kAudio, kVideo };

// Why a frame was dropped. The names (SframeDropReasonName) are the web
// worker's.
enum class SframeDropReason {
  kEmpty = 0,  // zero-length frame (sender: no Opus TOC; spec §9.1 [0.2])
  kCodec,      // not Opus (audio) / not VP8 (video) / H.264 not enabled — never
               // sent or played
  kNoKey,      // sender: no send KID or no key for it
  kCtrExhausted,  // sender: CTR reached kCtrLimit — needs a new epoch
  kShort,         // receiver: shorter than prefix + 1 + tag
  kBadHeader,     // receiver: truncated / non-minimal SFrame header
  kUnknownKid,    // receiver: no key for the KID (nothing passes while a key is
                  // missing)
  kReplay,        // receiver: CTR already seen inside the window
  kTooOld,        // receiver: CTR older than the window
  kBadTag,        // receiver: authentication failed (wrong key, tampering,
                  // relay-injected blank frame)
  kMalformed,     // H.264: no start code, unexpected NAL type, unreadable slice
                  // header, bad escaping, mixed KIDs
  kNoSink,        // no TransformedFrameCallback registered for the frame's SSRC
  kInternal,      // direction mismatch, BoringSSL failure
  kHeldExpired,   // receiver (video): held for the key of a known leg's next
                  // epoch that never arrived within the hold time (C-24)
  kHeldOverflow,  // receiver (video): the hold queue was full; the oldest held
                  // frame was dropped (C-24)
  kUnbound,       // receiver: the store requires a leg binding and this stream
                  // has none yet (S-7, ruling Q1: fail closed)
  kWrongLeg,      // receiver: the frame's KID belongs to another leg than the
                  // one this stream is bound to (S-7: a relay re-routing a
                  // member's frames under another participant's identity)
  kCount
};
RTC_EXPORT const char* SframeDropReasonName(SframeDropReason reason);
// spec §9.2 [0.2] storm rule: the reasons that count toward N (as in the web
// worker).
RTC_EXPORT bool SframeDropCountsForStorm(SframeDropReason reason);

struct RTC_EXPORT SframeStreamStats {
  std::string stream_id;
  SframeRole role = SframeRole::kSender;
  SframeMediaKind kind = SframeMediaKind::kAudio;
  uint64_t frames = 0;     // frames handed to the transformer
  uint64_t keyframes = 0;  // of which video keyframes
  uint64_t passed = 0;  // sealed (sender) / authenticated and opened (receiver)
  uint64_t bytes_in = 0;
  uint64_t bytes_out = 0;
  std::array<uint64_t, static_cast<size_t>(SframeDropReason::kCount)> dropped{};
  uint64_t consecutive = 0;  // consecutive storm-counting drops (receiver)
  bool storm = false;  // spec §9.2 storm: the app pauses this subscription
  uint64_t storms = 0;
  // Receiver video only (spec §9.2 [0.3], C-24): frames under a KID of a known
  // leg's NEXT epoch(s) are held until their key arrives instead of dropped.
  uint64_t held = 0;           // frames that entered the hold
  uint64_t held_released = 0;  // of which opened and delivered when the key came
  uint64_t held_now = 0;       // currently held
  // Receiver only (S-7): the leg_index this stream renders (the verified
  // roster's index of the relay participant whose track it is), set by
  // BindLeg; nullopt = unbound.
  std::optional<uint32_t> bound_leg;
  std::optional<uint64_t> last_kid;
  std::optional<Timestamp> first_frame_at;
  std::optional<Timestamp> first_pass_at;
  std::optional<Timestamp> last_frame_at;
  // Receive side only. Diagnostics, as the web worker's dropSamples: the first
  // drops of each reason as "reason len=N first=<hex of the first 12 bytes>"
  // (at most 3 per reason, 12 in all). Clear prefix / header / ciphertext only,
  // never a key.
  std::vector<std::string> drop_samples;
  uint64_t dropped_total() const;
};

struct RTC_EXPORT SframeEvent {
  enum class Type {
    kEngaged,     // first frame seen by this stream (engagement evidence, spec
                  // §9.2 [0.2])
    kFirstPass,   // first frame sealed / opened by this stream
    kDropping,    // a drop whose reason differs from the last reported one, or
                  // the first drop after a pass
    kStorm,       // N consecutive storm-counting drops: pause this subscription
    kRecovered,   // a stormed stream may resume: a frame under its last KID
                  // authenticated again (any stream)
    kResumed,     // a stormed stream may resume: a key changed (SetKey with new
                  // material)
    kKeyExpired,  // a retired key reached its retention deadline and was
                  // removed
    kKeyEvicted,  // a key was removed because its leg exceeded kMaxKeysPerLeg
    kHeld,        // a receive stream started holding frames for `kid` (its key
                  // is missing; C-24)
    kReleased,    // `count` held frames of a receive stream were opened and
                  // delivered after the key of `kid` arrived (C-24)
  };
  Type type = Type::kEngaged;
  std::string stream_id;  // empty for key events
  SframeRole role = SframeRole::kSender;
  SframeMediaKind kind = SframeMediaKind::kAudio;
  SframeDropReason reason =
      SframeDropReason::kCount;  // kDropping / kStorm: the triggering reason
  std::optional<uint64_t> kid;
  uint64_t consecutive = 0;
  uint64_t count = 0;  // kReleased: frames released
};
RTC_EXPORT const char* SframeEventTypeName(SframeEvent::Type type);

// Called synchronously on the media thread that processed the frame (or the
// thread calling the key store), never with an internal lock held. Must return
// quickly and must not call back into the transformer synchronously.
class SframeObserver : public RefCountInterface {
 public:
  virtual void OnSframeEvent(const SframeEvent& event) = 0;

 protected:
  ~SframeObserver() override = default;
};

class SframeTransformer;

// The keys of one call (one per app-level call session), shared by every
// transformer of that call: one CTR space per KID shared by audio and video
// (the web worker's rule), one replay window per KID, the storm/recovery
// registry.
class RTC_EXPORT SframeKeyStore : public RefCountInterface {
 public:
  enum class SetKeyResult { kChanged, kUnchanged, kInvalid };
  static constexpr size_t kMaxKeysPerLeg =
      4;  // spec §9.2 K-2: "a cap of a few epochs bounds memory"
  static constexpr int kDefaultStormThreshold = 30;
  // C-24 (spec §9.2 [0.3]): a VIDEO frame whose KID has no key, but whose leg
  // has a key for an epoch 1..kHoldEpochsAhead behind the frame's, is HELD
  // until the key arrives (SetKey releases it, in order), at most `hold time`
  // (default 10 s = the `retention` default), at most kMaxHeldFrames /
  // kMaxHeldBytes per stream (beyond that the oldest is dropped
  // kHeldOverflow). A dropped frame at an epoch switch breaks the VP8
  // reference chain until a keyframe (a 0.5 s freeze per rotation, C-24);
  // a held one costs only the key's lateness. Audio is never held (Opus PLC).
  static constexpr uint32_t kHoldEpochsAhead = 8;
  static constexpr size_t kMaxHeldFrames = 300;
  static constexpr size_t kMaxHeldBytes = 8 * 1024 * 1024;
  static constexpr int64_t kDefaultHoldMs = 10000;

  // `clock` = nullptr → the real-time clock.
  static scoped_refptr<SframeKeyStore> Create(Clock* clock = nullptr);

  // Installs the RFC 9605 §4.4.2 key and salt of `kid`, derived from `base_key`
  // (= sender_base_e of the leg, spec §6.1, exactly 32 bytes). kInvalid: a
  // reserved KID (leg_index 0, or > 16 bits) or a wrong base-key length.
  // kUnchanged: the same material is already installed (window and storms
  // untouched). kChanged: a new key (fresh replay window; every stormed receive
  // stream is resumed — spec §9.2 [0.2]). The base key is not retained.
  // Installing a 5th key of one leg evicts that leg's oldest key (kKeyEvicted
  // event).
  SetKeyResult SetKey(uint64_t kid, std::span<const uint8_t> base_key);
  // Removes a key now (and its replay window). The send KID is cleared if it
  // was this one. The CTR counter of the KID is kept for the store's life, so a
  // re-installed key never reuses a (key, nonce) pair.
  bool RemoveKey(uint64_t kid);
  // Explicit retention (spec §9.2: keys of every epoch kept until `retention`
  // after its successor was applied): the key stays usable until now +
  // retention, then is removed (kKeyExpired event). Re-SetKey of new material
  // clears it.
  bool RetireKey(uint64_t kid, TimeDelta retention);
  // The KID the senders seal under. False (and unchanged) if no key is
  // installed for it.
  bool SetSendKid(uint64_t kid);
  void ClearSendKid();
  std::optional<uint64_t> send_kid() const;
  std::vector<uint64_t> kids() const;
  bool HasKey(uint64_t kid) const;
  // spec §9.2 [0.2] storm rule N (initial 30).
  void SetStormThreshold(int n);
  // C-24: how long a receive video stream holds frames for a missing key of a
  // known leg's next epoch; zero disables holding (frames drop as unknown-kid).
  void SetHoldTime(TimeDelta hold);
  void SetObserver(scoped_refptr<SframeObserver> observer);
  std::vector<SframeStreamStats> GetAllStats() const;

  // S-7 (ruling Q1): when on, a receive stream opens frames ONLY after BindLeg
  // gave it a leg, and only under KIDs of that leg (kid >> 16): unbound →
  // drop kUnbound, another leg → drop kWrongLeg (both count toward the storm,
  // ruling Q3). Off (the default, for the pre-tkm.9 callers): an unbound
  // stream opens any installed KID, as before; a bound one is still filtered.
  // Call once at creation, before frames flow.
  void SetRequireLegBinding(bool required);
  bool require_leg_binding() const;
  // S-7: binds every receive stream labelled `stream_id` to `leg_index`
  // (1..65535), or unbinds it (nullopt). A change of binding drops the frames
  // that stream holds (C-24: they were held for the old leg) and resets its
  // storm state (kResumed if it was stormed): the drops before the binding
  // are not the new leg's fault. False if no receive stream has that label or
  // `leg_index` is not assignable (0 or > 0xFFFF).
  bool BindLeg(const std::string& stream_id, std::optional<uint32_t> leg_index);

  // Must be called once before frames flow: enables H.264 (spec §9.2 [0.2]
  // fallback layout). Default OFF: H.264 is dropped like any other codec until
  // the layout is fixed by test (a) on the fork (OPEN H-1 of the M1 report).
  void SetH264Enabled(bool enabled);

  // Vector checks for the platform bindings (JNI / Flutter platform channel):
  // seal / open ONE Opus- or VP8-shaped unit (clear prefix of `prefix_len`
  // bytes) with the same derivation and AEAD code the transformer uses, under
  // a key derived from `base_key` for `kid` and an explicit `ctr`. Static on
  // purpose: they never touch a store's live keys, CTR counters or replay
  // windows, so they cannot reuse a live (key, nonce) pair. Empty / nullopt on
  // any error (bad base key, prefix longer than the input, bad header, other
  // KID, bad tag).
  static std::vector<uint8_t> VectorSeal(std::span<const uint8_t> base_key,
                                         uint64_t kid,
                                         uint64_t ctr,
                                         std::span<const uint8_t> frame,
                                         size_t prefix_len);
  static std::optional<std::vector<uint8_t>> VectorOpen(
      std::span<const uint8_t> base_key,
      uint64_t kid,
      std::span<const uint8_t> unit,
      size_t prefix_len);

 protected:
  explicit SframeKeyStore(Clock* clock);
  ~SframeKeyStore() override;

 private:
  friend class SframeTransformer;

  struct KeyEntry {
    std::unique_ptr<sframe::SealingKey> key;
    sframe::ReplayWindow window;
    uint64_t installed_seq = 0;
    std::optional<Timestamp> expires_at;
  };
  struct HeldFrame {
    std::unique_ptr<TransformableFrameInterface> frame;
    uint64_t kid = 0;
    Timestamp deadline = Timestamp::MinusInfinity();
    size_t bytes = 0;
  };
  struct Stream {
    SframeStreamStats stats;
    std::optional<SframeDropReason> last_reported_drop;
    SframeTransformer* transformer = nullptr;  // delivers released frames
    std::deque<HeldFrame> held;                // C-24, receiver video only
    size_t held_bytes = 0;
  };
  struct Delivery {
    scoped_refptr<TransformedFrameCallback> sink;
    std::unique_ptr<TransformableFrameInterface> frame;
  };
  using Events = std::vector<SframeEvent>;

  // The whole per-frame work, under `mutex_`. Returns false (frame dropped, or
  // held: then `*held` is true and the store owns `frame`) or true with `out`
  // = the new payload.
  bool Process(Stream* stream,
               std::unique_ptr<TransformableFrameInterface>& frame,
               std::vector<uint8_t>* out,
               Events* events,
               bool* held);
  // The bookkeeping of an opened / sealed frame (passed, first pass, storm
  // recovery of the receiver).
  void PassLocked(Stream* stream, uint64_t kid, size_t out_bytes, Events* events)
      RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  // S-7: nullopt when the stream may open `kid`, else kUnbound / kWrongLeg.
  std::optional<SframeDropReason> LegCheckLocked(const Stream* stream,
                                                 uint64_t kid) const
      RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  bool BindStreamLeg(Stream* stream, std::optional<uint32_t> leg_index);
  bool BindLegLocked(Stream* stream,
                     std::optional<uint32_t> leg_index,
                     Events* events) RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  // C-24
  bool ShouldHoldLocked(const Stream* stream, uint64_t kid) const
      RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void HoldLocked(Stream* stream,
                  std::unique_ptr<TransformableFrameInterface> frame,
                  uint64_t kid,
                  Events* events) RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void ReleaseHeldLocked(uint64_t kid,
                         Events* events,
                         std::vector<Delivery>* deliveries)
      RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void ExpireHeldLocked(Events* events) RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  static void Deliver(std::vector<Delivery> deliveries);
  bool SealLocked(Stream* stream,
                  const TransformableFrameInterface& frame,
                  std::vector<uint8_t>* out,
                  SframeDropReason* why) RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  bool OpenLocked(Stream* stream,
                  const TransformableFrameInterface& frame,
                  std::vector<uint8_t>* out,
                  SframeDropReason* why,
                  uint64_t* kid_out) RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void DropLocked(Stream* stream, SframeDropReason why, Events* events)
      RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void RecordNoSink(Stream* stream, size_t bytes, Events* events);
  static void SampleDrop(Stream* stream,
                         SframeDropReason why,
                         std::span<const uint8_t> data);
  void PurgeExpiredLocked(Events* events) RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  KeyEntry* FindKeyLocked(uint64_t kid) RTC_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void Dispatch(const Events& events);

  Stream* RegisterStream(const std::string& stream_id,
                         SframeRole role,
                         SframeMediaKind kind,
                         SframeTransformer* transformer);
  void UnregisterStream(Stream* stream);
  SframeStreamStats StatsOf(const Stream* stream) const;

  Clock* const clock_;
  mutable Mutex mutex_;
  std::map<uint64_t, KeyEntry> keys_ RTC_GUARDED_BY(mutex_);
  std::map<uint64_t, uint64_t> next_ctr_ RTC_GUARDED_BY(mutex_);
  std::optional<uint64_t> send_kid_ RTC_GUARDED_BY(mutex_);
  uint64_t install_seq_ RTC_GUARDED_BY(mutex_) = 0;
  int storm_threshold_ RTC_GUARDED_BY(mutex_) = kDefaultStormThreshold;
  bool h264_enabled_ RTC_GUARDED_BY(mutex_) = false;
  bool require_leg_binding_ RTC_GUARDED_BY(mutex_) = false;  // S-7
  TimeDelta hold_time_ RTC_GUARDED_BY(mutex_) = TimeDelta::Millis(kDefaultHoldMs);
  std::vector<std::unique_ptr<Stream>> streams_ RTC_GUARDED_BY(mutex_);
  Mutex observer_mutex_;
  scoped_refptr<SframeObserver> observer_ RTC_GUARDED_BY(observer_mutex_);
};

// One direction of one track (one per RtpSender / RtpReceiver). Processes
// frames synchronously on the calling thread.
class RTC_EXPORT SframeTransformer : public FrameTransformerInterface {
 public:
  // `stream_id`: an app-chosen label for stats and events (e.g.
  // "recv:video:<track sid>").
  static scoped_refptr<SframeTransformer> Create(
      scoped_refptr<SframeKeyStore> store,
      SframeRole role,
      SframeMediaKind kind,
      const std::string& stream_id);

  SframeStreamStats GetStats() const;
  // S-7: binds this (receive) transformer to `leg_index`, or unbinds it
  // (nullopt); see SframeKeyStore::BindLeg. False on a sender or an
  // unassignable leg index.
  bool BindLeg(std::optional<uint32_t> leg_index);
  SframeRole role() const { return role_; }
  SframeMediaKind kind() const { return kind_; }
  const scoped_refptr<SframeKeyStore>& key_store() const { return store_; }

  // FrameTransformerInterface
  void Transform(std::unique_ptr<TransformableFrameInterface> frame) override;
  void RegisterTransformedFrameCallback(
      scoped_refptr<TransformedFrameCallback> callback) override;
  void RegisterTransformedFrameSinkCallback(
      scoped_refptr<TransformedFrameCallback> callback,
      uint32_t ssrc) override;
  void UnregisterTransformedFrameCallback() override;
  void UnregisterTransformedFrameSinkCallback(uint32_t ssrc) override;

 protected:
  SframeTransformer(scoped_refptr<SframeKeyStore> store,
                    SframeRole role,
                    SframeMediaKind kind,
                    const std::string& stream_id);
  ~SframeTransformer() override;

 private:
  friend class SframeKeyStore;
  scoped_refptr<TransformedFrameCallback> SinkFor(uint32_t ssrc);

  const scoped_refptr<SframeKeyStore> store_;
  const SframeRole role_;
  const SframeMediaKind kind_;
  SframeKeyStore::Stream* const
      stream_;  // owned by the store, unregistered in the destructor
  Mutex sink_mutex_;
  scoped_refptr<TransformedFrameCallback> sink_ RTC_GUARDED_BY(sink_mutex_);
  std::map<uint32_t, scoped_refptr<TransformedFrameCallback>> sinks_
      RTC_GUARDED_BY(sink_mutex_);
};

}  // namespace webrtc

#endif  // API_CRYPTO_SFRAME_TRANSFORMER_H_
