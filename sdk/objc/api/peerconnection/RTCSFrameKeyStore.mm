/*
 * Takamaka E2EE calls (C182 / DR-055) — RTCSFrameKeyStore over
 * webrtc::SframeKeyStore. No key byte crosses back to Objective-C and none is
 * logged; the copies of base keys made here are wiped.
 */

#import "RTCSFrameKeyStore+Private.h"

#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <vector>

#import "helpers/NSString+StdString.h"

#include "api/make_ref_counted.h"
#include "api/units/time_delta.h"
#include "rtc_base/zero_memory.h"

namespace webrtc {

namespace {

class RTCSFrameObserverAdapter : public SframeObserver {
 public:
  explicit RTCSFrameObserverAdapter(RTC_OBJC_TYPE(RTCSFrameKeyStore) * keyStore)
      : key_store_(keyStore) {}

  void OnSframeEvent(const SframeEvent& e) override {
    RTC_OBJC_TYPE(RTCSFrameKeyStore) *keyStore = key_store_;
    if (keyStore == nil) {
      return;
    }
    id<RTC_OBJC_TYPE(RTCSFrameKeyStoreDelegate)> delegate = keyStore.delegate;
    if (delegate == nil) {
      return;
    }
    const char* reason =
        e.reason == SframeDropReason::kCount ? "" : SframeDropReasonName(e.reason);
    [delegate sframeKeyStore:keyStore
            didEventWithType:[NSString stringWithUTF8String:SframeEventTypeName(e.type)]
                    streamId:[NSString stringForStdString:e.stream_id]
                      reason:[NSString stringWithUTF8String:reason]
                         kid:e.kid ? static_cast<int64_t>(*e.kid) : -1
                 consecutive:static_cast<int64_t>(e.consecutive)];
  }

 private:
  __weak RTC_OBJC_TYPE(RTCSFrameKeyStore) * key_store_;
};

std::string JsonString(const std::string& s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (static_cast<unsigned char>(c) < 0x20) {
      char buf[8];
      std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
      out += buf;
    } else {
      out += c;
    }
  }
  return out + "\"";
}

std::string OptionalMs(const std::optional<Timestamp>& t) {
  return t ? std::to_string(t->ms()) : std::string("null");
}

std::span<const uint8_t> Bytes(NSData* data) {
  return std::span<const uint8_t>(static_cast<const uint8_t*>(data.bytes), data.length);
}

NSData* ToNSData(const std::vector<uint8_t>& v) {
  return [NSData dataWithBytes:v.data() length:v.size()];
}

}  // namespace

std::string RTCSFrameStatsJson(const SframeStreamStats& s) {
  std::string j = "{\"streamId\":" + JsonString(s.stream_id);
  j += ",\"role\":\"" + std::string(s.role == SframeRole::kSender ? "send" : "recv") + "\"";
  j += ",\"kind\":\"" + std::string(s.kind == SframeMediaKind::kAudio ? "audio" : "video") + "\"";
  j += ",\"frames\":" + std::to_string(s.frames);
  j += ",\"keyframes\":" + std::to_string(s.keyframes);
  j += ",\"passed\":" + std::to_string(s.passed);
  j += ",\"bytesIn\":" + std::to_string(s.bytes_in);
  j += ",\"bytesOut\":" + std::to_string(s.bytes_out);
  j += ",\"dropped\":{";
  bool first = true;
  for (size_t i = 0; i < s.dropped.size(); ++i) {
    if (s.dropped[i] == 0) {
      continue;
    }
    j += first ? "" : ",";
    first = false;
    j += "\"" + std::string(SframeDropReasonName(static_cast<SframeDropReason>(i))) +
         "\":" + std::to_string(s.dropped[i]);
  }
  j += "}";
  j += ",\"dropSamples\":[";
  for (size_t i = 0; i < s.drop_samples.size(); ++i) {
    j += (i ? "," : "") + JsonString(s.drop_samples[i]);
  }
  j += "]";
  j += ",\"consecutive\":" + std::to_string(s.consecutive);
  j += ",\"storm\":" + std::string(s.storm ? "true" : "false");
  j += ",\"storms\":" + std::to_string(s.storms);
  j += ",\"lastKid\":" + (s.last_kid ? std::to_string(*s.last_kid) : std::string("null"));
  j += ",\"firstFrameAtMs\":" + OptionalMs(s.first_frame_at);
  j += ",\"firstPassAtMs\":" + OptionalMs(s.first_pass_at);
  j += ",\"lastFrameAtMs\":" + OptionalMs(s.last_frame_at);
  return j + "}";
}

}  // namespace webrtc

@implementation RTC_OBJC_TYPE (RTCSFrameKeyStore) {
  webrtc::scoped_refptr<webrtc::SframeKeyStore> _nativeKeyStore;
}

@synthesize delegate = _delegate;

- (instancetype)init {
  self = [super init];
  if (self) {
    _nativeKeyStore = webrtc::SframeKeyStore::Create();
    _nativeKeyStore->SetObserver(webrtc::make_ref_counted<webrtc::RTCSFrameObserverAdapter>(self));
  }
  return self;
}

- (void)dealloc {
  _nativeKeyStore->SetObserver(nullptr);
}

- (webrtc::scoped_refptr<webrtc::SframeKeyStore>)nativeKeyStore {
  return _nativeKeyStore;
}

- (RTCSFrameSetKeyResult)setKey:(int64_t)kid baseKey:(NSData *)baseKey {
  if (kid < 0 || baseKey == nil) {
    return RTCSFrameSetKeyResultInvalid;
  }
  std::vector<uint8_t> base(static_cast<const uint8_t *>(baseKey.bytes),
                            static_cast<const uint8_t *>(baseKey.bytes) + baseKey.length);
  const webrtc::SframeKeyStore::SetKeyResult r =
      _nativeKeyStore->SetKey(static_cast<uint64_t>(kid), std::span<const uint8_t>(base));
  if (!base.empty()) {
    webrtc::ExplicitZeroMemory(base.data(), base.size());
  }
  switch (r) {
    case webrtc::SframeKeyStore::SetKeyResult::kChanged:
      return RTCSFrameSetKeyResultChanged;
    case webrtc::SframeKeyStore::SetKeyResult::kUnchanged:
      return RTCSFrameSetKeyResultUnchanged;
    case webrtc::SframeKeyStore::SetKeyResult::kInvalid:
      return RTCSFrameSetKeyResultInvalid;
  }
  return RTCSFrameSetKeyResultInvalid;
}

- (BOOL)removeKey:(int64_t)kid {
  return kid >= 0 && _nativeKeyStore->RemoveKey(static_cast<uint64_t>(kid));
}

- (BOOL)retireKey:(int64_t)kid retentionMs:(int64_t)retentionMs {
  return kid >= 0 &&
         _nativeKeyStore->RetireKey(static_cast<uint64_t>(kid), webrtc::TimeDelta::Millis(retentionMs));
}

- (BOOL)setSendKid:(int64_t)kid {
  return kid >= 0 && _nativeKeyStore->SetSendKid(static_cast<uint64_t>(kid));
}

- (void)clearSendKid {
  _nativeKeyStore->ClearSendKid();
}

- (int64_t)sendKid {
  const std::optional<uint64_t> kid = _nativeKeyStore->send_kid();
  return kid ? static_cast<int64_t>(*kid) : -1;
}

- (void)setStormThreshold:(int)threshold {
  _nativeKeyStore->SetStormThreshold(threshold);
}

- (void)setH264Enabled:(BOOL)enabled {
  _nativeKeyStore->SetH264Enabled(enabled);
}

- (NSString *)statsJson {
  std::string j = "[";
  bool first = true;
  for (const webrtc::SframeStreamStats &s : _nativeKeyStore->GetAllStats()) {
    j += first ? "" : ",";
    first = false;
    j += webrtc::RTCSFrameStatsJson(s);
  }
  j += "]";
  return [NSString stringForStdString:j];
}

+ (nullable NSData *)vectorSealWithBaseKey:(NSData *)baseKey
                                       kid:(int64_t)kid
                                       ctr:(int64_t)ctr
                                     frame:(NSData *)frame
                              prefixLength:(NSInteger)prefixLength {
  if (baseKey == nil || frame == nil || kid < 0 || ctr < 0 || prefixLength < 0) {
    return nil;
  }
  const std::vector<uint8_t> unit = webrtc::SframeKeyStore::VectorSeal(
      webrtc::Bytes(baseKey), static_cast<uint64_t>(kid), static_cast<uint64_t>(ctr),
      webrtc::Bytes(frame), static_cast<size_t>(prefixLength));
  if (unit.empty()) {
    return nil;
  }
  return webrtc::ToNSData(unit);
}

+ (nullable NSData *)vectorOpenWithBaseKey:(NSData *)baseKey
                                       kid:(int64_t)kid
                                      unit:(NSData *)unit
                              prefixLength:(NSInteger)prefixLength {
  if (baseKey == nil || unit == nil || kid < 0 || prefixLength < 0) {
    return nil;
  }
  const std::optional<std::vector<uint8_t>> frame = webrtc::SframeKeyStore::VectorOpen(
      webrtc::Bytes(baseKey), static_cast<uint64_t>(kid), webrtc::Bytes(unit),
      static_cast<size_t>(prefixLength));
  if (!frame) {
    return nil;
  }
  return webrtc::ToNSData(*frame);
}

@end
