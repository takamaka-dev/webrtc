/*
 * Takamaka E2EE calls (C182 / DR-055) — JNI for org.webrtc.SFrameKeyStore and
 * org.webrtc.SFrameCryptor. No key byte crosses back to Java and none is
 * logged.
 */

#include <jni.h>

#include <algorithm>
#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "api/crypto/sframe_transformer.h"
#include "api/make_ref_counted.h"
#include "api/rtp_receiver_interface.h"
#include "api/rtp_sender_interface.h"
#include "api/units/time_delta.h"
#include "sdk/android/generated_peerconnection_jni/SFrameCryptor_jni.h"
#include "sdk/android/generated_peerconnection_jni/SFrameKeyStore_jni.h"
#include "sdk/android/native_api/jni/java_types.h"
#include "sdk/android/src/jni/jni_helpers.h"

namespace webrtc {
namespace jni {

namespace {

class SframeObserverJni : public SframeObserver {
 public:
  SframeObserverJni(JNIEnv* env, const JavaRef<jobject>& j_observer)
      : j_observer_(env, j_observer) {}

  void OnSframeEvent(const SframeEvent& e) override {
    JNIEnv* env = AttachCurrentThreadIfNeeded();
    const char* reason = e.reason == SframeDropReason::kCount
                             ? ""
                             : SframeDropReasonName(e.reason);
    Java_Observer_onSFrameEvent(
        env, j_observer_, NativeToJavaString(env, SframeEventTypeName(e.type)),
        NativeToJavaString(env, e.stream_id), NativeToJavaString(env, reason),
        e.kid ? static_cast<jlong>(*e.kid) : -1,
        static_cast<jlong>(e.consecutive));
  }

 private:
  const ScopedJavaGlobalRef<jobject> j_observer_;
};

SframeKeyStore* Store(jlong p) {
  return reinterpret_cast<SframeKeyStore*>(p);
}

std::string JsonString(const std::string& s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (static_cast<unsigned char>(c) < 0x20) {
      char buf[8];
      std::snprintf(buf, sizeof(buf), "\\u%04x", c);
      out += buf;
    } else {
      out += c;
    }
  }
  return out + "\"";
}

std::string StatsJson(const SframeStreamStats& s) {
  std::string j = "{\"streamId\":" + JsonString(s.stream_id);
  j += ",\"role\":\"" +
       std::string(s.role == SframeRole::kSender ? "send" : "recv") + "\"";
  j += ",\"kind\":\"" +
       std::string(s.kind == SframeMediaKind::kAudio ? "audio" : "video") +
       "\"";
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
    j += "\"" +
         std::string(SframeDropReasonName(static_cast<SframeDropReason>(i))) +
         "\":" + std::to_string(s.dropped[i]);
  }
  j += "}";
  j += ",\"consecutive\":" + std::to_string(s.consecutive);
  j += ",\"storm\":" + std::string(s.storm ? "true" : "false");
  j += ",\"storms\":" + std::to_string(s.storms);
  j += ",\"lastKid\":" +
       (s.last_kid ? std::to_string(*s.last_kid) : std::string("null"));
  j += ",\"firstFrameAtMs\":" + (s.first_frame_at
                                     ? std::to_string(s.first_frame_at->ms())
                                     : std::string("null"));
  j += ",\"firstPassAtMs\":" + (s.first_pass_at
                                    ? std::to_string(s.first_pass_at->ms())
                                    : std::string("null"));
  j += ",\"lastFrameAtMs\":" + (s.last_frame_at
                                    ? std::to_string(s.last_frame_at->ms())
                                    : std::string("null"));
  return j + "}";
}

SframeMediaKind KindFromIndex(jint kind) {
  return kind == 0 ? SframeMediaKind::kAudio : SframeMediaKind::kVideo;
}

}  // namespace

// ---- SFrameKeyStore
// ---------------------------------------------------------------------------------------------

static jlong JNI_SFrameKeyStore_Create(JNIEnv* env) {
  return jlongFromPointer(SframeKeyStore::Create().release());
}

static jint JNI_SFrameKeyStore_SetKey(
    JNIEnv* env,
    jlong j_store,
    jlong j_kid,
    const JavaParamRef<jbyteArray>& j_base_key) {
  if (j_kid < 0 || j_base_key.is_null()) {
    return static_cast<jint>(SframeKeyStore::SetKeyResult::kInvalid);
  }
  std::vector<int8_t> base = JavaToNativeByteArray(env, j_base_key);
  const SframeKeyStore::SetKeyResult r = Store(j_store)->SetKey(
      static_cast<uint64_t>(j_kid),
      std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(base.data()),
                               base.size()));
  std::fill(base.begin(), base.end(), 0);
  return static_cast<jint>(r);
}

static jboolean JNI_SFrameKeyStore_RemoveKey(JNIEnv* env,
                                             jlong j_store,
                                             jlong j_kid) {
  return j_kid >= 0 && Store(j_store)->RemoveKey(static_cast<uint64_t>(j_kid));
}

static jboolean JNI_SFrameKeyStore_RetireKey(JNIEnv* env,
                                             jlong j_store,
                                             jlong j_kid,
                                             jlong j_retention_ms) {
  return j_kid >= 0 &&
         Store(j_store)->RetireKey(static_cast<uint64_t>(j_kid),
                                   TimeDelta::Millis(j_retention_ms));
}

static jboolean JNI_SFrameKeyStore_SetSendKid(JNIEnv* env,
                                              jlong j_store,
                                              jlong j_kid) {
  return j_kid >= 0 && Store(j_store)->SetSendKid(static_cast<uint64_t>(j_kid));
}

static void JNI_SFrameKeyStore_ClearSendKid(JNIEnv* env, jlong j_store) {
  Store(j_store)->ClearSendKid();
}

static jlong JNI_SFrameKeyStore_GetSendKid(JNIEnv* env, jlong j_store) {
  const std::optional<uint64_t> kid = Store(j_store)->send_kid();
  return kid ? static_cast<jlong>(*kid) : -1;
}

static void JNI_SFrameKeyStore_SetStormThreshold(JNIEnv* env,
                                                 jlong j_store,
                                                 jint j_n) {
  Store(j_store)->SetStormThreshold(j_n);
}

static void JNI_SFrameKeyStore_SetH264Enabled(JNIEnv* env,
                                              jlong j_store,
                                              jboolean j_enabled) {
  Store(j_store)->SetH264Enabled(j_enabled);
}

static void JNI_SFrameKeyStore_SetObserver(
    JNIEnv* env,
    jlong j_store,
    const JavaParamRef<jobject>& j_observer) {
  if (j_observer.is_null()) {
    Store(j_store)->SetObserver(nullptr);
    return;
  }
  Store(j_store)->SetObserver(
      make_ref_counted<SframeObserverJni>(env, j_observer));
}

static ScopedJavaLocalRef<jstring> JNI_SFrameKeyStore_GetStatsJson(
    JNIEnv* env,
    jlong j_store) {
  std::string j = "[";
  bool first = true;
  for (const SframeStreamStats& s : Store(j_store)->GetAllStats()) {
    j += first ? "" : ",";
    first = false;
    j += StatsJson(s);
  }
  return NativeToJavaString(env, j + "]");
}

// ---- SFrameCryptor
// ----------------------------------------------------------------------------------------------

static jlong JNI_SFrameCryptor_CreateForRtpSender(
    JNIEnv* env,
    jlong j_rtp_sender,
    jlong j_store,
    jint j_kind,
    const JavaParamRef<jstring>& j_stream_id) {
  auto* sender = reinterpret_cast<RtpSenderInterface*>(j_rtp_sender);
  scoped_refptr<SframeTransformer> t = SframeTransformer::Create(
      scoped_refptr<SframeKeyStore>(Store(j_store)), SframeRole::kSender,
      KindFromIndex(j_kind), JavaToStdString(env, j_stream_id));
  sender->SetFrameTransformer(t);
  return jlongFromPointer(t.release());
}

static jlong JNI_SFrameCryptor_CreateForRtpReceiver(
    JNIEnv* env,
    jlong j_rtp_receiver,
    jlong j_store,
    jint j_kind,
    const JavaParamRef<jstring>& j_stream_id) {
  auto* receiver = reinterpret_cast<RtpReceiverInterface*>(j_rtp_receiver);
  scoped_refptr<SframeTransformer> t = SframeTransformer::Create(
      scoped_refptr<SframeKeyStore>(Store(j_store)), SframeRole::kReceiver,
      KindFromIndex(j_kind), JavaToStdString(env, j_stream_id));
  receiver->SetFrameTransformer(t);
  return jlongFromPointer(t.release());
}

static ScopedJavaLocalRef<jstring> JNI_SFrameCryptor_GetStatsJson(
    JNIEnv* env,
    jlong j_cryptor) {
  return NativeToJavaString(
      env,
      StatsJson(reinterpret_cast<SframeTransformer*>(j_cryptor)->GetStats()));
}

}  // namespace jni
}  // namespace webrtc
