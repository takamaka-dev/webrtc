/*
 * Takamaka E2EE calls (C182 / DR-055) — native access to the SFrame key store,
 * for RTCSFrameCryptor.
 */

#import "RTCSFrameKeyStore.h"

#include "api/crypto/sframe_transformer.h"
#include "api/scoped_refptr.h"

NS_ASSUME_NONNULL_BEGIN

@interface RTC_OBJC_TYPE (RTCSFrameKeyStore)
()

    @property(nonatomic, readonly) webrtc::scoped_refptr<webrtc::SframeKeyStore> nativeKeyStore;

@end

namespace webrtc {

/** Stats of one stream as the JSON object the Android binding emits. */
std::string RTCSFrameStatsJson(const SframeStreamStats& stats);

}  // namespace webrtc

NS_ASSUME_NONNULL_END
