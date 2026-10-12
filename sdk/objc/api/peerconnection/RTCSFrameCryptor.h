/*
 * Takamaka E2EE calls (C182 / DR-055) — attaches the RFC 9605 SFrame
 * transformer of an RTCSFrameKeyStore to one RTCRtpSender (seals) or one
 * RTCRtpReceiver (opens). Twin of the Android org.webrtc.SFrameCryptor.
 *
 * Active from creation: there is no enable switch and no pass-through. The
 * transformer stays attached to the sender/receiver for its life (WebRTC has no
 * detach); attaching another one replaces it.
 */

#import <Foundation/Foundation.h>

#import "RTCMacros.h"
#import "RTCSFrameKeyStore.h"

NS_ASSUME_NONNULL_BEGIN

@class RTC_OBJC_TYPE(RTCRtpSender);
@class RTC_OBJC_TYPE(RTCRtpReceiver);

RTC_OBJC_EXPORT
@interface RTC_OBJC_TYPE (RTCSFrameCryptor) : NSObject

@property(nonatomic, readonly) NSString *streamId;
@property(nonatomic, readonly) RTCSFrameMediaKind mediaKind;
/** YES for a sealing (sender) transformer, NO for an opening (receiver) one. */
@property(nonatomic, readonly) BOOL isSender;

- (instancetype)init NS_UNAVAILABLE;

- (nullable instancetype)initWithRtpSender:(RTC_OBJC_TYPE(RTCRtpSender) *)sender
                                  keyStore:(RTC_OBJC_TYPE(RTCSFrameKeyStore) *)keyStore
                                 mediaKind:(RTCSFrameMediaKind)mediaKind
                                  streamId:(NSString *)streamId;

- (nullable instancetype)initWithRtpReceiver:(RTC_OBJC_TYPE(RTCRtpReceiver) *)receiver
                                    keyStore:(RTC_OBJC_TYPE(RTCSFrameKeyStore) *)keyStore
                                   mediaKind:(RTCSFrameMediaKind)mediaKind
                                    streamId:(NSString *)streamId;

/** Counters of this stream as a JSON object. */
- (NSString *)statsJson;

@end

NS_ASSUME_NONNULL_END
