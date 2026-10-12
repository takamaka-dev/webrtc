/*
 * Takamaka E2EE calls (C182 / DR-055) — RTCSFrameCryptor: one SframeTransformer
 * attached to one RtpSender (seal) or RtpReceiver (open).
 */

#import "RTCSFrameCryptor.h"

#import "RTCRtpReceiver+Private.h"
#import "RTCRtpSender+Private.h"
#import "RTCSFrameKeyStore+Private.h"
#import "helpers/NSString+StdString.h"

#include "api/crypto/sframe_transformer.h"
#include "api/rtp_receiver_interface.h"
#include "api/rtp_sender_interface.h"

@implementation RTC_OBJC_TYPE (RTCSFrameCryptor) {
  webrtc::scoped_refptr<webrtc::SframeTransformer> _transformer;
}

@synthesize streamId = _streamId;
@synthesize mediaKind = _mediaKind;
@synthesize isSender = _isSender;

static webrtc::SframeMediaKind NativeKind(RTCSFrameMediaKind kind) {
  return kind == RTCSFrameMediaKindAudio ? webrtc::SframeMediaKind::kAudio
                                         : webrtc::SframeMediaKind::kVideo;
}

- (nullable instancetype)initWithRtpSender:(RTC_OBJC_TYPE(RTCRtpSender) *)sender
                                  keyStore:(RTC_OBJC_TYPE(RTCSFrameKeyStore) *)keyStore
                                 mediaKind:(RTCSFrameMediaKind)mediaKind
                                  streamId:(NSString *)streamId {
  self = [super init];
  if (self) {
    webrtc::scoped_refptr<webrtc::RtpSenderInterface> nativeSender = sender.nativeRtpSender;
    if (nativeSender == nullptr || keyStore == nil) {
      return nil;
    }
    _streamId = [streamId copy];
    _mediaKind = mediaKind;
    _isSender = YES;
    _transformer = webrtc::SframeTransformer::Create(keyStore.nativeKeyStore,
                                                     webrtc::SframeRole::kSender,
                                                     NativeKind(mediaKind),
                                                     [streamId stdString]);
    // The proxy marshals to the signaling thread (RtpSenderBase requires it).
    nativeSender->SetFrameTransformer(_transformer);
  }
  return self;
}

- (nullable instancetype)initWithRtpReceiver:(RTC_OBJC_TYPE(RTCRtpReceiver) *)receiver
                                    keyStore:(RTC_OBJC_TYPE(RTCSFrameKeyStore) *)keyStore
                                   mediaKind:(RTCSFrameMediaKind)mediaKind
                                    streamId:(NSString *)streamId {
  self = [super init];
  if (self) {
    webrtc::scoped_refptr<webrtc::RtpReceiverInterface> nativeReceiver = receiver.nativeRtpReceiver;
    if (nativeReceiver == nullptr || keyStore == nil) {
      return nil;
    }
    _streamId = [streamId copy];
    _mediaKind = mediaKind;
    _isSender = NO;
    _transformer = webrtc::SframeTransformer::Create(keyStore.nativeKeyStore,
                                                     webrtc::SframeRole::kReceiver,
                                                     NativeKind(mediaKind),
                                                     [streamId stdString]);
    nativeReceiver->SetFrameTransformer(_transformer);
  }
  return self;
}

- (NSString *)statsJson {
  return [NSString stringForStdString:webrtc::RTCSFrameStatsJson(_transformer->GetStats())];
}

@end
