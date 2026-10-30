/*
 * Takamaka E2EE calls (C182 / DR-055) — the iOS/macOS API of the RFC 9605
 * SFrame transformer (api/crypto/sframe_transformer.h). Twin of the Android
 * org.webrtc.SFrameKeyStore: suite 5 AES_256_GCM_SHA512, KID = leg_index *
 * 2^16 + (epoch mod 2^16), one CTR space per KID, a 128-frame replay window
 * per KID, the storm rule. Fail closed: no key, no send KID or an unknown KID
 * means frames are DROPPED, never passed in clear.
 *
 * A deliberately separate API from RTCFrameCryptor / RTCFrameCryptorKeyProvider
 * (whose unknown values fall back to the LiveKit cipher): on a framework
 * without these classes the lookup fails instead of running another cipher.
 * No key byte is ever returned or logged.
 */

#import <Foundation/Foundation.h>

#import "RTCMacros.h"

NS_ASSUME_NONNULL_BEGIN

@class RTC_OBJC_TYPE(RTCSFrameKeyStore);

/** Result of -setKey:baseKey: (same order as the Android SetKeyResult). */
typedef NS_ENUM(NSInteger, RTCSFrameSetKeyResult) {
  /** New key material for the KID: fresh replay window, stormed streams resumed. */
  RTCSFrameSetKeyResultChanged = 0,
  /** The same material was already installed: nothing changed. */
  RTCSFrameSetKeyResultUnchanged = 1,
  /** Reserved KID (leg_index 0, or >= 2^32) or a base key that is not 32 bytes. */
  RTCSFrameSetKeyResultInvalid = 2,
};

/** Media kind of a transformer: explicit, a sender may still have no track. */
typedef NS_ENUM(NSInteger, RTCSFrameMediaKind) {
  RTCSFrameMediaKindAudio = 0,
  RTCSFrameMediaKindVideo = 1,
};

/**
 * Transformer events (engaged, first-pass, dropping, storm, recovered, resumed,
 * key-expired, key-evicted, held, released). Called on a WebRTC media thread
 * with no lock held: return quickly, hand the event to your own queue. `count`
 * = the frames released (type `released`), else 0.
 */
RTC_OBJC_EXPORT
@protocol RTC_OBJC_TYPE(RTCSFrameKeyStoreDelegate)<NSObject>
- (void)sframeKeyStore:(RTC_OBJC_TYPE(RTCSFrameKeyStore) *)keyStore
      didEventWithType:(NSString *)type
              streamId:(NSString *)streamId
                reason:(NSString *)reason
                   kid:(int64_t)kid
           consecutive:(int64_t)consecutive
                 count:(int64_t)count;
@end

/** The keys of one call; shared by every RTCSFrameCryptor of that call. */
RTC_OBJC_EXPORT
@interface RTC_OBJC_TYPE (RTCSFrameKeyStore) : NSObject

@property(nonatomic, weak, nullable) id<RTC_OBJC_TYPE(RTCSFrameKeyStoreDelegate)> delegate;

- (instancetype)init NS_DESIGNATED_INITIALIZER;

/** Installs the RFC 9605 key and salt of `kid` derived from `baseKey` (sender_base_e, 32 bytes). */
- (RTCSFrameSetKeyResult)setKey:(int64_t)kid baseKey:(NSData *)baseKey;

- (BOOL)removeKey:(int64_t)kid;

/** Keeps `kid` usable for `retentionMs` more milliseconds, then removes it. */
- (BOOL)retireKey:(int64_t)kid retentionMs:(int64_t)retentionMs;

/** The KID every sender of this store seals under; NO if no key is installed for it. */
- (BOOL)setSendKid:(int64_t)kid;

- (void)clearSendKid;

/** The current send KID, or -1. */
- (int64_t)sendKid;

- (void)setStormThreshold:(int)threshold;

/**
 * C-24 (spec §9.2 [0.3]): how long a receive VIDEO stream holds frames of a known leg's next epoch(s) while their
 * key is missing (default 10 s = the retention default); 0 turns holding off (such frames drop as unknown-kid).
 */
- (void)setHoldTimeMs:(int64_t)holdMs;

/** H.264 units (spec §9.2 fallback layout). Off by default: H.264 frames are dropped. */
- (void)setH264Enabled:(BOOL)enabled;

/**
 * S-7 (ruling Q1): when YES, a receive stream opens frames only after -bindLeg:streamId: gave it a leg, and only
 * under KIDs of that leg (kid >> 16); others drop as "unbound" / "wrong-leg" and count toward the storm (Q3). YES by
 * default since tkm.10 (Iris §7.117 item 2, ruling R2) and a one-way latch: `setRequireLegBinding:NO` is ignored once
 * the flag is on — so, with the default, always; `YES` is a no-op kept for the callers of tkm.9. Independently of the
 * flag, a stream that was ever bound treats a later unbind as closed ("unbound"), never as "open any KID".
 */
- (void)setRequireLegBinding:(BOOL)required;

/**
 * S-7: binds every receive stream labelled `streamId` to `legIndex` (1..65535), or unbinds it (`legIndex` < 0). A
 * change drops the frames the stream holds and restarts its storm count. NO if no receive stream has that label or
 * the index is reserved.
 */
- (BOOL)bindLeg:(NSInteger)legIndex streamId:(NSString *)streamId;

/** Counters of every live stream of this store, as a JSON array. */
- (NSString *)statsJson;

/**
 * Vector check (no live key involved): seals ONE Opus/VP8-shaped unit with the
 * transformer's own derivation and AEAD under the key of `kid` derived from
 * `baseKey`, with an explicit `ctr`. nil on error.
 */
+ (nullable NSData *)vectorSealWithBaseKey:(NSData *)baseKey
                                       kid:(int64_t)kid
                                       ctr:(int64_t)ctr
                                     frame:(NSData *)frame
                              prefixLength:(NSInteger)prefixLength;

/** Vector check: opens ONE unit sealed under `kid`/`baseKey`. nil on any failure. */
+ (nullable NSData *)vectorOpenWithBaseKey:(NSData *)baseKey
                                       kid:(int64_t)kid
                                      unit:(NSData *)unit
                              prefixLength:(NSInteger)prefixLength;

@end

NS_ASSUME_NONNULL_END
