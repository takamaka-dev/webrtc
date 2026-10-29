/*
 * Takamaka E2EE calls (C182 / DR-055).
 *
 * The keys of one call for the RFC 9605 SFrame transformer (SFrameCryptor): suite 5 AES_256_GCM_SHA512,
 * KID = leg_index * 2^16 + (epoch mod 2^16), one CTR space per KID, a 128-frame replay window per KID, the storm
 * rule. Fail closed: no key, no send KID or an unknown KID means frames are DROPPED, never passed in clear.
 * A deliberately separate API from FrameCryptor/FrameCryptorKeyProvider (whose unknown values silently fall back to
 * the LiveKit cipher): on a binary without this class the call fails instead of running another cipher.
 */

package org.webrtc;

import androidx.annotation.Nullable;

public class SFrameKeyStore {
  /** Result of {@link #setKey}. */
  public enum SetKeyResult {
    /** New key material for the KID: fresh replay window, stormed receive streams resumed. */
    CHANGED,
    /** The same material was already installed: nothing changed. */
    UNCHANGED,
    /** Reserved KID (leg_index 0, or more than 16 bits) or a base key that is not 32 bytes. */
    INVALID;
  }

  /**
   * Transformer events (storm, recovered, resumed, dropping, engaged, first-pass, key-expired, key-evicted, held,
   * released). Called on a WebRTC media thread: return quickly, hand the event to your own thread. {@code count} =
   * the frames released (type {@code released}), else 0.
   */
  public interface Observer {
    @CalledByNative("Observer")
    void onSFrameEvent(String type, String streamId, String reason, long kid, long consecutive, long count);
  }

  private long nativeKeyStore;

  public static SFrameKeyStore create() {
    return new SFrameKeyStore(nativeCreate());
  }

  private SFrameKeyStore(long nativeKeyStore) {
    this.nativeKeyStore = nativeKeyStore;
  }

  /** Native pointer, for SFrameCryptor. */
  long getNativeKeyStore() {
    checkExists();
    return nativeKeyStore;
  }

  /** Installs the RFC 9605 key and salt of {@code kid} derived from {@code baseKey} (sender_base_e, 32 bytes). */
  public SetKeyResult setKey(long kid, byte[] baseKey) {
    checkExists();
    return SetKeyResult.values()[nativeSetKey(nativeKeyStore, kid, baseKey)];
  }

  public boolean removeKey(long kid) {
    checkExists();
    return nativeRemoveKey(nativeKeyStore, kid);
  }

  /** Keeps {@code kid} usable for {@code retentionMs} more milliseconds, then removes it. */
  public boolean retireKey(long kid, long retentionMs) {
    checkExists();
    return nativeRetireKey(nativeKeyStore, kid, retentionMs);
  }

  /** The KID every sender of this store seals under; false if no key is installed for it. */
  public boolean setSendKid(long kid) {
    checkExists();
    return nativeSetSendKid(nativeKeyStore, kid);
  }

  public void clearSendKid() {
    checkExists();
    nativeClearSendKid(nativeKeyStore);
  }

  /** The current send KID, or -1. */
  public long getSendKid() {
    checkExists();
    return nativeGetSendKid(nativeKeyStore);
  }

  public void setStormThreshold(int n) {
    checkExists();
    nativeSetStormThreshold(nativeKeyStore, n);
  }

  /** H.264 units (spec §9.2 fallback layout). Off by default: H.264 frames are dropped. */
  public void setH264Enabled(boolean enabled) {
    checkExists();
    nativeSetH264Enabled(nativeKeyStore, enabled);
  }

  /**
   * C-24 (spec §9.2 [0.3]): how long a receive VIDEO stream holds frames of a known leg's next epoch(s) while their
   * key is missing (default 10 s = the retention default); 0 turns holding off (such frames drop as unknown-kid).
   */
  public void setHoldTime(long holdMs) {
    checkExists();
    nativeSetHoldTime(nativeKeyStore, holdMs);
  }

  /**
   * S-7 (ruling Q1): when on, a receive stream opens frames only after {@link #bindLeg} gave it a leg, and only under
   * KIDs of that leg (kid >> 16); others drop as "unbound" / "wrong-leg" and count toward the storm (Q3). Off by
   * default (the pre-tkm.9 behaviour). Set once, at creation, before frames flow.
   */
  public void setRequireLegBinding(boolean required) {
    checkExists();
    nativeSetRequireLegBinding(nativeKeyStore, required);
  }

  /**
   * S-7: binds every receive stream labelled {@code streamId} to {@code legIndex} (1..65535), or unbinds it
   * ({@code legIndex} &lt; 0). A change drops the frames the stream holds and restarts its storm count. False if no
   * receive stream has that label or the index is reserved.
   */
  public boolean bindLeg(String streamId, int legIndex) {
    checkExists();
    return nativeBindLeg(nativeKeyStore, streamId, legIndex);
  }

  public void setObserver(@Nullable Observer observer) {
    checkExists();
    nativeSetObserver(nativeKeyStore, observer);
  }

  /** Counters of every live stream of this store, as a JSON array. */
  public String getStatsJson() {
    checkExists();
    return nativeGetStatsJson(nativeKeyStore);
  }

  /**
   * Vector check (no live key involved): seals ONE Opus/VP8-shaped unit with the transformer's own derivation and
   * AEAD, under the key of {@code kid} derived from {@code baseKey}, with an explicit {@code ctr}. Null on error.
   */
  @Nullable
  public static byte[] vectorSeal(byte[] baseKey, long kid, long ctr, byte[] frame, int prefixLen) {
    return nativeVectorSeal(baseKey, kid, ctr, frame, prefixLen);
  }

  /** Vector check: opens ONE unit sealed under {@code kid}/{@code baseKey}. Null on any failure (bad tag, other KID). */
  @Nullable
  public static byte[] vectorOpen(byte[] baseKey, long kid, byte[] unit, int prefixLen) {
    return nativeVectorOpen(baseKey, kid, unit, prefixLen);
  }

  public void dispose() {
    checkExists();
    nativeSetObserver(nativeKeyStore, null);
    JniCommon.nativeReleaseRef(nativeKeyStore);
    nativeKeyStore = 0;
  }

  private void checkExists() {
    if (nativeKeyStore == 0) {
      throw new IllegalStateException("SFrameKeyStore has been disposed.");
    }
  }

  private static native long nativeCreate();
  private static native int nativeSetKey(long keyStore, long kid, byte[] baseKey);
  private static native boolean nativeRemoveKey(long keyStore, long kid);
  private static native boolean nativeRetireKey(long keyStore, long kid, long retentionMs);
  private static native boolean nativeSetSendKid(long keyStore, long kid);
  private static native void nativeClearSendKid(long keyStore);
  private static native long nativeGetSendKid(long keyStore);
  private static native void nativeSetStormThreshold(long keyStore, int n);
  private static native void nativeSetH264Enabled(long keyStore, boolean enabled);
  private static native void nativeSetHoldTime(long keyStore, long holdMs);
  private static native void nativeSetRequireLegBinding(long keyStore, boolean required);
  private static native boolean nativeBindLeg(long keyStore, String streamId, int legIndex);
  private static native void nativeSetObserver(long keyStore, @Nullable Observer observer);
  private static native String nativeGetStatsJson(long keyStore);
  @Nullable
  private static native byte[] nativeVectorSeal(byte[] baseKey, long kid, long ctr, byte[] frame, int prefixLen);
  @Nullable
  private static native byte[] nativeVectorOpen(byte[] baseKey, long kid, byte[] unit, int prefixLen);
}
