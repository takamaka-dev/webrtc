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
   * Transformer events (storm, recovered, resumed, dropping, engaged, first-pass, key-expired, key-evicted). Called
   * on a WebRTC media thread: return quickly, hand the event to your own thread.
   */
  public interface Observer {
    @CalledByNative("Observer")
    void onSFrameEvent(String type, String streamId, String reason, long kid, long consecutive);
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

  public void setObserver(@Nullable Observer observer) {
    checkExists();
    nativeSetObserver(nativeKeyStore, observer);
  }

  /** Counters of every live stream of this store, as a JSON array. */
  public String getStatsJson() {
    checkExists();
    return nativeGetStatsJson(nativeKeyStore);
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
  private static native void nativeSetObserver(long keyStore, @Nullable Observer observer);
  private static native String nativeGetStatsJson(long keyStore);
}
