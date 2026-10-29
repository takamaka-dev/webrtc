/*
 * Takamaka E2EE calls (C182 / DR-055).
 *
 * The RFC 9605 SFrame transformer attached to one RtpSender or RtpReceiver. It is active from the moment it is
 * created — there is no enable switch and no pass-through: attach it BEFORE a track is set on the sender, so that no
 * frame ever leaves unsealed, and before a receiver's track is rendered.
 */

package org.webrtc;

public class SFrameCryptor {
  public enum MediaKind {
    AUDIO,
    VIDEO;
  }

  private long nativeCryptor;

  /** Attaches a sealing transformer to {@code sender}; frames are dropped until the store has a send KID. */
  public static SFrameCryptor createForRtpSender(
      RtpSender sender, SFrameKeyStore keyStore, MediaKind kind, String streamId) {
    return new SFrameCryptor(nativeCreateForRtpSender(
        sender.getNativeRtpSender(), keyStore.getNativeKeyStore(), kind.ordinal(), streamId));
  }

  /** Attaches an opening transformer to {@code receiver}; frames it cannot authenticate are dropped. */
  public static SFrameCryptor createForRtpReceiver(
      RtpReceiver receiver, SFrameKeyStore keyStore, MediaKind kind, String streamId) {
    return new SFrameCryptor(nativeCreateForRtpReceiver(
        receiver.getNativeRtpReceiver(), keyStore.getNativeKeyStore(), kind.ordinal(), streamId));
  }

  private SFrameCryptor(long nativeCryptor) {
    this.nativeCryptor = nativeCryptor;
  }

  /** This stream's counters (frames, passed, drops by reason, storm, last KID) as JSON. */
  public String getStatsJson() {
    checkExists();
    return nativeGetStatsJson(nativeCryptor);
  }

  /**
   * S-7: binds this receive transformer to {@code legIndex} (1..65535) or unbinds it ({@code legIndex} &lt; 0); see
   * {@link SFrameKeyStore#bindLeg}. False on a sender or a reserved index.
   */
  public boolean bindLeg(int legIndex) {
    checkExists();
    return nativeBindLeg(nativeCryptor, legIndex);
  }

  /**
   * Releases the Java handle. The transformer stays attached to its sender/receiver (WebRTC keeps a reference) and
   * keeps sealing/opening with its key store: disposing never turns encryption off.
   */
  public void dispose() {
    checkExists();
    JniCommon.nativeReleaseRef(nativeCryptor);
    nativeCryptor = 0;
  }

  private void checkExists() {
    if (nativeCryptor == 0) {
      throw new IllegalStateException("SFrameCryptor has been disposed.");
    }
  }

  private static native long nativeCreateForRtpSender(long rtpSender, long keyStore, int kind, String streamId);
  private static native long nativeCreateForRtpReceiver(long rtpReceiver, long keyStore, int kind, String streamId);
  private static native String nativeGetStatsJson(long cryptor);
  private static native boolean nativeBindLeg(long cryptor, int legIndex);
}
