// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.type;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.jni.JniUtil;

import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * TokenInfo.
 * <pre>
 * typedef struct CK_TOKEN_INFO {
 *   CK_UTF8CHAR   label[32];           // blank padded
 *   CK_UTF8CHAR   manufacturerID[32];  // blank padded
 *   CK_UTF8CHAR   model[16];           // blank padded
 *   CK_CHAR       serialNumber[16];    // blank padded
 *   CK_FLAGS      flags;               // see below
 *   CK_ULONG      ulMaxSessionCount;     // max open sessions
 *   CK_ULONG      ulSessionCount;        // sess. now open
 *   CK_ULONG      ulMaxRwSessionCount;   // max R/W sessions
 *   CK_ULONG      ulRwSessionCount;      // R/W sess. now open
 *   CK_ULONG      ulMaxPinLen;           // in bytes
 *   CK_ULONG      ulMinPinLen;           // in bytes
 *   CK_ULONG      ulTotalPublicMemory;   // in bytes
 *   CK_ULONG      ulFreePublicMemory;    // in bytes
 *   CK_ULONG      ulTotalPrivateMemory;  // in bytes
 *   CK_ULONG      ulFreePrivateMemory;   // in bytes
 *   CK_VERSION    hardwareVersion;       // version of hardware
 *   CK_VERSION    firmwareVersion;       // version of firmware
 *   CK_CHAR       utcTime[16];           // time
 * } CK_TOKEN_INFO;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CkTokenInfo extends AbstractInfo {

  private final String label; /* blank padded */

  private final String manufacturerID; /* blank padded */

  private final String model; /* blank padded */

  private final String serialNumber; /* blank padded */

  private final long flags; /* see below */

  private final long maxSessionCount; /* max open sessions */

  private final long sessionCount; /* session now open */

  private final long maxRwSessionCount; /* max R/W sessions */

  private final long rwSessionCount; /* R/W session now open */

  private final long maxPinLen; /* in bytes */

  private final long minPinLen; /* in bytes */

  private final long totalPublicMemory; /* in bytes */

  private final long freePublicMemory; /* in bytes */

  private final long totalPrivateMemory; /* in bytes */

  private final long freePrivateMemory; /* in bytes */

  private final CkVersion hardwareVersion; /* version of hardware */

  private final CkVersion firmwareVersion; /* version of firmware */

  /**
   * The current time on the token. This value only makes sense, if the token
   * contains a clock.
   */
  private final String utcTime;

  public CkTokenInfo(String label, String manufacturerID,
                     String model, String serialNumber, long flags,
                     long maxSessionCount, long sessionCount,
                     long maxRwSessionCount, long rwSessionCount,
                     long maxPinLen, long minPinLen,
                     long totalPublicMemory, long freePublicMemory,
                     long totalPrivateMemory, long freePrivateMemory,
                     CkVersion hardwareVersion, CkVersion firmwareVersion,
                     String utcTime) {
    this.label = label;
    this.manufacturerID = manufacturerID.trim();
    this.model = model.trim();
    this.serialNumber = serialNumber.trim();
    this.flags = flags;
    this.maxSessionCount = maxSessionCount;
    this.sessionCount = sessionCount;
    this.maxRwSessionCount = maxRwSessionCount;
    this.rwSessionCount = rwSessionCount;
    this.maxPinLen = maxPinLen;
    this.minPinLen = minPinLen;
    this.totalPublicMemory = totalPublicMemory;
    this.freePublicMemory = freePublicMemory;
    this.totalPrivateMemory = totalPrivateMemory;
    this.freePrivateMemory = freePrivateMemory;
    this.hardwareVersion = hardwareVersion;
    this.firmwareVersion = firmwareVersion;
    this.utcTime = utcTime;
  }

  /**
   * Get the label of this token.
   *
   * @return The label of this token.
   */
  public String label() {
    return label;
  }

  /**
   * Get the manufacturer identifier.
   *
   * @return A string identifying the manufacturer of this token.
   */
  public String manufacturerID() {
    return manufacturerID;
  }

  /**
   * Get the model of this token.
   *
   * @return A string specifying the model of this token.
   */
  public String model() {
    return model;
  }

  /**
   * Get the serial number of this token.
   *
   * @return A string holding the serial number of this token.
   */
  public String serialNumber() {
    return serialNumber;
  }

  /**
   * Get the maximum allowed number of (open) concurrent sessions.
   *
   * @return The maximum allowed number of (open) concurrent sessions.
   */
  public long maxSessionCount() {
    return maxSessionCount;
  }

  /**
   * Get the current number of open sessions.
   *
   * @return The current number of open sessions.
   */
  public long sessionCount() {
    return sessionCount;
  }

  /**
   * Get the maximum allowed number of (open) concurrent read-write sessions.
   *
   * @return The maximum allowed number of (open) concurrent read-write
   *         sessions.
   */
  public long maxRwSessionCount() {
    return maxRwSessionCount;
  }

  /**
   * Get the current number of open read-write sessions.
   *
   * @return The current number of open read-write sessions.
   */
  public long rwSessionCount() {
    return rwSessionCount;
  }

  /**
   * Get the maximum length for the PIN.
   *
   * @return The maximum length for the PIN.
   */
  public long maxPinLen() {
    return maxPinLen;
  }

  /**
   * Get the minimum length for the PIN.
   *
   * @return The minimum length for the PIN.
   */
  public long minPinLen() {
    return minPinLen;
  }

  /**
   * Get the total amount of memory for public objects.
   *
   * @return The total amount of memory for public objects.
   */
  public long totalPublicMemory() {
    return totalPublicMemory;
  }

  /**
   * Get the amount of free memory for public objects.
   *
   * @return The amount of free memory for public objects.
   */
  public long freePublicMemory() {
    return freePublicMemory;
  }

  /**
   * Get the total amount of memory for private objects.
   *
   * @return The total amount of memory for private objects.
   */
  public long totalPrivateMemory() {
    return totalPrivateMemory;
  }

  /**
   * Get the amount of free memory for private objects.
   *
   * @return The amount of free memory for private objects.
   */
  public long freePrivateMemory() {
    return freePrivateMemory;
  }

  /**
   * Get the version of the token's hardware.
   *
   * @return The version of the token's hardware.
   */
  public CkVersion hardwareVersion() {
    return hardwareVersion;
  }

  /**
   * Get the version of the token's firmware.
   *
   * @return The version of the token's firmware.
   */
  public CkVersion firmwareVersion() {
    return firmwareVersion;
  }

  /**
   * Get the current time of the token's clock. This value does only make
   * sense if the token has a clock. Remind that, this is the time this object
   * was created and not the time the application called this method.
   *
   * @return The current time on the token's clock.
   */
  public String utcTime() {
    return utcTime;
  }

  /**
   * Return the token flags.
   * @return the token flags.
   */
  public long getFlags() {
    return flags;
  }

  public boolean hasFlagBit(long flagMask) {
    return (flags & flagMask) != 0L;
  }

  public boolean isProtectedAuthenticationPath() {
    return hasFlagBit(CKF_PROTECTED_AUTHENTICATION_PATH);
  }

  public boolean isLoginRequired() {
    return hasFlagBit(CKF_LOGIN_REQUIRED);
  }

  public boolean isTokenInitialized() {
    return hasFlagBit(CKF_TOKEN_INITIALIZED);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    final String ni = "\n" + indent + "  ";
    String text = indent + "  Label:           " + label +
        ni + "Manufacturer ID: " + manufacturerID +
        ni + "Model:           " + model +
        ni + "Serial Number:   " + serialNumber +
        ni + "PIN Length:      [" + minPinLen + ", " + maxPinLen + "]" +
        ni + "utcTime:         " + utcTime +
        ni + "Versions:        [Hardware: " + hardwareVersion +
            ", Firmware: " + firmwareVersion + "]" +
        ni + "Session Counts:  [#: " + ct(sessionCount) +
            ", #Max: "   + mct(maxSessionCount) +
            ", #Max RW: " + mct(maxRwSessionCount) +
            ", #RW: "    + ct(rwSessionCount) + "]" +
        ni + "Memories:        [Total Private: " + ct(totalPrivateMemory) +
            ", Free Private: " + ct(freePrivateMemory) +
            ", Total Public: " + ct(totalPublicMemory) +
            ", Free Public: " + ct(freePublicMemory) + "]";

    return indent + "CK_TOKEN_INFO:\n" +
        text + "\n" + Functions.toStringFlags(Category.CKF_TOKEN,
        indent + "  Flags: ", flags,
        CKF_RNG,                      CKF_WRITE_PROTECTED,
        CKF_LOGIN_REQUIRED,           CKF_RESTORE_KEY_NOT_NEEDED,
        CKF_CLOCK_ON_TOKEN,           CKF_PROTECTED_AUTHENTICATION_PATH,
        CKF_DUAL_CRYPTO_OPERATIONS,   CKF_TOKEN_INITIALIZED,
        CKF_SECONDARY_AUTHENTICATION, CKF_USER_PIN_INITIALIZED,
        CKF_USER_PIN_COUNT_LOW,       CKF_USER_PIN_FINAL_TRY,
        CKF_USER_PIN_LOCKED,          CKF_USER_PIN_TO_BE_CHANGED,
        CKF_SO_PIN_COUNT_LOW,         CKF_SO_PIN_FINAL_TRY,
        CKF_SO_PIN_LOCKED,            CKF_SO_PIN_TO_BE_CHANGED);
  }

  private static String mct(long count) {
    return isUnavailableInformation(count) ? "N/A"
        : (count == CK_EFFECTIVELY_INFINITE) ? "unlimited"
        : Long.toString(count);
  }

  private static String ct(long count) {
    return isUnavailableInformation(count) ? "N/A" : Long.toString(count);
  }

  @Override
  protected EncodeList getEncodeList() {
    return new EncodeList().fixedLenV(JniUtil.padText(label, 32))
        .fixedLenV(JniUtil.padText(manufacturerID, 32))
        .fixedLenV(JniUtil.padText(model, 16))
        .fixedLenV(JniUtil.padText(serialNumber, 16))
        .v(flags).v(maxSessionCount).v(sessionCount)
        .v(maxRwSessionCount).v(rwSessionCount).v(maxPinLen).v(minPinLen)
        .v(totalPublicMemory).v(freePublicMemory)
        .v(totalPrivateMemory).v(freePrivateMemory)
        .v(hardwareVersion).v(firmwareVersion)
        .fixedLenV(JniUtil.padText(utcTime, 16));
  }

  public static CkTokenInfo decode(Arch arch, byte[] encoded) {
    AtomicInteger off = new AtomicInteger();
    return new CkTokenInfo(
        readFixedLenString(32, encoded, off),
        readFixedLenString(32, encoded, off),
        readFixedLenString(16, encoded, off),
        readFixedLenString(16, encoded, off),
        readLong(arch, encoded, off), readLong(arch, encoded, off),
        readLong(arch, encoded, off), readLong(arch, encoded, off),
        readLong(arch, encoded, off), readLong(arch, encoded, off),
        readLong(arch, encoded, off), readLong(arch, encoded, off),
        readLong(arch, encoded, off), readLong(arch, encoded, off),
        readLong(arch, encoded, off),
        readVersion(encoded, off),    readVersion(encoded, off),
        readFixedLenString(16, encoded, off)
    );
  }

}
