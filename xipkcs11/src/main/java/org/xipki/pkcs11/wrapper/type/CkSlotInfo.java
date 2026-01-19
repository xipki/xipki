// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.type;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.jni.JniUtil;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Objects of this call provide information about a slot.
 *
 * <pre>
 * typedef struct CK_SLOT_INFO {
 *   CK_UTF8CHAR   slotDescription[64];  // blank padded
 *   CK_UTF8CHAR   manufacturerID[32];   // blank padded
 *   CK_FLAGS      flags;
 *   CK_VERSION    hardwareVersion;  // version of hardware
 *   CK_VERSION    firmwareVersion;  // version of firmware
 * } CK_SLOT_INFO;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CkSlotInfo extends AbstractInfo {

  /**
   * A short description of this slot.
   */
  private final String slotDescription;

  /**
   * A string identifying the manufacturer of this slot.
   */
  private final String manufacturerID;

  /**
   * The flags.
   */
  private final long flags;
  /**
   * The version of the slot's hardware.
   */
  private final CkVersion hardwareVersion;

  /**
   * The version of the slot's firmware.
   */
  private final CkVersion firmwareVersion;

  public CkSlotInfo(String slotDescription, String manufacturerID, long flags,
                    CkVersion hardwareVersion, CkVersion firmwareVersion) {
    this.slotDescription = slotDescription.trim();
    this.manufacturerID  = manufacturerID.trim();
    this.flags = flags;
    this.hardwareVersion = hardwareVersion;
    this.firmwareVersion = firmwareVersion;
  }

  /**
   * Get a short description of this slot.
   *
   * @return A string describing this slot.
   */
  public String slotDescription() {
    return slotDescription;
  }

  /**
   * Get an identifier for the manufacturer of this slot.
   *
   * @return A string identifying the manufacturer of this slot.
   */
  public String manufacturerID() {
    return manufacturerID;
  }

  /**
   * Get the version of the slot's hardware.
   *
   * @return The version of the hardware of this slot.
   */
  public CkVersion hardwareVersion() {
    return hardwareVersion;
  }

  /**
   * Get the version of the slot's firmware.
   *
   * @return The version of the firmware of this slot.
   */
  public CkVersion firmwareVersion() {
    return firmwareVersion;
  }

  /**
   * Indicates, if there is a token present in this slot. Notice, that this
   * refers to the time this object was created and not when this method is
   * invoked.
   *
   * @return True, if there is a (compatible) token in the slot. False,
   *         otherwise.
   */
  public boolean isTokenPresent() {
    return (flags & PKCS11T.CKF_TOKEN_PRESENT) != 0L;
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, "CK_SLOT_INFO", null,
      "slotDescription", slotDescription,
      "manufacturerID", manufacturerID, "hardwareVersion", hardwareVersion,
      "firmwareVersion", firmwareVersion) + "\n" +
      Functions.toStringFlags(Category.CKF_SLOT, indent + "Flags: ", flags,
          PKCS11T.CKF_TOKEN_PRESENT, PKCS11T.CKF_REMOVABLE_DEVICE,
          PKCS11T.CKF_HW_SLOT);
  }

  @Override
  protected EncodeList getEncodeList() {
    return new EncodeList().fixedLenV(JniUtil.padText(slotDescription, 64))
        .fixedLenV(JniUtil.padText(manufacturerID, 32))
        .v(flags).v(hardwareVersion).v(firmwareVersion);
  }

  public static CkSlotInfo decode(Arch arch, byte[] encoded) {
    AtomicInteger off = new AtomicInteger();
    String slotDescription = readFixedLenString(64, encoded, off);
    String manufacturerID  = readFixedLenString(32, encoded, off);
    long flags = readLong(arch, encoded, off);
    CkVersion hardwareVersion = readVersion(encoded, off);
    CkVersion firmwareVersion = readVersion(encoded, off);
    return new CkSlotInfo(slotDescription, manufacturerID, flags,
        hardwareVersion, firmwareVersion);
  }

}
