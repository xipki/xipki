// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.type;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.jni.JniUtil;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Objects of this class provide information about a PKCS#11 module; i.e. the
 * driver for a specific token.
 *
 * <pre>
 * typedef struct CK_INFO {
 *   CK_VERSION    cryptokiVersion;        // Cryptoki interface ver
 *   CK_UTF8CHAR   manufacturerID[32];     // blank padded
 *   CK_FLAGS      flags;                  // must be zero
 *   CK_UTF8CHAR   libraryDescription[32]; // blank padded
 *   CK_VERSION    libraryVersion;         // version of library
 * } CK_INFO;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CkInfo extends AbstractInfo {

  /**
   * The module claims to be compliant to this version of PKCS#11.
   */
  private final CkVersion cryptokiVersion;

  /**
   * The identifier for the manufacturer of this module.
   */
  private final String manufacturerID;

  private final long flags;

  /**
   * A description of this module.
   */
  private final String libraryDescription;

  /**
   * The version number of this module.
   */
  private final CkVersion libraryVersion;

  public CkInfo(CkVersion cryptokiVersion, String manufacturerID, long flags,
                String libraryDescription, CkVersion libraryVersion) {
    this.cryptokiVersion = cryptokiVersion;
    this.manufacturerID = manufacturerID.trim();
    this.flags = flags;
    this.libraryDescription = libraryDescription.trim();
    this.libraryVersion = libraryVersion;
  }

  /**
   * Get the version of PKCS#11 that this module claims to be compliant to.
   *
   * @return The version object.
   */
  public CkVersion cryptokiVersion() {
    return cryptokiVersion;
  }

  /**
   * Get the identifier of the manufacturer.
   *
   * @return A string identifying the manufacturer of this module.
   */
  public String manufacturerID() {
    return manufacturerID;
  }

  /**
   * Get a short description of this module.
   *
   * @return A string describing the module.
   */
  public String libraryDescription() {
    return libraryDescription;
  }

  /**
   * Get the version of this PKCS#11 module.
   *
   * @return The version of this module.
   */
  public CkVersion libraryVersion() {
    return libraryVersion;
  }

  public long getFlags() {
    return flags;
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, "CK_INFO", null,
        "cryptokiVersion", cryptokiVersion,
        "manufacturerID", manufacturerID,
        "libraryDescription", libraryDescription,
        "libraryVersion", libraryVersion,
        "flags", "0x" + Functions.toFullHex(flags));
  }

  @Override
  protected EncodeList getEncodeList() {
    return new EncodeList().v(cryptokiVersion)
        .fixedLenV(JniUtil.padText(manufacturerID, 32)).v(flags)
        .fixedLenV(JniUtil.padText(libraryDescription, 32)).v(libraryVersion);
  }

  public static CkInfo decode(Arch arch, byte[] encoded) {
    AtomicInteger off = new AtomicInteger();
    CkVersion cryptokiVersion = readVersion(encoded, off);
    String manufacturerID = readFixedLenString(32, encoded, off);
    long flags = readLong(arch, encoded, off);
    String libraryDescription = readFixedLenString(32, encoded, off);
    CkVersion libraryVersion = readVersion(encoded, off);
    return new CkInfo(cryptokiVersion, manufacturerID, flags,
        libraryDescription, libraryVersion);
  }

}
