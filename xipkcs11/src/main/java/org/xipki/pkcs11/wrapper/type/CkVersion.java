// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.type;

import org.xipki.pkcs11.wrapper.PKCS11Module;

/**
 * Objects of this class represent a version. This consists of a major and a
 * minor version number.
 * <pre>
 * typedef struct CK_VERSION {
 *   CK_BYTE       major;  // integer portion of version number
 *   CK_BYTE       minor;  // 1/100ths portion of version number
 * } CK_VERSION;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CkVersion extends CkType {

  /**
   * The major version number.
   */
  private byte major;

  /**
   * The minor version number.
   */
  private byte minor;

  private int version;

  /**
   * Constructor for internal use only.
   *
   * @param major
   *        the major version
   * @param minor
   *        the minor version.
   */
  public CkVersion(byte major, byte minor) {
    setVersion(major, minor);
  }

  public void setVersion(byte major, byte minor) {
    this.major = major;
    this.minor = minor;
    this.version = ((0xFF & major) << 8) | (0xFF & minor);
  }

  public int version() {
    return version;
  }

  /**
   * Get the major version number.
   *
   * @return The major version number.
   */
  public byte major() {
    return major;
  }

  /**
   * Get the minor version number.
   *
   * @return The minor version number.
   */
  public byte minor() {
    return minor;
  }

  @Override
  public int hashCode() {
    return (0xFF & major) << 8 + (0xFF & minor);
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    } else if (!(other instanceof CkVersion)) {
      return false;
    }

    CkVersion b = (CkVersion) other;
    return major == b.major && minor == b.minor;
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return indent + "CK_VERSION: " + (major & 0xff) + "." + (minor & 0xff);
  }

}
