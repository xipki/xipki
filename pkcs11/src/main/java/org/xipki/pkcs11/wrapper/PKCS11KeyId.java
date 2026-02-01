// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import java.util.Arrays;
import java.util.Objects;

/**
 * Identifier of a PKCS#11 key Object.
 *
 * @author Lijun Liao (xipki)
 */

public class PKCS11KeyId {

  private final long handle;

  private final long keyType;

  private final KeyIdType type;

  private final byte[] id;

  private final String idHex;

  private final String label;

  private Long publicKeyHandle;

  /**
   * Constructor.
   *
   * @param handle
   *        The object handle.
   * @param type
   *        The keyId type.
   * @param keyType
   *        The key type.
   * @param id
   *        Identifier. Cannot be null or zero-length if label is
   *        {@code null} or blank.
   * @param label
   *        Label. Cannot be {@code null} and blank if id is null or
   *        zero-length.
   */
  public PKCS11KeyId(KeyIdType type, long handle, long keyType,
                     byte[] id, String label) {
    this.type = type;
    this.handle = handle;
    this.keyType = keyType;
    if (id == null || id.length == 0) {
      this.id = null;
      this.idHex = null;
    } else {
      this.id = id;
      this.idHex = Functions.toHex(id);
    }
    this.label = label;
  }

  public long getKeyType() {
    return keyType;
  }

  public KeyIdType type() {
    return type;
  }

  public long getHandle() {
    return handle;
  }

  public long[] getAllHandles() {
    return publicKeyHandle == null ? new long[]{handle}
        : new long[] {handle, publicKeyHandle};
  }

  public byte[] getId() {
    return id;
  }

  public String getIdHex() {
    return idHex;
  }

  public String getLabel() {
    return label;
  }

  public Long getPublicKeyHandle() {
    return publicKeyHandle;
  }

  public void setPublicKeyHandle(Long publicKeyHandle) {
    this.publicKeyHandle = publicKeyHandle;
  }

  @Override
  public String toString() {
    return String.format("(handle=%d, id=%s, label=%s)", handle, idHex, label);
  }

  @Override
  public int hashCode() {
    return (int) handle;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    else if (!(obj instanceof PKCS11KeyId)) return false;

    PKCS11KeyId other = (PKCS11KeyId) obj;
    return handle == other.handle
        && Arrays.equals(id, other.id)
        && Objects.equals(label, other.label);
  }

  public enum KeyIdType {
    SECRET_KEY,
    PRIVATE_KEY,
    PUBLIC_KEY,
    KEYPAIR
  }

}
