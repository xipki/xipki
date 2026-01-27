// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.mgr;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.crypt.HashAlgo;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncoder;

import java.util.Arrays;

/**
 * @author Lijun Liao (xipki)
 */
public class User {

  private final long userType;

  private final byte[] salt;

  private final byte[] sha256;

  public User(long userType, byte[] salt, byte[] sha256) {
    this.userType = userType;
    this.salt = salt;
    this.sha256 = sha256;
  }

  public long getUserType() {
    return userType;
  }

  public void verify(byte[] pin) throws HsmException {
    byte[] hashValue = HashAlgo.SHA256.hash(salt, pin);
    if (!Arrays.equals(sha256, hashValue)) {
      throw new HsmException(PKCS11T.CKR_PIN_INCORRECT,
          "PIN incorrect");
    }
  }

  public void encodeTo(CborEncoder encoder) throws HsmException {
    try {
      encoder.writeArrayStart(3);
      encoder.writeLong(userType);
      encoder.writeByteString(salt);
      encoder.writeByteString(sha256);
    } catch (CodecException e) {
      throw HsmException.newGeneralError("error encoding User", e);
    }
  }

  public static User decode(CborDecoder decoder) throws HsmException {
    try {
      decoder.readArrayLength(3);
      long userType = decoder.readLong();
      byte[] salt = decoder.readByteString();
      byte[] sha256 = decoder.readByteString();
      return new User(userType, salt, sha256);
    } catch (CodecException e) {
      throw HsmException.newGeneralError("error encoding User", e);
    }
  }

}
