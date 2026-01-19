// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.crypt;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.objects.XiKey;
import org.xipki.pkcs11.xihsm.objects.XiPrivateKey;
import org.xipki.pkcs11.xihsm.objects.XiPrivateOrSecretKey;
import org.xipki.pkcs11.xihsm.objects.XiPublicKey;
import org.xipki.pkcs11.xihsm.objects.XiSecretKey;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.OperationType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * @author Lijun Liao (xipki)
 */
public class MultiPartOperation {

  private final OperationType type;

  private final XiMechanism mechanism;

  private final XiKey key;

  private final SecureRandom rnd;

  private final ByteArrayOutputStream buffer;

  private boolean updated;

  public MultiPartOperation(OperationType type, XiKey key,
                            XiMechanism mechanism, SecureRandom rnd)
      throws HsmException {
    if (type == OperationType.DIGEST) {
      if (key != null) {
        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
            "key is not allowed for C_Digest");
      }
    } else {
      boolean keyMatch;
      if (type == OperationType.SIGN) {
        keyMatch = (key instanceof XiPrivateKey || key instanceof XiSecretKey);
      } else {
        keyMatch = (key instanceof XiPublicKey || key instanceof XiSecretKey);
      }

      if (!keyMatch) {
        throw new HsmException(
            PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
            type.getMethod() + " is not supported for the given key type " +
                key.getClass().getName());
      }
    }

    this.key = key;
    this.mechanism = mechanism;
    this.type = type;
    this.rnd = rnd;
    this.buffer = new ByteArrayOutputStream();
  }

  private void writeBuffer(byte[] data) throws HsmException {
    try {
      buffer.write(data);
    } catch (IOException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "error writing data to buffer", e);
    }
  }

  public OperationType getType() {
    return type;
  }

  public void update(byte[] part) throws HsmException {
    mechanism.assertUpdateSupported(type);
    updated = true;
    writeBuffer(part);
  }

  public byte[] doFinal(byte[] data) throws HsmException {
    assertNotUpdatedBefore();
    writeBuffer(data);
    return doFinal();
  }

  public byte[] doFinal() throws HsmException {
    byte[] data = buffer.toByteArray();

    switch (type) {
      case DIGEST:
        HashAlgo ha;
        long ckm = mechanism.getCkm();
        if (ckm == PKCS11T.CKM_SHA_1) {
          ha = HashAlgo.SHA1;
        } else if (ckm == PKCS11T.CKM_SHA224) {
          ha = HashAlgo.SHA224;
        } else if (ckm == PKCS11T.CKM_SHA256) {
          ha = HashAlgo.SHA256;
        } else if (ckm == PKCS11T.CKM_SHA384) {
          ha = HashAlgo.SHA384;
        } else if (ckm == PKCS11T.CKM_SHA512) {
          ha = HashAlgo.SHA512;
        } else if (ckm == PKCS11T.CKM_VENDOR_SM3) {
          ha = HashAlgo.SM3;
        } else {
          throw new HsmException(PKCS11T.CKR_MECHANISM_INVALID,
              "unsupported C_Digest algorithm " +
                  PKCS11T.ckmCodeToName(ckm));
        }
        return ha.hash(data);
      default:
        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
            "shall not reach here");
    }
  }

  public byte[] signFinal(byte[] data) throws HsmException {
    assertNotUpdatedBefore();
    writeBuffer(data);
    return signFinal();
  }

  public byte[] signFinal() throws HsmException {
    byte[] data = buffer.toByteArray();
    if (type != OperationType.SIGN) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "shall not reach here");
    }
    return ((XiPrivateOrSecretKey) key).sign(mechanism, data, rnd);
  }

  private void assertNotUpdatedBefore() throws HsmException {
    if (updated) {
      throw new HsmException(PKCS11T.CKR_OPERATION_NOT_INITIALIZED,
          type.getMethod() + "Update has been called before " +
          type.getMethod());
    }
  }

}
