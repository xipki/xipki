// Copyright (c) 2013-2026 xipki. All rights reserved.
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
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class MultiPartOperation {

  private final OperationType type;

  private final XiMechanism mechanism;

  private final XiKey key;

  private final SecureRandom rnd;

  private final ByteArrayOutputStream buffer;

  public MultiPartOperation(OperationType type, XiKey key, XiMechanism mechanism, SecureRandom rnd)
      throws HsmException {
    if (type == OperationType.DIGEST) {
      if (key != null) {
        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "key is not allowed for C_Digest");
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
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error writing data to buffer", e);
    }
  }

  public OperationType type() {
    return type;
  }

  public void update(byte[] part) throws HsmException {
    mechanism.assertUpdateSupported(type);
    writeBuffer(part);
  }

  public byte[] signFinal() throws HsmException {
    byte[] data = buffer.toByteArray();
    if (type != OperationType.SIGN) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "shall not reach here");
    }
    return ((XiPrivateOrSecretKey) key).sign(mechanism, data, rnd);
  }

}
