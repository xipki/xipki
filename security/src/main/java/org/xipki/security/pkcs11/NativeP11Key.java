// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.params.ExtraParams;
import org.xipki.security.EdECConstants;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Args;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_EC_POINT;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_VALUE;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_DSA;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_EC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_EC_EDWARDS;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_EC_MONTGOMERY;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_RSA;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_VENDOR_SM2;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckkCodeToName;

/**
 * {@link P11Key} based on the ipkcs11wrapper or jpkcs11wrapper.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class NativeP11Key extends P11Key {

  NativeP11Key(NativeP11Slot slot, PKCS11KeyId keyId) {
    super(slot, keyId);
  }

  @Override
  protected byte[] digestSecretKey0(long mechanism) throws TokenException {
    if (!isSecretKey()) {
      throw new TokenException("digestSecretKey could not be applied to non-SecretKey");
    }

    return slot.digestSecretKey(mechanism, keyId.getHandle());
  }

  @Override
  public void destroy() throws TokenException {
    if (keyId.getPublicKeyHandle() == null) {
      slot.destroyObjectsByHandle(keyId.getHandle());
    } else {
      slot.destroyObjectsByHandle(keyId.getHandle(), keyId.getPublicKeyHandle());
    }
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content) throws TokenException {
    Args.notNull(content, "content");
    ExtraParams extraParams = null;
    if (ecOrderBitSize != null) {
      extraParams = new ExtraParams().ecOrderBitSize(ecOrderBitSize);
    }
    return slot.sign(mechanism, parameters, extraParams, keyId.getHandle(), content);
  }

  @Override
  protected PublicKey getPublicKey0() throws TokenException {
    long keyType = keyId.getKeyType();
    if (keyType == CKK_RSA) {
      try {
        return KeyUtil.generateRSAPublicKey(
            new RSAPublicKeySpec(rsaModulus, rsaPublicExponent));
      } catch (InvalidKeySpecException ex) {
        throw new TokenException(ex.getMessage(), ex);
      }
    }

    Long publicKeyHandle = keyId.getPublicKeyHandle();
    if (publicKeyHandle == null) {
      return null;
    }

    if (keyType == CKK_DSA) {
      AttributeVector attrs = ((NativeP11Slot) slot).getAttrValues(publicKeyHandle, CKA_VALUE);
      DSAPublicKeySpec keySpec = new DSAPublicKeySpec(
          new BigInteger(1, attrs.value()), dsaP, dsaQ, dsaG);
      try {
        return KeyUtil.generateDSAPublicKey(keySpec);
      } catch (InvalidKeySpecException ex) {
        throw new TokenException(ex.getMessage(), ex);
      }
    } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
        || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
      byte[] ecPoint = ((NativeP11Slot) slot).getAttrValues(publicKeyHandle, CKA_EC_POINT).ecPoint();
      ASN1ObjectIdentifier curveOid = ecParams;

      if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
        if (keyType == CKK_EC_EDWARDS) {
          if (!EdECConstants.isEdwardsCurve(curveOid)) {
            throw new TokenException("unknown Edwards curve OID " + curveOid);
          }
        } else {
          if (!EdECConstants.isMontgomeryCurve(curveOid)) {
            throw new TokenException("unknown Montgomery curve OID " + curveOid);
          }
        }
        SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(curveOid), ecPoint);
        try {
          return KeyUtil.generatePublicKey(pkInfo);
        } catch (InvalidKeySpecException ex) {
          throw new TokenException(ex.getMessage(), ex);
        }
      } else {
        try {
          return KeyUtil.createECPublicKey(curveOid, ecPoint);
        } catch (InvalidKeySpecException ex) {
          throw new TokenException(ex.getMessage(), ex);
        }
      }
    } else {
      throw new TokenException("unknown key type " + ckkCodeToName(keyType));
    }
  }

}
