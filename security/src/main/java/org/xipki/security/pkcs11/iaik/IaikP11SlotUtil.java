/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs11.iaik;

import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.AttributeVector;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.OpaqueParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11Slot.P11KeyUsage;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;
import static org.xipki.security.pkcs11.P11Slot.getDescription;
import static org.xipki.util.CollectionUtil.isEmpty;
import static org.xipki.util.CollectionUtil.isNotEmpty;

/**
 * IAIK PKCS#11 wrapper util.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
class IaikP11SlotUtil {

  private static final Logger LOG = LoggerFactory.getLogger(IaikP11SlotUtil.class);

  static void singleLogin(Session session, long userType, char[] pin) throws P11TokenException {
    char[] tmpPin = pin;
    // some driver does not accept null PIN
    if (pin == null) {
      tmpPin = new char[]{};
    }

    String userTypeText = Functions.getUserTypeName(userType);
    try {
      session.login(userType, tmpPin);
      LOG.info("login successful as user " + userTypeText);
    } catch (TokenException ex) {
      // 0x100: user already logged in
      if (ex instanceof PKCS11Exception && ((PKCS11Exception) ex).getErrorCode() == CKR_USER_ALREADY_LOGGED_IN) {
        LOG.info("user already logged in");
      } else {
        LOG.info("login failed as user " + userTypeText);
        throw new P11TokenException("login failed as user " + userTypeText + ": " + ex.getMessage(), ex);
      }
    }
  } // method singleLogin

  static byte[] digestKey(Session session, int digestLen, Mechanism mechanism, long hKey)
      throws TokenException {
    session.digestInit(mechanism);
    session.digestKey(hKey);
    byte[] digest = new byte[digestLen];
    session.digestFinal(digest, 0, digestLen);
    return digest;
  } // method digestKey0

  static Mechanism getMechanism(long mechanism, P11Params parameters) throws P11TokenException {
    Mechanism ret = Mechanism.get(mechanism);
    if (parameters == null) {
      return ret;
    }

    Parameters paramObj;
    if (parameters instanceof P11Params.P11RSAPkcsPssParams) {
      P11Params.P11RSAPkcsPssParams param = (P11Params.P11RSAPkcsPssParams) parameters;
      paramObj = new RSAPkcsPssParameters(param.getHashAlgorithm(),
                    param.getMaskGenerationFunction(), param.getSaltLength());
    } else if (parameters instanceof P11Params.P11ByteArrayParams) {
      paramObj = new OpaqueParameters(((P11Params.P11ByteArrayParams) parameters).getBytes());
    } else if (parameters instanceof P11Params.P11IVParams) {
      paramObj = new InitializationVectorParameters(((P11Params.P11IVParams) parameters).getIV());
    } else {
      throw new P11TokenException("unknown P11Parameters " + parameters.getClass().getName());
    }

    ret.setParameters(paramObj);

    return ret;
  } // method getMechanism

  static Long getCertificateObject(Session session, byte[] keyId, char[] keyLabel)
      throws P11TokenException {
    List<Long> certs = getCertificateObjects(session, keyId, keyLabel);

    if (certs == null || certs.isEmpty()) {
      LOG.info("found no certificate identified by {}", getDescription(keyId, keyLabel));
      return null;
    }

    int size = certs.size();
    if (size > 1) {
      LOG.warn("found {} public key identified by {}, use the first one", size, getDescription(keyId, keyLabel));
    }

    return certs.get(0);
  } // method getCertificateObject

  static boolean checkSessionLoggedIn(Session session, long userType) throws P11TokenException {
    SessionInfo info;
    try {
      info = session.getSessionInfo();
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    if (LOG.isTraceEnabled()) {
      LOG.debug("SessionInfo: {}", info);
    }

    State state = info.getState();
    long deviceError = info.getDeviceError();

    LOG.debug("to be verified PKCS11Module: state = {}, deviceError: {}", state, deviceError);
    if (deviceError != 0) {
      LOG.error("deviceError {}", deviceError);
      return false;
    }

    boolean sessionLoggedIn;
    if (userType == PKCS11Constants.CKU_SO) {
      sessionLoggedIn = state.equals(State.RW_SO_FUNCTIONS);
    } else {
      sessionLoggedIn = state.equals(State.RW_USER_FUNCTIONS) || state.equals(State.RO_USER_FUNCTIONS);
    }

    LOG.debug("sessionLoggedIn: {}", sessionLoggedIn);
    return sessionLoggedIn;
  } // method checkSessionLoggedIn

  static List<Long> getObjects(Session session, AttributeVector template) throws P11TokenException {
    return getObjects(session, template, 9999);
  }

  static List<Long> getObjects(Session session, Attribute... attributes) throws P11TokenException {
    return getObjects(session, new AttributeVector(attributes), 9999);
  }

  static List<Long> getObjects(Session session, AttributeVector template, int maxNo)
      throws P11TokenException {
    List<Long> objList = new LinkedList<>();

    boolean initialized = false;

    try {
      session.findObjectsInit(template);
      initialized = true;

      while (objList.size() < maxNo) {
        int maxObjectCount = Math.min(maxNo - objList.size(), 100);
        long[] foundObjectHandles = session.findObjects(maxObjectCount);
        if (foundObjectHandles == null || foundObjectHandles.length == 0) {
          break;
        }

        for (long hObject : foundObjectHandles) {
          objList.add(hObject);
        }
      }
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    } finally {
      if (initialized) {
        try {
          session.findObjectsFinal();
        } catch (Exception ex) {
          LogUtil.error(LOG, ex, "session.findObjectsFinal() failed");
        }
      }
    }

    return objList;
  } // method getObjects

  static java.security.PublicKey generatePublicKey(Session session, long hP11Key, long keyType)
      throws XiSecurityException {
    try {
      if (keyType == CKK_RSA) {
        byte[][] attrValues = session.getByteArrayAttributeValues(hP11Key, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
        return buildRSAKey(asUnsignedBigInt(attrValues[0]), asUnsignedBigInt(attrValues[1]));
      } else if (keyType == CKK_DSA) {
        byte[][] attrValues = session.getByteArrayAttributeValues(hP11Key,
            CKA_VALUE, CKA_PRIME, CKA_SUBPRIME, CKA_BASE);

        DSAPublicKeySpec keySpec = new DSAPublicKeySpec(asUnsignedBigInt(attrValues[0]),
            asUnsignedBigInt(attrValues[1]), asUnsignedBigInt(attrValues[2]), asUnsignedBigInt(attrValues[3]));
        try {
          return KeyUtil.generateDSAPublicKey(keySpec);
        } catch (InvalidKeySpecException ex) {
          throw new XiSecurityException(ex.getMessage(), ex);
        }
      } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
          || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
        byte[][] attrValues = session.getByteArrayAttributeValues(hP11Key, CKA_EC_PARAMS, CKA_EC_POINT);

        byte[] ecParameters = attrValues[0];
        byte[] ecPoint = attrValues[1];

        byte[] encodedPoint = null;
        if (keyType == CKM_VENDOR_SM2) {
          if (ecParameters == null) {
            // some HSM does not return ECParameters
            // GMObjectIdentifiers.sm2p256v1.getEncoded()
            ecParameters = Hex.decode("06082a811ccf5501822d");
          }
        }

        ASN1ObjectIdentifier curveOid = ASN1ObjectIdentifier.getInstance(ecParameters);

        // some HSM does not return the standard conform ECPoint
        if (keyType == CKK_VENDOR_SM2 || keyType == CKK_EC) {
          int coordSize;
          if (GMObjectIdentifiers.sm2p256v1.equals(curveOid)
              || SECObjectIdentifiers.secp256r1.equals(curveOid)
              || TeleTrusTObjectIdentifiers.brainpoolP256r1.equals(curveOid)) {
            coordSize = 32;
          } else if (SECObjectIdentifiers.secp384r1.equals(curveOid)
              || TeleTrusTObjectIdentifiers.brainpoolP384r1.equals(curveOid)) {
            coordSize = 48;
          } else if (SECObjectIdentifiers.secp521r1.equals(curveOid)) {
            coordSize = 66;
          } else if (TeleTrusTObjectIdentifiers.brainpoolP512r1.equals(curveOid)) {
            coordSize = 64;
          } else {
            throw new XiSecurityException("unknown curve " + curveOid.getId());
          }

          if (ecPoint.length == 2 * coordSize) {
            // just return x_coord. || y_coord.
            encodedPoint = new byte[1 + 2 * coordSize];
            encodedPoint[0] = 4;
            System.arraycopy(ecPoint, 0, encodedPoint, 1, ecPoint.length);
          } else if (ecPoint.length == 1 + 2 * coordSize) {
            encodedPoint = ecPoint;
          }
        }

        if (encodedPoint == null) {
          encodedPoint = DEROctetString.getInstance(ecPoint).getOctets();
        }

        if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
          if (keyType == CKK_EC_EDWARDS) {
            if (!EdECConstants.isEdwardsCurve(curveOid)) {
              throw new XiSecurityException("unknown Edwards curve OID " + curveOid);
            }
          } else {
            if (!EdECConstants.isMontgomeryCurve(curveOid)) {
              throw new XiSecurityException("unknown Montgomery curve OID " + curveOid);
            }
          }
          SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(curveOid), encodedPoint);
          try {
            return KeyUtil.generatePublicKey(pkInfo);
          } catch (InvalidKeySpecException ex) {
            throw new XiSecurityException(ex.getMessage(), ex);
          }
        } else {
          try {
            return KeyUtil.createECPublicKey(ecParameters, encodedPoint);
          } catch (InvalidKeySpecException ex) {
            throw new XiSecurityException(ex.getMessage(), ex);
          }
        }
      } else {
        throw new XiSecurityException("unknown publicKey type " + Functions.getKeyTypeName(keyType));
      }
    } catch (PKCS11Exception ex) {
      throw new XiSecurityException("error reading PKCS#11 attribute values", ex);
    }
  } // method generatePublicKey

  static java.security.interfaces.RSAPublicKey buildRSAKey(BigInteger mod, BigInteger exp)
      throws XiSecurityException {
    try {
      return KeyUtil.generateRSAPublicKey(new RSAPublicKeySpec(mod, exp));
    } catch (InvalidKeySpecException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  }

  static X509Cert parseCert(byte[] certValue) throws P11TokenException {
    try {
      return X509Util.parseCert(certValue);
    } catch (CertificateException ex) {
      throw new P11TokenException("could not parse certificate: " + ex.getMessage(), ex);
    }
  } // method parseCert

  static List<Long> getAllCertificateObjects(Session session) throws P11TokenException {
    return getObjects(session, newX509Cert());
  } // method getAllCertificateObjects

  static int removeObjects0(Session session, AttributeVector template, String desc) throws P11TokenException {
    try {
      List<Long> objects = getObjects(session, template);
      for (Long obj : objects) {
        session.destroyObject(obj);
      }
      return objects.size();
    } catch (TokenException ex) {
      LogUtil.error(LOG, ex, "could not remove " + desc);
      throw new P11TokenException(ex.getMessage(), ex);
    }
  } // method removeObjects

  static void setKeyAttributes(P11NewKeyControl control, AttributeVector template, char[] label) {
    template.attr(CKA_TOKEN, true);
    if (label != null) {
      template.attr(CKA_LABEL, label);
    }

    if (control.getExtractable() != null) {
      template.attr(CKA_EXTRACTABLE, control.getExtractable());
    }

    if (control.getSensitive() != null) {
      template.attr(CKA_SENSITIVE, control.getSensitive());
    }

    Set<P11KeyUsage> usages = control.getUsages();
    if (isNotEmpty(usages)) {
      for (P11KeyUsage usage : usages) {
        template.attr(usage.getAttributeType(), true);
      }
    }
  }

  static List<Long> getCertificateObjectsForId(Session session, byte[] keyId) throws P11TokenException {
    return getCertificateObjects0(session, keyId, true, null);
  }

  static List<Long> getCertificateObjects(Session session, byte[] keyId, char[] keyLabel) throws P11TokenException {
    return getCertificateObjects0(session, keyId, false, keyLabel);
  }

  private static List<Long> getCertificateObjects0(
      Session session, byte[] keyId, boolean ignoreKeyLabel, char[] keyLabel)
      throws P11TokenException {
    AttributeVector template = newX509Cert();
    if (keyId != null) {
      template.attr(CKA_ID, keyId);
    }
    if (!ignoreKeyLabel) {
      template.attr(CKA_LABEL, keyLabel);
    }

    List<Long> tmpObjects = getObjects(session, template);

    if (isEmpty(tmpObjects)) {
      LOG.info("found no certificate identified by {}", getDescription(keyId, keyLabel));
      return null;
    }

    return tmpObjects;
  } // method getCertificateObjects

  static void logPkcs11ObjectAttributes(String prefix, AttributeVector p11Object) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("{}{}", prefix, p11Object);
    }
  }

  static String readLabel(Session session, long objectHandle) {
    try {
      return session.getCharAttributeStringValue(objectHandle, CKA_LABEL);
    } catch (Exception e) {
      LogUtil.warn(LOG, e, "error reading label for object " + objectHandle);
      return null;
    }
  }

  private static BigInteger asUnsignedBigInt(byte[] bytes) {
    return new BigInteger(1, bytes);
  }

  static AttributeVector newPrivateKey(long keyType) {
    return new AttributeVector().attr(CKA_CLASS, CKO_PRIVATE_KEY).attr(CKA_KEY_TYPE, keyType);
  }

  static AttributeVector newPublicKey(long keyType) {
    return new AttributeVector().attr(CKA_CLASS, CKO_PUBLIC_KEY).attr(CKA_KEY_TYPE, keyType);
  }

  static AttributeVector newSecretKey(long keyType) {
    return new AttributeVector().attr(CKA_CLASS, CKO_SECRET_KEY).attr(CKA_KEY_TYPE, keyType);
  }

  static AttributeVector newX509Cert() {
    return new AttributeVector().attr(CKA_CLASS, CKO_CERTIFICATE).attr(CKA_CERTIFICATE_TYPE, CKC_X_509);
  }

}
