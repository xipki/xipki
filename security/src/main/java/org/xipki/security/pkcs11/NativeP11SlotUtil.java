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

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.*;
import org.xipki.pkcs11.params.ByteArrayParams;
import org.xipki.pkcs11.params.CkParams;
import org.xipki.pkcs11.params.RSA_PKCS_PSS_PARAMS;
import org.xipki.security.EdECConstants;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11Slot.P11KeyUsage;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.xipki.pkcs11.PKCS11Constants.*;
import static org.xipki.security.pkcs11.P11Slot.getDescription;
import static org.xipki.util.CollectionUtil.isEmpty;
import static org.xipki.util.CollectionUtil.isNotEmpty;

/**
 * PKCS#11 wrapper util.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
class NativeP11SlotUtil {

  private static final Logger LOG = LoggerFactory.getLogger(NativeP11SlotUtil.class);

  static void singleLogin(Session session, long userType, char[] pin) throws P11TokenException {
    char[] tmpPin = pin;
    // some driver does not accept null PIN
    if (pin == null) {
      tmpPin = new char[]{};
    }

    String userTypeText = codeToName(Category.CKU, userType);
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
      throws PKCS11Exception {
    session.digestInit(mechanism);
    session.digestKey(hKey);
    byte[] digest = new byte[digestLen];
    int len = session.digestFinal(digest, 0, digestLen);
    if (len != digestLen) {
      LOG.warn("Token returns digest with unexpected length {}, expected {}", len, digestLen);
      throw new PKCS11Exception(CKR_FUNCTION_FAILED);
    }
    return digest;
  } // method digestKey0

  static Mechanism getMechanism(long mechanism, P11Params parameters) throws P11TokenException {
    if (parameters == null) {
      return new Mechanism(mechanism);
    }

    CkParams paramObj;
    if (parameters instanceof P11Params.P11RSAPkcsPssParams) {
      P11Params.P11RSAPkcsPssParams param = (P11Params.P11RSAPkcsPssParams) parameters;
      paramObj = new RSA_PKCS_PSS_PARAMS(param.getHashAlgorithm(),
                    param.getMaskGenerationFunction(), param.getSaltLength());
    } else if (parameters instanceof P11Params.P11ByteArrayParams) {
      paramObj = new ByteArrayParams(((P11Params.P11ByteArrayParams) parameters).getBytes());
    } else {
      throw new P11TokenException("unknown P11Parameters " + parameters.getClass().getName());
    }

    return new Mechanism(mechanism, paramObj);
  } // method getMechanism

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

    long state = info.getState();
    long deviceError = info.getDeviceError();

    LOG.debug("to be verified PKCS11Module: state = {}, deviceError: {}", codeToName(Category.CKS, state), deviceError);
    if (deviceError != 0) {
      LOG.error("deviceError {}", deviceError);
      return false;
    }

    boolean sessionLoggedIn = (userType == CKU_SO) ? (state == CKS_RW_SO_FUNCTIONS)
        : (state == CKS_RW_USER_FUNCTIONS) || (state == CKS_RO_USER_FUNCTIONS);

    LOG.debug("sessionLoggedIn: {}", sessionLoggedIn);
    return sessionLoggedIn;
  } // method checkSessionLoggedIn

  static List<Long> getObjects(Session session, AttributeVector template) throws P11TokenException {
    return getObjects(session, template, 9999);
  }

  static List<Long> getObjects(Session session, AttributeVector template, int maxNo) throws P11TokenException {
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

  static PublicKey generatePublicKey(Session session, long hP11Key, long keyType)
      throws P11TokenException {
    try {
      if (keyType == CKK_RSA) {
        AttributeVector attrs = session.getAttrValues(hP11Key, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
        return buildRSAKey(attrs.modulus(), attrs.publicExponent());
      } else if (keyType == CKK_DSA) {
        AttributeVector attrs = session.getAttrValues(hP11Key, CKA_VALUE, CKA_PRIME, CKA_SUBPRIME, CKA_BASE);

        DSAPublicKeySpec keySpec = new DSAPublicKeySpec(
            new BigInteger(1, attrs.value()), attrs.prime(), attrs.subprime(), attrs.base());
        try {
          return KeyUtil.generateDSAPublicKey(keySpec);
        } catch (InvalidKeySpecException ex) {
          throw new P11TokenException(ex.getMessage(), ex);
        }
      } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
          || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
        AttributeVector attrs = session.getAttrValues(hP11Key, CKA_EC_PARAMS, CKA_EC_POINT);

        byte[] ecParameters = attrs.ecParams();
        byte[] ecPoint = attrs.ecPoint();

        ASN1ObjectIdentifier curveOid = ASN1ObjectIdentifier.getInstance(ecParameters);

        byte[] encodedPoint = DEROctetString.getInstance(attrs.ecPoint()).getOctets();

        if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
          if (keyType == CKK_EC_EDWARDS) {
            if (!EdECConstants.isEdwardsCurve(curveOid)) {
              throw new P11TokenException("unknown Edwards curve OID " + curveOid);
            }
          } else {
            if (!EdECConstants.isMontgomeryCurve(curveOid)) {
              throw new P11TokenException("unknown Montgomery curve OID " + curveOid);
            }
          }
          SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(curveOid), encodedPoint);
          try {
            return KeyUtil.generatePublicKey(pkInfo);
          } catch (InvalidKeySpecException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
          }
        } else {
          try {
            return KeyUtil.createECPublicKey(ecParameters, encodedPoint);
          } catch (InvalidKeySpecException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
          }
        }
      } else {
        throw new P11TokenException("unknown publicKey type " + codeToName(Category.CKK, keyType));
      }
    } catch (PKCS11Exception ex) {
      throw new P11TokenException("error reading PKCS#11 attribute values", ex);
    }
  } // method generatePublicKey

  static RSAPublicKey buildRSAKey(BigInteger mod, BigInteger exp) throws P11TokenException {
    try {
      return KeyUtil.generateRSAPublicKey(new RSAPublicKeySpec(mod, exp));
    } catch (InvalidKeySpecException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
  }

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

  static void setKeyAttributes(P11NewKeyControl control, AttributeVector template, String label) {
    template.token(true);
    if (label != null) {
      template.label(label);
    }

    if (control.getExtractable() != null) {
      template.extractable(control.getExtractable());
    }

    if (control.getSensitive() != null) {
      template.sensitive(control.getSensitive());
    }

    Set<P11KeyUsage> usages = control.getUsages();
    if (isNotEmpty(usages)) {
      for (P11KeyUsage usage : usages) {
        template.attr(usage.getAttributeType(), true);
      }
    }
  }

  static void logPkcs11ObjectAttributes(String prefix, AttributeVector p11Object) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("{}{}", prefix, p11Object);
    }
  }

}
