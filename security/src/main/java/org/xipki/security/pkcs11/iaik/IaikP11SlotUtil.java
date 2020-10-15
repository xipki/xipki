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

import static org.xipki.security.pkcs11.P11Slot.getDescription;
import static org.xipki.util.CollectionUtil.isEmpty;
import static org.xipki.util.CollectionUtil.isNotEmpty;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11ModuleConf.P11NewObjectConf;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11Slot.P11KeyUsage;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.LogUtil;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.SessionInfo;
import iaik.pkcs.pkcs11.State;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.CharArrayAttribute;
import iaik.pkcs.pkcs11.objects.DSAPublicKey;
import iaik.pkcs.pkcs11.objects.ECPublicKey;
import iaik.pkcs.pkcs11.objects.Key.KeyType;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.objects.Storage;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.OpaqueParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * IAIK PKCS#11 wrapper util.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
class IaikP11SlotUtil {

  private static final Logger LOG = LoggerFactory.getLogger(IaikP11SlotUtil.class);

  static void singleLogin(Session session, long userType, char[] pin)
      throws P11TokenException {
    char[] tmpPin = pin;
    // some driver does not accept null PIN
    if (pin == null) {
      tmpPin = new char[]{};
    }

    String userTypeText = getUserTypeText(userType);
    try {
      session.login(userType, tmpPin);
      LOG.info("login successful as user " + userTypeText);
    } catch (TokenException ex) {
      // 0x100: user already logged in
      if (ex instanceof PKCS11Exception && ((PKCS11Exception) ex).getErrorCode() == 0x100) {
        LOG.info("user already logged in");
      } else {
        LOG.info("login failed as user " + userTypeText);
        throw new P11TokenException(
            "login failed as user " + userTypeText + ": " + ex.getMessage(), ex);
      }
    }
  } // method singleLogin

  private static String getUserTypeText(long userType) {
    if (userType == PKCS11Constants.CKU_SO) {
      return "CKU_SO";
    } else if (userType == PKCS11Constants.CKU_USER) {
      return "CKU_USER";
    } else if (userType == PKCS11Constants.CKU_CONTEXT_SPECIFIC) {
      return "CKU_CONTEXT_SPECIFIC";
    } else {
      return "VENDOR_" + userType;
    }
  }

  static byte[] digestKey(Session session, int digestLen, Mechanism mechanism, SecretKey key)
      throws TokenException {
    session.digestInit(mechanism);
    session.digestKey(key);
    byte[] digest = new byte[digestLen];
    session.digestFinal(digest, 0, digestLen);
    return digest;
  } // method digestKey0

  static Mechanism getMechanism(long mechanism, P11Params parameters)
      throws P11TokenException {
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

    if (paramObj != null) {
      ret.setParameters(paramObj);
    }

    return ret;
  } // method getMechanism

  static X509PublicKeyCertificate getCertificateObject(Session session, byte[] keyId,
      char[] keyLabel)
          throws P11TokenException {
    X509PublicKeyCertificate[] certs = getCertificateObjects(session, keyId, keyLabel);

    if (isEmpty(certs)) {
      LOG.info("found no certificate identified by {}", getDescription(keyId, keyLabel));
      return null;
    }

    int size = certs.length;
    if (size > 1) {
      LOG.warn("found {} public key identified by {}, use the first one", size,
          getDescription(keyId, keyLabel));
    }

    return certs[0];
  } // method getCertificateObject

  static boolean checkSessionLoggedIn(Session session, long userType)
      throws P11TokenException {
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
      sessionLoggedIn = state.equals(State.RW_USER_FUNCTIONS)
          || state.equals(State.RO_USER_FUNCTIONS);
    }

    LOG.debug("sessionLoggedIn: {}", sessionLoggedIn);
    return sessionLoggedIn;
  } // method checkSessionLoggedIn

  static byte[] value(ByteArrayAttribute attr) {
    return attr == null ? null : attr.getByteArrayValue();
  }

  static char[] value(CharArrayAttribute attr) {
    return attr == null ? null : attr.getCharArrayValue();
  }

  static String valueStr(CharArrayAttribute attr) {
    char[] chars = attr == null ? null : attr.getCharArrayValue();
    return chars == null ? null : new String(chars);
  }

  static List<Storage> getObjects(Session session, Storage template)
      throws P11TokenException {
    return getObjects(session, template, 9999);
  }

  static List<Storage> getObjects(Session session, Storage template, int maxNo)
      throws P11TokenException {
    List<Storage> objList = new LinkedList<>();

    try {
      session.findObjectsInit(template);

      while (objList.size() < maxNo) {
        PKCS11Object[] foundObjects = session.findObjects(1);
        if (foundObjects == null || foundObjects.length == 0) {
          break;
        }

        for (PKCS11Object object : foundObjects) {
          logPkcs11ObjectAttributes("found object: ", object);
          objList.add((Storage) object);
        }
      }
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    } finally {
      try {
        session.findObjectsFinal();
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "session.findObjectsFinal() failed");
      }
    }

    return objList;
  } // method getObjects

  static java.security.PublicKey generatePublicKey(PublicKey p11Key)
      throws XiSecurityException {
    if (p11Key instanceof RSAPublicKey) {
      RSAPublicKey rsaP11Key = (RSAPublicKey) p11Key;
      BigInteger exp = new BigInteger(1, value(rsaP11Key.getPublicExponent()));

      byte[] modBytes = value(rsaP11Key.getModulus());
      BigInteger mod = new BigInteger(1, modBytes);
      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
      try {
        return KeyUtil.generateRSAPublicKey(keySpec);
      } catch (InvalidKeySpecException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }
    } else if (p11Key instanceof DSAPublicKey) {
      DSAPublicKey dsaP11Key = (DSAPublicKey) p11Key;

      BigInteger prime = new BigInteger(1, value(dsaP11Key.getPrime())); // p
      BigInteger subPrime = new BigInteger(1, value(dsaP11Key.getSubprime())); // q
      BigInteger base = new BigInteger(1, value(dsaP11Key.getBase())); // g
      BigInteger value = new BigInteger(1, value(dsaP11Key.getValue())); // y
      DSAPublicKeySpec keySpec = new DSAPublicKeySpec(value, prime, subPrime, base);
      try {
        return KeyUtil.generateDSAPublicKey(keySpec);
      } catch (InvalidKeySpecException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }
    } else if (p11Key instanceof ECPublicKey) {
      ECPublicKey ecP11Key = (ECPublicKey) p11Key;
      long keyType = ecP11Key.getKeyType().getLongValue().longValue();
      byte[] ecParameters = value(ecP11Key.getEcdsaParams());
      byte[] encodedPoint = DEROctetString.getInstance(value(ecP11Key.getEcPoint())).getOctets();

      if (keyType == KeyType.EC_EDWARDS || keyType == KeyType.EC_MONTGOMERY) {
        ASN1ObjectIdentifier algOid = ASN1ObjectIdentifier.getInstance(ecParameters);
        if (keyType == KeyType.EC_EDWARDS) {
          if (!EdECConstants.isEdwardsCurve(algOid)) {
            throw new XiSecurityException("unknown Edwards curve OID " + algOid);
          }
        } else {
          if (!EdECConstants.isMontgomeryCurve(algOid)) {
            throw new XiSecurityException("unknown Montgomery curve OID " + algOid);
          }
        }
        SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(algOid),
            encodedPoint);
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
      throw new XiSecurityException("unknown publicKey class " + p11Key.getClass().getName());
    }
  } // method generatePublicKey

  static X509Cert parseCert(X509PublicKeyCertificate p11Cert)
      throws P11TokenException {
    try {
      byte[] encoded = value(p11Cert.getValue());
      return X509Util.parseCert(encoded);
    } catch (CertificateException ex) {
      throw new P11TokenException("could not parse certificate: " + ex.getMessage(), ex);
    }
  } // method parseCert

  static List<X509PublicKeyCertificate> getAllCertificateObjects(Session session)
      throws P11TokenException {
    X509PublicKeyCertificate template = new X509PublicKeyCertificate();
    List<Storage> tmpObjects = getObjects(session, template);

    List<X509PublicKeyCertificate> certs = new ArrayList<>(tmpObjects.size());
    for (PKCS11Object tmpObject : tmpObjects) {
      X509PublicKeyCertificate cert = (X509PublicKeyCertificate) tmpObject;
      certs.add(cert);
    }
    return certs;
  } // method getAllCertificateObjects

  static int removeObjects0(Session session, Storage template, String desc)
      throws P11TokenException {
    try {
      List<Storage> objects = getObjects(session, template);
      for (Storage obj : objects) {
        session.destroyObject(obj);
      }
      return objects.size();
    } catch (TokenException ex) {
      LogUtil.error(LOG, ex, "could not remove " + desc);
      throw new P11TokenException(ex.getMessage(), ex);
    }
  } // method removeObjects

  static void setKeyAttributes(P11NewKeyControl control,
      PublicKey publicKey, PrivateKey privateKey, P11NewObjectConf newObjectConf) {
    if (privateKey != null) {
      privateKey.getToken().setBooleanValue(true);
      if (!newObjectConf.isIgnoreLabel()) {
        privateKey.getLabel().setCharArrayValue(control.getLabel().toCharArray());
      }
      privateKey.getPrivate().setBooleanValue(true);

      if (control.getExtractable() != null) {
        privateKey.getExtractable().setBooleanValue(control.getExtractable());
      }

      if (control.getSensitive() != null) {
        privateKey.getSensitive().setBooleanValue(control.getSensitive());
      }

      Set<P11KeyUsage> usages = control.getUsages();
      // CHECKSTYLE:SKIP
      final Boolean TRUE = Boolean.TRUE;
      if (isNotEmpty(usages)) {
        for (P11KeyUsage usage : usages) {
          if (usage == P11KeyUsage.DECRYPT) {
            privateKey.getDecrypt().setBooleanValue(TRUE);
          } else if (usage == P11KeyUsage.DERIVE) {
            privateKey.getDerive().setBooleanValue(TRUE);
          } else if (usage == P11KeyUsage.SIGN) {
            privateKey.getSign().setBooleanValue(TRUE);
          } else if (usage == P11KeyUsage.SIGN_RECOVER) {
            privateKey.getSignRecover().setBooleanValue(TRUE);
          } else if (usage == P11KeyUsage.UNWRAP) {
            privateKey.getUnwrap().setBooleanValue(TRUE);
          }
        }
      } else {
        long keyType = privateKey.getKeyType().getLongValue().longValue();
        // if not set
        if (keyType == PKCS11Constants.CKK_EC
            || keyType == PKCS11Constants.CKK_RSA
            || keyType == PKCS11Constants.CKK_DSA
            || keyType == PKCS11Constants.CKK_VENDOR_SM2) {
          privateKey.getSign().setBooleanValue(TRUE);
        }

        if (keyType == PKCS11Constants.CKK_RSA) {
          privateKey.getUnwrap().setBooleanValue(TRUE);
          privateKey.getDecrypt().setBooleanValue(TRUE);
        }
      }
    }

    if (publicKey != null) {
      publicKey.getToken().setBooleanValue(true);
      if (!newObjectConf.isIgnoreLabel()) {
        publicKey.getLabel().setCharArrayValue(control.getLabel().toCharArray());
      }
      publicKey.getVerify().setBooleanValue(true);
    }
  } // method setKeyAttributes

  static void setKeyAttributes(P11NewKeyControl control,
      SecretKey template, char[] label) {
    template.getToken().setBooleanValue(true);
    if (label != null) {
      template.getLabel().setCharArrayValue(label);
    }

    if (control.getExtractable() != null) {
      template.getExtractable().setBooleanValue(control.getExtractable());
    }

    if (control.getSensitive() != null) {
      template.getSensitive().setBooleanValue(control.getSensitive());
    }

    Set<P11KeyUsage> usages = control.getUsages();
    // CHECKSTYLE:SKIP
    final Boolean TRUE = Boolean.TRUE;
    if (isNotEmpty(usages)) {
      for (P11KeyUsage usage : usages) {
        if (usage == P11KeyUsage.DECRYPT) {
          template.getDecrypt().setBooleanValue(TRUE);
        } else if (usage == P11KeyUsage.DERIVE) {
          template.getDerive().setBooleanValue(TRUE);
        } else if (usage == P11KeyUsage.SIGN) {
          template.getSign().setBooleanValue(TRUE);
        } else if (usage == P11KeyUsage.UNWRAP) {
          template.getUnwrap().setBooleanValue(TRUE);
        }
      }
    }
  }

  static X509PublicKeyCertificate[] getCertificateObjects(Session session, byte[] keyId,
      char[] keyLabel)
          throws P11TokenException {
    X509PublicKeyCertificate template = new X509PublicKeyCertificate();
    if (keyId != null) {
      template.getId().setByteArrayValue(keyId);
    }
    if (keyLabel != null) {
      template.getLabel().setCharArrayValue(keyLabel);
    }

    List<Storage> tmpObjects = getObjects(session, template);

    if (isEmpty(tmpObjects)) {
      LOG.info("found no certificate identified by {}", getDescription(keyId, keyLabel));
      return null;
    }

    int size = tmpObjects.size();
    X509PublicKeyCertificate[] certs = new X509PublicKeyCertificate[size];
    for (int i = 0; i < size; i++) {
      certs[i] = (X509PublicKeyCertificate) tmpObjects.get(i);
    }
    return certs;
  } // method getCertificateObjects

  static void logPkcs11ObjectAttributes(String prefix, PKCS11Object p11Object) {
    if (!LOG.isDebugEnabled()) {
      return;
    }

    Hashtable<Long, Attribute> table = p11Object.getAttributeTable();
    StringBuilder sb = new StringBuilder();
    if (prefix != null) {
      sb.append(prefix);
    }

    Enumeration<Long> keys = table.keys();
    while (keys.hasMoreElements()) {
      Attribute attr = p11Object.getAttribute(keys.nextElement());
      sb.append("\n  ").append(attr.toString(true));
    }

    LOG.debug(sb.toString());
  } // method logPkcs11ObjectAttributes

}
