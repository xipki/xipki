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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.*;
import org.xipki.pkcs11.params.ByteArrayParams;
import org.xipki.pkcs11.params.CkParams;
import org.xipki.pkcs11.params.RSA_PKCS_PSS_PARAMS;
import org.xipki.security.pkcs11.P11Slot.P11KeyUsage;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.LogUtil;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.xipki.pkcs11.PKCS11Constants.*;
import static org.xipki.util.CollectionUtil.isNotEmpty;

/**
 * PKCS#11 wrapper util.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
class NativeP11SlotUtil {

  private static final Logger LOG = LoggerFactory.getLogger(NativeP11SlotUtil.class);

  static void singleLogin(Session session, long userType, char[] pin) throws TokenException {
    char[] tmpPin = pin;
    // some driver does not accept null PIN
    if (pin == null) {
      tmpPin = new char[]{};
    }

    String userTypeText = codeToName(Category.CKU, userType);
    try {
      session.login(userType, tmpPin);
      LOG.info("login successful as user " + userTypeText);
    } catch (PKCS11Exception ex) {
      if (ex.getErrorCode() == CKR_USER_ALREADY_LOGGED_IN) {
        LOG.info("user already logged in");
      } else {
        LOG.info("login failed as user " + userTypeText);
        throw new TokenException("login failed as user " + userTypeText + ": " + ex.getMessage(), ex);
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

  static Mechanism getMechanism(long mechanism, P11Params parameters) throws TokenException {
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
      throw new TokenException("unknown P11Parameters " + parameters.getClass().getName());
    }

    return new Mechanism(mechanism, paramObj);
  } // method getMechanism

  static boolean checkSessionLoggedIn(Session session, long userType) throws TokenException {
    SessionInfo info = session.getSessionInfo();
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

  static List<Long> getObjects(Session session, AttributeVector template) throws TokenException {
    return getObjects(session, template, 9999);
  }

  static List<Long> getObjects(Session session, AttributeVector template, int maxNo) throws TokenException {
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

  static RSAPublicKey buildRSAKey(BigInteger mod, BigInteger exp) throws TokenException {
    try {
      return KeyUtil.generateRSAPublicKey(new RSAPublicKeySpec(mod, exp));
    } catch (InvalidKeySpecException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }
  }

  static int removeObjects0(Session session, AttributeVector template, String desc) throws TokenException {
    try {
      List<Long> objects = getObjects(session, template);
      for (Long obj : objects) {
        session.destroyObject(obj);
      }
      return objects.size();
    } catch (TokenException ex) {
      LogUtil.error(LOG, ex, "could not remove " + desc);
      throw new TokenException(ex.getMessage(), ex);
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

}
