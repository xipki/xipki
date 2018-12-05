/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.security.shell.pkcs11;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11NewKeyControl;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.exception.P11UnsupportedMechanismException;
import org.xipki.security.shell.SecurityCompleters;
import org.xipki.shell.IllegalCmdParamException;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

@Command(scope = "xi", name = "secretkey-p11",
    description = "generate secret key in PKCS#11 device")
@Service
// CHECKSTYLE:SKIP
public class P11SecretKeyGenAction extends P11KeyGenAction {

  private static final Logger LOG = LoggerFactory.getLogger(P11SecretKeyGenAction.class);

  @Option(name = "--key-type", required = true,
      description = "keytype, current only AES, DES3 and GENERIC are supported")
  @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
  private String keyType;

  @Option(name = "--key-size", required = true, description = "keysize in bit")
  private Integer keysize;

  @Option(name = "--extern-if-gen-unsupported",
      description = "If set, if the generation mechanism is not supported by the PKCS#11 "
          + "device, create in memory and then import it to the device")
  private Boolean createExternIfGenUnsupported = Boolean.FALSE;

  @Override
  protected Object execute0() throws Exception {
    if (keysize % 8 != 0) {
      throw new IllegalCmdParamException("keysize is not multiple of 8: " + keysize);
    }

    long p11KeyType;
    if ("AES".equalsIgnoreCase(keyType)) {
      p11KeyType = PKCS11Constants.CKK_AES;
    } else if ("DES3".equalsIgnoreCase(keyType)) {
      p11KeyType = PKCS11Constants.CKK_DES3;
    } else if ("GENERIC".equalsIgnoreCase(keyType)) {
      p11KeyType = PKCS11Constants.CKK_GENERIC_SECRET;
    } else {
      throw new IllegalCmdParamException("invalid keyType " + keyType);
    }

    P11Slot slot = getSlot();
    P11NewKeyControl control = getControl();

    P11IdentityId identityId = null;
    try {
      identityId = slot.generateSecretKey(p11KeyType, keysize, control);
      finalize(keyType, identityId);
    } catch (P11UnsupportedMechanismException ex) {
      if (!createExternIfGenUnsupported) {
        throw ex;
      }

      String msgPrefix = "could not generate secret key ";
      if (control.getId() != null) {
        msgPrefix += "id=" + Hex.toHexString(control.getId());

        if (control.getLabel() != null) {
          msgPrefix += " and ";
        }
      }

      if (control.getLabel() != null) {
        msgPrefix += "label=" + control.getLabel();
      }

      if (LOG.isInfoEnabled()) {
        LOG.info(msgPrefix + ex.getMessage());
      }

      if (LOG.isDebugEnabled()) {
        LOG.debug(msgPrefix, ex);
      }

      byte[] keyValue = new byte[keysize / 8];
      securityFactory.getRandom4Key().nextBytes(keyValue);

      P11ObjectIdentifier objId = slot.importSecretKey(p11KeyType, keyValue, control);
      Arrays.fill(keyValue, (byte) 0); // clear the memory
      println("generated in memory and imported " + keyType + " key " + objId);
    }

    return null;
  }

}
