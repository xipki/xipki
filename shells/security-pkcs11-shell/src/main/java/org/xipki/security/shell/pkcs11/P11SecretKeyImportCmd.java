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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.util.Enumeration;

import javax.crypto.SecretKey;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.shell.completer.SecretKeyTypeCompleter;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

@Command(scope = "xi", name = "import-secretkey-p11",
    description = "import secret key with given value in PKCS#11 device")
@Service
// CHECKSTYLE:SKIP
public class P11SecretKeyImportCmd extends P11KeyGenAction {

  @Option(name = "--key-type", required = true,
      description = "keytype, current only AES, DES3 and GENERIC are supported\n(required)")
  @Completion(SecretKeyTypeCompleter.class)
  private String keyType;

  @Option(name = "--keystore", required = true,
      description = "JCEKS keystore from which the key is imported\n(required)")
  @Completion(FilePathCompleter.class)
  private String keyOutFile;

  @Option(name = "--password",
      description = "password of the keystore file")
  private String password;

  @Override
  protected Object execute0() throws Exception {
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

    KeyStore ks = KeyStore.getInstance("JCEKS");
    InputStream ksStream = new FileInputStream(IoUtil.expandFilepath(keyOutFile));
    char[] pwd = getPassword();
    try {
      ks.load(ksStream, pwd);
    } finally {
      ksStream.close();
    }

    byte[] keyValue = null;
    Enumeration<String> aliases = ks.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      if (!ks.isKeyEntry(alias)) {
        continue;
      }

      Key key = ks.getKey(alias, pwd);
      if (key instanceof SecretKey) {
        keyValue = ((SecretKey) key).getEncoded();
        break;
      }
    }

    if (keyValue == null) {
      throw new IllegalCmdParamException("keystore does not contain secret key");
    }

    P11Slot slot = getSlot();
    P11ObjectIdentifier objId = slot.importSecretKey(p11KeyType, keyValue, label, getControl());
    println("imported " + keyType + " key " + objId);
    return null;
  }

  @Override
  protected boolean getDefaultExtractable() {
    return true;
  }

  protected char[] getPassword() throws IOException {
    char[] pwdInChar = readPasswordIfNotSet(password);
    if (pwdInChar != null) {
      password = new String(pwdInChar);
    }
    return pwdInChar;
  }

}
