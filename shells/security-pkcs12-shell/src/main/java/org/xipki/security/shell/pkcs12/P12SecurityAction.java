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

package org.xipki.security.shell.pkcs12;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.shell.SecurityAction;
import org.xipki.security.util.KeyUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P12SecurityAction extends SecurityAction {

  @Option(name = "--p12", required = true,
      description = "PKCS#12 keystore file\n(required)")
  @Completion(FilePathCompleter.class)
  protected String p12File;

  @Option(name = "--password",
      description = "password of the PKCS#12 file")
  protected String password;

  protected char[] getPassword() throws IOException {
    char[] pwdInChar = readPasswordIfNotSet(password);
    if (pwdInChar != null) {
      password = new String(pwdInChar);
    }
    return pwdInChar;
  }

  protected KeyStore getKeyStore()
      throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException,
        NoSuchProviderException {
    KeyStore ks;
    try (FileInputStream in = new FileInputStream(expandFilepath(p12File))) {
      ks = KeyUtil.getKeyStore("PKCS12");
      ks.load(in, getPassword());
    }
    return ks;
  }

}
