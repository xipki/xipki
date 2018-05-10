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
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.SignerConf;
import org.xipki.security.shell.CsrGenAction;
import org.xipki.security.util.KeyUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "csr-p12",
    description = "generate CSR with PKCS#12 keystore")
@Service
public class P12CsrGenCmd extends CsrGenAction {

  @Option(name = "--p12", required = true,
      description = "PKCS#12 keystore file\n(required)")
  @Completion(FileCompleter.class)
  private String p12File;

  @Option(name = "--password",
      description = "password of the PKCS#12 file")
  private String password;

  private char[] getPassword() throws IOException {
    char[] pwdInChar = readPasswordIfNotSet(password);
    if (pwdInChar != null) {
      password = new String(pwdInChar);
    }
    return pwdInChar;
  }

  public KeyStore getKeyStore()
      throws IOException, KeyStoreException, NoSuchProviderException,
        NoSuchAlgorithmException, CertificateException {
    KeyStore ks;
    try (FileInputStream in = new FileInputStream(expandFilepath(p12File))) {
      ks = KeyUtil.getKeyStore("PKCS12");
      ks.load(in, getPassword());
    }
    return ks;
  }

  @Override
  protected ConcurrentContentSigner getSigner(SignatureAlgoControl signatureAlgoControl)
      throws ObjectCreationException {
    ParamUtil.requireNonNull("signatureAlgoControl", signatureAlgoControl);
    char[] pwd;
    try {
      pwd = getPassword();
    } catch (IOException ex) {
      throw new ObjectCreationException("could not read password: " + ex.getMessage(), ex);
    }
    SignerConf conf = SignerConf.getKeystoreSignerConf(p12File, new String(pwd), 1,
        HashAlgo.getNonNullInstance(hashAlgo), signatureAlgoControl);
    return securityFactory.createSigner("PKCS12", conf, (X509Certificate[]) null);
  }

}
