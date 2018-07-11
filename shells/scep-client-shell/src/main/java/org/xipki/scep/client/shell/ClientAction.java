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

package org.xipki.scep.client.shell;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.scep.client.CaCertValidator;
import org.xipki.scep.client.CaIdentifier;
import org.xipki.scep.client.PreprovisionedCaCertValidator;
import org.xipki.scep.client.ScepClient;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.XiAction;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class ClientAction extends XiAction {

  @Option(name = "--url", required = true, description = "URL of the SCEP server")
  protected String url;

  @Option(name = "--ca-id", description = "CA identifier")
  protected String caId;

  @Option(name = "--ca-cert", required = true, description = "DER encoded CA certificate")
  @Completion(FileCompleter.class)
  private String caCertFile;

  @Option(name = "--p12", required = true, description = "PKCS#12 keystore file")
  @Completion(FileCompleter.class)
  private String p12File;

  @Option(name = "--password", description = "password of the PKCS#12 keystore file")
  private String password;

  private ScepClient scepClient;
  private PrivateKey identityKey;
  private X509Certificate identityCert;

  protected ScepClient getScepClient() throws CertificateException, IOException {
    if (scepClient == null) {
      X509Certificate caCert = X509Util.parseCert(new File(caCertFile));
      CaIdentifier tmpCaId = new CaIdentifier(url, caId);
      CaCertValidator caCertValidator = new PreprovisionedCaCertValidator(caCert);
      scepClient = new ScepClient(tmpCaId, caCertValidator);
    }
    return scepClient;
  }

  protected PrivateKey getIdentityKey() throws Exception {
    if (identityKey == null) {
      readIdentity();
    }
    return identityKey;
  }

  protected X509Certificate getIdentityCert() throws Exception {
    if (identityCert == null) {
      readIdentity();
    }

    return identityCert;
  }

  private void readIdentity() throws Exception {
    char[] pwd = readPasswordIfNotSet(password);

    KeyStore ks = KeyUtil.getKeyStore("PKCS12");
    ks.load(new FileInputStream(p12File), pwd);

    String keyname = null;
    Enumeration<String> aliases = ks.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      if (ks.isKeyEntry(alias)) {
        keyname = alias;
        break;
      }
    }

    if (keyname == null) {
      throw new Exception("no key entry is contained in the keystore");
    }

    this.identityKey = (PrivateKey) ks.getKey(keyname, pwd);
    this.identityCert = (X509Certificate) ks.getCertificate(keyname);
  }

}
