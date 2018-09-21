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

import java.io.File;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.ConfPairs;
import org.xipki.util.ObjectCreationException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
@Command(scope = "xi", name = "update-cert-p12",
    description = "update certificate in PKCS#12 keystore")
@Service
public class P12CertUpdateAction extends P12SecurityAction {

  @Option(name = "--cert", required = true, description = "certificate file")
  @Completion(FileCompleter.class)
  private String certFile;

  @Option(name = "--ca-cert", multiValued = true, description = "CA Certificate file")
  @Completion(FileCompleter.class)
  private Set<String> caCertFiles;

  @Override
  protected Object execute0() throws Exception {
    KeyStore ks = getKeyStore();

    char[] pwd = getPassword();
    X509Certificate newCert = X509Util.parseCert(new File(certFile));

    assertMatch(newCert, new String(pwd));

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
      throw new XiSecurityException("could not find private key");
    }

    Key key = ks.getKey(keyname, pwd);
    Set<X509Certificate> caCerts = new HashSet<>();
    if (isNotEmpty(caCertFiles)) {
      for (String caCertFile : caCertFiles) {
        caCerts.add(X509Util.parseCert(new File(caCertFile)));
      }
    }
    X509Certificate[] certChain = X509Util.buildCertPath(newCert, caCerts);
    ks.setKeyEntry(keyname, key, pwd, certChain);

    try (OutputStream out = Files.newOutputStream(Paths.get(p12File))) {
      ks.store(out, pwd);
      println("updated certificate");
      return null;
    }
  }

  private void assertMatch(X509Certificate cert, String password)
      throws ObjectCreationException {
    ConfPairs pairs = new ConfPairs("keystore", "file:" + p12File);
    if (password != null) {
      pairs.putPair("password", new String(password));
    }

    SignerConf conf = new SignerConf(pairs.getEncoded(), HashAlgo.SHA256, null);
    securityFactory.createSigner("PKCS12", conf, cert);
  }

}
