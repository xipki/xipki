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

package org.xipki.security.pkcs12;

import org.xipki.security.*;
import org.xipki.security.util.KeyUtil;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;

/**
 * Builder of PKCS#12 MAC signers.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

public class P12MacContentSignerBuilder {

  private final SecretKey key;

  public P12MacContentSignerBuilder(SecretKey key) {
    this.key = notNull(key, "key");
  }

  public P12MacContentSignerBuilder(
      String keystoreType, InputStream keystoreStream, char[] keystorePassword, String keyname, char[] keyPassword)
      throws XiSecurityException {
    if (!"JCEKS".equalsIgnoreCase(keystoreType)) {
      throw new IllegalArgumentException("unsupported keystore type: " + keystoreType);
    }
    notNull(keystoreStream, "keystoreStream");
    notNull(keystorePassword, "keystorePassword");
    notNull(keyPassword, "keyPassword");

    try {
      KeyStore ks = KeyUtil.getInKeyStore(keystoreType);
      ks.load(keystoreStream, keystorePassword);

      String tmpKeyname = keyname;
      if (tmpKeyname == null) {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          if (ks.isKeyEntry(alias)) {
            tmpKeyname = alias;
            break;
          }
        }
      } else {
        if (!ks.isKeyEntry(tmpKeyname)) {
          throw new XiSecurityException("unknown key named " + tmpKeyname);
        }
      }

      this.key = (SecretKey) ks.getKey(tmpKeyname, keyPassword);
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
             | UnrecoverableKeyException | ClassCastException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  } // constructor

  public ConcurrentContentSigner createSigner(SignAlgo sigAlgo, int parallelism)
      throws XiSecurityException {
    notNull(sigAlgo, "sigAlgo");
    positive(parallelism, "parallelism");

    List<XiContentSigner> signers = new ArrayList<>(parallelism);

    for (int i = 0; i < parallelism; i++) {
      XiContentSigner signer = sigAlgo.isGmac()
          ? new AESGmacContentSigner(sigAlgo, key) : new HmacContentSigner(sigAlgo, key);
      signers.add(signer);
    }

    final boolean mac = true;
    DfltConcurrentContentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentContentSigner(mac, signers, key);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
    concurrentSigner.setSha1DigestOfMacKey(HashAlgo.SHA1.hash(key.getEncoded()));

    return concurrentSigner;
  } // method createSigner

  public SecretKey getKey() {
    return key;
  }

}
