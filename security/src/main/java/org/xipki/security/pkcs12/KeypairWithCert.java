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

import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertPathBuilderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import static org.xipki.util.Args.min;
import static org.xipki.util.Args.notNull;

/**
 * Keypair with certificate.
 *
 * @author Lijun Liao
 *
 */
public class KeypairWithCert {

  private final PrivateKey key;

  private final PublicKey publicKey;

  private final X509Cert[] certificateChain;

  public KeypairWithCert(PrivateKey key, X509Cert[] certificateChain) {
    this.key = notNull(key, "key");
    this.certificateChain = notNull(certificateChain, "certificateChain");
    min(certificateChain.length, "certificateChain.length", 1);
    this.publicKey = certificateChain[0].getPublicKey();
  }

  public static KeypairWithCert fromKeystore(String keystoreType, InputStream keystoreStream,
      char[] keystorePassword, String keyname, char[] keyPassword, X509Cert cert)
          throws XiSecurityException {
    return fromKeystore(keystoreType, keystoreStream, keystorePassword, keyname, keyPassword,
        cert == null ? null : new X509Cert[] {cert});
  }

  public static KeypairWithCert fromKeystore(String keystoreType, InputStream keystoreStream,
      char[] keystorePassword, String keyname, char[] keyPassword,
      X509Cert[] certchain)
          throws XiSecurityException {
    if (!("PKCS12".equalsIgnoreCase(keystoreType) || "JCEKS".equalsIgnoreCase(keystoreType))) {
      throw new IllegalArgumentException("unsupported keystore type: " + keystoreType);
    }

    notNull(keystoreStream, "keystoreStream");
    notNull(keystorePassword, "keystorePassword");
    notNull(keyPassword, "keyPassword");

    KeyStore keystore;
    try {
      keystore = KeyUtil.getKeyStore(keystoreType);
    } catch (KeyStoreException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    try {
      keystore.load(keystoreStream, keystorePassword);
      return fromKeystore(keystore, keyname, keyPassword, certchain);
    } catch (NoSuchAlgorithmException | ClassCastException | CertificateException
        | IOException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    } finally {
      try {
        keystoreStream.close();
      } catch (IOException ex) {
        // CHECKSTYLE:SKIP
      }
    }
  }

  public static KeypairWithCert fromKeystore(KeyStore keystore,
      String keyname, char[] keyPassword, X509Cert[] certchain)
          throws XiSecurityException {
    notNull(keyPassword, "keyPassword");

    try {

      String tmpKeyname = keyname;
      if (tmpKeyname == null) {
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          if (keystore.isKeyEntry(alias)) {
            tmpKeyname = alias;
            break;
          }
        }
      } else {
        if (!keystore.isKeyEntry(tmpKeyname)) {
          throw new XiSecurityException("unknown key named " + tmpKeyname);
        }
      }

      PrivateKey key = (PrivateKey) keystore.getKey(tmpKeyname, keyPassword);

      if (!(key instanceof RSAPrivateKey || key instanceof DSAPrivateKey
          || key instanceof ECPrivateKey
          || key instanceof EdDSAKey || key instanceof XDHKey)) {
        throw new XiSecurityException("unsupported key " + key.getClass().getName());
      }

      Set<X509Cert> caCerts = new HashSet<>();

      X509Cert cert;
      if (certchain != null && certchain.length > 0) {
        cert = certchain[0];
        final int n = certchain.length;
        if (n > 1) {
          for (int i = 1; i < n; i++) {
            caCerts.add(certchain[i]);
          }
        }
      } else {
        cert = new X509Cert((X509Certificate) keystore.getCertificate(tmpKeyname));
      }

      Certificate[] certsInKeystore = keystore.getCertificateChain(tmpKeyname);
      if (certsInKeystore.length > 1) {
        for (int i = 1; i < certsInKeystore.length; i++) {
          caCerts.add(new X509Cert((X509Certificate) certsInKeystore[i]));
        }
      }

      X509Cert[] certificateChain = X509Util.buildCertPath(cert, caCerts);

      return new KeypairWithCert(key, certificateChain);
    } catch (KeyStoreException | NoSuchAlgorithmException
        | UnrecoverableKeyException | ClassCastException | CertPathBuilderException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  } // method fromKeystore

  public PrivateKey getKey() {
    return key;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  public X509Cert[] getCertificateChain() {
    return certificateChain;
  }

}
