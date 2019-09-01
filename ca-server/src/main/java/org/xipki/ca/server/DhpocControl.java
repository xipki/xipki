/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ca.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.SecurityFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;

/**
 * DHPoc control.
 *
 * @author Lijun Liao
 */
public class DhpocControl {

  private final List<DHSigStaticKeyCertPair> keyAndCerts = new ArrayList<>(1);

  private final X509Cert[] certs;

  public DhpocControl(String conf, SecurityFactory securityFactory) throws XiSecurityException {
    ConfPairs pairs = new ConfPairs(conf);
    String type = pairs.value("type");
    String passwordStr = pairs.value("password");
    String keystoreStr = pairs.value("keystore");
    if (StringUtil.isBlank(type)) {
      throw new IllegalArgumentException("no type is definied in conf");
    }

    if (StringUtil.isBlank(keystoreStr)) {
      throw new IllegalArgumentException("no keystore is definied in conf");
    }

    if (StringUtil.isBlank(passwordStr)) {
      throw new IllegalArgumentException("no password is definied in conf");
    }

    InputStream is;
    if (keystoreStr.startsWith("base64:")) {
      byte[] bytes = Base64.decode(keystoreStr.substring("base64:".length()));
      is = new ByteArrayInputStream(bytes);
    } else {
      throw new IllegalArgumentException("keystore not start with 'base64:'");
    }

    try {
      char[] password = passwordStr.toCharArray();
      KeyStore ks = KeyUtil.getKeyStore(type);
      ks.load(is, password);

      Enumeration<String> aliases = ks.aliases();
      List<X509Cert> certs = new LinkedList<>();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (!ks.isKeyEntry(alias)) {
          continue;
        }

        PrivateKey key = (PrivateKey) ks.getKey(alias, password);
        if (!(key instanceof XDHKey)) {
          // we consider only XDH key
          continue;
        }
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        keyAndCerts.add(new DHSigStaticKeyCertPair(key, cert));
        certs.add(new X509Cert(cert));
      }

      this.certs = certs.toArray(new X509Cert[0]);
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
        | UnrecoverableKeyException | ClassCastException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

  } // constructor

  public X509Cert[] getCertificates() {
    if (certs == null || certs.length == 0) {
      return null;
    } else {
      return Arrays.copyOf(certs, certs.length);
    }
  } // method getCertificates

  public DHSigStaticKeyCertPair getKeyCertPair(X500Name issuer, BigInteger serial,
      String keyAlgorithm) {
    for (DHSigStaticKeyCertPair m : keyAndCerts) {
      if (m.getIssuer().equals(issuer)
          && m.getSerialNumber().equals(serial)
          && m.getPrivateKey().getAlgorithm().equalsIgnoreCase(keyAlgorithm)) {
        return m;
      }
    }

    return null;
  } // method getKeyCertPair

}
