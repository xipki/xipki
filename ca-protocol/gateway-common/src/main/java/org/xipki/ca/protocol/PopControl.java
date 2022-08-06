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

package org.xipki.ca.protocol;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.xipki.ca.protocol.conf.KeystoreConf;
import org.xipki.ca.protocol.conf.PopControlConf;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.CollectionAlgorithmValidator;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Base64;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * POP (proof-of-possession) control.
 *
 * @author Lijun Liao
 */
public class PopControl {

  private final CollectionAlgorithmValidator popAlgoValidator;

  private final List<DHSigStaticKeyCertPair> dhKeyAndCerts = new ArrayList<>(1);

  private final X509Cert[] dhCerts;

  public PopControl(PopControlConf conf)
      throws InvalidConfException {
    // pop signature algorithms
    if (conf.getSigAlgos() == null) {
      this.popAlgoValidator = CollectionAlgorithmValidator.INSTANCE;
    } else {
      try {
        this.popAlgoValidator = CollectionAlgorithmValidator.buildAlgorithmValidator(
            conf.getSigAlgos());
      } catch (NoSuchAlgorithmException ex) {
        throw new InvalidConfException("invalid signature algorithm", ex);
      }
    }

    // Diffie-Hellman based POP
    KeystoreConf dh = conf.getDh();
    String type = dh.getType();
    String passwordStr = dh.getPassword();
    String keystoreStr = dh.getKeystore();
    if (StringUtil.isBlank(type) && StringUtil.isBlank(passwordStr)
        && StringUtil.isBlank(keystoreStr)) {
      dhCerts = null;
    } else {
      if (StringUtil.isBlank(type)) {
        throw new InvalidConfException("type is not defined in conf");
      }

      if (StringUtil.isBlank(keystoreStr)) {
        throw new InvalidConfException("keystore is not defined in conf");
      }

      if (StringUtil.isBlank(passwordStr)) {
        throw new InvalidConfException("password is not defined in conf");
      }

      InputStream is;
      if (keystoreStr.startsWith("base64:")) {
        byte[] bytes = Base64.decode(keystoreStr.substring("base64:".length()));
        is = new ByteArrayInputStream(bytes);
      } else {
        throw new InvalidConfException("keystore not start with 'base64:'");
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
          X509Cert cert = new X509Cert((X509Certificate) ks.getCertificate(alias));

          dhKeyAndCerts.add(new DHSigStaticKeyCertPair(key, cert));
          certs.add(cert);
        }

        this.dhCerts = certs.toArray(new X509Cert[0]);
      } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
          | UnrecoverableKeyException | ClassCastException ex) {
        throw new InvalidConfException("invalid dhStatic pop configuration", ex);
      }
    }
  } // constructor

  public X509Cert[] getDhCertificates() {
    if (dhCerts == null || dhCerts.length == 0) {
      return null;
    } else {
      return Arrays.copyOf(dhCerts, dhCerts.length);
    }
  } // method getCertificates

  public DHSigStaticKeyCertPair getDhKeyCertPair(X500Name issuer, BigInteger serial,
      String keyAlgorithm) {
    if (dhKeyAndCerts == null) {
      return null;
    }

    for (DHSigStaticKeyCertPair m : dhKeyAndCerts) {
      if (m.getIssuer().equals(issuer)
          && m.getSerialNumber().equals(serial)
          && m.getPrivateKey().getAlgorithm().equalsIgnoreCase(keyAlgorithm)) {
        return m;
      }
    }

    return null;
  } // method getKeyCertPair

  public AlgorithmValidator getPopAlgoValidator() {
    return popAlgoValidator;
  }

}
