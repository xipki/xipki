// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.xipki.ca.gateway.conf.KeystoreConf;
import org.xipki.ca.gateway.conf.PopControlConf;
import org.xipki.password.PasswordResolverException;
import org.xipki.password.Passwords;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.CollectionAlgorithmValidator;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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

/**
 * POP (proof-of-possession) control.
 *
 * @author Lijun Liao (xipki)
 */
public class PopControl {

  private final CollectionAlgorithmValidator popAlgoValidator;

  private final List<DHSigStaticKeyCertPair> dhKeyAndCerts = new ArrayList<>(1);

  private final X509Cert[] dhCerts;

  public PopControl(PopControlConf conf) throws InvalidConfException {
    // pop signature algorithms
    if (conf.getSigAlgos() == null) {
      this.popAlgoValidator = CollectionAlgorithmValidator.INSTANCE;
    } else {
      try {
        this.popAlgoValidator = CollectionAlgorithmValidator.buildAlgorithmValidator(conf.getSigAlgos());
      } catch (NoSuchAlgorithmException ex) {
        throw new InvalidConfException("invalid signature algorithm", ex);
      }
    }

    // Diffie-Hellman based POP
    KeystoreConf dh = conf.getDh();
    if (dh == null) {
      dhCerts = null;
      return;
    }

    String type = dh.getType();
    String passwordStr = dh.getPassword();
    String keystoreStr = dh.getKeystore();
    if (StringUtil.isBlank(type) && StringUtil.isBlank(passwordStr) && StringUtil.isBlank(keystoreStr)) {
      dhCerts = null;
      return;
    }

    if (StringUtil.isBlank(type)) {
      throw new InvalidConfException("type is not defined in conf");
    }

    if (StringUtil.isBlank(keystoreStr)) {
      throw new InvalidConfException("keystore is not defined in conf");
    }

    if (StringUtil.isBlank(passwordStr)) {
      throw new InvalidConfException("password is not defined in conf");
    }

    char[] password;
    try {
      password = Passwords.resolvePassword(passwordStr);
    } catch (PasswordResolverException ex) {
      throw new InvalidConfException("error resolving password");
    }

    try (InputStream is = getKeyStoreInputStream(keystoreStr)) {
      KeyStore ks = KeyUtil.getInKeyStore(type);
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
  } // constructor

  private InputStream getKeyStoreInputStream(String keystoreStr) throws InvalidConfException {
    if (keystoreStr.startsWith("base64:")) {
      byte[] bytes = Base64.decode(keystoreStr.substring("base64:".length()));
      return new ByteArrayInputStream(bytes);
    } else {
      try {
        return new FileInputStream(IoUtil.expandFilepath(keystoreStr, true));
      } catch (FileNotFoundException e) {
        throw new InvalidConfException(e.getMessage(), e);
      }
    }
  }

  public X509Cert[] getDhCertificates() {
    return (dhCerts == null || dhCerts.length == 0) ? null : Arrays.copyOf(dhCerts, dhCerts.length);
  } // method getCertificates

  public DHSigStaticKeyCertPair getDhKeyCertPair(X500Name issuer, BigInteger serial, String keyAlgorithm) {
    if (dhKeyAndCerts.isEmpty()) {
      return null;
    }

    for (DHSigStaticKeyCertPair m : dhKeyAndCerts) {
      if (m.getIssuer().equals(issuer) && m.getSerialNumber().equals(serial)
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
