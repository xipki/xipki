// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import org.xipki.ca.gateway.conf.PopControlConf;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.CollectionAlgorithmValidator;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.SecretKeyWithAlias;
import org.xipki.util.codec.Base64;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.KeystoreConf;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * POP (proof-of-possession) control.
 *
 * @author Lijun Liao (xipki)
 */
public class PopControl {

  private final CollectionAlgorithmValidator popAlgoValidator;

  private final List<DHSigStaticKeyCertPair> dhKeyAndCerts =
      new ArrayList<>(1);

  private final X509Cert[] dhCerts;

  private final Map<String, SecretKeyWithAlias> kemMasterSecretKeys =
      new HashMap<>(1);

  private SecretKeyWithAlias defaultKemMasterSecretKeys;

  public PopControl(PopControlConf conf) throws InvalidConfException {
    // pop signature algorithms
    if (conf.getSigAlgos() == null) {
      this.popAlgoValidator = CollectionAlgorithmValidator.INSTANCE;
    } else {
      try {
        this.popAlgoValidator = CollectionAlgorithmValidator
            .buildAlgorithmValidator(conf.getSigAlgos());
      } catch (NoSuchAlgorithmException ex) {
        throw new InvalidConfException("invalid signature algorithm", ex);
      }
    }

    // Diffie-Hellman based POP
    if (conf.getDh() == null) {
      dhCerts = null;
    } else {
      try {
        Object[] res = loadKeyStore(conf.getDh());
        char[] password = (char[]) res[0];
        KeyStore ks = (KeyStore) res[1];

        Enumeration<String> aliases = ks.aliases();
        List<X509Cert> certs = new LinkedList<>();
        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          if (!ks.isKeyEntry(alias)) {
            continue;
          }

          Key key = ks.getKey(alias, password);
          if (!(key instanceof XDHPrivateKey)) {
            // we consider only XDH key
            continue;
          }

          X509Cert cert = new X509Cert(
              (X509Certificate) ks.getCertificate(alias));

          dhKeyAndCerts.add(
              new DHSigStaticKeyCertPair((XDHPrivateKey) key, cert));
          certs.add(cert);
        }

        this.dhCerts = certs.toArray(new X509Cert[0]);
      } catch (GeneralSecurityException | ClassCastException ex) {
        throw new InvalidConfException(
            "invalid dhStatic pop configuration", ex);
      }
    }

    if (conf.getKem() == null) {
      return;
    }

    try {
      Object[] res = loadKeyStore(conf.getKem());
      char[] password = (char[]) res[0];
      KeyStore ks = (KeyStore) res[1];

      Enumeration<String> aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (!ks.isKeyEntry(alias)) {
          continue;
        }

        Key key = ks.getKey(alias, password);
        if (key instanceof SecretKey) {
          // we consider only Secret key
          this.kemMasterSecretKeys.put(alias,
              new SecretKeyWithAlias(alias, (SecretKey) key));
        }
      }

      if (!this.kemMasterSecretKeys.isEmpty()) {
        String alias = this.kemMasterSecretKeys.keySet().iterator().next();
        this.defaultKemMasterSecretKeys = this.kemMasterSecretKeys.get(alias);
      }
    } catch (InvalidConfException | KeyStoreException | NoSuchAlgorithmException
             | UnrecoverableKeyException ex) {
      throw new InvalidConfException("invalid KEM pop configuration", ex);
    }
  } // constructor

  private Object[] loadKeyStore(KeystoreConf conf) throws InvalidConfException {
    if (StringUtil.isBlank(conf.getType())) {
      throw new InvalidConfException("keystore type is not defined in conf");
    }

    if (conf.getKeystore() == null) {
      throw new InvalidConfException("keystore is not defined in conf");
    }

    if (StringUtil.isBlank(conf.getPassword())) {
      throw new InvalidConfException(
          "keystore password is not defined in conf");
    }

    char[] password;
    try {
      password = Passwords.resolvePassword(conf.getPassword());
    } catch (PasswordResolverException ex) {
      throw new InvalidConfException("error resolving password");
    }

    try (InputStream is = new ByteArrayInputStream(
        conf.getKeystore().readContent())) {
      KeyStore ks = KeyUtil.getInKeyStore(conf.getType());
      ks.load(is, password);
      return new Object[]{password, ks};
    } catch (IOException | KeyStoreException | NoSuchAlgorithmException
             | CertificateException ex) {
      throw new InvalidConfException("error loading keystore", ex);
    }
  }

  private InputStream getKeyStoreInputStream(String keystoreStr)
      throws InvalidConfException {
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
    return (dhCerts == null || dhCerts.length == 0) ? null
        : Arrays.copyOf(dhCerts, dhCerts.length);
  }

  public DHSigStaticKeyCertPair getDhKeyCertPair(
      X500Name issuer, BigInteger serial, String keyAlgorithm) {
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

  public SecretKeyWithAlias getKemMasterKey(String id) {
    return kemMasterSecretKeys.get(id);
  }

  public SecretKeyWithAlias getDefaultKemMasterKey() {
    return defaultKemMasterSecretKeys;
  }

  public AlgorithmValidator getPopAlgoValidator() {
    return popAlgoValidator;
  }

}
