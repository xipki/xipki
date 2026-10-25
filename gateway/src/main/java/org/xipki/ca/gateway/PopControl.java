// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.crypto.core.SecretKeyWithAlias;
import org.xipki.pkix.verify.AlgorithmValidator;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.pkix.util.conf.KeystoreConf;
import org.xipki.pkix.util.misc.StringUtil;
import org.xipki.pkix.util.password.PasswordResolverException;
import org.xipki.pkix.util.password.Passwords;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pop Control settings.
 *
 * @author Lijun Liao (xipki)
 */
public class PopControl {

  private final AlgorithmValidator popAlgoValidator;

  private final List<DHSigStaticKeyCertPair> dhKeyAndCerts = new ArrayList<>(1);

  private final X509Cert[] dhCerts;

  private final Map<String, SecretKeyWithAlias> kemMasterSecretKeys = new HashMap<>(1);

  private SecretKeyWithAlias defaultKemMasterSecretKeys;

  public PopControl(GatewayConf.PopControlConf conf) throws InvalidConfException {
    // pop signature algorithms
    if (conf.sigAlgos() == null) {
      this.popAlgoValidator = AlgorithmValidator.INSTANCE;
    } else {
      try {
        this.popAlgoValidator =
            AlgorithmValidator.buildAlgorithmValidator(conf.sigAlgos());
      } catch (NoSuchAlgorithmException ex) {
        throw new InvalidConfException("invalid signature algorithm", ex);
      }
    }

    // Diffie-Hellman based POP
    if (conf.dh() == null) {
      dhCerts = null;
    } else {
      try {
        LoadedKeyStore res = loadKeyStore(conf.dh());
        Pkcs12KeyStore ks = res.pkcs12KeyStore;
        if (ks == null) {
          throw new InvalidConfException("invalid dhSig keystore configuration: " +
              "keystore type is not PKCS12: " + conf.dh().type());
        }

        Set<String> aliases = ks.aliases();
        List<X509Cert> certs = new LinkedList<>();
        for (String alias : aliases) {
          if (!ks.isKeyEntry(alias)) {
            continue;
          }

          PrivateKeyInfo keyInfo = ks.getKey(alias);
          PrivateKey key = KeyInfoUtil.getPrivateKey(keyInfo);
          // by the algorithm OID: Key.getAlgorithm() is provider-specific (the JDK returns "XDH")
          EcCurveEnum curve = KeyInfoUtil.getCurve(key);
          if (curve != EcCurveEnum.X25519 && curve != EcCurveEnum.X448) {
            // we consider only XDH key
            continue;
          }

          X509Cert cert = new X509Cert(ks.getCertificate(alias));
          dhKeyAndCerts.add(new DHSigStaticKeyCertPair(key, cert));
          certs.add(cert);
        }

        this.dhCerts = certs.toArray(new X509Cert[0]);
      } catch (GeneralSecurityException | CodecException ex) {
        throw new InvalidConfException("invalid dhStatic pop configuration", ex);
      }
    }

    if (conf.kem() == null) {
      return;
    }

    try {
      LoadedKeyStore res = loadKeyStore(conf.kem());
      char[] password = res.password;
      KeyStore ks = res.keyStore;
      if (ks == null) {
        throw new InvalidConfException(
            "invalid kem keystore configuration: invalid keystore type " + conf.kem().type());
      }

      Enumeration<String> aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (!ks.isKeyEntry(alias)) {
          continue;
        }

        Key key = ks.getKey(alias, password);
        if (key instanceof SecretKey) {
          // we consider only Secret key
          this.kemMasterSecretKeys.put(alias, new SecretKeyWithAlias(alias, (SecretKey) key));
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

  private LoadedKeyStore loadKeyStore(KeystoreConf conf) throws InvalidConfException {
    if (StringUtil.isBlank(conf.type())) {
      throw new InvalidConfException("keystore type is not defined in conf");
    }

    if (conf.keystore() == null) {
      throw new InvalidConfException("keystore is not defined in conf");
    }

    if (StringUtil.isBlank(conf.password())) {
      throw new InvalidConfException("keystore password is not defined in conf");
    }

    char[] password;
    try {
      password = Passwords.resolvePassword(conf.password());
    } catch (PasswordResolverException ex) {
      throw new InvalidConfException("error resolving password");
    }

    try (InputStream is = new ByteArrayInputStream(conf.keystore().readContent())) {
      String confType = conf.type();
      LoadedKeyStore ret = new LoadedKeyStore();
      ret.password = password;

      if ("PKCS12".equalsIgnoreCase(confType) || "PKCS#12".equalsIgnoreCase(confType)) {
        ret.pkcs12KeyStore = KeyUtil.loadPKCS12KeyStore(is, password);
      } else {
        ret.keyStore = KeyUtil.loadKeyStore(conf.type(), is, password);
      }
      return ret;
    } catch (IOException | XiSecurityException ex) {
      throw new InvalidConfException("error loading keystore", ex);
    }
  }

  public X509Cert[] dhCertificates() {
    return (dhCerts == null || dhCerts.length == 0) ? null : Arrays.copyOf(dhCerts, dhCerts.length);
  }

  public DHSigStaticKeyCertPair getDhKeyCertPair(
      X500Name issuer, BigInteger serial, String keyAlgorithm) {
    if (dhKeyAndCerts.isEmpty()) {
      return null;
    }

    for (DHSigStaticKeyCertPair m : dhKeyAndCerts) {
      if (m.issuer().equals(issuer) && m.serialNumber().equals(serial)
          && KeyInfoUtil.getCurve(m.privateKey()) == EcCurveEnum.ofAlias(keyAlgorithm)) {
        return m;
      }
    }

    return null;
  } // method getKeyCertPair

  public SecretKeyWithAlias kemMasterKey(String id) {
    return kemMasterSecretKeys.get(id);
  }

  public SecretKeyWithAlias defaultKemMasterKey() {
    return defaultKemMasterSecretKeys;
  }

  public AlgorithmValidator popAlgoValidator() {
    return popAlgoValidator;
  }

  private static class LoadedKeyStore {

    private char[] password;

    private KeyStore keyStore;

    private Pkcs12KeyStore pkcs12KeyStore;

  }

}
