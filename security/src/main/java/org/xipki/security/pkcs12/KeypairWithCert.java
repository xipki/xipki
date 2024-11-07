// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * Keypair with certificate.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class KeypairWithCert {

  private final PrivateKey key;

  private final PublicKey publicKey;

  private final X509Cert[] certificateChain;

  public KeypairWithCert(PrivateKey key, X509Cert[] certificateChain) {
    this.key = Args.notNull(key, "key");
    this.certificateChain = Args.notNull(certificateChain, "certificateChain");
    Args.min(certificateChain.length, "certificateChain.length", 1);
    this.publicKey = certificateChain[0].getPublicKey();
  }

  /**
   * Read keypair and certificate from the keystore with external certificate.
   * The specified stream remains open after this method returns.
   *
   * @param keystoreType the keystore type.
   * @param keystoreStream the inputstream containing the keystore.
   * @param keystorePassword the password to read the keystore.
   * @param keyname the alias of key entry in the keystore.
   * @param keyPassword the password to read the key entry.
   * @param cert external certificate.
   * @return keypair and certificate pair read from the keystore.
   * @throws XiSecurityException if Security error occurs.
   */
  public static KeypairWithCert fromKeystore(
      String keystoreType, InputStream keystoreStream, char[] keystorePassword,
      String keyname, char[] keyPassword, X509Cert cert)
      throws XiSecurityException {
    return fromKeystore(keystoreType, keystoreStream, keystorePassword, keyname, keyPassword,
        cert == null ? null : new X509Cert[] {cert});
  }

  /**
   * Read keypair and certificate from the keystore with external certificate chain.
   * The specified stream remains open after this method returns.
   *
   * @param keystoreType the keystore type.
   * @param keystoreStream the inputstream containing the keystore.
   * @param keystorePassword the password to read the keystore.
   * @param keyname the alias of key entry in the keystore.
   * @param keyPassword the password to read the key entry.
   * @param certchain external certificate chain.
   * @return keypair and certificate pair read from the keystore.
   * @throws XiSecurityException if Security error occurs.
   */
  public static KeypairWithCert fromKeystore(
      String keystoreType, InputStream keystoreStream, char[] keystorePassword,
      String keyname, char[] keyPassword, X509Cert[] certchain)
      throws XiSecurityException {
    if (!StringUtil.orEqualsIgnoreCase(keystoreType, "PKCS12", "JCEKS")) {
      throw new IllegalArgumentException("unsupported keystore type: " + keystoreType);
    }

    Args.notNull(keystoreStream, "keystoreStream");
    Args.notNull(keystorePassword, "keystorePassword");
    Args.notNull(keyPassword, "keyPassword");

    KeyStore keystore;
    try {
      keystore = KeyUtil.getInKeyStore(keystoreType);
    } catch (KeyStoreException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    try {
      keystore.load(keystoreStream, keystorePassword);
      return fromKeystore(keystore, keyname, keyPassword, certchain);
    } catch (NoSuchAlgorithmException | ClassCastException | CertificateException | IOException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  }

  public static KeypairWithCert fromKeystore(
      KeyStore keystore, String keyname, char[] keyPassword, X509Cert[] certchain)
      throws XiSecurityException {
    Args.notNull(keyPassword, "keyPassword");

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
          || key instanceof ECPrivateKey || key instanceof EdDSAKey || key instanceof XDHKey)) {
        throw new XiSecurityException("unsupported key " + key.getClass().getName());
      }

      Set<X509Cert> caCerts = new HashSet<>();

      X509Cert cert;
      if (certchain != null && certchain.length > 0) {
        cert = certchain[0];
        final int n = certchain.length;
        if (n > 1) {
          caCerts.addAll(Arrays.asList(certchain).subList(1, n));
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
    } catch (KeyStoreException | NoSuchAlgorithmException  | UnrecoverableKeyException
             | ClassCastException | CertPathBuilderException ex) {
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
