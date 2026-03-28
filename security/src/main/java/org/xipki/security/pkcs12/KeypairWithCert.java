// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * Keypair With Cert certificate record.
 *
 * @author Lijun Liao (xipki)
 */
public class KeypairWithCert {

  private final PrivateKey key;

  private final PublicKey publicKey;

  private final X509Cert[] x509CertChain;

  public KeypairWithCert(PrivateKey key, X509Cert[] x509CertChain) {
    this.key = Args.notNull(key, "key");
    this.x509CertChain = Args.notNull(x509CertChain, "x509CertChain");
    Args.min(x509CertChain.length, "x509CertChain.length", 1);
    this.publicKey = x509CertChain[0].publicKey();
  }

  /**
   * Read keypair and certificate from the keystore with external certificate.
   * The specified stream remains open after this method returns.
   *
   * @param keystoreStream the inputstream containing the keystore.
   * @param keystorePassword the password to read the keystore.
   * @param keyname the alias of key entry in the keystore.
   * @param keyPassword the password to read the key entry.
   * @param cert external certificate.
   * @return keypair and certificate pair read from the keystore.
   * @throws XiSecurityException if Security error occurs.
   */
  public static KeypairWithCert fromPKCS12Keystore(
      InputStream keystoreStream, char[] keystorePassword,
      String keyname, char[] keyPassword, X509Cert cert)
      throws XiSecurityException {
    return fromPKCS12Keystore(keystoreStream, keystorePassword,
        keyname, keyPassword, cert == null ? null : new X509Cert[] {cert});
  }

  /**
   * Read keypair and certificate from the keystore with external certificate
   * chain.
   * <p>
   * The specified stream remains open after this method returns.
   *
   * @param keystoreStream the inputstream containing the keystore.
   * @param keystorePassword the password to read the keystore.
   * @param keyname the alias of key entry in the keystore.
   * @param keyPassword the password to read the key entry.
   * @param certchain external certificate chain.
   * @return keypair and certificate pair read from the keystore.
   * @throws XiSecurityException if Security error occurs.
   */
  public static KeypairWithCert fromPKCS12Keystore(
      InputStream keystoreStream, char[] keystorePassword,
      String keyname, char[] keyPassword, X509Cert[] certchain)
      throws XiSecurityException {
    Args.notNull(keystoreStream, "keystoreStream");
    Args.notNull(keystorePassword, "keystorePassword");
    Args.notNull(keyPassword, "keyPassword");

    PKCS12KeyStore keystore = KeyUtil.loadPKCS12KeyStore(keystoreStream, keystorePassword);
    return fromKeystore(keystore, keyname, keyPassword, certchain);
  }

  public static KeypairWithCert fromKeystore(
      PKCS12KeyStore keystore, String keyname, char[] keyPassword, X509Cert[] certchain)
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

      PrivateKeyInfo keyInfo = keystore.getKey(tmpKeyname);
      PrivateKey key = KeyUtil.getPrivateKey(keyInfo);

      Set<X509Cert> caCerts = new HashSet<>();

      X509Cert cert;
      if (certchain != null && certchain.length > 0) {
        cert = certchain[0];
        final int n = certchain.length;
        if (n > 1) {
          caCerts.addAll(Arrays.asList(certchain).subList(1, n));
        }
      } else {
        cert = new X509Cert(keystore.getCertificate(tmpKeyname));
      }

      Certificate[] certsInKeystore = keystore.getCertificateChain(tmpKeyname);
      if (certsInKeystore.length > 1) {
        for (int i = 1; i < certsInKeystore.length; i++) {
          caCerts.add(new X509Cert(certsInKeystore[i]));
        }
      }

      X509Cert[] certificateChain = X509Util.buildCertPath(cert, caCerts);

      return new KeypairWithCert(key, certificateChain);
    } catch (ClassCastException | InvalidKeySpecException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  } // method fromKeystore

  public PrivateKey getKey() {
    return key;
  }

  public PublicKey publicKey() {
    return publicKey;
  }

  public X509Cert[] x509CertChain() {
    return x509CertChain;
  }

}
