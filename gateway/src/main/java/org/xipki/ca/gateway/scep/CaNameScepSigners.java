// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.xipki.ca.gateway.CaNameSigners;
import org.xipki.ca.gateway.GatewayConf;
import org.xipki.codec.util.Args;
import org.xipki.codec.Base64;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.pkcs12.KeypairWithCert;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.util.X509Util;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.pkix.util.io.XipkiIoUtil;
import org.xipki.pkix.util.misc.StringUtil;
import org.xipki.pkix.util.password.PasswordResolverException;
import org.xipki.pkix.util.password.Passwords;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * CA Name SCEP Signers.
 *
 * @author Lijun Liao (xipki)
 */
public class CaNameScepSigners {

  private final ScepSigner defaultSigner;

  private final Map<String, ScepSigner> signers;

  public CaNameScepSigners(CaNameSigners signers) throws InvalidConfException {
    this(signers, null);
  }

  /**
   * Constructor.
   * @param signers the signers.
   * @param decryptorsConf the decryptors. If null, or if not configured for a CA, the signing
   *                       key decrypts the requests.
   * @throws InvalidConfException if the configuration is invalid.
   */
  public CaNameScepSigners(
      CaNameSigners signers, ScepProtocolConf.CaNameDecryptorsConf decryptorsConf)
      throws InvalidConfException {
    KeypairWithCert defaultDecryptor = null;
    Map<String, KeypairWithCert> decryptors = new HashMap<>();
    if (decryptorsConf != null) {
      if (decryptorsConf.getDefault() != null) {
        defaultDecryptor = loadDecryptor(decryptorsConf.getDefault());
      }

      List<ScepProtocolConf.CaNameDecryptorConf> confs = decryptorsConf.decryptors();
      if (confs != null) {
        for (ScepProtocolConf.CaNameDecryptorConf m : confs) {
          KeypairWithCert decryptor = loadDecryptor(m.decryptor());
          for (String name : m.names()) {
            if (decryptors.put(name.toLowerCase(Locale.ROOT), decryptor) != null) {
              throw new InvalidConfException(
                  "at least two decryptors for the CA " + name + " are set");
            }
          }
        }
      }
    }

    ConcurrentSigner signer = signers.defaultSigner();
    try {
      this.defaultSigner = signer == null ? null : new ScepSigner(signer, defaultDecryptor);
    } catch (IllegalArgumentException ex) {
      throw new InvalidConfException("default SCEP signer: " + ex.getMessage(), ex);
    }

    Set<String> names = new HashSet<>(signers.signerNames());
    names.addAll(decryptors.keySet());

    this.signers = new HashMap<>();
    for (String name : names) {
      signer = signers.getSigner(name);
      if (signer == null) {
        throw new InvalidConfException("no signer is configured for the CA " + name);
      }

      KeypairWithCert decryptor = decryptors.get(name);
      if (decryptor == null) {
        decryptor = defaultDecryptor;
      }

      try {
        this.signers.put(name, new ScepSigner(signer, decryptor));
      } catch (IllegalArgumentException ex) {
        throw new InvalidConfException(
            "SCEP signer for the CA " + name + ": " + ex.getMessage(), ex);
      }
    }
  }

  public ScepSigner getSigner(String caName) {
    ScepSigner signer = signers.get(Args.toNonBlankLower(caName, "caName"));
    return signer != null ? signer : defaultSigner;
  }

  /**
   * Loads the key and certificate from the PKCS#12 keystore. The key is not used for signing
   * (e.g. no test signature as by the signer factory).
   */
  private static KeypairWithCert loadDecryptor(GatewayConf.SignerConf decryptorConf)
      throws InvalidConfException {
    if (!"pkcs12".equalsIgnoreCase(decryptorConf.type())) {
      throw new InvalidConfException(
          "unsupported decryptor type " + decryptorConf.type() + ", only pkcs12 is supported");
    }

    SignerConf conf = new SignerConf(decryptorConf.conf());
    char[] password = getPassword(conf.password());
    if (password == null) {
      throw new InvalidConfException("password of the decryptor is not specified");
    }

    String keystore = conf.keystore();
    if (keystore == null) {
      throw new InvalidConfException("keystore of the decryptor is not specified");
    }

    List<X509Cert> certs = X509Util.parseCerts(decryptorConf.certs());
    X509Cert[] certchain = certs.isEmpty() ? null : certs.toArray(new X509Cert[0]);

    try (InputStream is = getInputStream(keystore)) {
      return KeypairWithCert.fromPKCS12Keystore(
          is, password, conf.keyLabel(), password, certchain);
    } catch (IOException | XiSecurityException ex) {
      throw new InvalidConfException("could not load the decryptor: " + ex.getMessage(), ex);
    }
  }

  private static char[] getPassword(String passwordHint) throws InvalidConfException {
    if (passwordHint == null) {
      return null;
    } else if (!passwordHint.contains(":")) {
      return passwordHint.toCharArray();
    } else {
      try {
        return Passwords.resolvePassword(passwordHint);
      } catch (PasswordResolverException ex) {
        throw new InvalidConfException("could not resolve password: " + ex.getMessage());
      }
    }
  }

  private static InputStream getInputStream(String str) throws IOException, InvalidConfException {
    if (StringUtil.startsWithIgnoreCase(str, "base64:")) {
      return new ByteArrayInputStream(Base64.decode(str.substring(7))); // "base64:".length() = 7
    } else if (StringUtil.startsWithIgnoreCase(str, "file:")) {
      return Files.newInputStream(Paths.get(XipkiIoUtil.detectPath(str.substring(5))));
    } else {
      throw new InvalidConfException("unknown content format of the keystore");
    }
  }

}
