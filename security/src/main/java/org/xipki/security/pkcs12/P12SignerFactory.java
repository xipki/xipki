// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.KeySpec;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.SignerFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.codec.Base64;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * {@link SignerFactory} for the types pkcs12 and jceks.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P12SignerFactory implements SignerFactory {

  private static final String TYPE_PKCS12 = "pkcs12";
  private static final String TYPE_JCEKS = "jceks";

  private static final Set<String> types = Set.of(TYPE_PKCS12, TYPE_JCEKS);

  private SecurityFactory securityFactory;

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  @Override
  public Set<String> getSupportedSignerTypes() {
    return types;
  }

  @Override
  public boolean canCreateSigner(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public ConcurrentContentSigner newSigner(
      String type, SignerConf conf, X509Cert[] certificateChain)
      throws ObjectCreationException {
    if (!canCreateSigner(type)) {
      throw new ObjectCreationException("unknown signer type " + type);
    }

    Integer iParallelism;
    try {
      iParallelism = conf.getParallelism();
    } catch (InvalidConfException e) {
      throw new ObjectCreationException(e);
    }

    int parallelism = Objects.requireNonNullElseGet(iParallelism,
        () -> securityFactory.getDfltSignerParallelism());

    String passwordHint = conf.getPassword();
    char[] password = getPassword(passwordHint);

    String keystore = conf.getKeystore();
    String keyLabel = conf.getKeyLabel();

    try (InputStream keystoreStream = getInputStream(keystore)) {
      SignAlgo sigAlgo = conf.getAlgo();
      if (sigAlgo != null && sigAlgo.isMac()) {
        P12MacContentSignerBuilder signerBuilder =
            new P12MacContentSignerBuilder(type, keystoreStream,
                password, keyLabel, password);
        return signerBuilder.createSigner(sigAlgo, parallelism);
      } else {
        KeypairWithCert keypairWithCert = KeypairWithCert.fromKeystore(type,
            keystoreStream, password, keyLabel, password, certificateChain);
        if (sigAlgo == null) {
          SubjectPublicKeyInfo pkInfo = keypairWithCert
              .getCertificateChain()[0].getSubjectPublicKeyInfo();
          sigAlgo = conf.getCallback().getSignAlgo(
                      KeySpec.ofPublicKey(pkInfo), conf.getMode());
          conf.setAlgo(sigAlgo);
        }

        PublicKey publicKey = keypairWithCert.getPublicKey();

        if (publicKey instanceof XDHPublicKey) {
          P12XdhMacContentSignerBuilder signerBuilder =
              getP12XdhMacContentSignerBuilder(conf, keypairWithCert);
          return signerBuilder.createSigner(parallelism);
        }

        if (SignAlgo.KEM_HMAC_SHA256 == sigAlgo) {
          SubjectPublicKeyInfo publicKeyInfo = keypairWithCert
              .getCertificateChain()[0].getSubjectPublicKeyInfo();
          P12KemMacContentSignerBuilder signerBuilder =
              new P12KemMacContentSignerBuilder(keypairWithCert,
                  conf.getCallback().generateKemEncapKey(
                      securityFactory, publicKeyInfo));
          return signerBuilder.createSigner(sigAlgo, parallelism);
        } else {
          P12ContentSignerBuilder signerBuilder =
              new P12ContentSignerBuilder(keypairWithCert);

          return signerBuilder.createSigner(sigAlgo, parallelism,
              securityFactory.getRandom4Sign());
        }
      }
    } catch (XiSecurityException | IOException | InvalidConfException ex) {
      throw new ObjectCreationException(String.format(
          "%s: %s", ex.getClass().getName(), ex.getMessage()));
    }
  } // method newSigner

  private static P12XdhMacContentSignerBuilder getP12XdhMacContentSignerBuilder(
      SignerConf conf, KeypairWithCert keypairWithCert)
      throws ObjectCreationException, XiSecurityException {
    // peer certificate is needed
    List<X509Cert> peerCerts = conf.getPeerCertificates();
    if (peerCerts == null || peerCerts.isEmpty()) {
      throw new ObjectCreationException("no peer certificate is specified");
    }

    X509Cert myCert = keypairWithCert.getCertificateChain()[0];
    X509Cert peerCert = null;

    AlgorithmIdentifier myKeyAlg =
        myCert.getSubjectPublicKeyInfo().getAlgorithm();
    for (X509Cert m : peerCerts) {
      if (m.getSubjectPublicKeyInfo().getAlgorithm().equals(myKeyAlg)) {
        peerCert = m;
        break;
      }
    }

    if (peerCert == null) {
      throw new ObjectCreationException("could not find peer certificate");
    }

    return new P12XdhMacContentSignerBuilder(keypairWithCert, peerCert);
  }

  private char[] getPassword(String passwordHint)
      throws ObjectCreationException {
    char[] password;
    if (passwordHint == null) {
      password = null;
    } else if (!passwordHint.contains(":")) {
      password = passwordHint.toCharArray();
    } else {
      try {
        password = Passwords.resolvePassword(passwordHint);
      } catch (PasswordResolverException ex) {
        throw new ObjectCreationException(
            "could not resolve password. Message: " + ex.getMessage());
      }
    }
    return password;
  }

  private static InputStream getInputStream(String str)
      throws ObjectCreationException {
    if (StringUtil.startsWithIgnoreCase(str, "base64:")) {
      return new ByteArrayInputStream(
          Base64.decode(str.substring(7))); // "base64:".length() = 7
    } else if (StringUtil.startsWithIgnoreCase(str, "file:")) {
      String fn = str.substring(5); // "file:".length() = 5
      try {
        return Files.newInputStream(Paths.get(IoUtil.detectPath(fn)));
      } catch (IOException ex) {
        throw new ObjectCreationException("file not found: " + fn);
      }
    } else {
      throw new ObjectCreationException("unknown content format");
    }
  } // method getInputStream
}
