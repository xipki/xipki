// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.password.PasswordResolverException;
import org.xipki.password.Passwords;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.EdECConstants;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.SignerFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.ObjectCreationException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
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
  public ConcurrentContentSigner newSigner(String type, SignerConf conf, X509Cert[] certificateChain)
      throws ObjectCreationException {
    if (!canCreateSigner(type)) {
      throw new ObjectCreationException("unknown signer type " + type);
    }

    String str = conf.getConfValue("parallelism");
    int parallelism = securityFactory.getDfltSignerParallelism();
    if (str != null) {
      try {
        parallelism = Integer.parseInt(str);
      } catch (NumberFormatException ex) {
        throw new ObjectCreationException("invalid parallelism " + str);
      }

      if (parallelism < 1) {
        throw new ObjectCreationException("invalid parallelism " + str);
      }
    }

    String passwordHint = conf.getConfValue("password");
    char[] password = getPassword(passwordHint);

    str = conf.getConfValue("keystore");
    String keyLabel = conf.getConfValue("key-label");

    try (InputStream keystoreStream = getInputStream(str)) {
      SignAlgo sigAlgo = null;
      String algoName = conf.getConfValue("algo");
      if (algoName != null) {
        sigAlgo = SignAlgo.getInstance(algoName);
      }

      if (sigAlgo != null && sigAlgo.isMac()) {
        P12MacContentSignerBuilder signerBuilder = new P12MacContentSignerBuilder(
            type, keystoreStream, password, keyLabel, password);
        return signerBuilder.createSigner(sigAlgo, parallelism);
      } else {
        KeypairWithCert keypairWithCert = KeypairWithCert.fromKeystore(
            type, keystoreStream, password, keyLabel, password, certificateChain);
        PublicKey publicKey = keypairWithCert.getPublicKey();
        ASN1ObjectIdentifier xdhCurveOid = null;
        if (!(publicKey instanceof RSAPublicKey || publicKey instanceof ECPublicKey
            || publicKey instanceof DSAPublicKey)) {
          SubjectPublicKeyInfo spki = keypairWithCert.getCertificateChain()[0].getSubjectPublicKeyInfo();
          xdhCurveOid = spki.getAlgorithm().getAlgorithm();
          if (!EdECConstants.isMontgomeryCurve(xdhCurveOid)) {
            xdhCurveOid = null;
          }
        }

        if (xdhCurveOid != null) {
          P12XdhMacContentSignerBuilder signerBuilder =
              getP12XdhMacContentSignerBuilder(conf, xdhCurveOid, keypairWithCert);
          return signerBuilder.createSigner(parallelism);
        } else {
          P12ContentSignerBuilder signerBuilder = new P12ContentSignerBuilder(keypairWithCert);

          if (sigAlgo == null) {
            PublicKey pubKey = signerBuilder.getCertificate().getPublicKey();
            sigAlgo = SignAlgo.getInstance(pubKey, conf);
          }

          return signerBuilder.createSigner(sigAlgo, parallelism, securityFactory.getRandom4Sign());
        }
      }
    } catch (NoSuchAlgorithmException | XiSecurityException | IOException ex) {
      throw new ObjectCreationException(String.format("%s: %s", ex.getClass().getName(), ex.getMessage()));
    }
  } // method newSigner

  private static P12XdhMacContentSignerBuilder getP12XdhMacContentSignerBuilder(
      SignerConf conf, ASN1ObjectIdentifier curveId, KeypairWithCert keypairWithCert)
      throws ObjectCreationException, XiSecurityException {
    X509Cert peerCert = null;
    // peer certificate is needed
    List<X509Cert> peerCerts = conf.getPeerCertificates();
    if (peerCerts != null) {
      for (X509Cert m : conf.getPeerCertificates()) {
        if (curveId.equals(m.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm())) {
          peerCert = m;
          break;
        }
      }
    }

    if (peerCert == null) {
      throw new ObjectCreationException("could not find peer certificate for algorithm " + curveId.getId());
    }

    return new P12XdhMacContentSignerBuilder(keypairWithCert, peerCert);
  }

  private char[] getPassword(String passwordHint) throws ObjectCreationException {
    char[] password;
    if (passwordHint == null) {
      password = null;
    } else if (!passwordHint.contains(":")) {
      password = passwordHint.toCharArray();
    } else {
      try {
        password = Passwords.resolvePassword(passwordHint);
      } catch (PasswordResolverException ex) {
        throw new ObjectCreationException("could not resolve password. Message: " + ex.getMessage());
      }
    }
    return password;
  }

  private static InputStream getInputStream(String str) throws ObjectCreationException {
    if (StringUtil.startsWithIgnoreCase(str, "base64:")) {
      return new ByteArrayInputStream(Base64.decode(str.substring("base64:".length())));
    } else if (StringUtil.startsWithIgnoreCase(str, "file:")) {
      String fn = str.substring("file:".length());
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
