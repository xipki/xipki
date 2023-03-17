// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.*;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.ObjectCreationException;

import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.*;

/**
 * {@link SignerFactory} for the types pkcs12 and jceks.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P12SignerFactory implements SignerFactory {

  private static final String TYPE_PKCS12 = "pkcs12";
  private static final String TYPE_JCEKS = "jceks";

  private static final Set<String> types = Collections.unmodifiableSet(
      new HashSet<>(Arrays.asList(TYPE_PKCS12, TYPE_JCEKS)));

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
    char[] password;
    if (passwordHint == null) {
      password = null;
    } else {
      PasswordResolver passwordResolver = securityFactory.getPasswordResolver();
      if (passwordResolver == null) {
        password = passwordHint.toCharArray();
      } else {
        try {
          password = passwordResolver.resolvePassword(passwordHint);
        } catch (PasswordResolverException ex) {
          throw new ObjectCreationException("could not resolve password. Message: " + ex.getMessage());
        }
      }
    }

    str = conf.getConfValue("keystore");
    String keyLabel = conf.getConfValue("key-label");

    InputStream keystoreStream = getInputStream(str);

    try {
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
        String publicKeyAlg = keypairWithCert.getPublicKey().getAlgorithm();

        ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(publicKeyAlg);
        if (curveOid != null && EdECConstants.isMontgomeryCurve(curveOid)) {
          X509Cert peerCert = null;
          // peer certificate is needed
          List<X509Cert> peerCerts = conf.getPeerCertificates();
          if (peerCerts != null) {
            for (X509Cert m : conf.getPeerCertificates()) {
              if (publicKeyAlg.equalsIgnoreCase(m.getPublicKey().getAlgorithm())) {
                peerCert = m;
                break;
              }
            }
          }

          if (peerCert == null) {
            throw new ObjectCreationException("could not find peer certificate for algorithm " + publicKeyAlg);
          }

          P12XdhMacContentSignerBuilder signerBuilder = new P12XdhMacContentSignerBuilder(keypairWithCert, peerCert);
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
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | XiSecurityException ex) {
      throw new ObjectCreationException(String.format("%s: %s", ex.getClass().getName(), ex.getMessage()));
    }
  } // method newSigner

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
