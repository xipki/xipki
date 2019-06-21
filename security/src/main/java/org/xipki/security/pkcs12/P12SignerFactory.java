/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.security.pkcs12;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.EdECConstants;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.SignerFactory;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.StringUtil;

/**
 * {@link SignerFactory} for the types pkcs12, jks and jceks.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

// CHECKSTYLE:SKIP
public class P12SignerFactory implements SignerFactory {

  private static final String TYPE_PKCS12 = "pkcs12";
  private static final String TYPE_JKS = "jks";
  private static final String TYPE_JCEKS = "jceks";

  private static final Set<String> types = Collections.unmodifiableSet(
      new HashSet<>(Arrays.asList(TYPE_PKCS12, TYPE_JKS, TYPE_JCEKS)));

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
  public ConcurrentContentSigner newSigner(String type, SignerConf conf,
      X509Certificate[] certificateChain) throws ObjectCreationException {
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
          throw new ObjectCreationException(
              "could not resolve password. Message: " + ex.getMessage());
        }
      }
    }

    str = conf.getConfValue("keystore");
    String keyLabel = conf.getConfValue("key-label");

    InputStream keystoreStream = getInputStream(str);

    try {
      AlgorithmIdentifier macAlgId = null;
      String algoName = conf.getConfValue("algo");
      if (algoName != null) {
        try {
          macAlgId = AlgorithmUtil.getMacAlgId(algoName);
        } catch (NoSuchAlgorithmException ex) {
          // do nothing
        }
      }

      if (macAlgId != null) {
        P12MacContentSignerBuilder signerBuilder = new P12MacContentSignerBuilder(
            type, keystoreStream, password, keyLabel, password);

        return signerBuilder.createSigner(macAlgId, parallelism, securityFactory.getRandom4Sign());
      } else {
        KeypairWithCert keypairWithCert = KeypairWithCert.fromKeystore(
            type, keystoreStream, password, keyLabel, password, certificateChain);
        String publicKeyAlg = keypairWithCert.getPublicKey().getAlgorithm();

        ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(publicKeyAlg);
        if (curveOid != null && EdECConstants.isMontgomeryCurve(curveOid)) {
          X509Certificate peerCert = null;
          // peer certificate is needed
          List<X509Certificate> peerCerts = conf.getPeerCertificates();
          if (peerCerts != null) {
            for (X509Certificate m : conf.getPeerCertificates()) {
              if (publicKeyAlg.equalsIgnoreCase(m.getPublicKey().getAlgorithm())) {
                peerCert = m;
                break;
              }
            }
          }

          if (peerCert == null) {
            throw new ObjectCreationException(
                "could not find peer certificate for algorithm " + publicKeyAlg);
          }

          P12XdhMacContentSignerBuilder signerBuilder =
              new P12XdhMacContentSignerBuilder(keypairWithCert, peerCert);
          return signerBuilder.createSigner(parallelism);
        } else {
          P12ContentSignerBuilder signerBuilder = new P12ContentSignerBuilder(keypairWithCert);

          AlgorithmIdentifier signatureAlgId;
          if (conf.getHashAlgo() == null) {
            signatureAlgId = AlgorithmUtil.getSigAlgId(null, conf);
          } else {
            PublicKey pubKey = signerBuilder.getCertificate().getPublicKey();
            signatureAlgId = AlgorithmUtil.getSigAlgId(pubKey, conf);
          }

          return signerBuilder.createSigner(signatureAlgId, parallelism,
              securityFactory.getRandom4Sign());
        }
      }
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | XiSecurityException ex) {
      throw new ObjectCreationException(String.format("%s: %s", ex.getClass().getName(),
          ex.getMessage()));
    }
  }

  @Override
  public void refreshToken(String type) throws XiSecurityException {
    // Nothing to do.
  }

  private static InputStream getInputStream(String str) throws ObjectCreationException {
    if (StringUtil.startsWithIgnoreCase(str, "base64:")) {
      return new ByteArrayInputStream(Base64.decode(str.substring("base64:".length())));
    } else if (StringUtil.startsWithIgnoreCase(str, "file:")) {
      String fn = str.substring("file:".length());
      try {
        return Files.newInputStream(Paths.get(IoUtil.expandFilepath(fn)));
      } catch (IOException ex) {
        throw new ObjectCreationException("file not found: " + fn);
      }
    } else {
      throw new ObjectCreationException("unknown content format");
    }
  }
}
