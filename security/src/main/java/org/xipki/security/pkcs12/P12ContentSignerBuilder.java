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

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DSAPlainDigestSigner;
import org.xipki.security.DfltConcurrentContentSigner;
import org.xipki.security.SignatureSigner;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;
import org.xipki.security.XiWrappedContentSigner;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P12ContentSignerBuilder {

  private static final AlgorithmIdentifier ALGID_SM2_SM3 =
      new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3);

  private static final AlgorithmIdentifier ALGID_SM3 =
      new AlgorithmIdentifier(GMObjectIdentifiers.sm3);

  // CHECKSTYLE:SKIP
  private static class RSAContentSignerBuilder extends BcContentSignerBuilder {

    private RSAContentSignerBuilder(AlgorithmIdentifier signatureAlgId)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
      super(signatureAlgId, AlgorithmUtil.extractDigesetAlgFromSigAlg(signatureAlgId));
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException {
      if (!AlgorithmUtil.isRSASigAlgId(sigAlgId)) {
        throw new OperatorCreationException("the given algorithm is not a valid RSA signature "
            + "algirthm '" + sigAlgId.getAlgorithm().getId() + "'");
      }

      if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm())) {
        Digest dig = digestProvider.get(digAlgId);
        return new RSADigestSigner(dig);
      }

      try {
        return SignerUtil.createPSSRSASigner(sigAlgId);
      } catch (XiSecurityException ex) {
        throw new OperatorCreationException(ex.getMessage(), ex);
      }
    }

  } // class RSAContentSignerBuilder

  // CHECKSTYLE:SKIP
  private static class DSAContentSignerBuilder extends BcContentSignerBuilder {

    private final boolean plain;

    private DSAContentSignerBuilder(AlgorithmIdentifier signatureAlgId, boolean plain)
        throws NoSuchAlgorithmException {
      super(signatureAlgId, AlgorithmUtil.extractDigesetAlgFromSigAlg(signatureAlgId));
      this.plain = plain;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException {
      if (!AlgorithmUtil.isDSASigAlg(sigAlgId)) {
        throw new OperatorCreationException("the given algorithm is not a valid DSA signature "
            + "algirthm '" + sigAlgId.getAlgorithm().getId() + "'");
      }

      Digest dig = digestProvider.get(digAlgId);
      DSASigner dsaSigner = new DSASigner();
      return plain ? new DSAPlainDigestSigner(dsaSigner, dig) : new DSADigestSigner(dsaSigner, dig);
    }

  } // class DSAContentSignerBuilder

  // CHECKSTYLE:SKIP
  private static class ECDSAContentSignerBuilder extends BcContentSignerBuilder {

    private final boolean plain;

    private ECDSAContentSignerBuilder(AlgorithmIdentifier signatureAlgId, boolean plain)
        throws NoSuchAlgorithmException {
      super(signatureAlgId, AlgorithmUtil.extractDigesetAlgFromSigAlg(signatureAlgId));
      this.plain = plain;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException {
      if (!AlgorithmUtil.isECSigAlg(sigAlgId)) {
        throw new OperatorCreationException("the given algorithm is not a valid EC signature "
            + "algorithm '" + sigAlgId.getAlgorithm().getId() + "'");
      }

      Digest dig = digestProvider.get(digAlgId);
      ECDSASigner dsaSigner = new ECDSASigner();

      return plain ? new DSAPlainDigestSigner(dsaSigner, dig) : new DSADigestSigner(dsaSigner, dig);
    }

  } // class ECDSAContentSignerBuilder

  private static class SM2ContentSignerBuilder extends BcContentSignerBuilder {

    private SM2ContentSignerBuilder() throws NoSuchAlgorithmException {
      super(ALGID_SM2_SM3, ALGID_SM3);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
            throws OperatorCreationException {
      if (!AlgorithmUtil.isSM2SigAlg(sigAlgId)) {
        throw new OperatorCreationException("the given algorithm is not a valid EC signature "
            + "algorithm '" + sigAlgId.getAlgorithm().getId() + "'");
      }

      return new SM2Signer();
    }

  } // class SM2ContentSignerBuilder

  private final PrivateKey key;

  private final PublicKey publicKey;

  private final X509Certificate[] certificateChain;

  public P12ContentSignerBuilder(PrivateKey privateKey, PublicKey publicKey)
      throws XiSecurityException {
    this.key = Args.notNull(privateKey, "privateKey");
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.certificateChain = null;
  }

  public P12ContentSignerBuilder(String keystoreType, InputStream keystoreStream,
      char[] keystorePassword, String keyname, char[] keyPassword,
      X509Certificate[] certificateChain) throws XiSecurityException {
    if (!("PKCS12".equalsIgnoreCase(keystoreType) || "JKS".equalsIgnoreCase(keystoreType))) {
      throw new IllegalArgumentException("unsupported keystore type: " + keystoreType);
    }

    Args.notNull(keystoreStream, "keystoreStream");
    Args.notNull(keystorePassword, "keystorePassword");
    Args.notNull(keyPassword, "keyPassword");

    try {
      KeyStore ks = KeyUtil.getKeyStore(keystoreType);
      ks.load(keystoreStream, keystorePassword);

      String tmpKeyname = keyname;
      if (tmpKeyname == null) {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          if (ks.isKeyEntry(alias)) {
            tmpKeyname = alias;
            break;
          }
        }
      } else {
        if (!ks.isKeyEntry(tmpKeyname)) {
          throw new XiSecurityException("unknown key named " + tmpKeyname);
        }
      }

      this.key = (PrivateKey) ks.getKey(tmpKeyname, keyPassword);

      if (!(key instanceof RSAPrivateKey || key instanceof DSAPrivateKey
          || key instanceof ECPrivateKey)) {
        throw new XiSecurityException("unsupported key " + key.getClass().getName());
      }

      Set<Certificate> caCerts = new HashSet<>();

      X509Certificate cert;
      if (certificateChain != null && certificateChain.length > 0) {
        cert = certificateChain[0];
        final int n = certificateChain.length;
        if (n > 1) {
          for (int i = 1; i < n; i++) {
            caCerts.add(certificateChain[i]);
          }
        }
      } else {
        cert = (X509Certificate) ks.getCertificate(tmpKeyname);
      }

      Certificate[] certsInKeystore = ks.getCertificateChain(tmpKeyname);
      if (certsInKeystore.length > 1) {
        for (int i = 1; i < certsInKeystore.length; i++) {
          caCerts.add(certsInKeystore[i]);
        }
      }

      this.publicKey = cert.getPublicKey();
      this.certificateChain = X509Util.buildCertPath(cert, caCerts);
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
        | UnrecoverableKeyException | ClassCastException | CertPathBuilderException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  }

  public ConcurrentContentSigner createSigner(AlgorithmIdentifier signatureAlgId, int parallelism,
      SecureRandom random) throws XiSecurityException, NoSuchPaddingException {
    Args.notNull(signatureAlgId, "signatureAlgId");
    Args.positive(parallelism, "parallelism");

    List<XiContentSigner> signers = new ArrayList<>(parallelism);

    String provName = null;
    if (AlgorithmUtil.isRSASigAlgId(signatureAlgId)) {
      provName = "SunRsaSign";
    } else if (AlgorithmUtil.isECSigAlg(signatureAlgId)) {
      // Currently, the provider SunEC is much slower (5x) than BC
      provName = null;
    } else if (AlgorithmUtil.isDSASigAlg(signatureAlgId)) {
      provName = "SUN";
    }

    if (provName != null && Security.getProvider(provName) != null) {
      String algoName;
      try {
        algoName = AlgorithmUtil.getSignatureAlgoName(signatureAlgId);
      } catch (NoSuchAlgorithmException ex) {
        throw new XiSecurityException(ex.getMessage());
      }

      try {
        for (int i = 0; i < parallelism; i++) {
          Signature signature = Signature.getInstance(algoName, provName);
          signature.initSign(key);
          if (i == 0) {
            signature.update(new byte[]{1, 2, 3, 4});
            signature.sign();
          }
          XiContentSigner signer = new SignatureSigner(signatureAlgId, signature, key);
          signers.add(signer);
        }
      } catch (Exception ex) {
        signers.clear();
      }
    }

    if (CollectionUtil.isEmpty(signers)) {
      BcContentSignerBuilder signerBuilder;
      AsymmetricKeyParameter keyparam;
      try {
        if (key instanceof RSAPrivateKey) {
          keyparam = SignerUtil.generateRSAPrivateKeyParameter((RSAPrivateKey) key);
          signerBuilder = new RSAContentSignerBuilder(signatureAlgId);
        } else if (key instanceof DSAPrivateKey) {
          keyparam = DSAUtil.generatePrivateKeyParameter(key);
          signerBuilder = new DSAContentSignerBuilder(signatureAlgId,
              AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId));
        } else if (key instanceof ECPrivateKey) {
          keyparam = ECUtil.generatePrivateKeyParameter(key);
          EllipticCurve curve = ((ECPrivateKey) key).getParams().getCurve();
          if (GMUtil.isSm2primev2Curve(curve)) {
            signerBuilder = new SM2ContentSignerBuilder();
          } else {
            signerBuilder = new ECDSAContentSignerBuilder(signatureAlgId,
                AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId));
          }
        } else {
          throw new XiSecurityException("unsupported key " + key.getClass().getName());
        }
      } catch (InvalidKeyException ex) {
        throw new XiSecurityException("invalid key", ex);
      } catch (NoSuchAlgorithmException ex) {
        throw new XiSecurityException("no such algorithm", ex);
      }

      for (int i = 0; i < parallelism; i++) {
        if (random != null) {
          signerBuilder.setSecureRandom(random);
        }

        ContentSigner signer;
        try {
          signer = signerBuilder.build(keyparam);
        } catch (OperatorCreationException ex) {
          throw new XiSecurityException("operator creation error", ex);
        }
        signers.add(new XiWrappedContentSigner(signer, true));
      }
    }

    final boolean mac = false;
    ConcurrentContentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentContentSigner(mac, signers, key);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    if (certificateChain != null) {
      concurrentSigner.setCertificateChain(certificateChain);
    } else {
      concurrentSigner.setPublicKey(publicKey);
    }
    return concurrentSigner;
  } // createSigner

  public X509Certificate getCertificate() {
    return (certificateChain != null && certificateChain.length > 0) ? certificateChain[0] : null;
  }

  public X509Certificate[] getCertificateChain() {
    return certificateChain;
  }

  public PrivateKey getKey() {
    return key;
  }

}
