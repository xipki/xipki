/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

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
import org.xipki.security.SignAlgo;
import org.xipki.security.SignatureSigner;
import org.xipki.security.X509Cert;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;
import org.xipki.security.XiWrappedContentSigner;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.CollectionUtil;

/**
 * Builder of signer based PKCS#12 keystore.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P12ContentSignerBuilder {

  // CHECKSTYLE:SKIP
  private static class RSAContentSignerBuilder extends BcContentSignerBuilder {

    private final SignAlgo sigAlgo;

    private RSAContentSignerBuilder(SignAlgo sigAlgo)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
      super(sigAlgo.getAlgorithmIdentifier(), sigAlgo.getHashAlgo().getAlgorithmIdentifier());
      if (!(sigAlgo.isRSAPSSSigAlgo() || sigAlgo.isRSAPkcs1SigAlgo())) {
        throw new NoSuchAlgorithmException("the given algorithm is not a valid RSA signature "
            + "algorithm '" + sigAlgo + "'");
      }
      this.sigAlgo = sigAlgo;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException {
      sigAlgo.assertSameAlgorithm(sigAlgId, digAlgId);
      if (sigAlgo.isRSAPSSSigAlgo()) {
        try {
          return SignerUtil.createPSSRSASigner(sigAlgo);
        } catch (XiSecurityException ex) {
          throw new OperatorCreationException(ex.getMessage(), ex);
        }
      } else {
        Digest dig = digestProvider.get(digAlgId);
        return new RSADigestSigner(dig);
      }
    }

  } // class RSAContentSignerBuilder

  // CHECKSTYLE:SKIP
  private static class DSAContentSignerBuilder extends BcContentSignerBuilder {

    private final SignAlgo sigAlgo;

    private DSAContentSignerBuilder(SignAlgo sigAlgo)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
      super(sigAlgo.getAlgorithmIdentifier(), sigAlgo.getHashAlgo().getAlgorithmIdentifier());
      if (!sigAlgo.isDSASigAlgo()) {
        throw new NoSuchAlgorithmException("the given algorithm is not a valid DSA signature "
            + "algirthm " + sigAlgo);
      }
      this.sigAlgo = sigAlgo;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException {
      sigAlgo.assertSameAlgorithm(sigAlgId, digAlgId);
      Digest dig = sigAlgo.getHashAlgo().createDigest();
      return new DSADigestSigner(new DSASigner(), dig);
    }

  } // class DSAContentSignerBuilder

  // CHECKSTYLE:SKIP
  private static class ECDSAContentSignerBuilder extends BcContentSignerBuilder {

    private final SignAlgo sigAlgo;

    private ECDSAContentSignerBuilder(SignAlgo sigAlgo)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
      super(sigAlgo.getAlgorithmIdentifier(), sigAlgo.getHashAlgo().getAlgorithmIdentifier());
      if (!sigAlgo.isECDSASigAlgo()) {
        throw new NoSuchAlgorithmException("the given algorithm is not a valid ECDSA signature "
            + "algirthm " + sigAlgo);
      }
      this.sigAlgo = sigAlgo;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException {
      sigAlgo.assertSameAlgorithm(sigAlgId, digAlgId);

      Digest dig = sigAlgo.getHashAlgo().createDigest();
      ECDSASigner dsaSigner = new ECDSASigner();

      return sigAlgo.isPlainECDSASigAlgo()
          ? new DSAPlainDigestSigner(dsaSigner, dig)
          : new DSADigestSigner(dsaSigner, dig);
    }

  } // class ECDSAContentSignerBuilder

  // CHECKSTYLE:SKIP
  private static class SM2ContentSignerBuilder extends BcContentSignerBuilder {

    private final SignAlgo sigAlgo;

    private SM2ContentSignerBuilder(SignAlgo sigAlgo)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
      super(sigAlgo.getAlgorithmIdentifier(), sigAlgo.getHashAlgo().getAlgorithmIdentifier());
      if (!sigAlgo.isSM2SigAlgo()) {
        throw new NoSuchAlgorithmException("the given algorithm is not a valid SM2 signature "
            + "algirthm " + sigAlgo);
      }
      this.sigAlgo = sigAlgo;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException {
      sigAlgo.assertSameAlgorithm(sigAlgId, digAlgId);
      return new SM2Signer(sigAlgo.getHashAlgo().createDigest());
    }

  } // class SM2ContentSignerBuilder

  private final PrivateKey key;

  private final PublicKey publicKey;

  private final X509Cert[] certificateChain;

  public P12ContentSignerBuilder(PrivateKey privateKey, PublicKey publicKey)
      throws XiSecurityException {
    this.key = notNull(privateKey, "privateKey");
    this.publicKey = notNull(publicKey, "publicKey");
    this.certificateChain = null;
  }

  public P12ContentSignerBuilder(KeypairWithCert keypairWithCert)
      throws XiSecurityException {
    notNull(keypairWithCert, "keypairWithCert");
    this.key = keypairWithCert.getKey();
    this.publicKey = keypairWithCert.getPublicKey();
    this.certificateChain = keypairWithCert.getCertificateChain();
  }

  public X509Cert getCertificate() {
    return (certificateChain != null && certificateChain.length > 0) ? certificateChain[0] : null;
  }

  public X509Cert[] getCertificateChain() {
    return certificateChain;
  }

  public PrivateKey getKey() {
    return key;
  }

  public ContentSigner createContentSigner(SignAlgo sigAlgo, SecureRandom random)
          throws XiSecurityException, NoSuchPaddingException {
    notNull(sigAlgo, "sigAlgo");

    String provName = getProviderName(sigAlgo);

    if (provName != null && Security.getProvider(provName) != null) {
      try {
        Signature signature = createSignature(sigAlgo, provName, true);
        return new SignatureSigner(sigAlgo, signature, key);
      } catch (Exception ex) {
        // do nothing
      }
    }

    Object[] rv = ff(sigAlgo, random);
    BcContentSignerBuilder signerBuilder = (BcContentSignerBuilder) rv[0];
    AsymmetricKeyParameter keyparam = (AsymmetricKeyParameter) rv[1];

    try {
      return signerBuilder.build(keyparam);
    } catch (OperatorCreationException ex) {
      throw new XiSecurityException("operator creation error", ex);
    }
  } // method createContentSigner

  public ConcurrentContentSigner createSigner(SignAlgo sigAlgo, int parallelism,
      SecureRandom random)
          throws XiSecurityException, NoSuchPaddingException {
    notNull(sigAlgo, "sigAlgo");
    positive(parallelism, "parallelism");

    List<XiContentSigner> signers = new ArrayList<>(parallelism);

    String provName = getProviderName(sigAlgo);
    if (provName != null && Security.getProvider(provName) != null) {
      try {
        for (int i = 0; i < parallelism; i++) {
          Signature signature = createSignature(sigAlgo, provName, i == 0);
          XiContentSigner signer = new SignatureSigner(sigAlgo, signature, key);
          signers.add(signer);
        }
      } catch (Exception ex) {
        signers.clear();
      }
    }

    if (CollectionUtil.isEmpty(signers)) {
      Object[] rv = ff(sigAlgo, random);
      BcContentSignerBuilder signerBuilder = (BcContentSignerBuilder) rv[0];
      AsymmetricKeyParameter keyparam = (AsymmetricKeyParameter) rv[1];

      for (int i = 0; i < parallelism; i++) {
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
  } // method createSigner

  private String getProviderName(SignAlgo sigAlgo) {
    String provName = null;
    if (sigAlgo.isRSAPkcs1SigAlgo()) {
      provName = "SunRsaSign";
    } else if (sigAlgo.isECDSASigAlgo()) {
      // Currently, the provider SunEC is much slower (5x) than BC,
      // so we do not use the Signature variant.
      provName = null;
    } else if (sigAlgo.isDSASigAlgo()) {
      provName = "SUN";
    } else if (sigAlgo.isEDDSASigAlgo()) {
      provName = "BC";
    }
    return provName;
  }

  private Signature createSignature(SignAlgo sigAlgo, String provName, boolean test)
      throws NoSuchAlgorithmException, NoSuchProviderException,
      InvalidKeyException, SignatureException {
    Signature signature = Signature.getInstance(sigAlgo.getJceName(), provName);
    signature.initSign(key);
    if (test) {
      signature.update(new byte[]{1, 2, 3, 4});
      signature.sign();
    }
    return signature;
  }

  private Object[] ff(SignAlgo sigAlgo, SecureRandom random)
      throws NoSuchPaddingException, XiSecurityException {
    BcContentSignerBuilder signerBuilder;
    AsymmetricKeyParameter keyparam;
    try {
      if (key instanceof RSAPrivateKey) {
        keyparam = SignerUtil.generateRSAPrivateKeyParameter((RSAPrivateKey) key);
        signerBuilder = new RSAContentSignerBuilder(sigAlgo);
      } else if (key instanceof DSAPrivateKey) {
        keyparam = DSAUtil.generatePrivateKeyParameter(key);
        signerBuilder = new DSAContentSignerBuilder(sigAlgo);
      } else if (key instanceof ECPrivateKey) {
        keyparam = ECUtil.generatePrivateKeyParameter(key);
        EllipticCurve curve = ((ECPrivateKey) key).getParams().getCurve();
        if (GMUtil.isSm2primev2Curve(curve)) {
          signerBuilder = new SM2ContentSignerBuilder(sigAlgo);
        } else {
          signerBuilder = new ECDSAContentSignerBuilder(sigAlgo);
        }
      } else {
        throw new XiSecurityException("unsupported key " + key.getClass().getName());
      }
    } catch (InvalidKeyException ex) {
      throw new XiSecurityException("invalid key", ex);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException("no such algorithm", ex);
    }

    if (random != null) {
      signerBuilder.setSecureRandom(random);
    }

    return new Object[] {signerBuilder, keyparam};
  }

}
