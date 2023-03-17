// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.exception.ObjectCreationException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

import static org.xipki.util.Args.positive;

/**
 * An implementation of {@link SecurityFactory}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class SecurityFactoryImpl extends AbstractSecurityFactory {

  private static final Logger LOG = LoggerFactory.getLogger(SecurityFactoryImpl.class);

  private int defaultSignerParallelism = 32;

  private PasswordResolver passwordResolver;

  private SignerFactoryRegister signerFactoryRegister;

  private KeypairGeneratorFactoryRegister keypairGeneratorFactoryRegister;

  private boolean strongRandom4KeyEnabled;

  private boolean strongRandom4SignEnabled;

  static {
    // Log the System Information
    LogUtil.logSystemInfo(LOG);
  }

  public SecurityFactoryImpl() {
  }

  @Override
  public Set<String> getSupportedSignerTypes() {
    return signerFactoryRegister.getSupportedSignerTypes();
  }

  public boolean isStrongRandom4KeyEnabled() {
    return strongRandom4KeyEnabled;
  }

  public void setStrongRandom4KeyEnabled(boolean strongRandom4KeyEnabled) {
    this.strongRandom4KeyEnabled = strongRandom4KeyEnabled;
  }

  public boolean isStrongRandom4SignEnabled() {
    return strongRandom4SignEnabled;
  }

  public void setStrongRandom4SignEnabled(boolean strongRandom4SignEnabled) {
    this.strongRandom4SignEnabled = strongRandom4SignEnabled;
  }

  @Override
  public ConcurrentContentSigner createSigner(String type, SignerConf conf, X509Cert[] certificateChain)
      throws ObjectCreationException {
    ConcurrentContentSigner signer = signerFactoryRegister.newSigner(this, type, conf, certificateChain);
    if (!signer.isMac()) {
      validateSigner(signer, type, conf);
    }
    return signer;
  }

  @Override
  public Set<String> getSupportedKeypairGeneratorTypes() {
    return keypairGeneratorFactoryRegister.getSupportedGeneratorTypes();
  }

  @Override
  public KeypairGenerator createKeypairGenerator(String type, String conf) throws ObjectCreationException {
    return keypairGeneratorFactoryRegister.newKeypairGenerator(this, type, conf);
  }

  @Override
  public ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey, DHSigStaticKeyCertPair ownerKeyAndCert)
      throws InvalidKeyException {
    return SignerUtil.getContentVerifierProvider(publicKey, ownerKeyAndCert);
  }

  @Override
  public PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws InvalidKeyException {
    try {
      return KeyUtil.generatePublicKey(subjectPublicKeyInfo);
    } catch (InvalidKeySpecException ex) {
      throw new InvalidKeyException(ex.getMessage(), ex);
    }
  }

  @Override
  public boolean verifyPop(PKCS10CertificationRequest csr, AlgorithmValidator algoValidator,
                           DHSigStaticKeyCertPair ownerKeyAndCert) {
    if (algoValidator == null) {
      algoValidator = CollectionAlgorithmValidator.INSTANCE;
    }

    AlgorithmIdentifier algId = csr.getSignatureAlgorithm();

    if (!algoValidator.isAlgorithmPermitted(algId)) {
      String algoName;
      try {
        algoName = SignAlgo.getInstance(algId).getJceName();
      } catch (NoSuchAlgorithmException ex) {
        algoName = algId.getAlgorithm().getId();
      }

      LOG.error("POP signature algorithm {} not permitted", algoName);
      return false;
    }

    SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();

    try {
      PublicKey pk = KeyUtil.generatePublicKey(pkInfo);
      ContentVerifierProvider cvp = getContentVerifierProvider(pk, ownerKeyAndCert);
      return csr.isSignatureValid(cvp);
    } catch (InvalidKeyException | PKCSException | InvalidKeySpecException ex) {
      LogUtil.error(LOG, ex, "could not validate POP of CSR");
      return false;
    }
  } // method verifyPop

  @Override
  public int getDfltSignerParallelism() {
    return defaultSignerParallelism;
  }

  public void setDefaultSignerParallelism(int defaultSignerParallelism) {
    this.defaultSignerParallelism = positive(defaultSignerParallelism, "defaultSignerParallelism");
  }

  public void setSignerFactoryRegister(SignerFactoryRegister signerFactoryRegister) {
    this.signerFactoryRegister = signerFactoryRegister;
  }

  public void setKeypairGeneratorFactoryRegister(KeypairGeneratorFactoryRegister keypairGeneratorFactoryRegister) {
    this.keypairGeneratorFactoryRegister = keypairGeneratorFactoryRegister;
  }

  public void setPasswordResolver(PasswordResolver passwordResolver) {
    this.passwordResolver = passwordResolver;
  }

  @Override
  public PasswordResolver getPasswordResolver() {
    return passwordResolver;
  }

  @Override
  public SecureRandom getRandom4Key() {
    return getSecureRandom(strongRandom4KeyEnabled);
  }

  @Override
  public SecureRandom getRandom4Sign() {
    return getSecureRandom(strongRandom4SignEnabled);
  }

  private static SecureRandom getSecureRandom(boolean strong) {
    if (!strong) {
      return new SecureRandom();
    }

    try {
      return SecureRandom.getInstanceStrong();
    } catch (NoSuchAlgorithmException ex) {
      throw new RuntimeCryptoException("could not get strong SecureRandom: " + ex.getMessage());
    }
  } // method getSecureRandom

  private static void validateSigner(ConcurrentContentSigner signer, String signerType, SignerConf signerConf)
      throws ObjectCreationException {
    if (signer.getPublicKey() == null) {
      return;
    }

    try {
      String signatureAlgoName = signer.getAlgorithm().getJceName();

      byte[] dummyContent = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      Signature verifier;
      try {
        verifier = Signature.getInstance(signatureAlgoName, "BC");
      } catch (NoSuchAlgorithmException ex) {
        verifier = Signature.getInstance(signatureAlgoName);
      }

      byte[] signatureValue = signer.sign(dummyContent);

      verifier.initVerify(signer.getPublicKey());
      verifier.update(dummyContent);
      boolean valid = verifier.verify(signatureValue);

      if (!valid) {
        StringBuilder sb = new StringBuilder()
            .append("private key and public key does not match, key type='").append(signerType).append("'; ");
        String pwd = signerConf.getConfValue("password");
        if (pwd != null) {
          signerConf.putConfEntry("password", "****");
        }
        signerConf.putConfEntry("algo", signatureAlgoName);
        sb.append("conf='").append(signerConf.getConf());
        X509Cert cert = signer.getCertificate();
        if (cert != null) {
          sb.append("', certificate subject='").append(cert.getSubjectText()).append("'");
        }

        throw new ObjectCreationException(sb.toString());
      }
    } catch (GeneralSecurityException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }
  } // method validateSigner

}
