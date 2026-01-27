// Copyright (c) 2013-2026 xipki. All rights reserved.
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
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.io.IoUtil;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

/**
 * An implementation of {@link SecurityFactory}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class SecurityFactoryImpl implements SecurityFactory {

  private static final Logger LOG =
      LoggerFactory.getLogger(SecurityFactoryImpl.class);

  private int defaultSignerParallelism = 32;

  private SignerFactoryRegister signerFactoryRegister;

  private boolean strongRandom4KeyEnabled;

  private boolean strongRandom4SignEnabled;

  private String csrConfFile;

  private CsrControl csrControl;

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
  public CsrControl getCsrControl() {
    if (csrControl == null) {
      Path confFilePath = null;
      // ignore if file does not exist or is not configured.
      if (csrConfFile != null) {
        confFilePath = Path.of(IoUtil.expandFilepath(csrConfFile));
        if (!Files.exists(confFilePath)) {
          confFilePath = null;
        }
      }

      if (confFilePath != null) {
        try {
          JsonMap root = JsonParser.parseMap(confFilePath, true);
          CsrControl.CsrControlConf conf =
              CsrControl.CsrControlConf.parse(root);
          this.csrControl = new CsrControl(conf);
        } catch (Exception e) {
          LogUtil.error(LOG, e,
              "error initializing CsrControl with conf file " + csrConfFile);
        }
      }

      if (this.csrControl == null) {
        this.csrControl = new CsrControl();
      }
    }

    return csrControl;
  }

  public void setCsrConfFile(String csrConfFile) {
    this.csrConfFile = csrConfFile;
  }

  @Override
  public ConcurrentContentSigner createSigner(
      String type, SignerConf conf, X509Cert[] certificateChain)
      throws ObjectCreationException {
    ConcurrentContentSigner signer = signerFactoryRegister.newSigner(
        this, type, conf, certificateChain);
    if (!signer.isMac()) {
      validateSigner(signer, type, conf);
    }
    return signer;
  }

  @Override
  public ContentVerifierProvider getContentVerifierProvider(
      PublicKey publicKey, DHSigStaticKeyCertPair ownerKeyAndCert,
      SecretKey ownerMasterKey) throws InvalidKeyException {
    return KeyUtil.getContentVerifierProvider(publicKey, ownerKeyAndCert,
        ownerMasterKey);
  }

  @Override
  public PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
      throws InvalidKeyException {
    try {
      return KeyUtil.getPublicKey(subjectPublicKeyInfo);
    } catch (InvalidKeySpecException ex) {
      throw new InvalidKeyException(ex.getMessage(), ex);
    }
  }

  @Override
  public boolean verifyPop(
      PKCS10CertificationRequest csr, AlgorithmValidator algoValidator,
      DHSigStaticKeyCertPair ownerKeyAndCert, SecretKey ownerMasterKey) {
    if (algoValidator == null) {
      algoValidator = CollectionAlgorithmValidator.INSTANCE;
    }

    AlgorithmIdentifier algId = csr.getSignatureAlgorithm();

    if (!algoValidator.isAlgorithmPermitted(algId)) {
      String algoName;
      try {
        algoName = SignAlgo.getInstance(algId).getJceName();
      } catch (Exception ex) {
        algoName = algId.getAlgorithm().getId();
      }

      LOG.error("POP signature algorithm {} not permitted", algoName);
      return false;
    }

    SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();

    try {
      PublicKey pk = KeyUtil.getPublicKey(pkInfo);
      ContentVerifierProvider cvp = getContentVerifierProvider(
          pk, ownerKeyAndCert, ownerMasterKey);
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
    this.defaultSignerParallelism = Args.positive(
        defaultSignerParallelism, "defaultSignerParallelism");
  }

  public void setSignerFactoryRegister(
      SignerFactoryRegister signerFactoryRegister) {
    this.signerFactoryRegister = signerFactoryRegister;
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
      throw new RuntimeCryptoException(
          "could not get strong SecureRandom: " + ex.getMessage());
    }
  } // method getSecureRandom

  private static void validateSigner(
      ConcurrentContentSigner signer, String signerType, SignerConf signerConf)
      throws ObjectCreationException {
    if (signer.getPublicKey() == null) {
      return;
    }

    try {
      SignAlgo signatureAlgo = signer.getAlgorithm();

      byte[] dummyContent = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      Signature verifier;
      try {
        verifier = Signature.getInstance(signatureAlgo.getJceName(), "BC");
      } catch (NoSuchAlgorithmException ex) {
        verifier = Signature.getInstance(signatureAlgo.getJceName());
      }

      byte[] signatureValue = signer.sign(dummyContent);
      verifier.initVerify(signer.getPublicKey());
      verifier.update(dummyContent);
      boolean valid = verifier.verify(signatureValue);

      if (!valid) {
        SignerConf copy = signerConf.copy();
        StringBuilder sb = new StringBuilder()
            .append("private key and public key does not match, key type='")
            .append(signerType).append("'; ");
        String pwd = copy.getPassword();
        if (pwd != null) {
          copy.setPassword("****");
        }
        copy.setAlgo(signatureAlgo);
        sb.append("conf='").append(copy.getConf());
        X509Cert cert = signer.getCertificate();
        if (cert != null) {
          sb.append("', certificate subject='").append(cert.getSubjectText())
              .append("'");
        }

        throw new ObjectCreationException(sb.toString());
      }
    } catch (GeneralSecurityException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }
  } // method validateSigner

}
