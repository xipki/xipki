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
import org.xipki.util.ObjectCreationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;
import java.util.Set;

import static org.xipki.util.Args.*;

/**
 * An implementation of {@link SecurityFactory}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SecurityFactoryImpl extends AbstractSecurityFactory {

  private static final Logger LOG = LoggerFactory.getLogger(SecurityFactoryImpl.class);

  private int defaultSignerParallelism = 32;

  private PasswordResolver passwordResolver;

  private SignerFactoryRegister signerFactoryRegister;

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
  public ConcurrentContentSigner createSigner(String type, SignerConf conf,
      X509Cert[] certificateChain)
          throws ObjectCreationException {
    ConcurrentContentSigner signer = signerFactoryRegister.newSigner(this, type, conf,
        certificateChain);

    if (!signer.isMac()) {
      validateSigner(signer, type, conf);
    }
    return signer;
  }

  @Override
  public ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey,
      DHSigStaticKeyCertPair ownerKeyAndCert)
          throws InvalidKeyException {
    return SignerUtil.getContentVerifierProvider(publicKey, ownerKeyAndCert);
  }

  @Override
  public PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
      throws InvalidKeyException {
    try {
      return KeyUtil.generatePublicKey(subjectPublicKeyInfo);
    } catch (InvalidKeySpecException ex) {
      throw new InvalidKeyException(ex.getMessage(), ex);
    }
  }

  @Override
  public boolean verifyPop(PKCS10CertificationRequest csr, AlgorithmValidator algoValidator,
      DHSigStaticKeyCertPair ownerKeyAndCert) {
    if (algoValidator != null) {
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
    this.defaultSignerParallelism = positive(
        defaultSignerParallelism, "defaultSignerParallelism");
  }

  public void setSignerFactoryRegister(SignerFactoryRegister signerFactoryRegister) {
    this.signerFactoryRegister = signerFactoryRegister;
  }

  public void setPasswordResolver(PasswordResolver passwordResolver) {
    this.passwordResolver = passwordResolver;
  }

  @Override
  public PasswordResolver getPasswordResolver() {
    return passwordResolver;
  }

  @Override
  public KeyCertPair createPrivateKeyAndCert(String type, SignerConf conf,
      X509Cert cert)
      throws ObjectCreationException {
    conf.putConfEntry("parallelism", Integer.toString(1));

    X509Cert[] certs = null;
    if (cert != null) {
      certs = new X509Cert[]{cert};
    }

    ConcurrentContentSigner signer = signerFactoryRegister.newSigner(this, type, conf, certs);
    PrivateKey privateKey = (PrivateKey) signer.getSigningKey();
    return new KeyCertPair(privateKey, signer.getCertificate());
  } // method createPrivateKeyAndCert

  @Override
  public SecureRandom getRandom4Key() {
    return getSecureRandom(strongRandom4KeyEnabled);
  }

  @Override
  public SecureRandom getRandom4Sign() {
    return getSecureRandom(strongRandom4SignEnabled);
  }

  @Override
  public byte[] extractMinimalKeyStore(String keystoreType, byte[] keystoreBytes, String keyname,
      char[] password, X509Cert[] newCertChain)
          throws KeyStoreException {
    notBlank(keystoreType, "keystoreType");
    notNull(keystoreBytes, "keystoreBytes");

    try {
      KeyStore ks = KeyUtil.getKeyStore(keystoreType);
      ks.load(new ByteArrayInputStream(keystoreBytes), password);

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
          throw new KeyStoreException("unknown key named " + tmpKeyname);
        }
      }

      Enumeration<String> aliases = ks.aliases();
      int numAliases = 0;
      while (aliases.hasMoreElements()) {
        aliases.nextElement();
        numAliases++;
      }

      if (tmpKeyname == null) {
        throw new KeyStoreException("no key entry is contained in the keystore");
      }

      java.security.cert.Certificate[] certs;
      if (newCertChain == null || newCertChain.length < 1) {
        if (numAliases == 1) {
          return keystoreBytes;
        }
        certs = ks.getCertificateChain(tmpKeyname);
      } else {
        certs = new java.security.cert.Certificate[newCertChain.length];
        for (int i = 0; i < newCertChain.length; i++) {
          certs[i] = newCertChain[i].toJceCert();
        }
      }

      KeyStore newKs = KeyUtil.getKeyStore(keystoreType);
      newKs.load(null, password);

      PrivateKey key = (PrivateKey) ks.getKey(tmpKeyname, password);
      newKs.setKeyEntry(tmpKeyname, key, password, certs);
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      newKs.store(bout, password);
      byte[] bytes = bout.toByteArray();
      bout.close();
      return bytes;
    } catch (Exception ex) {
      if (ex instanceof KeyStoreException) {
        throw (KeyStoreException) ex;
      } else {
        throw new KeyStoreException(ex.getMessage(), ex);
      }
    }
  } // method extractMinimalKeyStore

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

  private static void validateSigner(ConcurrentContentSigner signer, String signerType,
      SignerConf signerConf)
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
        StringBuilder sb = new StringBuilder();
        sb.append("private key and public key does not match, ");
        sb.append("key type='").append(signerType).append("'; ");
        String pwd = signerConf.getConfValue("password");
        if (pwd != null) {
          signerConf.putConfEntry("password", "****");
        }
        signerConf.putConfEntry("algo", signatureAlgoName);
        sb.append("conf='").append(signerConf.getConf());
        X509Cert cert = signer.getCertificate();
        if (cert != null) {
          String subject = cert.getSubjectRfc4519Text();
          sb.append("', certificate subject='").append(subject).append("'");
        }

        throw new ObjectCreationException(sb.toString());
      }
    } catch (NoSuchAlgorithmException | InvalidKeyException
        | SignatureException | NoSuchProviderException | NoIdleSignerException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }
  } // method validateSigner

  @Override
  public void refreshTokenForSignerType(String signerType)
      throws XiSecurityException {
    signerFactoryRegister.refreshTokenForSignerType(signerType);
  }

}
