// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cmp.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.crypto.core.SignAlgo;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;

/**
 * Keys, certificates, signers and verifiers for the tests. BouncyCastle is used as the
 * reference implementation.
 *
 * @author Lijun Liao (xipki)
 */
public class TestUtil {

  public static final String BC = "BC";

  static {
    if (Security.getProvider(BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public static class KeyAndCert {
    public final KeyPair keyPair;
    public final X509CertificateHolder bcCert;
    public final Certificate cert;

    KeyAndCert(KeyPair keyPair, X509CertificateHolder bcCert) throws Exception {
      this.keyPair = keyPair;
      this.bcCert = bcCert;
      this.cert = Certificate.fromEncoded(bcCert.getEncoded());
    }

    public X509Certificate jceCert() throws Exception {
      return new JcaX509CertificateConverter()
          .setProvider(BC).getCertificate(bcCert);
    }
  }

  private static KeyAndCert rsa;

  private static KeyAndCert ec;

  public static synchronized KeyAndCert rsa() throws Exception {
    if (rsa == null) {
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BC);
      kpGen.initialize(2048);
      rsa = selfSigned(kpGen.generateKeyPair(), "SHA256withRSA", "CN=RSA Test");
    }
    return rsa;
  }

  public static synchronized KeyAndCert ec() throws Exception {
    if (ec == null) {
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", BC);
      kpGen.initialize(new ECGenParameterSpec("secp256r1"));
      ec = selfSigned(kpGen.generateKeyPair(), "SHA256withECDSA", "CN=EC Test");
    }
    return ec;
  }

  public static KeyPair newEcKeyPair() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", BC);
    kpGen.initialize(new ECGenParameterSpec("secp256r1"));
    return kpGen.generateKeyPair();
  }

  private static KeyAndCert selfSigned(KeyPair kp, String sigAlg, String subject)
      throws Exception {
    X500Name name = new X500Name(subject);
    long now = System.currentTimeMillis();
    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name,
        BigInteger.valueOf(now), new Date(now - 60_000), new Date(now + 86_400_000L), name,
        kp.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(Extension.subjectKeyIdentifier, false,
        new JcaX509ExtensionUtils().createSubjectKeyIdentifier(kp.getPublic()));
    X509CertificateHolder cert = builder.build(
        new JcaContentSignerBuilder(sigAlg).setProvider(BC).build(kp.getPrivate()));
    return new KeyAndCert(kp, cert);
  }

  /**
   * A {@link ContentSigner} with JCA {@link Signature}.
   */
  public static ContentSigner signer(PrivateKey key, String jceAlg, AlgorithmIdentifier algId) {

    final Integer c509AlgId = x509ToC509AlgId(algId);

    return new ContentSigner() {
      private final ByteArrayOutputStream out = new ByteArrayOutputStream();

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algId;
      }

      @Override
      public Integer getC509AlgorithmIdentifier() {
        return c509AlgId;
      }

      @Override
      public OutputStream getOutputStream() {
        out.reset();
        return out;
      }

      @Override
      public byte[] getSignature() throws SignatureException {
        try {
          Signature sig = Signature.getInstance(jceAlg, BC);
          sig.initSign(key);
          sig.update(out.toByteArray());
          return sig.sign();
        } catch (GeneralSecurityException e) {
          throw new SignatureException(e);
        }
      }
    };
  }

  /**
   * A {@link ContentVerifierProvider} with JCA {@link Signature}, the algorithm name is
   * resolved by BouncyCastle.
   */
  public static ContentVerifierProvider verifierProvider(PublicKey key, Certificate cert) {
    return new ContentVerifierProvider() {
      @Override
      public boolean hasAssociatedCertificate() {
        return cert != null;
      }

      @Override
      public boolean isAssociatedCertificateValidOn(Instant time) {
        return cert != null && cert.isValidOn(time);
      }

      private ContentVerifier get(
          ByteArrayOutputStream out, String name, AlgorithmIdentifier algId, Integer c509AlgId)
          throws GenerationException {
        return new ContentVerifier() {
          @Override
          public AlgorithmIdentifier getAlgorithmIdentifier() {
            return algId;
          }

          @Override
          public Integer getC509AlgorithmIdentifier() {
            return c509AlgId;
          }

          @Override
          public OutputStream getOutputStream() {
            out.reset();
            return out;
          }

          @Override
          public boolean verify(byte[] signature) throws SignatureException {
            try {
              Signature sig = Signature.getInstance(name, BC);
              sig.initVerify(key);
              sig.update(out.toByteArray());
              return sig.verify(signature);
            } catch (GeneralSecurityException e) {
              throw new SignatureException(e);
            }
          }
        };
      }

      @Override
      public ContentVerifier get(AlgorithmIdentifier algId) throws GenerationException {
        String name = new DefaultAlgorithmNameFinder().getAlgorithmName(
            org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(algId.getEncoded()));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        final Integer c509AlgId = x509ToC509AlgId(algId);
        return get(out, name, algId, c509AlgId);
      }

      @Override
      public ContentVerifier getForC509(int c509AlgId) throws GenerationException {
        SignAlgo signAlgo;
        try {
          signAlgo = SignAlgo.ofC509AlgorithmIdentifier(c509AlgId);
        } catch (NoSuchAlgorithmException e) {
          throw new GenerationException(e);
        }

        AlgorithmIdentifier algId = signAlgo.algorithmIdentifier();
        String name = new DefaultAlgorithmNameFinder().getAlgorithmName(
            org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(algId.getEncoded()));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        return get(out, name, algId, c509AlgId);
      }
    };
  }

  private static Integer x509ToC509AlgId(AlgorithmIdentifier x509AlgId) {
    try {
      return SignAlgo.ofAlgorithmIdentifier(x509AlgId).c509AlgorithmIdentifier();
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
  }

}
