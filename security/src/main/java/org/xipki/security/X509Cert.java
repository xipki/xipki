// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Arrays;

import static org.xipki.util.Args.notNull;

/**
 * Wrapper to an {@link X509Certificate}.
 *
 * @author Lijun Liao (xipki)
 * @since 5.3.8
 */

public class X509Cert {

  private final Object sync = new Object();

  private X509CertificateHolder bcInstance;

  private X509Certificate jceInstance;

  private final boolean selfSigned;

  private final X500Name issuer;

  private final BigInteger serialNumber;

  private final X500Name subject;

  private final Instant notBefore;

  private final Instant notAfter;

  private String issuerText;

  private String subjectText;

  private byte[] subjectKeyId;

  private byte[] authorityKeyId;

  private int basicConstraints = -2;

  private boolean keyUsageProcessed;

  private boolean[] keyUsage;

  private boolean sanProcessed;

  private byte[] san;

  private SubjectPublicKeyInfo subjectPublicKeyInfo;

  private PublicKey publicKey;

  private byte[] encoded;

  public X509Cert(Certificate cert) {
    this(new X509CertificateHolder(cert), null);
  }

  public X509Cert(Certificate cert, byte[] encoded) {
    this(new X509CertificateHolder(cert), encoded);
  }

  public X509Cert(X509Certificate cert) {
    this(cert, null);
  }

  public X509Cert(X509Certificate cert, byte[] encoded) {
    this.bcInstance = null;
    this.jceInstance = notNull(cert, "cert");
    this.encoded = encoded;

    this.notBefore = cert.getNotBefore().toInstant();
    this.notAfter = cert.getNotAfter().toInstant();
    this.serialNumber = cert.getSerialNumber();

    this.issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
    this.subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());

    this.selfSigned = subject.equals(issuer);

    byte[] bytes = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
    this.san = bytes == null ? null : ASN1OctetString.getInstance(bytes).getOctets();
    // TODO
  }

  public X509Cert(X509CertificateHolder cert) {
    this(cert, null);
  }

  public X509Cert(X509CertificateHolder cert, byte[] encoded) {
    this.bcInstance = notNull(cert, "cert");
    this.jceInstance = null;
    this.encoded = encoded;

    this.notBefore = cert.getNotBefore().toInstant();
    this.notAfter = cert.getNotAfter().toInstant();
    this.serialNumber = cert.getSerialNumber();

    this.issuer = cert.getIssuer();
    this.subject = cert.getSubject();
    this.selfSigned = subject.equals(issuer);
    this.san = X509Util.getCoreExtValue(cert.getExtensions(), Extension.subjectAlternativeName);
  }

  /**
   * Gets the certificate constraints path length from the
   * critical {@code BasicConstraints} extension, (OID = 2.5.29.19).
   * <p>
   * The basic constraints extension identifies whether the subject
   * of the certificate is a Certificate Authority (CA) and
   * how deep a certification path may exist through that CA. The
   * {@code pathLenConstraint} field (see below) is meaningful
   * only if {@code cA} is set to TRUE. In this case, it gives the
   * maximum number of CA certificates that may follow this certificate in a
   * certification path. A value of zero indicates that only an end-entity
   * certificate may follow in the path.
   * <p>
   * The ASN.1 definition for this is:
   * <pre>
   * BasicConstraints ::= SEQUENCE {
   *     cA                  BOOLEAN DEFAULT FALSE,
   *     pathLenConstraint   INTEGER (0..MAX) OPTIONAL }
   * </pre>
   *
   * @return the value of {@code pathLenConstraint} if the
   *     BasicConstraints extension is present in the certificate and the
   *     subject of the certificate is a CA, otherwise -1.
   *     If the subject of the certificate is a CA and
   *     {@code pathLenConstraint} does not appear,
   *     {@code Integer.MAX_VALUE} is returned to indicate that there is no
   *     limit to the allowed length of the certification path.
   */
  public int getBasicConstraints() {
    if (basicConstraints == -2) {
      synchronized (sync) {
        if (bcInstance != null) {
          byte[] extnValue = getCoreExtValue(Extension.basicConstraints);
          if (extnValue == null) {
            basicConstraints = -1;
          } else {
            BasicConstraints bc = BasicConstraints.getInstance(extnValue);
            if (bc.isCA()) {
              BigInteger bn = bc.getPathLenConstraint();
              basicConstraints = bn == null ? Integer.MAX_VALUE : bn.intValueExact();
            } else {
              basicConstraints = -1;
            }
          }
        } else {
          basicConstraints = jceInstance.getBasicConstraints();
        }
      }
    }

    return basicConstraints;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public String getSerialNumberHex() {
    return "0x" + Hex.encode(serialNumber.toByteArray());
  }

  public PublicKey getPublicKey() {
    if (publicKey == null) {
      synchronized (sync) {
        if (bcInstance != null) {
          try {
            this.publicKey = KeyUtil.generatePublicKey(bcInstance.getSubjectPublicKeyInfo());
          } catch (InvalidKeySpecException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
          }
        } else {
          publicKey = jceInstance.getPublicKey();
        }
      }
    }

    return publicKey;
  }

  public boolean[] getKeyUsage() {
    if (!keyUsageProcessed) {
      synchronized (sync) {
        if (bcInstance != null) {
          byte[] extnValue = getCoreExtValue(Extension.keyUsage);
          if (extnValue == null) {
            keyUsage = null;
          } else {
            org.bouncycastle.asn1.x509.KeyUsage bc =
                org.bouncycastle.asn1.x509.KeyUsage.getInstance(extnValue);
            keyUsage = new boolean[9];
            for (KeyUsage ku : KeyUsage.values()) {
              keyUsage[ku.getBit()] = bc.hasUsages(ku.getBcUsage());
            }
          }
        } else {
          keyUsage = jceInstance.getKeyUsage();
        }
      }

      keyUsageProcessed = true;
    }

    return keyUsage;
  }

  public byte[] getSubjectAltNames() {
    if (!sanProcessed) {
      synchronized (sync) {
        this.san = getCoreExtValue(Extension.subjectAlternativeName);
        sanProcessed = true;
      }
    }

    return san == null ? null : san.clone();
  }

  public X500Name getIssuer() {
    return issuer;
  }

  public X500Name getSubject() {
    return subject;
  }

  public byte[] getSubjectKeyId() {
    if (subjectKeyId == null) {
      synchronized (sync) {
        byte[] extnValue = getCoreExtValue(Extension.subjectKeyIdentifier);
        if (extnValue != null) {
          subjectKeyId = ASN1OctetString.getInstance(extnValue).getOctets();
        }
      }
    }

    return subjectKeyId;
  }

  public byte[] getAuthorityKeyId() {
    if (authorityKeyId == null) {
      synchronized (sync) {
        byte[] extnValue = getCoreExtValue(Extension.authorityKeyIdentifier);
        if (extnValue != null) {
          authorityKeyId = AuthorityKeyIdentifier.getInstance(extnValue).getKeyIdentifier();
        }
      }
    }

    return authorityKeyId;
  }

  public String getSubjectText() {
    if (subjectText == null) {
      synchronized (sync) {
        subjectText = X509Util.x500NameText(subject);
      }
    }

    return subjectText;
  }

  public String getIssuerText() {
    if (issuerText == null) {
      synchronized (sync) {
        issuerText = X509Util.x500NameText(subject);
      }
    }

    return issuerText;
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
    if (subjectPublicKeyInfo == null) {
      synchronized (sync) {
        if (bcInstance != null) {
          subjectPublicKeyInfo = bcInstance.getSubjectPublicKeyInfo();
        } else {
          try {
            subjectPublicKeyInfo = KeyUtil.createSubjectPublicKeyInfo(jceInstance.getPublicKey());
          } catch (InvalidKeyException ex) {
            throw new IllegalStateException("error creating SubjectPublicKeyInfo from PublicKey", ex);
          }
        }
      }
    }

    return subjectPublicKeyInfo;
  }

  public X509Certificate toJceCert() {
    if (jceInstance == null) {
      synchronized (sync) {
        encoded = getEncoded();
        try {
          jceInstance = X509Util.parseX509Certificate(new ByteArrayInputStream(encoded));
        } catch (CertificateException ex) {
          throw new IllegalStateException("error converting to X509Certificate", ex);
        }
      }
    }

    return jceInstance;
  }

  public X509CertificateHolder toBcCert() {
    if (bcInstance == null) {
      synchronized (sync) {
        try {
          encoded = jceInstance.getEncoded();
          bcInstance = new X509CertificateHolder(encoded);
        } catch (CertificateEncodingException | IOException ex) {
          throw new IllegalStateException("error encoding certificate", ex);
        }
      }
    }

    return bcInstance;
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  public Instant getNotBefore() {
    return notBefore;
  }

  public Instant getNotAfter() {
    return notAfter;
  }

  public byte[] getEncoded() {
    if (encoded == null) {
      synchronized (sync) {
        try {
          encoded = (bcInstance != null) ? bcInstance.getEncoded() : jceInstance.getEncoded();
        } catch (CertificateEncodingException | IOException ex) {
          throw new IllegalStateException("error encoding certificate", ex);
        }
      }
    }

    return encoded;
  }

  public String getCommonName() {
    return X509Util.getCommonName(subject);
  }

  public void verify(PublicKey key)
      throws SignatureException, InvalidKeyException, CertificateException,
      NoSuchAlgorithmException, NoSuchProviderException {
    if (jceInstance != null) {
      jceInstance.verify(key, "BC");
    } else {
      SignAlgo signAlgo = SignAlgo.getInstance(bcInstance.getSignatureAlgorithm());
      if (signAlgo == null) {
        throw new NoSuchAlgorithmException("could not detect SignAlgo");
      }
      Signature signature = signAlgo.newSignature("BC");
      checkBcSignature(key, signature);
    }
  }

  public void verify(PublicKey key, String sigProvider)
      throws CertificateException, NoSuchAlgorithmException,
      InvalidKeyException, SignatureException, NoSuchProviderException {
    if (sigProvider == null) {
      verify(key);
    } else {
      if (jceInstance != null) {
        jceInstance.verify(key, sigProvider);
      } else {
        SignAlgo signAlgo = SignAlgo.getInstance(bcInstance.getSignatureAlgorithm());
        if (signAlgo == null) {
          throw new NoSuchAlgorithmException("could not detect SignAlgo");
        }
        Signature signature = signAlgo.newSignature(sigProvider);
        checkBcSignature(key, signature);
      }
    }
  }

  private void checkBcSignature(PublicKey key, Signature signature)
      throws CertificateException, SignatureException, InvalidKeyException {
    Certificate c = bcInstance.toASN1Structure();
    if (!c.getSignatureAlgorithm().equals(c.getTBSCertificate().getSignature())) {
      throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
    }

    signature.initVerify(key);
    try {
      signature.update(c.getTBSCertificate().getEncoded());
    } catch (IOException ex) {
      throw new CertificateException("error encoding TBSCertificate");
    }

    if (!signature.verify(c.getSignature().getBytes())) {
      throw new SignatureException("certificate does not verify with supplied key");
    }
  }

  public byte[] getExtensionCoreValue(ASN1ObjectIdentifier extnType) {
    if (bcInstance != null) {
      Extension extn = bcInstance.getExtensions().getExtension(extnType);
      return extn == null ? null : extn.getExtnValue().getOctets();
    } else {
      byte[] rawValue = jceInstance.getExtensionValue(extnType.getId());
      return rawValue == null ? null : ASN1OctetString.getInstance(rawValue).getOctets();
    }
  }

  public boolean hasKeyusage(KeyUsage usage) {
    boolean[] usages = getKeyUsage();
    return usages == null || usages[usage.getBit()];
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getEncoded());
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    } else if (!(obj instanceof X509Cert)) {
      return false;
    }

    return Arrays.equals(getEncoded(), ((X509Cert) obj).getEncoded());
  }

  private byte[] getCoreExtValue(ASN1ObjectIdentifier extnType) {
    if (bcInstance != null) {
      Extensions extns = bcInstance.getExtensions();
      if (extns == null) {
        return null;
      }
      Extension extn = extns.getExtension(extnType);
      return extn == null ? null : extn.getExtnValue().getOctets();
    } else {
      byte[] rawValue = jceInstance.getExtensionValue(extnType.getId());
      return rawValue == null ? null : ASN1OctetString.getInstance(rawValue).getOctets();
    }
  }

}
