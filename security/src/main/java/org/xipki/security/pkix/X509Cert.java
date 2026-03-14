// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkix;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.BigIntegers;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.asn1.ASIdOrRange;
import org.xipki.security.asn1.ASIdentifierChoice;
import org.xipki.security.asn1.ASIdentifiers;
import org.xipki.security.asn1.ASN1IPAddressFamily;
import org.xipki.security.asn1.IPAddrBlocks;
import org.xipki.security.asn1.IPAddressChoice;
import org.xipki.security.asn1.IPAddressOrRange;
import org.xipki.security.composite.CompositeMLDSAPublicKey;
import org.xipki.security.composite.CompositeSigUtil;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Vector;

/**
 * Wrapper to an {@link Certificate}.
 *
 * @author Lijun Liao (xipki)
 */

public class X509Cert {

  private static final byte[] DER_NULL = new byte[] {5, 0};

  private final Certificate cert;

  private final X509CertificateHolder certHolder;

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

  private final int basicConstraints;

  private final boolean[] keyUsage;

  private final byte[] encoded;

  private final int hashCode;

  private final byte[] sha256fp;

  private boolean sanProcessed;

  private byte[] san;

  private PublicKey publicKey;

  public X509Cert(Certificate cert) {
    this(cert, null);
  }

  public X509Cert(Certificate cert, byte[] encoded) {
    this(new X509CertificateHolder(Args.notNull(cert, "cert")), encoded);
  }

  public X509Cert(X509CertificateHolder certHolder) {
    this(certHolder, null);
  }

  public X509Cert(X509CertificateHolder certHolder, byte[] encoded) {
    this.certHolder = Args.notNull(certHolder, "certHolder");
    this.cert = certHolder.toASN1Structure();

    this.notBefore = certHolder.getNotBefore().toInstant();
    this.notAfter = certHolder.getNotAfter().toInstant();
    this.serialNumber = certHolder.getSerialNumber();

    this.issuer = cert.getIssuer();
    this.subject = cert.getSubject();
    this.selfSigned = subject.equals(issuer);
    this.san = getCoreExtValue(OIDs.Extn.subjectAlternativeName);

    // basic constraints
    byte[] extnValue = getCoreExtValue(OIDs.Extn.basicConstraints);
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

    // keyusage
    extnValue = getCoreExtValue(OIDs.Extn.keyUsage);
    if (extnValue == null) {
      keyUsage = null;
    } else {
      org.bouncycastle.asn1.x509.KeyUsage bc =
          org.bouncycastle.asn1.x509.KeyUsage.getInstance(extnValue);
      keyUsage = new boolean[9];
      for (org.xipki.security.pkix.KeyUsage ku : org.xipki.security.pkix.KeyUsage.values()) {
        keyUsage[ku.bit()] = bc.hasUsages(ku.bcUsage());
      }
    }

    if (encoded != null) {
      this.encoded = encoded;
    } else {
      try {
        this.encoded = cert.getEncoded();
      } catch (IOException ex) {
        throw new IllegalStateException("error encoding certificate", ex);
      }
    }

    this.sha256fp = HashAlgo.SHA256.hash(this.encoded);
    this.hashCode = Arrays.hashCode(this.sha256fp);
  }

  public X509CertificateHolder getCertHolder() {
    return certHolder;
  }

  public Certificate getCert() {
    return cert;
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
  public int basicConstraints() {
    return basicConstraints;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public String serialNumberHex() {
    return "0x" + Hex.encode(serialNumber.toByteArray());
  }

  public PublicKey publicKey() {
    if (publicKey == null) {
      try {
        this.publicKey = KeyUtil.getPublicKey(cert.getSubjectPublicKeyInfo());
      } catch (InvalidKeySpecException ex) {
        throw new IllegalStateException(ex.getMessage(), ex);
      }
    }
    return publicKey;
  }

  public boolean[] keyUsage() {
    return keyUsage;
  }

  public byte[] subjectAltNames() {
    if (!sanProcessed) {
      this.san = getCoreExtValue(OIDs.Extn.subjectAlternativeName);
      sanProcessed = true;
    }

    return san == null ? null : san.clone();
  }

  public X500Name issuer() {
    return issuer;
  }

  public X500Name subject() {
    return subject;
  }

  public byte[] subjectKeyId() {
    if (subjectKeyId == null) {
      byte[] extnValue = getCoreExtValue(OIDs.Extn.subjectKeyIdentifier);
      if (extnValue != null) {
        subjectKeyId = Asn1Util.getOctetStringOctets(extnValue);
      }
    }
    return subjectKeyId;
  }

  public byte[] authorityKeyId() {
    if (authorityKeyId == null) {
      byte[] extnValue = getCoreExtValue(OIDs.Extn.authorityKeyIdentifier);
      if (extnValue != null) {
        authorityKeyId = Asn1Util.getKeyIdentifier(AuthorityKeyIdentifier.getInstance(extnValue));
      }
    }

    return authorityKeyId;
  }

  public String subjectText() {
    if (subjectText == null) {
      subjectText = X509Util.x500NameText(subject);
    }
    return subjectText;
  }

  public String issuerText() {
    if (issuerText == null) {
      issuerText = X509Util.x500NameText(subject);
    }
    return issuerText;
  }

  public SubjectPublicKeyInfo subjectPublicKeyInfo() {
    return cert.getSubjectPublicKeyInfo();
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  public Instant notBefore() {
    return notBefore;
  }

  public Instant notAfter() {
    return notAfter;
  }

  public byte[] getEncoded() {
    return encoded.clone();
  }

  public String commonName() {
    return X509Util.getCommonName(subject);
  }

  public void verify(PublicKey key) throws SignatureException, InvalidKeyException,
      CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
    if (key instanceof CompositeMLDSAPublicKey) {
      verifyComposite((CompositeMLDSAPublicKey) key);
      return;
    }

    SignAlgo signAlgo = Optional.ofNullable(SignAlgo.getInstance(cert.getSignatureAlgorithm()))
        .orElseThrow(() -> new NoSuchAlgorithmException("could not detect SignAlgo"));
    Signature signature = signAlgo.newSignature(KeyUtil.providerName(signAlgo.jceName()));
    checkBcSignature(key, signature);
  }

  private void verifyComposite(CompositeMLDSAPublicKey key)
      throws SignatureException, CertificateException,
      NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
    if (!cert.getSignatureAlgorithm().equals(cert.getTBSCertificate().getSignature())) {
      throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
    }

    byte[] m;
    try {
      m = cert.getTBSCertificate().getEncoded();
    } catch (IOException e) {
      throw new SignatureException(e);
    }
    byte[] digestValue = key.suite().ph().hash(m);
    boolean valid = CompositeSigUtil.verifyHash(key, new byte[0], digestValue,
                      Asn1Util.getSignature(cert));
    if (!valid) {
      throw new SignatureException("certificate does not verify with supplied key");
    }
  }

  private void checkBcSignature(PublicKey key, Signature signature)
      throws CertificateException, SignatureException, InvalidKeyException {
    if (!cert.getSignatureAlgorithm().equals(cert.getTBSCertificate().getSignature())) {
      throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
    }

    signature.initVerify(key);
    try {
      signature.update(cert.getTBSCertificate().getEncoded());
    } catch (IOException ex) {
      throw new CertificateException("error encoding TBSCertificate");
    }

    if (!signature.verify(Asn1Util.getSignature(cert))) {
      throw new SignatureException("certificate does not verify with supplied key");
    }
  }

  public byte[] getExtensionCoreValue(ASN1ObjectIdentifier extnType) {
    Extension extn = cert.getTBSCertificate().getExtensions().getExtension(extnType);
    return extn == null ? null : Asn1Util.getOctetStringOctets(extn.getExtnValue());
  }

  public boolean hasKeyusage(KeyUsage usage) {
    boolean[] usages = keyUsage();
    return usages == null || usages[usage.bit()];
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  public boolean equals(Object obj) {
    return obj == this || obj instanceof X509Cert
        && Arrays.equals(sha256fp, ((X509Cert) obj).sha256fp);
  }

  private byte[] getCoreExtValue(ASN1ObjectIdentifier extnType) {
    Extensions extns = cert.getTBSCertificate().getExtensions();
    if (extns == null) {
      return null;
    }
    Extension extn = extns.getExtension(extnType);
    return extn == null ? null : Asn1Util.getOctetStringOctets(extn.getExtnValue());
  }

  @Override
  public String toString() {
    return toString(0);
  }

  public String toString(int level) {
    return toString(cert, level, sha256fp);
  }

  public static String toString(Certificate cert, int level) {
    return toString(cert, level, null);
  }

  public static String toString(Certificate cert, int level, byte[] sha256Fp) {
    StringBuilder sb = new StringBuilder(1000);
    addIndent(sb, level).append("Certificate:\n");
    if (sha256Fp != null) {
      addIndent(sb, level + 1).append("SHA256 Fingerprint:\n");
      addIndent(sb, level + 2).append(Hex.encode(sha256Fp)).append("\n");
    }
    addIndent(sb, level + 1).append("Data:\n");
    printTbsCert(sb, level + 2, cert);
    printSignature(sb, level, cert.getSignatureAlgorithm(), Asn1Util.getSignature(cert));

    sb.deleteCharAt(sb.length() - 1);
    return sb.toString();
  }

  static void printSignature(StringBuilder sb, int level,
                            AlgorithmIdentifier sigAlg, byte[] sigValue) {
    boolean ecdhPop = false;
    String signAlgoText;
    try {
      SignAlgo signAlgo = SignAlgo.getInstance(sigAlg);
      if (signAlgo != null) {
        signAlgoText = signAlgo.jceName();
        if (signAlgoText == null) {
          signAlgoText = signAlgo.name();
        }
      } else {
        String oid = sigAlg.getAlgorithm().getId();
        if ("1.3.6.1.5.5.7.6.26".equals(oid)) {
          ecdhPop = true;
          signAlgoText = "sa-ecdhPop-sha256-hmac-sha256";
        } else if ("1.3.6.1.5.5.7.6.27".equals(oid)) {
          ecdhPop = true;
          signAlgoText = "sa-ecdhPop-sha384-hmac-sha384";
        } else if ("1.3.6.1.5.5.7.6.28".equals(oid)) {
          ecdhPop = true;
          signAlgoText = "sa-ecdhPop-sha512-hmac-sha512";
        } else if ("1.3.6.1.5.5.7.6.36".equals(oid)) {
          signAlgoText = "unsigned";
        } else {
          signAlgoText = oid;
        }
      }
    } catch (Exception e) {
      signAlgoText = sigAlg.getAlgorithm().getId();
    }
    addIndent(sb, level + 1).append("Signature Algorithm: ").append(signAlgoText).append("\n");
    addIndent(sb, level + 1).append("Signature Value:\n");

    if (ecdhPop) {
      DhSigStatic dhSig = DhSigStatic.getInstance(sigValue);
      IssuerAndSerialNumber isn = dhSig.getIssuerAndSerial();
      if (isn != null) {
        toString(sb, level + 2, "Issuer", isn.getName());
        addIndent(sb, level + 2).append("Serial Number:\n");
        byte[] snBytes = BigIntegers.asUnsignedByteArray(isn.getSerialNumber().getPositiveValue());
        Hex.append(sb, snBytes, 0, snBytes.length, ":", 100, "  ".repeat(level + 3));
      }

      addIndent(sb, level + 2).append("Hash Value:\n");
      byte[] hashValue = dhSig.getHashValue();
      Hex.append(sb, hashValue, 0, hashValue.length, ":", 18, "  ".repeat(level + 3));
    } else {
      Hex.append(sb, sigValue, 0, sigValue.length, ":", 18, "  ".repeat(level + 2));
    }
  }

  private static void printTbsCert(StringBuilder sb, int level, Certificate cert) {
    int version = cert.getVersionNumber();
    addIndent(sb, level).append("Version: v").append(version)
        .append(" (").append(version - 1).append(")\n");

    TBSCertificate tbs = cert.getTBSCertificate();
    // serial number
    addIndent(sb, level).append("Serial Number:\n");
    byte[] snBytes = BigIntegers.asUnsignedByteArray(tbs.getSerialNumber().getValue());
    Hex.append(sb, snBytes, 0, snBytes.length, ":", 100, "  ".repeat(level + 1));

    // issuer
    toString(sb, level, "Issuer", cert.getIssuer());

    // validity
    addIndent(sb, level).append("Validity:\n");
    addIndent(sb, level + 1).append("Not Before: ")
        .append(tbs.getStartDate().getDate()).append("\n");
    addIndent(sb, level + 1).append("Not After : ")
        .append(tbs.getEndDate().getDate()).append("\n");

    // subject
    toString(sb, level, "Subject", cert.getSubject());

    // Subject Public Key Info
    printSubjectPublicKeyInfo(sb, level, cert.getSubjectPublicKeyInfo());

    // extensions
    addIndent(sb, level).append("X509v3 extensions:\n");
    printExtensions(sb, level + 1, tbs.getExtensions());
  }

  static void printSubjectPublicKeyInfo(StringBuilder sb, int level, SubjectPublicKeyInfo pkInfo) {
    // Subject Public Key Info
    KeySpec keySpec = KeySpec.ofPublicKey(pkInfo);
    byte[] pkData = Asn1Util.getPublicKeyData(pkInfo);
    addIndent(sb, level).append("Subject Public Key Info:\n");

    addIndent(sb, level + 1).append("Public Key Algorithm: ");
    if (keySpec != null) {
      if (keySpec.isWeierstrassEC()) {
        sb.append("EC/");
      }
      sb.append(keySpec);
    } else {
      sb.append(pkInfo.getAlgorithm().getAlgorithm().getId());
    }
    sb.append("\n");

    if (keySpec != null && keySpec.isRSA()) {
      RSAPublicKey pk = RSAPublicKey.getInstance(pkData);
      addIndent(sb, level + 1).append("Modulus:\n");
      byte[] bytes = pk.getModulus().toByteArray();
      Hex.append(sb, bytes, 0, bytes.length, ":", 18, "  ".repeat(level + 2));
      addIndent(sb, level + 1).append("Exponent:\n");
      bytes = pk.getPublicExponent().toByteArray();
      Hex.append(sb, bytes, 0, bytes.length, ":", 18, "  ".repeat(level + 2));
    } else {
      addIndent(sb, level + 1).append("Pub:\n");
      Hex.append(sb, pkData, 0, pkData.length, ":", 18, "  ".repeat(level + 2));
    }
  }

  static void printExtensions(StringBuilder sb, int level, Extensions extensions) {
    for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
      String name = OIDs.getName(oid);
      if (name == null) {
        name = oid.getId();
      }
      addIndent(sb, level).append("X509v3 ").append(name).append(":");
      Extension extn = extensions.getExtension(oid);
      ASN1Encodable extnValue = extn.getParsedValue();

      if (extn.isCritical()) {
        sb.append(" critical");
      }
      sb.append("\n");

      final int level1 = level + 1;
      final int level2 = level1 + 1;

      if (Extension.basicConstraints.equals(oid)) {
        BasicConstraints bc = BasicConstraints.getInstance(extnValue);
        if (bc.isCA()) {
          addIndent(sb, level1).append("CA: true, pathlen: ")
              .append(bc.getPathLenConstraint()).append("\n");
        } else {
          addIndent(sb, level1).append("CA: false\n");
        }
      } else if (Extension.keyUsage.equals(oid)) {
        org.bouncycastle.asn1.x509.KeyUsage ev =
            org.bouncycastle.asn1.x509.KeyUsage.getInstance(extnValue);
        int[] bcUsages = {
            org.bouncycastle.asn1.x509.KeyUsage.digitalSignature,
            org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation,
            org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment,
            org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment,
            org.bouncycastle.asn1.x509.KeyUsage.keyAgreement,
            org.bouncycastle.asn1.x509.KeyUsage.keyCertSign,
            org.bouncycastle.asn1.x509.KeyUsage.cRLSign,
            org.bouncycastle.asn1.x509.KeyUsage.encipherOnly,
            org.bouncycastle.asn1.x509.KeyUsage.decipherOnly};
        KeyUsage[] xiUsages = {
            KeyUsage.digitalSignature, KeyUsage.contentCommitment,
            KeyUsage.keyEncipherment,  KeyUsage.dataEncipherment,
            KeyUsage.keyEncipherment,  KeyUsage.keyCertSign,
            KeyUsage.cRLSign, KeyUsage.encipherOnly, KeyUsage.decipherOnly};

        List<KeyUsage> usages = new LinkedList<>();
        for (int i = 0; i < bcUsages.length; i++) {
          if (ev.hasUsages(bcUsages[i])) {
            usages.add(xiUsages[i]);
          }
        }

        String str = usages.toString();
        addIndent(sb, level1).append(str, 1, str.length() - 1).append("\n");
      } else if (Extension.extendedKeyUsage.equals(oid)) {
        ASN1Sequence seq = ASN1Sequence.getInstance(extnValue);
        for (int i = 0; i < seq.size(); i++) {
          ASN1ObjectIdentifier kp = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(i));
          String kpName = OIDs.getName(kp);
          addIndent(sb, level1).append(kpName == null ? kp.getId() : kpName).append("\n");
        }
      } else if (Extension.authorityKeyIdentifier.equals(oid)) {
        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(extnValue);
        byte[] bytes = Asn1Util.getKeyIdentifier(aki);
        Hex.append(sb, bytes, 0, bytes.length, ":", 20, "  ".repeat(level1));
        if (aki.getAuthorityCertIssuer() != null) {
          addIndent(sb, level1).append("Issuer: ");
          GeneralName[] gns = aki.getAuthorityCertIssuer().getNames();
          if (gns.length == 1) {
            sb.append(toString(gns[0])).append("\n");
          } else {
            sb.append("\n");
            print(sb, level2, aki.getAuthorityCertIssuer());
          }
        }

        if (aki.getAuthorityCertSerialNumber() != null) {
          addIndent(sb, level1).append("Serial Number:\n");
          byte[] snBytes = BigIntegers.asUnsignedByteArray(aki.getAuthorityCertSerialNumber());

          Hex.append(sb, snBytes, 0, snBytes.length, ":", 100, "  ".repeat(level2));
        }
      } else if (Extension.subjectKeyIdentifier.equals(oid)) {
        byte[] bytes = Asn1Util.getOctetStringOctets(extnValue);
        Hex.append(sb, bytes, 0, bytes.length, ":", 20, "  ".repeat(level1));
      } else if (Extension.subjectAlternativeName.equals(oid)) {
        GeneralNames seq = GeneralNames.getInstance(extnValue);
        print(sb, level1, seq);
      } else if (Extension.authorityInfoAccess.equals(oid) ||
          Extension.subjectInfoAccess.equals(oid)) {
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(extnValue);
        for (AccessDescription ad : aia.getAccessDescriptions()) {
          ASN1ObjectIdentifier id = ad.getAccessMethod();

          String name0 = OIDs.getName(id);
          if (name0 == null) {
            name0 = id.getId();
          }

          addIndent(sb, level1).append(name0).append(": ")
              .append(toString(ad.getAccessLocation())).append("\n");
        }
      } else if (Extension.certificatePolicies.equals(oid)) {
        PolicyInformation[] policies =
            CertificatePolicies.getInstance(extnValue).getPolicyInformation();
        for (PolicyInformation pi : policies) {
          String policyId = pi.getPolicyIdentifier().getId();
          addIndent(sb, level1).append("Policy: ").append(OIDs.getName(policyId)).append("\n");
          if (pi.getPolicyQualifiers() != null) {
            ASN1Sequence qualifiers = pi.getPolicyQualifiers();
            for (int i = 0; i < qualifiers.size(); i++) {
              PolicyQualifierInfo q = PolicyQualifierInfo.getInstance(qualifiers.getObjectAt(i));
              ASN1ObjectIdentifier qId = q.getPolicyQualifierId();
              String qName = OIDs.getName(qId);
              addIndent(sb, level2).append(qName).append(": ")
                  .append(q.getQualifier()).append("\n");
            }
          }
        }
      } else if (Extension.cRLDistributionPoints.equals(oid) || Extension.freshestCRL.equals(oid)) {
        CRLDistPoint points = CRLDistPoint.getInstance(extnValue);
        for (DistributionPoint point : points.getDistributionPoints()) {
          if (point.getCRLIssuer() != null) {
            addIndent(sb, level1).append("CRL Issuer:\n");
            print(sb, level2, point.getCRLIssuer());
          }

          List<String> tokens = new ArrayList<>(8);
          if (point.getReasons() != null) {
            byte[] bytes = point.getReasons().getBytes();
            int v = (0xFF & bytes[0]) << 8;
            if (bytes.length > 1) {
              v |= (0xFF & bytes[1]);
            }

            String[] reasonTexts = new String[] {
                "unused", "keyCompromise", "cACompromise", "affiliationChanged", "superseded",
                "cessationOfOperation", "certificateHold", "privilegeWithdrawn", "aACompromise"};

            for (int i = 0; i < reasonTexts.length; i++) {
              int mask = 1 << (15 - i);
              if ((v & mask) != 0) {
                tokens.add(reasonTexts[i]);
              }
            }

            addIndent(sb, level1).append("Reasons: ").append(tokens).append("\n");
          }

          if (point.getDistributionPoint() != null) {
            int type = point.getDistributionPoint().getType();
            String name0 = (type == DistributionPointName.FULL_NAME) ? "Full Name"
                : (type == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
                    ? "Relative to CRL Issuer" : "type " + type;

            addIndent(sb, level1).append(name0).append(":\n");
            GeneralNames gns = GeneralNames.getInstance(point.getDistributionPoint().getName());
            print(sb, level2, gns);
          }
        }
      } else if (OIDs.Extn.subjectDirectoryAttributes.equals(oid)) {
        SubjectDirectoryAttributes sda = SubjectDirectoryAttributes.getInstance(extnValue);
        Vector<?> attrs = sda.getAttributes();
        for (Object o : attrs) {
          Attribute attr = Attribute.getInstance(o);
          ASN1ObjectIdentifier attrType = attr.getAttrType();
          ASN1Encodable[] attrValues = attr.getAttributeValues();

          addIndent(sb, level1).append(OIDs.getName(attrType)).append("\n");
          for (ASN1Encodable attrValue : attrValues) {
            addIndent(sb, level2).append(attrValue).append("\n");
          }
        }
      } else if (Extension.nameConstraints.equals(oid)) {
        NameConstraints constraints = NameConstraints.getInstance(extnValue);
        GeneralSubtree[] permitted = constraints.getPermittedSubtrees();
        GeneralSubtree[] excluded = constraints.getExcludedSubtrees();
        if (permitted != null) {
          toString(sb, level1, "Permitted", permitted);
        }

        if (excluded != null) {
          toString(sb, level1, "Excluded", excluded);
        }
      } else if (Extension.policyConstraints.equals(oid)) {
        PolicyConstraints constraints = PolicyConstraints.getInstance(extnValue);
        addIndent(sb, level1).append("Require Explicit Policy:")
            .append(constraints.getRequireExplicitPolicyMapping()).append(", ")
            .append("Inhibit Explicit Policy:")
            .append(constraints.getInhibitPolicyMapping()).append("\n");
      } else if (Extension.policyMappings.equals(oid)) {
        PolicyMappings mappings = PolicyMappings.getInstance(extnValue);
        ASN1Sequence seq = ASN1Sequence.getInstance(mappings.toASN1Primitive());
        for (int i = 0; i < seq.size(); i++) {
          ASN1Sequence seq2 = ASN1Sequence.getInstance(seq.getObjectAt(i));
          ASN1ObjectIdentifier issuerDomainPolicy =
              ASN1ObjectIdentifier.getInstance(seq2.getObjectAt(0));
          ASN1ObjectIdentifier subjectDomainPolicy =
              ASN1ObjectIdentifier.getInstance(seq2.getObjectAt(1));
          addIndent(sb, level1).append(issuerDomainPolicy.getId())
              .append(" : ").append(subjectDomainPolicy.getId()).append("\n");
        }
      } else if (OIDs.Extn.id_SignedCertificateTimestampList.equals(oid)) {
        CtLog.SerializedSCT sctl = CtLog.SignedCertificateTimestampList.getInstance(
                Asn1Util.getOctetStringOctets(extnValue)).sctList();
        for (int i = 0; i < sctl.size(); i++) {
          CtLog.SignedCertificateTimestamp sct = sctl.get(i);
          int version = sct.version();
          addIndent(sb, level1).append("Signed Certificate Timestamp:\n");

          addIndent(sb, level2).append("Version:    ").append("v")
              .append(version + 1).append("(").append(version).append(")").append("\n");

          addIndent(sb, level2).append("Log ID:\n");
          Hex.append(sb, sct.logId(), 16, "  ".repeat(level + 3));

          addIndent(sb, level2).append("Timestamp:  ")
              .append(Instant.ofEpochMilli(sct.timestamp())).append("\n");
          byte[] sctExtensions = sct.extensions();
          if (sctExtensions == null || sctExtensions.length == 0) {
            addIndent(sb, level2).append("Extensions: none\n");
          } else {
            addIndent(sb, level2).append("Extensions:\n");
            Hex.append(sb, sctExtensions, 16, "  ".repeat(level + 3));
          }

          CtLog.SignatureAndHashAlgorithm sigAlg = sct.digitallySigned().algorithm();
          String sigAlgText = sigAlg.signature() + "-with-" + sigAlg.hash();
          byte[] sigValue = sct.digitallySigned().signature();
          addIndent(sb, level2).append("Signature:  ").append(sigAlgText).append("\n");
          Hex.append(sb, sigValue, 16, "  ".repeat(level + 3));
        }
      } else if (OIDs.Extn.autonomousSysIds.equals(oid) ||
          OIDs.Extn.autonomousSysIdsV2.equals(oid)) {
        ASIdentifiers asIdentifiers = ASIdentifiers.getInstance(extnValue);
        ASIdentifierChoice asNum = asIdentifiers.asnum();
        ASIdentifierChoice rdi = asIdentifiers.rdi();
        if (asNum != null) {
          addIndent(sb, level1).append("Autonomous System Numbers:");
          if (asNum.isInherit()) {
            sb.append(" inherit\n");
          } else {
            sb.append("\n");
            for (ASIdOrRange asIdOrRange : asNum.asIdsOrRanges()) {
              addIndent(sb, level2).append(asIdOrRange).append("\n");
            }
          }
        }

        if (rdi != null) {
          addIndent(sb, level1).append("Routing Domain Identifier (RDI):");
          if (rdi.isInherit()) {
            sb.append(" inherit\n");
          } else {
            sb.append("\n");
            for (ASIdOrRange asIdOrRange : rdi.asIdsOrRanges()) {
              if (asIdOrRange.id() != null) {
                addIndent(sb, level2).append(asIdOrRange).append("\n");
              }
            }
          }
        }
      } else if (OIDs.Extn.ipAddrBlocks.equals(oid) || OIDs.Extn.ipAddrBlocksV2.equals(oid)) {
        IPAddrBlocks blocks = IPAddrBlocks.getInstance(extnValue);
        for (ASN1IPAddressFamily block : blocks.blocks()) {
          int afi = block.afi();
          addIndent(sb, level1).append(block.addressFamilyToString()).append(":");
          IPAddressChoice choice = block.ipAddressChoice();
          if (choice.isInherit()) {
            sb.append(" inherit\n");
          } else {
            sb.append("\n");
            for (IPAddressOrRange addrOrRange : choice.addressesOrRanges()) {
              addIndent(sb, level2).append(addrOrRange.toString(afi)).append("\n");
            }
          }
        }
      } else if (oid.equals(OIDs.Extn.id_pe_tlsfeature)) {
        ASN1Sequence seq = (ASN1Sequence) extnValue;
        for (int i= 0; i < seq.size(); i++) {
          addIndent(sb, level1).append(seq.getObjectAt(i)).append("\n");
        }
      } else if (oid.equals(OIDs.Extn.id_dmtf_spdm_extension)) {
        ASN1Sequence seq = (ASN1Sequence) extnValue;
        for (int i= 0; i < seq.size(); i++) {
          ASN1Sequence seq0 = (ASN1Sequence) seq.getObjectAt(i);
          ASN1ObjectIdentifier sqrtOid = (ASN1ObjectIdentifier) seq0.getObjectAt(0);
          addIndent(sb, level1).append(OIDs.getName(sqrtOid));
          if (seq0.size() > 1) {
            byte[] oidDefinition = Asn1Util.getOctetStringOctets(seq0.getObjectAt(1));
            sb.append("\n");
            Hex.append(sb, oidDefinition, 0, oidDefinition.length, ":", 18,
                "  ".repeat(level1 + 1));
          }
          sb.append("\n");
        }
      } else {
        byte[] bytes = Asn1Util.getOctetStringOctets(extn.getExtnValue());
        if (Arrays.equals(DER_NULL, bytes)) {
          addIndent(sb, level1).append("NULL").append("\n");
        } else {
          Hex.append(sb, bytes, 0, bytes.length, ":", 18, "  ".repeat(level1));
        }
      }
    }
  }

  private static void toString(
      StringBuilder sb, int level, String title, GeneralSubtree[] subtrees) {
    addIndent(sb, level).append(title).append("\n");
    for (GeneralSubtree subtree : subtrees) {
      addIndent(sb, level + 1).append(toString(subtree.getBase()));
      BigInteger min = subtree.getMinimum();
      BigInteger max = subtree.getMaximum();

      if (!min.equals(BigInteger.ZERO) || max != null) {
        sb.append(", ").append(min).append("-");
        if (max != null) {
          sb.append(max);
        }
      }
      sb.append("\n");
    }
  }

  static StringBuilder addIndent(StringBuilder sb, int level) {
    sb.append("  ".repeat(level));
    return sb;
  }

  private static void print(StringBuilder sb, int level, GeneralNames gns) {
    for (GeneralName gn : gns.getNames()) {
      addIndent(sb, level).append(toString(gn)).append("\n");
    }
  }

  static void toString(StringBuilder sb, int level, String title, X500Name name) {
    String nameStr = name.toString();
    int numPerLine = 70 - (2 * level + title.length() + 2);
    int numLines = (nameStr.length() + numPerLine - 1) / numPerLine;
    for (int i = 0; i < numLines; i++) {
      if (i == 0) {
        addIndent(sb, level).append(title).append(": ");
      } else {
        addIndent(sb, level).append(" ".repeat(title.length() + 2));
      }

      int off = i * numPerLine;
      sb.append(nameStr, off, Math.min(off + numPerLine, nameStr.length())).append("\n");
    }
  }

  private static String toString(GeneralName gn) {
    StringBuilder sb = new StringBuilder();
    sb.append(getGeneralNameType(gn)).append(": ");

    int tagNo = gn.getTagNo();
    ASN1Encodable name = gn.getName();
    switch (tagNo) {
      case GeneralName.directoryName:
      case GeneralName.dNSName:
      case GeneralName.rfc822Name:
      case GeneralName.uniformResourceIdentifier:
      case GeneralName.registeredID:
        sb.append(gn.getName());
        break;
      case GeneralName.iPAddress:
        byte[] bytes = Asn1Util.getOctetStringOctets(name);
        for (int i = 0; i < bytes.length; i++) {
          if (i != 0) {
            sb.append(".");
          }
          sb.append(bytes[i] & 0xFF);
        }
        break;
      case GeneralName.otherName: {
        OtherName on = OtherName.getInstance(name);
        ASN1ObjectIdentifier onId = on.getTypeID();
        ASN1Encodable value = on.getValue();
        if (onId.equals(OIDs.X509.id_on_SmtpUTF8Mailbox)) {
          sb.append("SmtpUTF8Mailbox:").append(value);
        } else if (onId.equals(OIDs.X509.id_on_hardwareModuleName)) {
          sb.append("hardwareModuleName:");
          ASN1Sequence seq = ASN1Sequence.getInstance(value);
          sb.append(seq.getObjectAt(0)).append(":"); // OID
          sb.append("<unsupported>"); // value
        } else if (onId.equals(OIDs.Spdm.id_DMTF_device_info)) {
          sb.append("DMTF device info:").append(value);
        } else {
          sb.append(onId.getId()).append(":<unsupported>");
        }
        break;
      }
      default:
        sb.append("<unsupported>");
    }

    return sb.toString();
  }

  private static String getGeneralNameType(GeneralName gn) {
    switch (gn.getTagNo()) {
      case GeneralName.directoryName:
        return "Directory Name";
      case GeneralName.iPAddress:
        return "IP";
      case GeneralName.dNSName:
        return "DNS";
      case GeneralName.uniformResourceIdentifier:
        return "URI";
      case GeneralName.otherName:
        return "OtherName";
      case GeneralName.registeredID:
        return "RegisteredID";
      case GeneralName.rfc822Name:
        return "RFC822";
      case GeneralName.x400Address:
        return "X400";
      case GeneralName.ediPartyName:
        return "EDI";
      default:
        return "tag-" + gn.getTagNo();
    }
  }

}
