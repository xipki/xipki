// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.util.codec.Args;

/**
 * Wrapper to an {@link CertificationRequest}.
 *
 * @author Lijun Liao (xipki)
 * @since 5.3.8
 */

public class X509Csr {

  private final CertificationRequest csr;

  public X509Csr(CertificationRequest csr) {
    this.csr = Args.notNull(csr, "csr");
  }

  public X509Csr(PKCS10CertificationRequest csr) {
    this.csr = Args.notNull(csr, "csr").toASN1Structure();
  }

  @Override
  public String toString() {
    return toString(0);
  }

  public String toString(int level) {
    return toString(csr, level);
  }

  public static String toString(CertificationRequest csr, int level) {
    StringBuilder sb = new StringBuilder(1000);
    X509Cert.addIndent(sb, level).append("Certificate Request:\n");
    X509Cert.addIndent(sb, level + 1).append("Data:\n");
    printTbsCsr(sb, level + 2, csr);
    X509Cert.printSignature(sb, level, csr.getSignatureAlgorithm(),
        csr.getSignature().getOctets());
    sb.deleteCharAt(sb.length() - 1);
    return sb.toString();
  }

  private static void printTbsCsr(
      StringBuilder sb, int level, CertificationRequest csr) {
    CertificationRequestInfo tbs = csr.getCertificationRequestInfo();
    int version = tbs.getVersion().getValue().intValueExact();
    X509Cert.addIndent(sb, level).append("Version: v").append(version + 1)
        .append(" (").append(version).append(")\n");

    // subject
    X509Cert.toString(sb, level, "Subject", tbs.getSubject());

    // Subject Public Key Info
    X509Cert.printSubjectPublicKeyInfo(
        sb, level, tbs.getSubjectPublicKeyInfo());

    // attributes
    X509Cert.addIndent(sb, level).append("Attributes:\n");
    ASN1Set attributes = tbs.getAttributes();
    int size = attributes.size();
    for (int i = 0; i < size; i++) {
      ASN1Encodable ele = attributes.getObjectAt(i);

      Attribute attr = Attribute.getInstance(ele);
      ASN1ObjectIdentifier attrOid = attr.getAttrType();
      if (attrOid.equals(OIDs.PKCS9.pkcs9_at_challengePassword)) {
        X509Cert.addIndent(sb, level + 1).append("challengePassword: ")
            .append(((ASN1String) attr.getAttributeValues()[0]).getString())
            .append("\n");
      } else if (attrOid.equals(OIDs.PKCS9.pkcs9_at_extensionRequest)) {
        // extensions
        X509Cert.addIndent(sb, level + 1).append("X509v3 extensions:\n");
        X509Cert.printExtensions(sb, level + 2,
            Extensions.getInstance(attr.getAttributeValues()[0]));
      } else {
        X509Cert.addIndent(sb, level + 1).append(attrOid.getId())
            .append(": <unsupported>\n");
      }
    }
  }

}
