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

package org.xipki.scep.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ScepUtil {
  private static CertificateFactory certFact;
  private static Object certFactLock = new Object();

  private ScepUtil() {
  }

  /**
   * The first one is a non-CA certificate if there exists one non-CA certificate.
   */
  public static List<X509Certificate> getCertsFromSignedData(SignedData signedData)
      throws CertificateException {
    Args.notNull(signedData, "signedData");
    ASN1Set set = signedData.getCertificates();
    if (set == null) {
      return Collections.emptyList();
    }

    final int n = set.size();
    if (n == 0) {
      return Collections.emptyList();
    }

    List<X509Certificate> certs = new LinkedList<X509Certificate>();

    X509Certificate eeCert = null;
    for (int i = 0; i < n; i++) {
      X509Certificate cert;
      try {
        cert = toX509Cert(Certificate.getInstance(set.getObjectAt(i)));
      } catch (IllegalArgumentException ex) {
        throw new CertificateException(ex);
      }

      if (eeCert == null && cert.getBasicConstraints() == -1) {
        eeCert = cert;
      } else {
        certs.add(cert);
      }
    }

    if (eeCert != null) {
      certs.add(0, eeCert);
    }

    return certs;
  } // method getCertsFromSignedData

  public static X509CRL getCrlFromPkiMessage(SignedData signedData) throws CRLException {
    Args.notNull(signedData, "signedData");
    ASN1Set set = signedData.getCRLs();
    if (set == null || set.size() == 0) {
      return null;
    }

    try {
      CertificateList cl = CertificateList.getInstance(set.getObjectAt(0));

      byte[] encodedCrl;
      try {
        encodedCrl = cl.getEncoded();
      } catch (IOException ex) {
        throw new CRLException("could not get encoded CRL", ex);
      }

      X509CRL crl = (X509CRL) getCertFactory().generateCRL(new ByteArrayInputStream(encodedCrl));
      if (crl == null) {
        throw new CRLException("the given one is not a valid X.509 CRL");
      }
      return crl;
    } catch (IllegalArgumentException | CertificateException | CRLException ex) {
      throw new CRLException(ex);
    }
  }

  public static String getSignatureAlgorithm(PrivateKey key, ScepHashAlgo hashAlgo) {
    Args.notNull(key, "key");
    Args.notNull(hashAlgo, "hashAlgo");
    String algorithm = key.getAlgorithm();
    if ("RSA".equalsIgnoreCase(algorithm)) {
      return hashAlgo.getName() + "withRSA";
    } else {
      throw new UnsupportedOperationException(
          "getSignatureAlgorithm() for non-RSA is not supported yet.");
    }
  }

  public static X509Certificate toX509Cert(org.bouncycastle.asn1.x509.Certificate asn1Cert)
      throws CertificateException {
    byte[] encodedCert;
    try {
      encodedCert = asn1Cert.getEncoded();
    } catch (IOException ex) {
      throw new CertificateEncodingException("could not get encoded certificate", ex);
    }

    return parseCert(encodedCert);
  }

  public static X509Certificate parseCert(byte[] certBytes) throws CertificateException {
    Args.notNull(certBytes, "certBytes");
    return (X509Certificate) getCertFactory().generateCertificate(
              new ByteArrayInputStream(certBytes));
  }

  private static byte[] extractSki(X509Certificate cert) throws CertificateEncodingException {
    byte[] extValue = getCoreExtValue(cert, Extension.subjectKeyIdentifier);
    if (extValue == null) {
      return null;
    }

    try {
      return ASN1OctetString.getInstance(extValue).getOctets();
    } catch (IllegalArgumentException ex) {
      throw new CertificateEncodingException(ex.getMessage());
    }
  }

  private static byte[] extractAki(X509Certificate cert) throws CertificateEncodingException {
    byte[] extValue = getCoreExtValue(cert, Extension.authorityKeyIdentifier);
    if (extValue == null) {
      return null;
    }

    try {
      AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(extValue);
      return aki.getKeyIdentifier();
    } catch (IllegalArgumentException ex) {
      throw new CertificateEncodingException(
          "invalid extension AuthorityKeyIdentifier: " + ex.getMessage());
    }
  }

  private static byte[] getCoreExtValue(X509Certificate cert, ASN1ObjectIdentifier type)
      throws CertificateEncodingException {
    Args.notNull(cert, "cert");
    Args.notNull(type, "type");
    byte[] fullExtValue = cert.getExtensionValue(type.getId());
    if (fullExtValue == null) {
      return null;
    }
    try {
      return ASN1OctetString.getInstance(fullExtValue).getOctets();
    } catch (IllegalArgumentException ex) {
      throw new CertificateEncodingException("invalid extension " + type.getId()
        + ": " + ex.getMessage());
    }
  }

  public static boolean isSelfSigned(X509Certificate cert) {
    Args.notNull(cert, "cert");
    boolean equals = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    if (!equals) {
      return false;
    }

    try {
      byte[] ski = extractSki(cert);
      byte[] aki = extractAki(cert);

      return (ski != null && aki != null) ? Arrays.equals(ski, aki) : true;
    } catch (CertificateEncodingException ex) {
      return false;
    }
  }

  public static boolean issues(X509Certificate issuerCert, X509Certificate cert)
      throws CertificateEncodingException {
    Args.notNull(issuerCert, "issuerCert");
    Args.notNull(cert, "cert");
    boolean isCa = issuerCert.getBasicConstraints() >= 0;
    if (!isCa) {
      return false;
    }

    boolean issues = issuerCert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    if (issues) {
      byte[] ski = extractSki(issuerCert);
      byte[] aki = extractAki(cert);
      if (ski != null) {
        issues = Arrays.equals(ski, aki);
      }
    }

    if (issues) {
      long issuerNotBefore = issuerCert.getNotBefore().getTime();
      long issuerNotAfter = issuerCert.getNotAfter().getTime();
      long notBefore = cert.getNotBefore().getTime();
      issues = notBefore <= issuerNotAfter && notBefore >= issuerNotBefore;
    }

    return issues;
  }

  public static ASN1ObjectIdentifier extractDigesetAlgorithmIdentifier(String sigOid,
      byte[] sigParams) throws NoSuchAlgorithmException {
    Args.notBlank(sigOid, "sigOid");

    ASN1ObjectIdentifier algOid = new ASN1ObjectIdentifier(sigOid);

    ASN1ObjectIdentifier digestAlgOid;
    if (PKCSObjectIdentifiers.md5WithRSAEncryption.equals(algOid)) {
      digestAlgOid = PKCSObjectIdentifiers.md5;
    } else if (PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(algOid)) {
      digestAlgOid = X509ObjectIdentifiers.id_SHA1;
    } else if (PKCSObjectIdentifiers.sha224WithRSAEncryption.equals(algOid)) {
      digestAlgOid = NISTObjectIdentifiers.id_sha224;
    } else if (PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(algOid)) {
      digestAlgOid = NISTObjectIdentifiers.id_sha256;
    } else if (PKCSObjectIdentifiers.sha384WithRSAEncryption.equals(algOid)) {
      digestAlgOid = NISTObjectIdentifiers.id_sha384;
    } else if (PKCSObjectIdentifiers.sha512WithRSAEncryption.equals(algOid)) {
      digestAlgOid = NISTObjectIdentifiers.id_sha512;
    } else if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid)) {
      RSASSAPSSparams param = RSASSAPSSparams.getInstance(sigParams);
      digestAlgOid = param.getHashAlgorithm().getAlgorithm();
    } else {
      throw new NoSuchAlgorithmException("unknown signature algorithm" + algOid.getId());
    }

    return digestAlgOid;
  }

  public static ASN1Encodable getFirstAttrValue(AttributeTable attrs, ASN1ObjectIdentifier type) {
    Args.notNull(attrs, "attrs");
    Args.notNull(type, "type");
    Attribute attr = attrs.get(type);
    if (attr == null) {
      return null;
    }
    ASN1Set set = attr.getAttrValues();
    return (set.size() == 0) ? null : set.getObjectAt(0);
  }

  public static void addCmsCertSet(CMSSignedDataGenerator generator, X509Certificate[] cmsCertSet)
      throws CertificateEncodingException, CMSException {
    if (cmsCertSet == null || cmsCertSet.length == 0) {
      return;
    }
    Args.notNull(generator, "geneator");
    Collection<X509Certificate> certColl = new LinkedList<X509Certificate>();
    for (X509Certificate m : cmsCertSet) {
      certColl.add(m);
    }

    JcaCertStore certStore = new JcaCertStore(certColl);
    generator.addCertificates(certStore);
  }

  private static CertificateFactory getCertFactory() throws CertificateException {
    synchronized (certFactLock) {
      if (certFact == null) {
        try {
          certFact = CertificateFactory.getInstance("X.509", "BC");
        } catch (NoSuchProviderException ex) {
          certFact = CertificateFactory.getInstance("X.509");
        }
      }
      return certFact;
    }
  }

}
