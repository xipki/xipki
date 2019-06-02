/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep.crypto.KeyUsage;
import org.xipki.scep.crypto.ScepHashAlgo;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ScepUtil {
  private static final Logger LOG = LoggerFactory.getLogger(ScepUtil.class);

  private static final long MIN_IN_MS = 60L * 1000;
  private static final long DAY_IN_MS = 24L * 60 * MIN_IN_MS;

  private static final AlgorithmIdentifier ALGID_RSA =
      new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

  private static CertificateFactory certFact;
  private static Object certFactLock = new Object();

  private ScepUtil() {
  }

  public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(PublicKey publicKey)
      throws IOException {
    requireNonNull("publicKey", publicKey);
    if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
      java.security.interfaces.RSAPublicKey rsaPubKey =
          (java.security.interfaces.RSAPublicKey) publicKey;
      return new SubjectPublicKeyInfo(ALGID_RSA,
          new RSAPublicKey(rsaPubKey.getModulus(), rsaPubKey.getPublicExponent()));
    } else {
      throw new IllegalArgumentException("unsupported public key " + publicKey);
    }
  }

  public static PKCS10CertificationRequest generateRequest(PrivateKey privatekey,
      SubjectPublicKeyInfo subjectPublicKeyInfo, X500Name subjectDn,
      Map<ASN1ObjectIdentifier, ASN1Encodable> attributes) throws OperatorCreationException {
    requireNonNull("privatekey", privatekey);
    requireNonNull("subjectPublicKeyInfo", subjectPublicKeyInfo);
    requireNonNull("subjectDn", subjectDn);

    PKCS10CertificationRequestBuilder csrBuilder =
        new PKCS10CertificationRequestBuilder(subjectDn, subjectPublicKeyInfo);

    if (attributes != null) {
      for (ASN1ObjectIdentifier attrType : attributes.keySet()) {
        csrBuilder.addAttribute(attrType, attributes.get(attrType));
      }
    }

    ContentSigner contentSigner = new JcaContentSignerBuilder(
        getSignatureAlgorithm(privatekey, ScepHashAlgo.SHA1)).build(privatekey);
    return csrBuilder.build(contentSigner);
  }

  public static PKCS10CertificationRequest generateRequest(PrivateKey privatekey,
      SubjectPublicKeyInfo subjectPublicKeyInfo, X500Name subjectDn,
      String challengePassword, List<Extension> extensions)
      throws OperatorCreationException {
    requireNonNull("privatekey", privatekey);
    requireNonNull("subjectPublicKeyInfo", subjectPublicKeyInfo);
    requireNonNull("subjectDn", subjectDn);

    Map<ASN1ObjectIdentifier, ASN1Encodable> attributes =
        new HashMap<ASN1ObjectIdentifier, ASN1Encodable>();

    if (challengePassword != null && !challengePassword.isEmpty()) {
      DERPrintableString asn1Pwd = new DERPrintableString(challengePassword);
      attributes.put(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, asn1Pwd);
    }

    if (extensions != null && !extensions.isEmpty()) {
      Extensions asn1Extensions = new Extensions(extensions.toArray(new Extension[0]));
      attributes.put(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, asn1Extensions);
    }

    return generateRequest(privatekey, subjectPublicKeyInfo, subjectDn, attributes);
  }

  public static X509Certificate generateSelfsignedCert(CertificationRequest csr,
      PrivateKey identityKey) throws CertificateException {
    requireNonNull("csr", csr);
    return generateSelfsignedCert(csr.getCertificationRequestInfo().getSubject(),
        csr.getCertificationRequestInfo().getSubjectPublicKeyInfo(), identityKey);
  }

  public static X509Certificate generateSelfsignedCert(X500Name subjectDn, PublicKey pubKey,
      PrivateKey identityKey) throws CertificateException {
    SubjectPublicKeyInfo pubKeyInfo;
    try {
      pubKeyInfo = createSubjectPublicKeyInfo(pubKey);
    } catch (IOException ex) {
      throw new CertificateException(ex.getMessage(), ex);
    }
    return generateSelfsignedCert(subjectDn, pubKeyInfo, identityKey);
  }

  public static X509Certificate generateSelfsignedCert(X500Name subjectDn,
      SubjectPublicKeyInfo pubKeyInfo, PrivateKey identityKey) throws CertificateException {
    requireNonNull("subjectDn", subjectDn);
    requireNonNull("pubKeyInfo", pubKeyInfo);
    requireNonNull("identityKey", identityKey);

    Date notBefore = new Date(System.currentTimeMillis() - 5 * MIN_IN_MS);
    Date notAfter = new Date(notBefore.getTime() + 30 * DAY_IN_MS);

    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(subjectDn,
        BigInteger.ONE, notBefore, notAfter, subjectDn, pubKeyInfo);

    X509KeyUsage ku = new X509KeyUsage(X509KeyUsage.digitalSignature
        | X509KeyUsage.dataEncipherment | X509KeyUsage.keyAgreement | X509KeyUsage.keyEncipherment);
    try {
      certGenerator.addExtension(Extension.keyUsage, true, ku);
    } catch (CertIOException ex) {
      throw new CertificateException(
          "could not generate self-signed certificate: " + ex.getMessage(), ex);
    }

    String sigAlgorithm = ScepUtil.getSignatureAlgorithm(identityKey, ScepHashAlgo.SHA1);
    ContentSigner contentSigner;
    try {
      contentSigner = new JcaContentSignerBuilder(sigAlgorithm).build(identityKey);
    } catch (OperatorCreationException ex) {
      throw new CertificateException("error while creating signer", ex);
    }

    Certificate asn1Cert = certGenerator.build(contentSigner).toASN1Structure();
    return toX509Cert(asn1Cert);
  } // method generateSelfsignedCert

  /**
   * The first one is a non-CA certificate if there exists one non-CA certificate.
   */
  public static List<X509Certificate> getCertsFromSignedData(SignedData signedData)
      throws CertificateException {
    requireNonNull("signedData", signedData);
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
    requireNonNull("signedData", signedData);
    ASN1Set set = signedData.getCRLs();
    if (set == null || set.size() == 0) {
      return null;
    }

    try {
      CertificateList cl = CertificateList.getInstance(set.getObjectAt(0));
      return ScepUtil.toX509Crl(cl);
    } catch (IllegalArgumentException | CertificateException | CRLException ex) {
      throw new CRLException(ex);
    }
  }

  public static String getSignatureAlgorithm(PrivateKey key, ScepHashAlgo hashAlgo) {
    requireNonNull("key", key);
    requireNonNull("hashAlgo", hashAlgo);
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

  public static X509CRL toX509Crl(CertificateList asn1CertList)
      throws CertificateException, CRLException {
    byte[] encodedCrl;
    try {
      encodedCrl = asn1CertList.getEncoded();
    } catch (IOException ex) {
      throw new CRLException("could not get encoded CRL", ex);
    }

    return parseCrl(encodedCrl);
  }

  public static X509CRL parseCrl(byte[] encodedCrl) throws CertificateException, CRLException {
    requireNonNull("encodedCrl", encodedCrl);
    return parseCrl(new ByteArrayInputStream(encodedCrl));
  }

  public static X509CRL parseCrl(InputStream crlStream) throws CertificateException, CRLException {
    requireNonNull("crlStream", crlStream);
    X509CRL crl = (X509CRL) getCertFactory().generateCRL(crlStream);
    if (crl == null) {
      throw new CRLException("the given one is not a valid X.509 CRL");
    }
    return crl;
  }

  public static X509Certificate parseCert(byte[] certBytes) throws CertificateException {
    requireNonNull("certBytes", certBytes);
    return parseCert(new ByteArrayInputStream(certBytes));
  }

  private static X509Certificate parseCert(InputStream certStream) throws CertificateException {
    requireNonNull("certStream", certStream);
    return (X509Certificate) getCertFactory().generateCertificate(certStream);
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

  public static boolean hasKeyusage(X509Certificate cert, KeyUsage usage) {
    boolean[] keyusage = cert.getKeyUsage();
    if (keyusage != null && keyusage.length > usage.getBit()) {
      return keyusage[usage.getBit()];
    }
    return false;
  }

  private static byte[] getCoreExtValue(X509Certificate cert, ASN1ObjectIdentifier type)
      throws CertificateEncodingException {
    requireNonNull("cert", cert);
    requireNonNull("type", type);
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
    requireNonNull("cert", cert);
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
    requireNonNull("issuerCert", issuerCert);
    requireNonNull("cert", cert);
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
    requireNonBlank("sigOid", sigOid);

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
    requireNonNull("attrs", attrs);
    requireNonNull("type", type);
    Attribute attr = attrs.get(type);
    if (attr == null) {
      return null;
    }
    ASN1Set set = attr.getAttrValues();
    return (set.size() == 0) ? null : set.getObjectAt(0);
  }

  public static byte[] read(InputStream in) throws IOException {
    requireNonNull("in", in);
    try {
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      int readed = 0;
      byte[] buffer = new byte[2048];
      while ((readed = in.read(buffer)) != -1) {
        bout.write(buffer, 0, readed);
      }

      return bout.toByteArray();
    } finally {
      try {
        in.close();
      } catch (IOException ex) {
        LOG.error("could not close stream: {}", ex.getMessage());
      }
    }
  }

  public static void addCmsCertSet(CMSSignedDataGenerator generator, X509Certificate[] cmsCertSet)
      throws CertificateEncodingException, CMSException {
    if (cmsCertSet == null || cmsCertSet.length == 0) {
      return;
    }
    requireNonNull("geneator", generator);
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

  public static <T> T requireNonNull(String objName, T obj) {
    return Objects.requireNonNull(obj, objName + " must not be null");
  }

  public static String requireNonBlank(String objName, String obj) {
    Objects.requireNonNull(obj, objName + " must not be null");
    if (obj.isEmpty()) {
      throw new IllegalArgumentException(objName + " must not be blank");
    }
    return obj;
  }

  public static <T> Collection<T> requireNonEmpty(String objName, Collection<T> obj) {
    Objects.requireNonNull(obj, objName + " must not be null");
    if (obj.isEmpty()) {
      throw new IllegalArgumentException(objName + " must not be empty");
    }
    return obj;
  }

}
