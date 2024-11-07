// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.BadInputException;
import org.xipki.security.EdECConstants;
import org.xipki.security.FpIdCalculator;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.asn1.Asn1StreamParser;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.FileOrBinary;
import org.xipki.util.Hex;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.PemEncoder;
import org.xipki.util.PemEncoder.PemLabel;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.xipki.util.Args.notNull;

/**
 * X.509 certificate utility class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class X509Util {
  private static final Logger LOG = LoggerFactory.getLogger(X509Util.class);

  private static final byte[] BEGIN_PEM = StringUtil.toUtf8Bytes("-----BEGIN");

  private static final byte[] END_PEM = StringUtil.toUtf8Bytes("-----END");

  private static final byte[] PEM_SEP = StringUtil.toUtf8Bytes("-----");

  private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";

  private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

  private static final byte[] PEM_PREFIX = StringUtil.toUtf8Bytes("-----BEGIN");

  private static CertificateFactory certFact;

  private static final Object certFactLock = new Object();

  private X509Util() {
  }

  public static String getCommonName(X500Name name) {
    RDN[] rdns = notNull(name, "name").getRDNs(ObjectIdentifiers.DN.CN);
    if (rdns != null && rdns.length > 0) {
      RDN rdn = rdns[0];
      AttributeTypeAndValue atv = null;
      if (rdn.isMultiValued()) {
        for (AttributeTypeAndValue m : rdn.getTypesAndValues()) {
          if (m.getType().equals(ObjectIdentifiers.DN.CN)) {
            atv = m;
            break;
          }
        }
      } else {
        atv = rdn.getFirst();
      }
      return (atv == null) ? null : rdnValueToString(atv.getValue());
    }
    return null;
  } // method getCommonName

  public static X500Name reverse(X500Name name) {
    RDN[] orig = notNull(name, "name").getRDNs();
    final int n = orig.length;
    RDN[] newRdn = new RDN[n];
    for (int i = 0; i < n; i++) {
      newRdn[i] = orig[n - 1 - i];
    }
    return new X500Name(newRdn);
  }

  public static X509Cert parseCert(File file) throws IOException, CertificateException {
    return parseCert(IoUtil.read(
        IoUtil.expandFilepath(notNull(file, "file"))));
  }

  public static List<X509Cert> parseCerts(byte[] certsBytes) throws IOException, CertificateException {
    try (InputStream is = new ByteArrayInputStream(certsBytes)) {
      return parseCerts(is);
    }
  }

  public static List<X509Cert> parseCerts(File certsFile) throws IOException, CertificateException {
    try (InputStream is = Files.newInputStream(certsFile.toPath())) {
      return parseCerts(is);
    }
  }

  /**
   * Read a list of X.509 certificates from the input stream consisting of several
   * PEM certificates.
   * The specified stream remains open after this method returns.
   * @param certsStream the input stream of PEM certificates.
   * @return a list of X.509 certificates.
   * @throws IOException if IO error occurs while reading the input stream.
   * @throws CertificateException if error occurs parsing the certificates.
   */
  private static List<X509Cert> parseCerts(InputStream certsStream) throws IOException, CertificateException {
    List<X509Cert> certs = new LinkedList<>();
    try (PemReader pemReader = new PemReader(
        new InputStreamReader(certsStream, StandardCharsets.UTF_8))) {
      PemObject pemObj;
      while ((pemObj = pemReader.readPemObject()) != null) {
        if ("CERTIFICATE".equalsIgnoreCase(pemObj.getType())) {
          certs.add(parseCert(pemObj.getContent()));
        }
      }
    }
    return certs;
  }

  public static X509Cert parseCert(byte[] bytes) throws CertificateEncodingException {
    byte[] certBytes = null;
    if (CompareUtil.areEqual(notNull(bytes, "bytes"), 0, PEM_PREFIX, 0, PEM_PREFIX.length)) {
      try (PemReader r = new PemReader(
          new InputStreamReader(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8))) {
        PemObject obj;
        while (true) {
          obj = r.readPemObject();
          if (obj == null) {
            break;
          }

          if (obj.getType().equalsIgnoreCase("CERTIFICATE")) {
            certBytes = obj.getContent();
            break;
          }
        }

        if (certBytes == null) {
          throw new CertificateEncodingException("found no certificate");
        }
      } catch (IOException ex) {
        throw new CertificateEncodingException("error while parsing bytes");
      }
    } else {
      certBytes = bytes;
    }

    try {
      byte[] derBytes = toDerEncoded(certBytes);
      return new X509Cert(new X509CertificateHolder(derBytes), derBytes);
    } catch (IOException ex) {
      throw new CertificateEncodingException("error decoding certificate: " + ex.getMessage(), ex);
    }
  }

  public static CertificationRequest parseCsr(File file) throws IOException {
    return parseCsr(IoUtil.read(IoUtil.expandFilepath(notNull(file, "file"))));
  }

  public static CertificationRequest parseCsr(byte[] csrBytes) throws IOException {
    try {
      return CertificationRequest.getInstance(toDerEncoded(notNull(csrBytes, "csrBytes")));
    } catch (IllegalArgumentException ex) {
      throw new IOException("invalid CSR bytes", ex);
    }
  }

  public static byte[] toDerEncoded(byte[] bytes) {
    Args.notNull(bytes, "bytes");
    final int len = bytes.length;

    if (len > 23) {
      // check if PEM encoded
      if (CompareUtil.areEqual(bytes, 0, BEGIN_PEM, 0, BEGIN_PEM.length)) {
        int base64Start = -1;
        int base64End = -1;

        for (int i = BEGIN_PEM.length + 1; i < len; i++) {
          if (CompareUtil.areEqual(bytes, i, PEM_SEP, 0, PEM_SEP.length)) {
            base64Start = i + PEM_SEP.length;
            break;
          }
        }

        if (bytes[base64Start] == '\n') {
          base64Start++;
        }

        for (int i = len - END_PEM.length - 6; i > 0; i--) {
          if (CompareUtil.areEqual(bytes, i, END_PEM, 0, END_PEM.length)) {
            base64End = i - 1;
            break;
          }
        }

        if (bytes[base64End - 1] == '\r') {
          base64End--;
        }

        byte[] base64Bytes = new byte[base64End - base64Start + 1];
        System.arraycopy(bytes, base64Start, base64Bytes, 0, base64Bytes.length);
        return Base64.decode(base64Bytes);
      }
    }

    // check whether base64 encoded
    if (Base64.containsOnlyBase64Chars(bytes, 0, 10)) {
      return Base64.decode(bytes);
    }

    return bytes;
  } // method toDerEncoded

  private static CertificateFactory getCertFactory() throws CertificateException {
    synchronized (certFactLock) {
      if (certFact == null) {
        try {
          certFact = CertificateFactory.getInstance("X.509", "BC");
        } catch (NoSuchProviderException ex) {
          throw new CertificateException("NoSuchProviderException: " + ex.getMessage());
        }
      }
      return certFact;
    }
  }

  public static String toPemCert(X509Cert cert) {
    return StringUtil.toUtf8String(PemEncoder.encode(notNull(cert, "cert").getEncoded(), PemLabel.CERTIFICATE));
  }

  public static X509Certificate parseX509Certificate(byte[] bytes) throws CertificateException {
    try (InputStream is = new ByteArrayInputStream(notNull(bytes, "bytes"))) {
      return (X509Certificate) getCertFactory().generateCertificate(is);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static X509CRLHolder parseCrl(File file) throws IOException, CRLException {
    return parseCrl(Files.readAllBytes(IoUtil.expandFilepath(notNull(file, "file")).toPath()));
  }

  public static X509CRLHolder parseCrl(byte[] encodedCrl) throws CRLException {
    try {
      return new X509CRLHolder(toDerEncoded(notNull(encodedCrl, "encodedCrl")));
    } catch (IOException ex) {
      throw new CRLException("the given one is not a valid X.509 CRL");
    }
  }

  public static String x500NameText(X500Name name) {
    return BCStyle.INSTANCE.toString(notNull(name, "name"));
  }

  public static long fpCanonicalizedName(X500Name name) {
    return FpIdCalculator.hash(StringUtil.toUtf8Bytes(canonicalizeName(notNull(name, "name"))));
  }

  @Deprecated
  public static String canonicalizName(X500Name name) {
    return canonicalizeName(name);
  }

  public static String canonicalizeName(X500Name name) {
    ASN1ObjectIdentifier[] tmpTypes = notNull(name, "name").getAttributeTypes();
    int len = tmpTypes.length;
    List<String> types = new ArrayList<>(len);
    for (ASN1ObjectIdentifier type : tmpTypes) {
      types.add(type.getId());
    }

    Collections.sort(types);

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < len; i++) {
      String type = types.get(i);
      if (i > 0) {
        sb.append(",");
      }
      sb.append(type).append("=");
      RDN[] rdns = name.getRDNs(new ASN1ObjectIdentifier(type));

      List<String> values = new ArrayList<>(1);
      for (RDN rdn : rdns) {
        if (rdn.isMultiValued()) {
          AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
          for (AttributeTypeAndValue atv : atvs) {
            if (type.equals(atv.getType().getId())) {
              values.add(IETFUtils.valueToString(atv.getValue()).toLowerCase());
            }
          }
        } else {
          values.add(IETFUtils.valueToString(rdn.getFirst().getValue()).toLowerCase());
        }
      } // end for(j)

      sb.append(values.get(0));

      final int n2 = values.size();
      if (n2 > 1) {
        for (int j = 1; j < n2; j++) {
          sb.append(";").append(values.get(j));
        }
      }
    } // end for(i)

    return sb.toString();
  } // method canonicalizeName

  public static String rdnValueToString(ASN1Encodable value) {
    Args.notNull(value, "value");
    if (value instanceof ASN1String && !(value instanceof DERUniversalString)) {
      return ((ASN1String) value).getString();
    } else {
      try {
        return "#" + Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
      } catch (IOException ex) {
        throw new IllegalArgumentException("other value has no encoded form");
      }
    }
  }

  public static org.bouncycastle.asn1.x509.KeyUsage createKeyUsage(Set<KeyUsage> usages) {
    if (CollectionUtil.isEmpty(usages)) {
      return null;
    }

    int usage = 0;
    for (KeyUsage keyUsage : usages) {
      usage |= keyUsage.getBcUsage();
    }

    return new org.bouncycastle.asn1.x509.KeyUsage(usage);
  }

  public static ExtendedKeyUsage createExtendedUsage(Collection<ASN1ObjectIdentifier> usages) {
    if (CollectionUtil.isEmpty(usages)) {
      return null;
    }

    List<ASN1ObjectIdentifier> list = new ArrayList<>(usages);
    list.sort(Comparator.comparing(ASN1ObjectIdentifier::getId));
    list = removeDuplication(list);

    KeyPurposeId[] kps = new KeyPurposeId[list.size()];

    int idx = 0;
    for (ASN1ObjectIdentifier oid : list) {
      kps[idx++] = KeyPurposeId.getInstance(oid);
    }

    return new ExtendedKeyUsage(kps);
  }

  // sort the list and remove duplicated OID.
  private static List<ASN1ObjectIdentifier> removeDuplication(List<ASN1ObjectIdentifier> oids) {
    List<ASN1ObjectIdentifier> res = new ArrayList<>(oids.size());
    for (ASN1ObjectIdentifier n : oids) {
      if (!res.contains(n)) {
        res.add(n);
      }
    }
    return res;
  }

  public static byte[] getCoreExtValue(Extensions extensions, ASN1ObjectIdentifier extnType) {
    if (extensions == null) {
      return null;
    }
    Extension extn = extensions.getExtension(notNull(extnType, "extnType"));
    if (extn == null) {
      return null;
    }

    return extn.getExtnValue().getOctets();
  }

  /**
   * Build the certificate path. Cross certificate will not be considered.
   * @param targetCert certificate for which the certificate path will be built
   * @param certs collection of certificates.
   * @return the certificate path
   * @throws CertPathBuilderException
   *           If a valid certificate path can not be built.
   */
  public static X509Cert[] buildCertPath(X509Cert targetCert, Collection<X509Cert> certs)
      throws CertPathBuilderException {
    return buildCertPath(targetCert, certs, true);
  }

  /**
   * Build the certificate path. Cross certificate will not be considered.
   * @param targetCert certificate for which the certificate path will be built
   * @param certs collection of certificates.
   * @param includeTargetCert whether to include {@code targetCert} in the result.
   * @return the certificate path
   */
  public static X509Cert[] buildCertPath(X509Cert targetCert, Collection<X509Cert> certs, boolean includeTargetCert) {
    return buildCertPath(targetCert, certs, null, includeTargetCert);
  }

  public static X509Cert[] buildCertPath(
      X509Cert targetCert, Collection<X509Cert> certs, Collection<X509Cert> trustanchors, boolean includeTargetCert) {
    Args.notNull(targetCert, "cert");

    if (trustanchors == null) {
      trustanchors = Collections.emptySet();
    }

    if (!trustanchors.isEmpty()) {
      Set<X509Cert> coll = certs == null ? new HashSet<>() : new HashSet<>(certs);
      coll.addAll(trustanchors);
      certs = coll;
    }

    List<X509Cert> certChain = new LinkedList<>();
    certChain.add(targetCert);
    try {
      if (certs != null && !targetCert.isSelfSigned()) {
        while (true) {
          X509Cert caCert = getCaCertOf(certChain.get(certChain.size() - 1), certs);
          if (caCert == null) {
            break;
          }
          certChain.add(caCert);
          if (caCert.isSelfSigned() || trustanchors.contains(caCert)) {
            // reaches root self-signed certificate or trustanchor
            break;
          }
        }
      }
    } catch (CertificateEncodingException ex) {
      LOG.warn("CertificateEncodingException: {}", ex.getMessage());
    }

    if (!trustanchors.isEmpty()) {
      if (!trustanchors.contains(certChain.get(certChain.size() - 1))) {
        return null;
      }
    }

    final int n = certChain.size();
    if (n == 1) {
      return includeTargetCert ? certChain.toArray(new X509Cert[0]) : null;
    }

    if (!includeTargetCert) {
      certChain.remove(0);
    }

    return certChain.toArray(new X509Cert[0]);
  } // method buildCertPath

  public static String encodeCertificates(X509Cert[] certchain) {
    if (CollectionUtil.isEmpty(certchain)) {
      return null;
    }

    byte[][] certchainBytes = new byte[certchain.length][];
    for (int i = 0; i < certchain.length; i++) {
      certchainBytes[i] = certchain[i].getEncoded();
    }
    return encodeCertificates(certchainBytes);
  }

  public static String encodeCertificates(byte[][] certchain) {
    if (CollectionUtil.isEmpty(certchain)) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    for (byte[] bytes : certchain) {
      sb.append(StringUtil.toUtf8String(
          PemEncoder.encode(bytes, PemLabel.CERTIFICATE)));
    }
    return sb.toString();
  }

  public static List<X509Cert> listCertificates(String encodedCerts) throws CertificateException, IOException {
    List<X509Cert> certs = new LinkedList<>();
    try (BufferedReader reader = new BufferedReader(new StringReader(encodedCerts));
         ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (BEGIN_CERTIFICATE.equals(line)) {
          bout.reset();
        } else if (END_CERTIFICATE.equals(line)) {
          certs.add(parseCert(bout.toByteArray()));
          bout.reset();
        } else {
          bout.write(StringUtil.toUtf8Bytes(line));
        }
      }
    }
    return certs;
  }

  private static X509Cert getCaCertOf(X509Cert cert, Collection<X509Cert> caCerts) throws CertificateEncodingException {
    if (notNull(cert, "cert").isSelfSigned()) {
      return null;
    }

    for (X509Cert caCert : caCerts) {
      if (!issues(caCert, cert)) {
        continue;
      }

      try {
        cert.verify(caCert.getPublicKey());
        return caCert;
      } catch (Exception ex) {
        LOG.warn("could not verify certificate: {}", ex.getMessage());
      }
    }

    return null;
  }

  public static boolean issues(X509Cert issuerCert, X509Cert cert) {
    Args.notNull(cert, "cert");

    // check basicConstraints
    int pathLen = notNull(issuerCert, "issuerCert").getBasicConstraints();
    if (pathLen == -1) {
      // issuerCert is not a CA certificate
      return false;
    }

    // assert issuerCert.pathLen > cert.pathLen
    if (pathLen != Integer.MAX_VALUE) {
      if (pathLen <= cert.getBasicConstraints()) {
        return false;
      }
    }

    boolean issues = issuerCert.getSubject().equals(cert.getIssuer());
    if (issues) {
      byte[] ski = issuerCert.getSubjectKeyId();
      byte[] aki = cert.getAuthorityKeyId();
      if (ski != null && aki != null) {
        issues = Arrays.equals(ski, aki);
      }
    }

    if (issues) {
      long issuerNotBefore = issuerCert.getNotBefore().toEpochMilli();
      long issuerNotAfter = issuerCert.getNotAfter().toEpochMilli();
      long notBefore = cert.getNotBefore().toEpochMilli();
      issues = notBefore <= issuerNotAfter && notBefore >= issuerNotBefore;
    }

    return issues;
  } // method issues

  public static SubjectPublicKeyInfo toRfc3279Style(SubjectPublicKeyInfo publicKeyInfo)
      throws InvalidKeySpecException {
    ASN1ObjectIdentifier algOid = notNull(publicKeyInfo, "publicKeyInfo").getAlgorithm().getAlgorithm();
    ASN1Encodable keyParameters = publicKeyInfo.getAlgorithm().getParameters();

    if (PKCSObjectIdentifiers.rsaEncryption.equals(algOid)) {
      if (DERNull.INSTANCE.equals(keyParameters)) {
        return publicKeyInfo;
      } else {
        AlgorithmIdentifier keyAlgId = new AlgorithmIdentifier(algOid, DERNull.INSTANCE);
        return new SubjectPublicKeyInfo(keyAlgId, publicKeyInfo.getPublicKeyData().getBytes());
      }
    } else if (X9ObjectIdentifiers.id_dsa.equals(algOid)) {
      if (keyParameters == null) {
        return publicKeyInfo;
      } else if (DERNull.INSTANCE.equals(keyParameters)) {
        AlgorithmIdentifier keyAlgId = new AlgorithmIdentifier(algOid);
        return new SubjectPublicKeyInfo(keyAlgId, publicKeyInfo.getPublicKeyData().getBytes());
      } else {
        try {
          DSAParameter.getInstance(keyParameters);
        } catch (IllegalArgumentException ex) {
          throw new InvalidKeySpecException("keyParameters is not null and Dss-Parms");
        }
        return publicKeyInfo;
      }
    } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(algOid)
        || algOid.getId().equals("1.3.132.1.12")) { // id-ECDH
      if (keyParameters == null) {
        throw new InvalidKeySpecException("keyParameters is not an OBJECT IDENTIFIER");
      }
      try {
        ASN1ObjectIdentifier.getInstance(keyParameters);
      } catch (IllegalArgumentException ex) {
        throw new InvalidKeySpecException("keyParameters is not an OBJECT IDENTIFIER");
      }
      return publicKeyInfo;
    } else if (EdECConstants.isEdwardsOrMontgomeryCurve(algOid)) {
      if (keyParameters == null) {
        return publicKeyInfo;
      } else {
        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(algOid), publicKeyInfo.getPublicKeyData().getBytes());
      }
    } else {
      return publicKeyInfo;
    }
  } // method toRfc3279Style

  public static String cutText(String text, int maxLen) {
    if (notNull(text, "text").length() <= maxLen) {
      return text;
    }
    return StringUtil.concat(text.substring(0, maxLen - 13), "...skipped...");
  }

  public static String cutX500Name(X500Name name, int maxLen) {
    return cutText(x500NameText(name), maxLen);
  }

  public static Extension createExtnSubjectAltName(List<String> taggedValues, boolean critical)
      throws BadInputException {
    GeneralNames names = createGeneralNames(taggedValues);
    if (names == null) {
      return null;
    }

    try {
      return new Extension(Extension.subjectAlternativeName, critical, names.getEncoded());
    } catch (IOException ex) {
      throw new IllegalStateException(ex.getMessage(), ex);
    }
  } // method createExtnSubjectAltName

  public static Extension createExtnSubjectInfoAccess(List<String> accessMethodAndLocations, boolean critical)
      throws BadInputException {
    if (CollectionUtil.isEmpty(accessMethodAndLocations)) {
      return null;
    }

    ASN1EncodableVector vector = new ASN1EncodableVector();
    for (String accessMethodAndLocation : accessMethodAndLocations) {
      vector.add(createAccessDescription(accessMethodAndLocation));
    }
    ASN1Sequence seq = new DERSequence(vector);
    try {
      return new Extension(Extension.subjectInfoAccess, critical, seq.getEncoded());
    } catch (IOException ex) {
      throw new IllegalStateException(ex.getMessage(), ex);
    }
  } // method createExtnSubjectInfoAccess

  private static AccessDescription createAccessDescription(String accessMethodAndLocation) throws BadInputException {
    ConfPairs pairs;
    try {
      pairs = new ConfPairs(notNull(accessMethodAndLocation, "accessMethodAndLocation"));
    } catch (IllegalArgumentException ex) {
      throw new BadInputException("invalid accessMethodAndLocation " + accessMethodAndLocation);
    }

    Set<String> oids = pairs.names();
    if (oids == null || oids.size() != 1) {
      throw new BadInputException("invalid accessMethodAndLocation " + accessMethodAndLocation);
    }

    String accessMethodS = oids.iterator().next();
    String taggedValue = pairs.value(accessMethodS);
    ASN1ObjectIdentifier accessMethod = new ASN1ObjectIdentifier(accessMethodS);

    GeneralName location = createGeneralName(taggedValue);
    return new AccessDescription(accessMethod, location);
  } // method createAccessDescription

  private static GeneralNames createGeneralNames(List<String> taggedValues) throws BadInputException {
    if (CollectionUtil.isEmpty(taggedValues)) {
      return null;
    }

    int len = taggedValues.size();
    GeneralName[] names = new GeneralName[len];
    for (int i = 0; i < len; i++) {
      names[i] = createGeneralName(taggedValues.get(i));
    }
    return new GeneralNames(names);
  } // method createGeneralNames

  /**
  * Creates {@link GeneralName} from the tagged value.
  * @param taggedValue [tag]value, and the value for tags otherName and ediPartyName is
  *     type=value.
  * @return the created {@link GeneralName}
  * @throws BadInputException
  *         if the {@code taggedValue} is invalid.
  */
  private static GeneralName createGeneralName(String taggedValue) throws BadInputException {
    String tagS = null;
    String value = null;
    if (Args.notBlank(taggedValue, "taggedValue").charAt(0) == '[') {
      int idx = taggedValue.indexOf(']', 1);
      if (idx > 1 && idx < taggedValue.length() - 1) {
        tagS = taggedValue.substring(1, idx).toLowerCase();
        value = taggedValue.substring(idx + 1);
      }
    }

    int tag;
    try {
      if ("0".equals(tagS) || "othername".equals(tagS)) {
        tag = 0;
      } else if ("1".equals(tagS) || "email".equals(tagS) || "rfc822".equals(tagS)) {
        tag = 1;
      } else if ("2".equals(tagS) || "dns".equals(tagS) || "dnsname".equals(tagS)) {
        tag = 2;
      } else if ("4".equals(tagS) || "dirname".equals(tagS)) {
        tag = 4;
      } else if ("5".equals(tagS) || "edi".equals(tagS)) {
        tag = 5;
      } else if ("6".equals(tagS) || "uri".equals(tagS)) {
        tag = 6;
      } else if ("7".equals(tagS) || "ip".equals(tagS) || "ipaddress".equals(tagS)) {
        tag = 7;
      } else if ("8".equals(tagS) || "rid".equals(tagS) || "registeredid".equals(tagS)) {
        tag = 8;
      } else {
        throw new BadInputException("unknown tag " + tagS);
      }
    } catch (NumberFormatException ex) {
      throw new BadInputException("invalid tag '" + tagS + "'");
    }

    switch (tag) {
      case GeneralName.otherName: {
        int idxSep = value.indexOf("=");
        if (idxSep == -1 || idxSep == 0 || idxSep == value.length() - 1) {
          throw new BadInputException("invalid otherName " + value);
        }
        String otherTypeOid = value.substring(0, idxSep);
        ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(otherTypeOid);
        String otherValue = value.substring(idxSep + 1);
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(type);

        ASN1Encodable asn1Value;
        if (StringUtil.startsWithIgnoreCase(otherValue, "printablestring:")) {
          asn1Value = new DERPrintableString(otherValue.substring("printablestring:".length()));
        } else if (StringUtil.startsWithIgnoreCase(otherValue, "utf8string:")) {
          asn1Value = new DERUTF8String(otherValue.substring("utf8string:".length()));
        } else {
          asn1Value = new DERUTF8String(otherValue);
        }

        vector.add(new DERTaggedObject(true, 0, asn1Value));
        DERSequence seq = new DERSequence(vector);
        return new GeneralName(tag, seq);
      }
      case GeneralName.rfc822Name:
      case GeneralName.uniformResourceIdentifier:
      case GeneralName.iPAddress:
      case GeneralName.registeredID:
      case GeneralName.dNSName:
        return new GeneralName(tag, value);
      case GeneralName.directoryName:
        return new GeneralName(tag, reverse(new X500Name(value)));
      case GeneralName.ediPartyName: {
        int idxSep = value.indexOf("=");
        if (idxSep == -1 || idxSep == value.length() - 1) {
          throw new BadInputException("invalid ediPartyName " + value);
        }
        String nameAssigner = (idxSep == 0) ? null : value.substring(0, idxSep);
        String partyName = value.substring(idxSep + 1);
        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (nameAssigner != null) {
          vector.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
        }
        vector.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
        return new GeneralName(tag, new DERSequence(vector));
      }
      default:
        throw new IllegalStateException("unsupported tag " + tag);
    } // end switch (tag)
  } // method createGeneralName

  public static String formatCert(X509Cert cert, boolean verbose) {
    if (cert == null) {
      return "  null";
    }

    StringBuilder sb = new StringBuilder(verbose ? 1000 : 100);
    sb.append("  issuer:       ").append(x500NameText(cert.getIssuer())).append('\n');
    sb.append("  serialNumber: ").append(LogUtil.formatCsn(cert.getSerialNumber())).append('\n');
    sb.append("  subject:      ").append(x500NameText(cert.getSubject())).append('\n');
    sb.append("  notBefore:    ").append(cert.getNotBefore()).append("\n");
    sb.append("  notAfter:     ").append(cert.getNotAfter());

    if (verbose) {
      sb.append("\n  encoded:      ").append(Base64.encodeToString(cert.getEncoded()));
    }

    return sb.toString();
  } // method formatCert

  public static Extensions getExtensions(CertificationRequestInfo csr) {
    ASN1Set attrs = notNull(csr, "csr").getAttributes();
    for (int i = 0; i < attrs.size(); i++) {
      org.bouncycastle.asn1.pkcs.Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
      if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
        return Extensions.getInstance(attr.getAttributeValues()[0]);
      }
    }
    return null;
  } // method getExtensions

  public static String getChallengePassword(CertificationRequestInfo csr) {
    Attribute attr = getAttribute(csr, PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
    return attr == null ? null : ((ASN1String) attr.getAttributeValues()[0]).getString();
  }

  public static Attribute getAttribute(CertificationRequestInfo csr, ASN1ObjectIdentifier type) {
    Args.notNull(type, "type");
    ASN1Set attrs = notNull(csr, "csr").getAttributes();
    for (int i = 0; i < attrs.size(); i++) {
      Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
      if (type.equals(attr.getAttrType())) {
        return attr;
      }
    }
    return null;
  } // method getChallengePassword

  public static List<X509Cert> parseCerts(List<FileOrBinary> certsConf) throws InvalidConfException {
    if (CollectionUtil.isEmpty(certsConf)) {
      return Collections.emptyList();
    }

    List<X509Cert> certs = new ArrayList<>(certsConf.size());

    for (FileOrBinary m : certsConf) {
      try {
        X509Cert cert = parseCert(m.readContent());
        certs.add(cert);
      } catch (CertificateException | IOException ex) {
        String msg = "could not parse the certificate";
        if (m.getFile() != null) {
          msg += " " + m.getFile();
        }
        throw new InvalidConfException(msg, ex);
      }
    }

    return certs;
  }

  public static void assertCsrAndCertMatch(CertificationRequest csr, Certificate targetCert, boolean caCertRequired)
      throws XiSecurityException {
    CertificationRequestInfo cri = csr.getCertificationRequestInfo();

    try {
      if (!Arrays.equals(cri.getSubject().getEncoded(), targetCert.getSubject().getEncoded())) {
        throw new XiSecurityException("CSR and certificate do not have the same subject");
      }

      if (!Arrays.equals(cri.getSubjectPublicKeyInfo().getEncoded(),
          targetCert.getSubjectPublicKeyInfo().getEncoded())) {
        throw new XiSecurityException("CSR and certificate do not have the same SubjectPublicKeyInfo");
      }

      if (caCertRequired) {
        Extension extn = targetCert.getTBSCertificate().getExtensions().getExtension(Extension.basicConstraints);
        BasicConstraints bc = extn == null ? null : BasicConstraints.getInstance(extn.getParsedValue());
        if (bc == null || !bc.isCA()) {
          throw new XiSecurityException("targetCert is not a CA certificate");
        }
      }
    } catch (IOException | RuntimeException ex) {
      throw new XiSecurityException("error while encoding Subject or SubjectPublicKeyInfo");
    }
  }

  public static byte[] extractCertSubject(byte[] certBytes) {
    return extractCertField(certBytes, "subject");
  }

  public static byte[] extractCertIssuer(byte[] certBytes) {
    return extractCertField(certBytes, "issuer");
  }

  public static long extractCertNotBefore(byte[] certBytes) {
    return extractTime(certBytes, "notBefore");
  }

  public static long extractCertNotAfter(byte[] certBytes) {
    return extractTime(certBytes, "notAfter");
  }

  private static long extractTime(byte[] certBytes, String fieldName) {
    byte[] bytes = extractCertField(certBytes, fieldName);
    if (bytes[0] == BERTags.UTC_TIME) {
      return Time.getInstance(ASN1UTCTime.getInstance(bytes)).getDate().getTime() / 1000;
    } else {
      return Time.getInstance(ASN1GeneralizedTime.getInstance(bytes)).getDate().getTime() / 1000;
    }
  }

  private static byte[] extractCertField(byte[] certBytes, String fieldName) {
    try (BufferedInputStream instream = new BufferedInputStream(new ByteArrayInputStream(certBytes))) {
      // SEQUENCE of Certificate
      Asn1StreamParser.skipTagLen(instream);

      // SEQUENCE OF TBSCertificate
      Asn1StreamParser.skipTagLen(instream);

      // #num = 3: version, serialNumber, signature
      int numFields = 3;
      for (int i = 0; i < numFields; i++) {
        Asn1StreamParser.skipField(instream);
      }

      // issuer
      if ("issuer".equalsIgnoreCase(fieldName)) {
        return Asn1StreamParser.readBlock(Asn1StreamParser.TAG_CONSTRUCTED_SEQUENCE, instream, "issuer");
      } else {
        Asn1StreamParser.skipField(instream);
      }

      // Validity
      if ("notBefore".equalsIgnoreCase(fieldName) || "notAfter".equalsIgnoreCase(fieldName)) {
        Asn1StreamParser.skipTagLen(instream);

        // notBefore
        if ("notBefore".equalsIgnoreCase(fieldName)) {
          return Asn1StreamParser.readBlock(instream, "notBefore");
        } else {
          Asn1StreamParser.skipField(instream);
        }

        // notAfter
        if ("notAfter".equalsIgnoreCase(fieldName)) {
          return Asn1StreamParser.readBlock(instream, "notAfter");
        } else {
          Asn1StreamParser.skipField(instream);
        }
      } else {
        Asn1StreamParser.skipField(instream);
      }

      if ("subject".equalsIgnoreCase(fieldName)) {
        return Asn1StreamParser.readBlock(Asn1StreamParser.TAG_CONSTRUCTED_SEQUENCE, instream, "subject");
      }
    } catch (IOException e) {
      throw new RuntimeException("invalid certificate", e);
    }

    throw new IllegalArgumentException("unknown fieldName " + fieldName);
  }

}
