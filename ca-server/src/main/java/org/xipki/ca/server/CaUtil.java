// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.SubjectDnSpec;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Util class of CA.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CaUtil {

  private static final ASN1ObjectIdentifier id_ce = new ASN1ObjectIdentifier("2.5.29");

  private static final List<ASN1ObjectIdentifier> SORTED_EXTENSIONS;

  static {
    SORTED_EXTENSIONS = Collections.unmodifiableList(
        Arrays.asList(Extension.subjectKeyIdentifier, Extension.authorityKeyIdentifier,
            Extension.basicConstraints,      Extension.keyUsage,               Extension.extendedKeyUsage,
            Extension.privateKeyUsagePeriod, Extension.subjectAlternativeName, Extension.issuerAlternativeName,
            Extension.authorityInfoAccess,   Extension.cRLDistributionPoints,  Extension.freshestCRL,
            Extension.certificatePolicies,   Extension.qCStatements,           Extension.nameConstraints,
            Extension.policyConstraints,     Extension.policyMappings,         Extension.subjectInfoAccess,
            Extension.subjectDirectoryAttributes));
  }

  private CaUtil() {
  }

  public static void addExtensions(ExtensionValues extensionValues, X509v3CertificateBuilder certBuilder)
      throws CertIOException {
    if (extensionValues == null) {
      return;
    }

    // sort the extensions
    // 1. extensions with given order
    for (ASN1ObjectIdentifier type : SORTED_EXTENSIONS) {
      ExtensionValue value = extensionValues.removeExtensionTuple(type);
      if (value != null) {
        certBuilder.addExtension(type, value.isCritical(), value.getValue());
      }
    }

    // 2. id-ce
    // Get a copy of the types, without copy concurrent access exception may be thrown.
    for (ASN1ObjectIdentifier type : new HashSet<>(extensionValues.getExtensionTypes())) {
      if (type.on(id_ce)) {
        ExtensionValue value = extensionValues.removeExtensionTuple(type);
        certBuilder.addExtension(type, value.isCritical(), value.getValue());
      }
    }

    // 3. non-PEN extensions
    for (ASN1ObjectIdentifier type : new HashSet<>(extensionValues.getExtensionTypes())) {
      if (!type.on(ObjectIdentifiers.id_pen)) {
        ExtensionValue value = extensionValues.removeExtensionTuple(type);
        certBuilder.addExtension(type, value.isCritical(), value.getValue());
      }
    }

    // 4. PEN extensions
    for (ASN1ObjectIdentifier type : new HashSet<>(extensionValues.getExtensionTypes())) {
      ExtensionValue value = extensionValues.removeExtensionTuple(type);
      certBuilder.addExtension(type, value.isCritical(), value.getValue());
    }
  }

  @SafeVarargs
  public static <T> List<T> asModifiableList(T... a) {
    List<T> list = new ArrayList<>(a.length);
    list.addAll(Arrays.asList(a));
    return list;
  }

  public static BasicConstraints createBasicConstraints(CertLevel level, Integer pathLen) {
    return (level == CertLevel.EndEntity) ? new BasicConstraints(false)
        : (pathLen != null) ? new BasicConstraints(pathLen) : new BasicConstraints(true);
  } // method createBasicConstraints

  public static AuthorityInformationAccess createAuthorityInformationAccess(
      List<String> caIssuerUris, List<String> ocspUris) {
    if (CollectionUtil.isEmpty(caIssuerUris) && CollectionUtil.isEmpty(ocspUris)) {
      throw new IllegalArgumentException("caIssuerUris and ospUris may not be both empty");
    }

    ASN1EncodableVector accessDescriptions = new ASN1EncodableVector();

    if (CollectionUtil.isNotEmpty(caIssuerUris)) {
      for (String uri : caIssuerUris) {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
        accessDescriptions.add(new AccessDescription(X509ObjectIdentifiers.id_ad_caIssuers, gn));
      }
    }

    if (CollectionUtil.isNotEmpty(ocspUris)) {
      for (String uri : ocspUris) {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
        accessDescriptions.add(new AccessDescription(X509ObjectIdentifiers.id_ad_ocsp, gn));
      }
    }

    return AuthorityInformationAccess.getInstance(new DERSequence(accessDescriptions));
  } // method createAuthorityInformationAccess

  public static CRLDistPoint createCrlDistributionPoints(
      List<String> crlUris, X500Name caSubject, X500Name crlSignerSubject) {
    int size = Args.notEmpty(crlUris, "crlUris").size();
    DistributionPoint[] points = new DistributionPoint[1];

    GeneralName[] names = new GeneralName[size];
    for (int i = 0; i < size; i++) {
      names[i] = new GeneralName(GeneralName.uniformResourceIdentifier, crlUris.get(i));
    }
    // Distribution Point
    DistributionPointName pointName = new DistributionPointName(new GeneralNames(names));

    GeneralNames crlIssuer = null;
    if (crlSignerSubject != null && !crlSignerSubject.equals(caSubject)) {
      GeneralName crlIssuerName = new GeneralName(crlSignerSubject);
      crlIssuer = new GeneralNames(crlIssuerName);
    }

    points[0] = new DistributionPoint(pointName, null, crlIssuer);

    return new CRLDistPoint(points);
  } // method createCrlDistributionPoints

  public static X500Name sortX509Name(X500Name name) {
    RDN[] requestedRdns = Args.notNull(name, "name").getRDNs();
    List<RDN> rdns = new LinkedList<>();

    List<ASN1ObjectIdentifier> sortedDNs = SubjectDnSpec.getForwardDNs();
    for (ASN1ObjectIdentifier type : sortedDNs) {
      RDN[] thisRdns = getRdns(requestedRdns, type);
      if (thisRdns == null) {
        continue;
      }
      if (thisRdns.length == 0) {
        continue;
      }

      rdns.addAll(Arrays.asList(thisRdns));
    }

    return new X500Name(rdns.toArray(new RDN[0]));
  } // method sortX509Name

  private static RDN[] getRdns(RDN[] rdns, ASN1ObjectIdentifier type) {
    Args.notNull(rdns, "rdns");
    Args.notNull(type, "type");
    List<RDN> ret = new ArrayList<>(1);
    for (RDN rdn : rdns) {
      if (rdn.getFirst().getType().equals(type)) {
        ret.add(rdn);
      }
    }

    return CollectionUtil.isEmpty(ret) ? null : ret.toArray(new RDN[0]);
  } // method getRdns

  public static String canonicalizeSignerConf(String signerConf) throws CaMgmtException {
    if (!signerConf.contains("file:") && !signerConf.contains("base64:")) {
      return signerConf;
    }

    ConfPairs pairs = new ConfPairs(signerConf);

    String algo = pairs.value("algo");
    if (algo != null) {
      try {
        algo = SignAlgo.getInstance(algo).getJceName();
      } catch (NoSuchAlgorithmException ex) {
        throw new CaMgmtException(ex);
      }
      pairs.putPair("algo", algo);
    }

    String keystoreConf = pairs.value("keystore");

    byte[] ksBytes;
    if (StringUtil.startsWithIgnoreCase(keystoreConf, "file:")) {
      String keystoreFile = keystoreConf.substring("file:".length());
      try {
        ksBytes = IoUtil.read(keystoreFile, true);
      } catch (IOException ex) {
        throw new CaMgmtException("IOException: " + ex.getMessage(), ex);
      }
    } else if (StringUtil.startsWithIgnoreCase(keystoreConf, "base64:")) {
      ksBytes = Base64.decode(keystoreConf.substring("base64:".length()));
    } else {
      return signerConf;
    }

    pairs.putPair("keystore", "base64:" + Base64.encodeToString(ksBytes));
    return pairs.getEncoded();
  } // method canonicalizeSignerConf

  /**
   * If the content has less than 256 chars, then returns a {@link FileOrValue} with text content,
   * otherwise, the content is written to the zipStream and a {@link FileOrValue}, with file name
   * pointing to the location in the ZIP file, is returned.
   * The specified stream remains open after this method returns.
   * @param content the content
   * @param zipStream the ZIP output stream
   * @param fileName the file name in the ZIP stream when writing to the ZIp stream.
   * @return a {@link FileOrBinary} with the content or fileName as value.
   * @throws IOException if IO error occurs when writing to the ZIP output stream.
   */
  public static FileOrValue createFileOrValue(ZipOutputStream zipStream, String content, String fileName)
      throws IOException {
    if (StringUtil.isBlank(content)) {
      return null;
    }

    FileOrValue ret = new FileOrValue();
    if (content.length() < 256) {
      ret.setValue(content);
    } else {
      ret.setFile(fileName);
      ZipEntry certZipEntry = new ZipEntry(fileName);
      zipStream.putNextEntry(certZipEntry);
      try {
        zipStream.write(StringUtil.toUtf8Bytes(content));
      } finally {
        zipStream.closeEntry();
      }
    }
    return ret;
  } // method createFileOrValue

  /**
   * If the content of the decoded b64Content is less than 256 bytes, then returns a {@link FileOrBinary}
   * with binary content, otherwise, the content is written to the zipStream and a {@link FileOrBinary},
   * with file name pointing to the location in the ZIP file, is returned.
   * The specified stream remains open after this method returns.
   * @param b64Content the BASE64-encoded content
   * @param zipStream the ZIP output stream
   * @param fileName the file name in the ZIP stream when writing to the ZIp stream.
   * @return a {@link FileOrBinary} with the content or fileName as value.
   * @throws IOException if IO error occurs when writing to the ZIP output stream.
   */
  public static FileOrBinary createFileOrBase64Value(ZipOutputStream zipStream, String b64Content, String fileName)
      throws IOException {
    if (StringUtil.isBlank(b64Content)) {
      return null;
    }

    return createFileOrBinary(zipStream, Base64.decode(b64Content), fileName);
  } // method createFileOrBase64Value

  /**
   * If the content is less than 256 bytes, then returns a {@link FileOrBinary} with binary content,
   * otherwise, the content is written to the zipStream and a {@link FileOrBinary}, with file name
   * pointing to the location in the ZIP file, is returned.
   * The specified stream remains open after this method returns.
   * @param content the content
   * @param zipStream the ZIP output stream
   * @param fileName the file name in the ZIP stream when writing to the ZIp stream.
   * @return a {@link FileOrBinary} with the content or fileName as value.
   * @throws IOException if IO error occurs when writing to the ZIP output stream.
   */
  public static FileOrBinary createFileOrBinary(ZipOutputStream zipStream, byte[] content, String fileName)
      throws IOException {
    if (content == null || content.length == 0) {
      return null;
    }

    FileOrBinary ret = new FileOrBinary();
    if (content.length < 256) {
      ret.setBinary(content);
    } else {
      ret.setFile(fileName);
      ZipEntry certZipEntry = new ZipEntry(fileName);
      zipStream.putNextEntry(certZipEntry);
      try {
        zipStream.write(content);
      } finally {
        zipStream.closeEntry();
      }
    }
    return ret;
  } // method createFileOrBinary

  public static List<String> getPermissions(int permission) {
    List<String> list = new LinkedList<>();
    if (PermissionConstants.ALL == permission) {
      list.add(PermissionConstants.getTextForCode(permission));
    } else {
      for (Integer code : PermissionConstants.getPermissions()) {
        if ((permission & code) != 0) {
          list.add(PermissionConstants.getTextForCode(code));
        }
      }
    }

    return list;
  } // method getPermissions

  public static String encodeCertchain(List<X509Cert> certs) {
    return X509Util.encodeCertificates(certs.toArray(new X509Cert[0]));
  }

  public static List<X509Cert> buildCertChain(X509Cert targetCert, List<X509Cert> certs)
      throws CaMgmtException {
    X509Cert[] certchain = X509Util.buildCertPath(targetCert, certs, false);
    if (certchain == null || certs.size() != certchain.length) {
      throw new CaMgmtException("could not build certchain containing all specified certs");
    }
    return Arrays.asList(certchain);
  } // method buildCertChain

  public static X509Cert parseCert(byte[] encodedCert) throws CaMgmtException {
    try {
      return X509Util.parseCert(encodedCert);
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse certificate", ex);
    }
  } // method parseCert

  // remove the RDNs with empty content
  public static X500Name removeEmptyRdns(X500Name name) {
    RDN[] rdns = name.getRDNs();
    List<RDN> tmpRdns = new ArrayList<>(rdns.length);
    boolean changed = false;
    for (RDN rdn : rdns) {
      String textValue = X509Util.rdnValueToString(rdn.getFirst().getValue());
      if (StringUtil.isBlank(textValue)) {
        changed = true;
      } else {
        tmpRdns.add(rdn);
      }
    }

    return changed ? new X500Name(tmpRdns.toArray(new RDN[0])) : name;
  } // method removeEmptyRdns

}
