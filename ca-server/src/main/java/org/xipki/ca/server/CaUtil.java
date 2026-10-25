// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.GenerationException;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.X509OIDs;
import org.xipki.pkix.asn1.x500.RDN;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.*;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.ExtensionsControl;
import org.xipki.ca.api.profile.ctrl.SubjectDnSpec;
import org.xipki.codec.util.Args;
import org.xipki.codec.Base64;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.codec.ConfPairs;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.pkix.util.conf.FileOrBinary;
import org.xipki.pkix.util.conf.FileOrValue;
import org.xipki.pkix.util.io.XipkiIoUtil;
import org.xipki.pkix.util.misc.StringUtil;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * CA Util.
 *
 * @author Lijun Liao (xipki)
 */
public class CaUtil {

  private static final String id_ce_prefix = "2.5.29.";

  private static final String id_pen_prefix = "1.3.6.1.4.1.";

  private static final List<Asn1Oid> SORTED_EXTENSIONS;

  static {
    SORTED_EXTENSIONS = List.of(ExtensionOIDs.subjectKeyIdentifier,
        ExtensionOIDs.authorityKeyIdentifier, ExtensionOIDs.basicConstraints,
        ExtensionOIDs.keyUsage,               ExtensionOIDs.extendedKeyUsage,
        ExtensionOIDs.privateKeyUsagePeriod,  ExtensionOIDs.subjectAlternativeName,
        ExtensionOIDs.issuerAlternativeName,  ExtensionOIDs.authorityInfoAccess,
        ExtensionOIDs.cRLDistributionPoints,  ExtensionOIDs.freshestCRL,
        ExtensionOIDs.certificatePolicies,    ExtensionOIDs.qCStatements,
        ExtensionOIDs.nameConstraints,        ExtensionOIDs.policyConstraints,
        ExtensionOIDs.policyMappings,         ExtensionOIDs.subjectInfoAccess,
        ExtensionOIDs.subjectDirectoryAttributes);
  }

  private CaUtil() {
  }

  public static void addExtensions(
      ExtensionValues extensionValues, Certificate.V3CertBuilder certBuilder,
      ExtensionsControl control) throws GenerationException {
    if (extensionValues == null) {
      return;
    }

    if (control.isKeepOrder()) {
      for (Asn1Oid type : control.types()) {
        ExtensionValue value = extensionValues.removeExtensionValue(type);
        if (value != null) {
          certBuilder.addExtension(
              Extension.createNoParse(type, value.isCritical(), value.value()));
        }
      }

      return;
    }

    // sort the extensions
    // 1. extensions with given order
    for (Asn1Oid type : SORTED_EXTENSIONS) {
      ExtensionValue value = extensionValues.removeExtensionValue(type);
      if (value != null) {
        certBuilder.addExtension(
            Extension.createNoParse(type, value.isCritical(), value.value()));
      }
    }

    // 2. id-ce
    // Get a copy of the types, without copy concurrent access exception may
    // be thrown.
    for (Asn1Oid type : new HashSet<>(extensionValues.getExtensionTypes())) {
      if (type.getId().startsWith(id_ce_prefix)) {
        ExtensionValue value = extensionValues.removeExtensionValue(type);
        certBuilder.addExtension(Extension.createNoParse(
            type, value.isCritical(), value.value()));
      }
    }

    // 3. non-PEN extensions
    for (Asn1Oid type : new HashSet<>(extensionValues.getExtensionTypes())) {
      if (!type.getId().startsWith(id_pen_prefix)) {
        ExtensionValue value = extensionValues.removeExtensionValue(type);
        certBuilder.addExtension(Extension.createNoParse(
            type, value.isCritical(), value.value()));
      }
    }

    // 4. PEN extensions
    for (Asn1Oid type : new HashSet<>(extensionValues.getExtensionTypes())) {
      ExtensionValue value = extensionValues.removeExtensionValue(type);
      certBuilder.addExtension(Extension.createNoParse(
          type, value.isCritical(), value.value()));
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

  public static AuthorityInfoAccessSyntax createAuthorityInformationAccess(
      List<String> caIssuerUris, List<String> ocspUris) {
    if (CollectionUtil.isEmpty(caIssuerUris) && CollectionUtil.isEmpty(ocspUris)) {
      throw new IllegalArgumentException("caIssuerUris and ospUris may not be both empty");
    }

    List<AccessDescription> accessDescriptions = new LinkedList<>();

    if (CollectionUtil.isNotEmpty(caIssuerUris)) {
      for (String uri : caIssuerUris) {
        GeneralName gn = GeneralName.ofUri(uri);
        accessDescriptions.add(new AccessDescription(X509OIDs.id_ad_caIssuers, gn));
      }
    }

    if (CollectionUtil.isNotEmpty(ocspUris)) {
      for (String uri : ocspUris) {
        GeneralName gn = GeneralName.ofUri(uri);
        accessDescriptions.add(new AccessDescription(X509OIDs.id_ad_ocsp, gn));
      }
    }

    return new AuthorityInfoAccessSyntax(accessDescriptions);
  } // method createX509AuthorityInformationAccess

  public static CRLDistributionPoints createCrlDistributionPoints(
      List<String> crlUris, X500Name caSubject, X500Name crlSignerSubject) {
    int size = Args.notEmpty(crlUris, "crlUris").size();
    DistributionPoint[] points = new DistributionPoint[1];

    GeneralName[] names = new GeneralName[size];
    for (int i = 0; i < size; i++) {
      names[i] = GeneralName.ofUri(crlUris.get(i));
    }
    // Distribution Point
    DistributionPointName pointName = DistributionPointName.ofName(new GeneralNames(names));

    GeneralNames crlIssuer = null;
    if (crlSignerSubject != null && !crlSignerSubject.equals(caSubject)) {
      GeneralName crlIssuerName = GeneralName.ofDirectoryName(crlSignerSubject);
      crlIssuer = new GeneralNames(crlIssuerName);
    }

    points[0] = new DistributionPoint(pointName, null, crlIssuer);

    return new CRLDistributionPoints(points);
  } // method createCrlDistributionPoints

  public static X500Name sortX509Name(X500Name name) {
    List<RDN> requestedRdns = name.getRDNs();
    List<RDN> rdns = new LinkedList<>();

    List<Asn1Oid> sortedDNs = SubjectDnSpec.getForwardDNs();
    for (Asn1Oid type : sortedDNs) {
      RDN[] thisRdns = getX509Rdns(requestedRdns, type);
      if (thisRdns == null || thisRdns.length == 0) {
        continue;
      }

      rdns.addAll(Arrays.asList(thisRdns));
    }

    // add all remaining RDNs
    for (RDN rdn : requestedRdns) {
      Asn1Oid type = rdn.getFirst().getType();
      if (!sortedDNs.contains(type)) {
        rdns.add(rdn);
      }
    }

    return new X500Name(rdns.toArray(new RDN[0]));
  }

  private static RDN[] getX509Rdns(List<RDN> rdns, Asn1Oid type) {
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
        algo = SignAlgo.getInstance(algo).jceName();
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
        ksBytes = XipkiIoUtil.read(keystoreFile, true);
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
   * If the content has less than 256 chars, then returns a {@link FileOrValue}
   * with text content, otherwise, the content is written to the zipStream and
   * a {@link FileOrValue}, with file name pointing to the location in the
   * ZIP file, is returned.
   * <p>
   * The specified stream remains open after this method returns.
   * @param content
   *        the content
   * @param zipStream
   *        the ZIP output stream
   * @param fileName
   *        the file name in the ZIP stream when writing to the ZIp stream.
   * @return a {@link FileOrBinary} with the content or fileName as value.
   * @throws IOException
   *         if IO error occurs when writing to the ZIP output stream.
   */
  public static FileOrValue createFileOrValue(
      ZipOutputStream zipStream, String content, String fileName) throws IOException {
    if (StringUtil.isBlank(content)) {
      return null;
    }

    FileOrValue ret;
    if (content.length() < 256) {
      ret = FileOrValue.ofValue(content);
    } else {
      ret = FileOrValue.ofFile(fileName);
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
   * If the content of the decoded b64Content is less than 256 bytes, then
   * returns a {@link FileOrBinary} with binary content, otherwise, the content
   * is written to the zipStream and a {@link FileOrBinary}, with file name
   * pointing to the location in the ZIP file, is returned.s
   * <p/>
   *
   * The specified stream remains open after this method returns.
   * @param b64Content
   *        the BASE64-encoded content
   * @param zipStream
   *        the ZIP output stream
   * @param fileName
   *        the file name in the ZIP stream when writing to the ZIp stream.
   * @return a {@link FileOrBinary} with the content or fileName as value.
   * @throws IOException
   *         if IO error occurs when writing to the ZIP output stream.
   */
  public static FileOrBinary createFileOrBase64Value(
      ZipOutputStream zipStream, String b64Content, String fileName) throws IOException {
    if (StringUtil.isBlank(b64Content)) {
      return null;
    }

    return createFileOrBinary(zipStream, Base64.decode(b64Content), fileName);
  } // method createFileOrBase64Value

  /**
   * If the content is less than 256 bytes, then returns a {@link FileOrBinary}
   * with binary content, otherwise, the content is written to the zipStream
   * and a {@link FileOrBinary}, with file name pointing to the location in the
   * ZIP file, is returned.
   * <p>
   * The specified stream remains open after this method returns.
   * @param content
   *        the content
   * @param zipStream
   *        the ZIP output stream
   * @param fileName
   *        the file name in the ZIP stream when writing to the ZIp stream.
   * @return a {@link FileOrBinary} with the content or fileName as value.
   * @throws IOException
   *         if IO error occurs when writing to the ZIP output stream.
   */
  public static FileOrBinary createFileOrBinary(
      ZipOutputStream zipStream, byte[] content, String fileName) throws IOException {
    if (content == null || content.length == 0) {
      return null;
    }

    FileOrBinary ret;
    if (content.length < 256) {
      ret = FileOrBinary.ofBinary(content);
    } else {
      ret = FileOrBinary.ofFile(fileName);
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
    List<RDN> rdns = name.getRDNs();
    List<RDN> tmpRdns = new ArrayList<>(rdns.size());
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
