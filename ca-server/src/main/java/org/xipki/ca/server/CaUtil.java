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

package org.xipki.ca.server;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.SubjectDnSpec;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.*;
import org.xipki.security.ObjectIdentifiers.Xipki;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.xipki.util.Args.notEmpty;
import static org.xipki.util.Args.notNull;

/**
 * Util class of CA.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaUtil {

  private CaUtil() {
  }

  public static Extensions getExtensions(CertificationRequestInfo csr) {
    notNull(csr, "csr");
    ASN1Set attrs = csr.getAttributes();
    for (int i = 0; i < attrs.size(); i++) {
      Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
      if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
        return Extensions.getInstance(attr.getAttributeValues()[0]);
      }
    }
    return null;
  } // method getExtensions

  public static String getChallengePassword(CertificationRequestInfo csr) {
    notNull(csr, "csr");
    ASN1Set attrs = csr.getAttributes();
    for (int i = 0; i < attrs.size(); i++) {
      Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
      if (PKCSObjectIdentifiers.pkcs_9_at_challengePassword.equals(attr.getAttrType())) {
        ASN1String str = (ASN1String) attr.getAttributeValues()[0];
        return str.getString();
      }
    }
    return null;
  } // method getChallengePassword

  public static BasicConstraints createBasicConstraints(CertLevel level, Integer pathLen) {
    BasicConstraints basicConstraints;
    if (level == CertLevel.RootCA || level == CertLevel.SubCA) {
      basicConstraints = (pathLen != null)  ? new BasicConstraints(pathLen)
          : new BasicConstraints(true);
    } else if (level == CertLevel.EndEntity) {
      basicConstraints = new BasicConstraints(false);
    } else {
      throw new IllegalStateException("unknown CertLevel " + level);
    }
    return basicConstraints;
  } // method createBasicConstraints

  public static AuthorityInformationAccess createAuthorityInformationAccess(
      List<String> caIssuerUris, List<String> ocspUris) {
    if (CollectionUtil.isEmpty(caIssuerUris) && CollectionUtil.isEmpty(ocspUris)) {
      throw new IllegalArgumentException("caIssuerUris and ospUris may not be both empty");
    }

    List<AccessDescription> accessDescriptions = new ArrayList<>(ocspUris.size());

    if (CollectionUtil.isNotEmpty(caIssuerUris)) {
      for (String uri : caIssuerUris) {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
        accessDescriptions.add(
            new AccessDescription(X509ObjectIdentifiers.id_ad_caIssuers, gn));
      }
    }

    if (CollectionUtil.isNotEmpty(ocspUris)) {
      for (String uri : ocspUris) {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
        accessDescriptions.add(new AccessDescription(X509ObjectIdentifiers.id_ad_ocsp, gn));
      }
    }

    DERSequence seq = new DERSequence(accessDescriptions.toArray(new AccessDescription[0]));
    return AuthorityInformationAccess.getInstance(seq);
  } // method createAuthorityInformationAccess

  public static CRLDistPoint createCrlDistributionPoints(List<String> crlUris, X500Name caSubject,
      X500Name crlSignerSubject) {
    notEmpty(crlUris, "crlUris");
    int size = crlUris.size();
    DistributionPoint[] points = new DistributionPoint[1];

    GeneralName[] names = new GeneralName[size];
    for (int i = 0; i < size; i++) {
      names[i] = new GeneralName(GeneralName.uniformResourceIdentifier, crlUris.get(i));
    }
    // Distribution Point
    GeneralNames gns = new GeneralNames(names);
    DistributionPointName pointName = new DistributionPointName(gns);

    GeneralNames crlIssuer = null;
    if (crlSignerSubject != null && !crlSignerSubject.equals(caSubject)) {
      GeneralName crlIssuerName = new GeneralName(crlSignerSubject);
      crlIssuer = new GeneralNames(crlIssuerName);
    }

    points[0] = new DistributionPoint(pointName, null, crlIssuer);

    return new CRLDistPoint(points);
  } // method createCrlDistributionPoints

  public static X500Name sortX509Name(X500Name name) {
    notNull(name, "name");
    RDN[] requestedRdns = name.getRDNs();

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

  public static boolean verifyCsr(CertificationRequest csr, SecurityFactory securityFactory,
      AlgorithmValidator algorithmValidator, DhpocControl dhpocControl) {
    notNull(csr, "csr");

    ASN1ObjectIdentifier algOid = csr.getSignatureAlgorithm().getAlgorithm();

    DHSigStaticKeyCertPair kaKeyAndCert = null;
    if (Xipki.id_alg_dhPop_x25519.equals(algOid)
            || Xipki.id_alg_dhPop_x448.equals(algOid)) {
      if (dhpocControl != null) {
        DhSigStatic dhSigStatic = DhSigStatic.getInstance(csr.getSignature().getBytes());
        IssuerAndSerialNumber isn = dhSigStatic.getIssuerAndSerial();

        ASN1ObjectIdentifier keyOid = csr.getCertificationRequestInfo().getSubjectPublicKeyInfo()
                                        .getAlgorithm().getAlgorithm();
        kaKeyAndCert = dhpocControl.getKeyCertPair(isn.getName(), isn.getSerialNumber().getValue(),
            EdECConstants.getName(keyOid));
      }

      if (kaKeyAndCert == null) {
        return false;
      }
    }

    return securityFactory.verifyPopo(csr, algorithmValidator, kaKeyAndCert);
  } // method verifyCsr

  private static RDN[] getRdns(RDN[] rdns, ASN1ObjectIdentifier type) {
    notNull(rdns, "rdns");
    notNull(type, "type");
    List<RDN> ret = new ArrayList<>(1);
    for (RDN rdn : rdns) {
      if (rdn.getFirst().getType().equals(type)) {
        ret.add(rdn);
      }
    }

    return CollectionUtil.isEmpty(ret) ? null : ret.toArray(new RDN[0]);
  } // method getRdns

  public static String canonicalizeSignerConf(String keystoreType, String signerConf,
      X509Cert[] certChain, SecurityFactory securityFactory)
          throws CaMgmtException {
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
    String passwordHint = pairs.value("password");
    String keyLabel = pairs.value("key-label");

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

    try {
      char[] password = securityFactory.getPasswordResolver().resolvePassword(passwordHint);
      ksBytes = securityFactory.extractMinimalKeyStore(keystoreType, ksBytes, keyLabel,
          password, certChain);
    } catch (KeyStoreException ex) {
      throw new CaMgmtException("KeyStoreException: " + ex.getMessage(), ex);
    } catch (PasswordResolverException ex) {
      throw new CaMgmtException("PasswordResolverException: " + ex.getMessage(), ex);
    }
    pairs.putPair("keystore", "base64:" + Base64.encodeToString(ksBytes));
    return pairs.getEncoded();
  } // method canonicalizeSignerConf

  public static FileOrValue createFileOrValue(ZipOutputStream zipStream,
      String content, String fileName)
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

  public static FileOrBinary createFileOrBase64Value(ZipOutputStream zipStream,
      String b64Content, String fileName)
          throws IOException {
    if (StringUtil.isBlank(b64Content)) {
      return null;
    }

    return createFileOrBinary(zipStream, Base64.decode(b64Content), fileName);
  } // method createFileOrBase64Value

  public static FileOrBinary createFileOrBinary(ZipOutputStream zipStream,
      byte[] content, String fileName)
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

  public static String encodeCertchain(List<X509Cert> certs)
      throws CaMgmtException {
    try {
      return X509Util.encodeCertificates(certs.toArray(new X509Cert[0]));
    } catch (CertificateException | IOException ex) {
      throw new CaMgmtException(ex);
    }
  } // method encodeCertchain

  public static List<X509Cert> buildCertChain(X509Cert targetCert,
      List<X509Cert> certs)
          throws CaMgmtException {
    X509Cert[] certchain;
    try {
      certchain = X509Util.buildCertPath(targetCert, certs, false);
    } catch (CertPathBuilderException ex) {
      throw new CaMgmtException(ex);
    }

    if (certchain == null || certs.size() != certchain.length) {
      throw new CaMgmtException("could not build certchain containing all specified certs");
    }
    return Arrays.asList(certchain);
  } // method buildCertChain

  public static X509Cert parseCert(byte[] encodedCert)
      throws CaMgmtException {
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
