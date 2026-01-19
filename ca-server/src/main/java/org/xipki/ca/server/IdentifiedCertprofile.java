// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.ctrl.*;
import org.xipki.security.KeySpec;
import org.xipki.security.KeyUsage;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.type.Validity;

import java.io.Closeable;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CertProfile with identifier.
 *
 * @author Lijun Liao
 *
 */

public class IdentifiedCertprofile implements Closeable {

  private final CertprofileEntry dbEntry;
  private final Certprofile certprofile;

  public IdentifiedCertprofile(
      CertprofileEntry dbEntry, Certprofile certprofile)
      throws CertprofileException {
    this.dbEntry = Args.notNull(dbEntry, "dbEntry");
    this.certprofile = Args.notNull(certprofile, "certprofile");

    this.certprofile.initialize(dbEntry.getConf());
    if (this.certprofile.getCertLevel() != CertLevel.EndEntity
        && this.certprofile.hasNoWellDefinedExpirationDate()) {
      throw new CertprofileException(
          "CA certificate is not allowed to have notAfter 99991231235959Z");
    }
  } // constructor

  public NameId getIdent() {
    return dbEntry.getIdent();
  }

  public Certprofile getCertprofile() {
    return certprofile;
  }

  public CertprofileEntry getDbEntry() {
    return dbEntry;
  }

  public List<SignAlgo> getSignatureAlgorithms() {
    return certprofile.getSignatureAlgorithms();
  }

  public Instant getNotBefore(Instant notBefore) {
    return certprofile.getNotBefore(notBefore);
  }

  public Validity getValidity() {
    return certprofile.getValidity();
  }

  public boolean hasNoWellDefinedExpirationDate() {
    return certprofile.hasNoWellDefinedExpirationDate();
  }

  public ValidityMode getNotAfterMode() {
    return certprofile.getNotAfterMode();
  }

  public CertLevel getCertLevel() {
    return certprofile.getCertLevel();
  }

  public KeypairGenControl getKeypairGenControl() {
    return certprofile.getKeypairGenControl();
  }

  public SubjectPublicKeyInfo checkPublicKey(SubjectPublicKeyInfo publicKey)
      throws CertprofileException, BadCertTemplateException {
    return certprofile.checkPublicKey(Args.notNull(publicKey, "publicKey"));
  }

  public byte[] getSubjectKeyIdentifier(SubjectPublicKeyInfo publicKey)
      throws CertprofileException {
    return certprofile.getSubjectKeyIdentifier(publicKey);
  }

  @Override
  public void close() {
    if (certprofile != null) {
      certprofile.close();
    }
  }

  public ExtensionsControl getExtensionControls() {
    return certprofile.getExtensionsControl();
  }

  public Integer getPathLenBasicConstraint() {
    return certprofile.getPathLenBasicConstraint();
  }

  public int getMaxCertSize() {
    return certprofile.getMaxCertSize();
  }

  public SubjectInfo getSubject(X500Name requestedSubject)
      throws CertprofileException, BadCertTemplateException {
    return CertprofileUtil.getSubject(certprofile, requestedSubject);
  }

  /**
   * Get the extensions.
   *
   * @param requestedSubject
   *        Subject requested subject. Must not be {@code null}.
   * @param grantedSubject
   *        Granted subject. Must not be {@code null}.
   * @param requestedExtensions
   *        Extensions requested by the requestor. Could be {@code null}.
   * @param publicKeyInfo
   *        Subject public key. Must not be {@code null}.
   * @param publicCaInfo
   *        CA information. Must not be {@code null}.
   * @param crlSignerCert
   *        CRL signer certificate. Could be {@code null}.
   * @param notBefore
   *        NotBefore. Must not be {@code null}.
   * @param notAfter
   *        NotAfter. Must not be {@code null}.
   * @return the extensions of the certificate to be issued.
   * @throws BadCertTemplateException
   *         if the requestedSubject, requestedExtensions and publicKeyInfo
   *         does not match the requested certificate profile.
   * @throws CertprofileException
   *         if any error occurs.
   */
  public ExtensionValues getExtensions(
      X500Name requestedSubject, X500Name grantedSubject,
      Extensions requestedExtensions, SubjectPublicKeyInfo publicKeyInfo,
      PublicCaInfo publicCaInfo, X509Cert crlSignerCert,
      Instant notBefore, Instant notAfter)
      throws CertprofileException, BadCertTemplateException {
    Args.notNull(publicKeyInfo, "publicKeyInfo");
    ExtensionValues values = new ExtensionValues();

    ExtensionsControl controls = certprofile.getExtensionsControl();
    List<ASN1ObjectIdentifier> types = new ArrayList<>(controls.getTypes());

    // CTLog extension will be processed by the CA
    types.remove(OIDs.Extn.id_SignedCertificateTimestampList);

    Map<ASN1ObjectIdentifier, Extension> requestedExtns = new HashMap<>();
    // remove the request extensions which are not permitted in the request
    if (requestedExtensions != null) {
      ASN1ObjectIdentifier[] oids = requestedExtensions.getExtensionOIDs();
      for (ASN1ObjectIdentifier m : oids) {
        ExtensionControl control = controls.getControl(m);
        if (control == null || control.isPermittedInRequest()) {
          requestedExtns.put(m, requestedExtensions.getExtension(m));
        }
      }
    }

    // SubjectKeyIdentifier
    addExtnSubjectKeyIdentifier(values, types, controls, publicKeyInfo);

    // Authority key identifier
    addExtnAuthorityKeyIdentifier(values, types, controls, publicCaInfo);

    // IssuerAltName
    addExtnIssuerAltName(values, types, controls, publicCaInfo);

    // AuthorityInfoAccess
    addExtnAuthorityInfoAccess(values, types, controls, publicCaInfo);

    // CRLDistributionPoints
    addExtnCRLDistributionPoints(values, types, controls, publicCaInfo);

    // FreshestCRL
    addExtnFreshestCRL(values, types, controls, publicCaInfo);

    // BasicConstraints
    addExtnBasicConstraints(values, types, controls, requestedExtns);

    // KeyUsage
    KeySpec publicKeySpec = KeySpec.ofPublicKey(publicKeyInfo);
    if (publicKeySpec == null) {
      throw new BadCertTemplateException("Unknown public key spec");
    }
    addExtnKeyUsage(values, types, controls, requestedExtns, publicKeySpec);

    // ExtendedKeyUsage
    addExtnExtendedKeyUsage(values, types, controls, requestedExtns);

    // ocsp-nocheck
    addExtnPkixOcspNoCheck(values, types, controls);

    // SubjectInfoAccess
    addExtnSubjectInfoAccess(values, types, controls, requestedExtns);

    // CertificatePolicies
    addExtnCertificatePolicies(values, types, controls);

    ExtensionValues subvalues = certprofile.getExtensions(types,
        requestedSubject, grantedSubject, requestedExtns, notBefore,
        notAfter, publicCaInfo);

    for (ASN1ObjectIdentifier type : new ArrayList<>(types)) {
      ExtensionControl extControl = controls.getControl(type);
      ExtensionValue value = subvalues.getExtensionValue(type);
      if (value == null && extControl.isPermittedInRequest()) {
        Extension reqExt = requestedExtns.get(type);
        if (reqExt != null) {
          value = new ExtensionValue(extControl.isCritical(), reqExt);
        }
      }

      if (value != null) {
        CertprofileUtil.addExtension(values, type, extControl,
            value.getValue());
        types.remove(type);
      }
    }

    Set<ASN1ObjectIdentifier> unprocessedExtTypes = new HashSet<>();
    for (ASN1ObjectIdentifier type : types) {
      if (controls.getControl(type).isRequired()) {
        unprocessedExtTypes.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(unprocessedExtTypes)) {
      throw new CertprofileException("could not add required extensions " +
          CertprofileUtil.toString(unprocessedExtTypes));
    }

    // Check the SubjectAltNames
    if (certprofile.getCertDomain() == CertDomain.CABForumBR
        && getCertLevel() == CertLevel.EndEntity) {
      assertCommonNameInSAN(grantedSubject, values);
    }

    return values;
  } // method getExtensions

  private void addExtnSubjectKeyIdentifier(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls, SubjectPublicKeyInfo publicKeyInfo)
      throws CertprofileException {
    ASN1ObjectIdentifier extType = OIDs.Extn.subjectKeyIdentifier;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    byte[] value = certprofile.getSubjectKeyIdentifier(publicKeyInfo);
    CertprofileUtil.addExtension(values, extType, extControl,
          new SubjectKeyIdentifier(value));
  }

  private void addExtnAuthorityKeyIdentifier(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls, PublicCaInfo publicCaInfo)
      throws CertprofileException {
    byte[] ikiValue = publicCaInfo.getSubjectKeyIdentifier();
    if (ikiValue == null) {
      return;
    }

    ASN1ObjectIdentifier extType = OIDs.Extn.authorityKeyIdentifier;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    CertprofileUtil.addExtension(values, extType, extControl,
          new AuthorityKeyIdentifier(ikiValue));
  }

  private void addExtnIssuerAltName(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls, PublicCaInfo publicCaInfo)
      throws CertprofileException {
    ASN1ObjectIdentifier extType = OIDs.Extn.issuerAlternativeName;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    GeneralNames value = publicCaInfo.getSubjectAltName();
    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void addExtnAuthorityInfoAccess(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls, PublicCaInfo publicCaInfo)
      throws CertprofileException {
    ASN1ObjectIdentifier extType = OIDs.Extn.authorityInfoAccess;
    ExtensionControl extControl = controls.getControl(extType);
    CaUris caUris = publicCaInfo.getCaUris();

    if (extControl == null) {
      return;
    }

    types.remove(extType);
    AuthorityInfoAccessControl aiaControl = certprofile.getAiaControl();

    List<String> caIssuers = null;
    if (aiaControl != null && aiaControl.isIncludesCaIssuers()) {
      caIssuers = caUris.getCacertUris();
    }

    List<String> ocspUris = null;
    if (aiaControl != null && aiaControl.isIncludesOcsp()) {
      ocspUris = caUris.getOcspUris();
    }

    boolean noUri = CollectionUtil.isEmpty(caIssuers)
        && CollectionUtil.isEmpty(ocspUris);

    AuthorityInformationAccess value = noUri ? null
        : CaUtil.createAuthorityInformationAccess(caIssuers, ocspUris);

    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void addExtnCRLDistributionPoints(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls, PublicCaInfo publicCaInfo)
      throws CertprofileException {
    // CRLDistributionPoints
    ASN1ObjectIdentifier extType = OIDs.Extn.cRLDistributionPoints;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    X509Cert crlSignerCert = publicCaInfo.getCrlSignerCert();
    X500Name crlSignerSubject = (crlSignerCert == null) ? null
        : crlSignerCert.getSubject();
    X500Name x500CaPrincipal = publicCaInfo.getSubject();

    List<String> uris = publicCaInfo.getCaUris().getCrlUris();
    boolean noUri = CollectionUtil.isEmpty(uris);
    CRLDistPoint value = noUri ? null
        : CaUtil.createCrlDistributionPoints(uris, x500CaPrincipal,
            crlSignerSubject);

    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void addExtnFreshestCRL(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls, PublicCaInfo publicCaInfo)
      throws CertprofileException {
    ASN1ObjectIdentifier extType = OIDs.Extn.freshestCRL;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    X509Cert crlSignerCert = publicCaInfo.getCrlSignerCert();
    X500Name crlSignerSubject = (crlSignerCert == null) ? null
        : crlSignerCert.getSubject();

    X500Name x500CaPrincipal = publicCaInfo.getSubject();

    List<String> uris = publicCaInfo.getCaUris().getDeltaCrlUris();
    boolean noUri = CollectionUtil.isEmpty(uris);
    CRLDistPoint value = noUri ? null
        : CaUtil.createCrlDistributionPoints(uris, x500CaPrincipal,
            crlSignerSubject);
    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void addExtnBasicConstraints(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls,
      Map<ASN1ObjectIdentifier, Extension> requestedExtns)
      throws CertprofileException {
    ASN1ObjectIdentifier extType = OIDs.Extn.basicConstraints;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    CertLevel certLevel = certprofile.getCertLevel();

    // Level EE
    if (certLevel == CertLevel.EndEntity) {
      CertprofileUtil.addExtension(values, extType, extControl,
          CaUtil.createBasicConstraints(CertLevel.EndEntity, null));
      return;
    }

    // Level CA+
    Integer pathLen = certprofile.getPathLenBasicConstraint();
    Extension requestedExtn = requestedExtns.get(extType);

    if (requestedExtn != null) {
      BasicConstraints requested =
          BasicConstraints.getInstance(requestedExtn.getParsedValue());
      boolean requestedIsCa = requested.isCA();
      BigInteger bn = requested.getPathLenConstraint();
      Integer requestedPathLen = (bn == null) ? null : bn.intValueExact();

      if (!requestedIsCa) {
        throw new CertprofileException(
            "could not enroll a CA certificate for an EndEntity request");
      }

      if (requestedPathLen != null) {
        if (pathLen == null) {
          pathLen = requestedPathLen;
        } else if (requestedPathLen >= 0 && requestedPathLen < pathLen) {
          pathLen = requestedPathLen;
        }
      }
    }

    CertprofileUtil.addExtension(values, extType, extControl,
        CaUtil.createBasicConstraints(certLevel, pathLen));
  }

  private void addExtnKeyUsage(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls,
      Map<ASN1ObjectIdentifier, Extension> requestedExtns, KeySpec keySpec)
      throws CertprofileException {
    ASN1ObjectIdentifier extType = OIDs.Extn.keyUsage;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    Set<KeyUsage> usages = new HashSet<>();
    // have a copy
    Set<KeySingleUsage> thisKeyUsage = certprofile.getKeyUsage(keySpec);
    if (thisKeyUsage == null || thisKeyUsage.isEmpty()) {
      throw new CertprofileException("KeyUsage does not allow empty usages.");
    }

    Set<KeySingleUsage> usageOccs = new HashSet<>(thisKeyUsage);

    // Signature only key specs
    if (keySpec.isMldsa() || keySpec.isEdwardsEC()) {
      removeKeyUsage(keySpec, usageOccs, KeyUsage.keyAgreement,
          KeyUsage.dataEncipherment, KeyUsage.keyEncipherment,
          KeyUsage.decipherOnly,     KeyUsage.encipherOnly);
    } else if (keySpec.isMlkem()) {
      removeKeyUsage(keySpec, usageOccs, KeyUsage.keyCertSign, KeyUsage.cRLSign,
          KeyUsage.digitalSignature, KeyUsage.contentCommitment);
    } else if (keySpec.isMontgomeryEC()) {
      removeKeyUsage(keySpec, usageOccs, KeyUsage.keyCertSign, KeyUsage.cRLSign,
          KeyUsage.digitalSignature, KeyUsage.contentCommitment);
    } else if (keySpec.isRSA()) {
      removeKeyUsage(keySpec, usageOccs, KeyUsage.keyAgreement);
    } else if (keySpec.isWeierstrassEC()) {
      // all usages are allowed
    }

    CertLevel certLevel = certprofile.getCertLevel();
    CertDomain certDomain = certprofile.getCertDomain();
    if (certLevel == CertLevel.EndEntity) {
      // make sure the EE certificate does not contain CA-only usages
      if (containsKeyusage(usageOccs, KeyUsage.keyCertSign)) {
        throw new CertprofileException(
            "EndEntity profile must not contain CA-only keyUsage keyCertSign");
      }
    } else {
      // make sure the CA certificate contains usage keyCertSign and cRLSign
      boolean containsCaUsage =
          containsKeyusage(usageOccs, KeyUsage.keyCertSign)
              || containsKeyusage(usageOccs, KeyUsage.cRLSign);
      if (!containsCaUsage) {
        throw new CertprofileException(
            "CA profile does not contain any of keyCertSign and cRLSign, ");
      }
    }

    if (certDomain == CertDomain.CABForumBR) {
      if (certLevel == CertLevel.RootCA || certLevel == CertLevel.SubCA) {
        if (!containsKeyusage(usageOccs, KeyUsage.cRLSign)) {
          throw new CertprofileException(
              "CA profile does contain keyUsage cRLSign");
        }
      } else if (certLevel == CertLevel.EndEntity) {
        if (containsKeyusage(usageOccs, KeyUsage.cRLSign)) {
          throw new CertprofileException(
              "EndEntity profile must not contain keyUsage cRLSign");
        }
      }
    }

    for (KeySingleUsage k : usageOccs) {
      if (k.isRequired()) {
        usages.add(k.getKeyUsage());
      }
    }

    // the optional KeyUsage will only be set if requested explicitly
    CertprofileUtil.addRequestedKeyusage(usages, requestedExtns, usageOccs);

    if (usages.isEmpty()) {
      throw new CertprofileException("KeyUsage does not allow empty usages.");
    }

    CertprofileUtil.addExtension(values, extType, extControl,
        X509Util.createKeyUsage(usages));
  }

  private static void removeKeyUsage(
      KeySpec keySpec, Set<KeySingleUsage> usageControls, KeyUsage... usages)
      throws CertprofileException {
    for (KeyUsage usage : usages) {
      KeySingleUsage singleUsage = null;
      for (KeySingleUsage control : usageControls) {
        if (usage == control.getKeyUsage()) {
          if (!control.isRequired()) {
            singleUsage = control;
            break;
          }

          throw new CertprofileException("KeyUsage " + usage +
              " is required but is not allowed for the key-spec " + keySpec);
        }
      }

      if (singleUsage != null) {
        usageControls.remove(singleUsage);
      }
    }
  }

  private static boolean containsKeyusage(
      Set<KeySingleUsage> usageControls, KeyUsage usage) {
    for (KeySingleUsage entry : usageControls) {
      if (usage == entry.getKeyUsage()) {
        return true;
      }
    }
    return false;
  }

  private void addExtnExtendedKeyUsage(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls,
      Map<ASN1ObjectIdentifier, Extension> requestedExtns)
      throws CertprofileException {
    ASN1ObjectIdentifier extType = OIDs.Extn.extendedKeyUsage;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    List<ASN1ObjectIdentifier> usages = new LinkedList<>();
    Set<ExtKeyUsageControl> usageOccs = certprofile.getExtendedKeyUsages();
    for (ExtKeyUsageControl k : usageOccs) {
      if (k.isRequired()) {
        usages.add(k.getExtKeyUsage());
      }
    }

    // the optional ExtKeyUsage will only be set if requested explicitly
    CertprofileUtil.addRequestedExtKeyusage(usages, requestedExtns, usageOccs);

    if (extControl.isCritical()
        && usages.contains(OIDs.XKU.id_kp_anyExtendedKeyUsage)) {
      extControl = new ExtensionControl(extControl.getType(), false,
          extControl.isRequired(), extControl.getInRequest());
    }

    if (!extControl.isCritical()
        && usages.contains(OIDs.XKU.id_kp_timeStamping)) {
      extControl = new ExtensionControl(extControl.getType(), true,
          extControl.isRequired(), extControl.getInRequest());
    }

    CertprofileUtil.addExtension(values, extType, extControl,
          X509Util.createExtendedUsage(usages));
  }

  private void addExtnPkixOcspNoCheck(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls)
      throws CertprofileException {
    ASN1ObjectIdentifier extType = OIDs.Extn.id_pkix_ocsp_nocheck;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    // the extension ocsp-nocheck will only be set if requested explicitly
    CertprofileUtil.addExtension(values, extType, extControl, DERNull.INSTANCE);
  }

  private void addExtnSubjectInfoAccess(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls,
      Map<ASN1ObjectIdentifier, Extension> requestedExtns)
      throws BadCertTemplateException, CertprofileException {
    ASN1ObjectIdentifier extType = OIDs.Extn.subjectInfoAccess;
    types.remove(extType);
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    ASN1Sequence value = CertprofileUtil.createSubjectInfoAccess(
        requestedExtns, certprofile.getSubjectInfoAccessModes());
    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void addExtnCertificatePolicies(
      ExtensionValues values, List<ASN1ObjectIdentifier> types,
      ExtensionsControl controls)
      throws CertprofileException {
    ASN1ObjectIdentifier extType = OIDs.Extn.certificatePolicies;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    CertificatePolicies value = certprofile.getCertificatePolicies();
    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void assertCommonNameInSAN(X500Name subject, ExtensionValues values)
      throws BadCertTemplateException {
    // Make sure that the commonName is included in SubjectAltName
    String commonName = X509Util.getCommonName(subject);
    boolean commonNameInSan = commonName == null;

    ExtensionValue extValue =
        values.getExtensionValue(OIDs.Extn.subjectAlternativeName);

    // No private IP address is permitted
    GeneralName[] x509Names =
        GeneralNames.getInstance(extValue.getValue()).getNames();

    for (GeneralName m : x509Names) {
      String domain = null;
      byte[] ipAddress = null;
      if (GeneralName.dNSName == m.getTagNo()) {
        domain = ASN1IA5String.getInstance(m.getName()).getString();
      } else if (GeneralName.iPAddress == m.getTagNo()) {
        ipAddress = DEROctetString.getInstance(m.getName()).getOctets();
      }

      if (domain != null) {
        if (!commonNameInSan && domain.equals(commonName)) {
          commonNameInSan = true;
        }

        if (domain.indexOf('_') != -1) {
          throw new BadCertTemplateException("invalid DNSName " + domain);
        }

        if (!ExtensionSpec.isValidPublicDomain(domain)) {
          throw new BadCertTemplateException("invalid DNSName " + domain);
        }
      } else if (ipAddress != null) {
        if (ipAddress.length == 4) { // IPv4 address
          if (!commonNameInSan) {
            String ipAddressText =
                (0xFF & ipAddress[0]) + "." + (0xFF & ipAddress[1])
                + "." + (0xFF & ipAddress[2]) + "." + (0xFF & ipAddress[3]);
            if (ipAddressText.equals(commonName)) {
              commonNameInSan = true;
            }
          }

          //if (!ExtensionSpec.isValidPublicIPv4Address(octets)) {
          //  throw new BadCertTemplateException(
          //      "invalid IPv4Address " + ipAddressText);
          //}
        } else if (ipAddress.length == 8) { // IPv6 address
          if (!commonNameInSan) {
            // get the number of ":"
            List<Integer> positions = new ArrayList<>(7);
            int n = commonName.length();

            for (int i = 0; i < n; i++) {
              if (commonName.charAt(i) == ':') {
                positions.add(i);
              }
            }

            if (positions.size() == 7) {
              String[] blocks = new String[8];
              blocks[0] = commonName.substring(0, positions.get(0));
              for (int i = 0; i < 6; i++) {
                blocks[i + 1] = commonName.substring(
                    positions.get(i) + 1, positions.get(i + 1));
              }
              blocks[7] = commonName.substring(positions.get(6) + 1);

              byte[] commonNameBytes = new byte[16];
              for (int i = 0; i < 8; i++) {
                String block = blocks[i];
                int blen = block.length();
                if (blen == 1 | blen == 2) {
                  commonNameBytes[i * 2 + 1] =
                      (byte) Integer.parseInt(block, 16);
                } else if (blen == 3 | blen == 4) {
                  commonNameBytes[i * 2] = (byte)
                      Integer.parseInt(block.substring(0, blen - 2), 16);
                  commonNameBytes[i * 2 + 1] = (byte)
                      Integer.parseInt(block.substring(blen - 2), 16);
                } else if (blen != 0) {
                  throw new BadCertTemplateException(
                      "invalid IP address in commonName " + commonName);
                }
              }

              if (Arrays.equals(commonNameBytes, ipAddress)) {
                commonNameInSan = true;
              }
            }
          }
        } else {
          throw new BadCertTemplateException(
              "invalid IP address " + Hex.toHexString(ipAddress));
        }
      }
    }

    if (!commonNameInSan) {
      throw new BadCertTemplateException("content of subject:commonName " +
          "is not included in extension:SubjectAlternativeNames");
    }
  }

}
