// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.KeyPurposeOIDs;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.*;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.ctrl.*;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.exception.BadCertTemplateException;
import org.xipki.pkix.cert.KeyUsage;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.ca.api.CertprofileException;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.pkix.util.conf.Validity;

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
 * Identified certificate profile definition.
 *
 * @author Lijun Liao (xipki)
 */
public class IdentifiedCertprofile {

  private static final Logger log = LoggerFactory.getLogger(IdentifiedCertprofile.class);
  private final CertprofileEntry dbEntry;
  private final Certprofile certprofile;

  public IdentifiedCertprofile(CertprofileEntry dbEntry, Certprofile certprofile)
      throws CertprofileException {
    this.dbEntry = Args.notNull(dbEntry, "dbEntry");
    this.certprofile = Args.notNull(certprofile, "certprofile");

    this.certprofile.initialize(dbEntry.conf());
  } // constructor

  public NameId ident() {
    return dbEntry.ident();
  }

  public Certprofile certprofile() {
    return certprofile;
  }

  public CertprofileEntry dbEntry() {
    return dbEntry;
  }

  public List<SignAlgo> signatureAlgorithms() {
    return certprofile.signatureAlgorithms();
  }

  public Instant getNotBefore(Instant notBefore) {
    return certprofile.notBefore(notBefore);
  }

  public Validity validity() {
    return certprofile.validity();
  }

  public boolean hasNoWellDefinedExpirationDate() {
    return certprofile.hasNoWellDefinedExpirationDate();
  }

  public ValidityMode notAfterMode() {
    return certprofile.notAfterMode();
  }

  public CertLevel certLevel() {
    return certprofile.certLevel();
  }

  public KeypairGenControl keypairGenControl() {
    return certprofile.keypairGenControl();
  }

  public SubjectPublicKeyInfo checkPublicKey(SubjectPublicKeyInfo publicKey)
      throws BadCertTemplateException {
    return certprofile.checkPublicKey(Args.notNull(publicKey, "publicKey"));
  }

  public byte[] getSubjectKeyIdentifier(SubjectPublicKeyInfo publicKey) {
    return certprofile.subjectKeyIdentifier(publicKey);
  }

  public ExtensionsControl extensionControls() {
    return certprofile.extensionsControl();
  }

  public Integer pathLenBasicConstraint() {
    return certprofile.pathLenBasicConstraint();
  }

  public int maxCertSize() {
    return certprofile.maxCertSize();
  }

  public SubjectInfo getSubject(X500Name requestedSubject)
      throws BadCertTemplateException {
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
      X500Name requestedSubject, X500Name grantedSubject, Extensions requestedExtensions,
      SubjectPublicKeyInfo publicKeyInfo, PublicCaInfo publicCaInfo, X509Cert crlSignerCert,
      Instant notBefore, Instant notAfter)
      throws CertprofileException, BadCertTemplateException {
    Args.notNull(publicKeyInfo, "publicKeyInfo");
    ExtensionValues values = new ExtensionValues();

    ExtensionsControl controls = certprofile.extensionsControl();
    List<Asn1Oid> types = new ArrayList<>(controls.types());

    // CTLog extension will be processed by the CA
    types.remove(ExtensionOIDs.id_SignedCertificateTimestampList);

    Map<Asn1Oid, Extension> requestedExtns = new HashMap<>();
    // remove the request extensions which are not permitted in the request
    if (requestedExtensions != null) {
      Set<Asn1Oid> oids = requestedExtensions.getExtensionIds();
      for (Asn1Oid m : oids) {
        ExtensionControl control = controls.getControl(m);
        if (control == null) {
          log.warn("ignore extension {}, it is defined in the profile", m.getId());
        } else {
          if (control.isPermittedInRequest()) {
            requestedExtns.put(m, requestedExtensions.getExtension(m));
          } else {
            log.warn("ignore extension {}, it is allowed in the request", m.getId());
          }
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
    KeySpec publicKeySpec;
    try {
      publicKeySpec = KeySpec.ofPublicKey(publicKeyInfo);
    } catch (CodecException e) {
      throw new BadCertTemplateException("could not parsing SubjectPublicKeyInfo", e);
    }

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
        requestedSubject, grantedSubject, requestedExtns, notBefore, notAfter, publicCaInfo);

    for (Asn1Oid type : new ArrayList<>(types)) {
      ExtensionControl extControl = controls.getControl(type);
      ExtensionValue value = subvalues.getExtensionValue(type);
      if (value == null && extControl.isPermittedInRequest()) {
        Extension reqExt = requestedExtns.get(type);
        if (reqExt != null) {
          try {
            value = new ExtensionValue(extControl.isCritical(),
                Asn1Util.readAsn1Object(reqExt.extnValue()));
          } catch (CodecException e) {
            throw new BadCertTemplateException("could not parse requested extension " + type, e);
          }
        }
      }

      if (value != null) {
        CertprofileUtil.addExtension(values, type, extControl, value.value());
        types.remove(type);
      }
    }

    Set<Asn1Oid> unprocessedExtTypes = new HashSet<>();
    for (Asn1Oid type : types) {
      if (controls.getControl(type).isRequired()) {
        unprocessedExtTypes.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(unprocessedExtTypes)) {
      throw new CertprofileException("could not add required extensions " +
          CertprofileUtil.toString(unprocessedExtTypes));
    }

    // Check the SubjectAltNames
    if (certprofile.certDomain() == CertDomain.CABForumBR && certLevel() == CertLevel.EndEntity) {
      assertCommonNameInSAN(grantedSubject, values);
    }

    return values;
  } // method getExtensions

  private void addExtnSubjectKeyIdentifier(
      ExtensionValues values, List<Asn1Oid> types, ExtensionsControl controls,
      SubjectPublicKeyInfo publicKeyInfo) throws CertprofileException {
    Asn1Oid extType = ExtensionOIDs.subjectKeyIdentifier;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    byte[] value = certprofile.subjectKeyIdentifier(publicKeyInfo);
    CertprofileUtil.addExtension(values, extType, extControl, new SubjectKeyIdentifier(value));
  }

  private void addExtnAuthorityKeyIdentifier(
      ExtensionValues values, List<Asn1Oid> types, ExtensionsControl controls,
      PublicCaInfo publicCaInfo) throws CertprofileException {
    byte[] ikiValue = publicCaInfo.subjectKeyIdentifier();
    if (ikiValue == null) {
      return;
    }

    Asn1Oid extType = ExtensionOIDs.authorityKeyIdentifier;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    CertprofileUtil.addExtension(values, extType, extControl, new AuthorityKeyIdentifier(ikiValue));
  }

  private void addExtnIssuerAltName(
      ExtensionValues values, List<Asn1Oid> types,
      ExtensionsControl controls, PublicCaInfo publicCaInfo) throws CertprofileException {
    Asn1Oid extType = ExtensionOIDs.issuerAlternativeName;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    GeneralNames value = publicCaInfo.subjectAltName();
    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void addExtnAuthorityInfoAccess(
      ExtensionValues values, List<Asn1Oid> types,
      ExtensionsControl controls, PublicCaInfo publicCaInfo) throws CertprofileException {
    Asn1Oid extType = ExtensionOIDs.authorityInfoAccess;
    ExtensionControl extControl = controls.getControl(extType);
    CaUris caUris = publicCaInfo.caUris();

    if (extControl == null) {
      return;
    }

    types.remove(extType);
    AuthorityInfoAccessControl aiaControl = certprofile.aiaControl();

    List<String> caIssuers = null;
    if (aiaControl != null && aiaControl.isIncludesCaIssuers()) {
      caIssuers = caUris.cacertUris();
    }

    List<String> ocspUris = null;
    if (aiaControl != null && aiaControl.isIncludesOcsp()) {
      ocspUris = caUris.ocspUris();
    }

    boolean noUri = CollectionUtil.isEmpty(caIssuers) && CollectionUtil.isEmpty(ocspUris);

    AuthorityInfoAccessSyntax value = noUri ? null
        : CaUtil.createAuthorityInformationAccess(caIssuers, ocspUris);

    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void addExtnCRLDistributionPoints(
      ExtensionValues values, List<Asn1Oid> types,
      ExtensionsControl controls, PublicCaInfo publicCaInfo) throws CertprofileException {
    // CRLDistributionPoints
    Asn1Oid extType = ExtensionOIDs.cRLDistributionPoints;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    X509Cert crlSignerCert = publicCaInfo.crlSignerCert();
    X500Name crlSignerSubject = (crlSignerCert == null) ? null : crlSignerCert.subject();
    X500Name x500CaPrincipal = publicCaInfo.subject();

    List<String> uris = publicCaInfo.caUris().crlUris();
    boolean noUri = CollectionUtil.isEmpty(uris);
    CRLDistributionPoints value = noUri ? null
        : CaUtil.createCrlDistributionPoints(uris, x500CaPrincipal, crlSignerSubject);

    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void addExtnFreshestCRL(
      ExtensionValues values, List<Asn1Oid> types,
      ExtensionsControl controls, PublicCaInfo publicCaInfo) throws CertprofileException {
    Asn1Oid extType = ExtensionOIDs.freshestCRL;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    X509Cert crlSignerCert = publicCaInfo.crlSignerCert();
    X500Name crlSignerSubject = (crlSignerCert == null) ? null : crlSignerCert.subject();

    X500Name x500CaPrincipal = publicCaInfo.subject();

    List<String> uris = publicCaInfo.caUris().deltaCrlUris();
    boolean noUri = CollectionUtil.isEmpty(uris);
    CRLDistributionPoints value = noUri ? null
        : CaUtil.createCrlDistributionPoints(uris, x500CaPrincipal, crlSignerSubject);
    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void addExtnBasicConstraints(
      ExtensionValues values, List<Asn1Oid> types, ExtensionsControl controls,
      Map<Asn1Oid, Extension> requestedExtns) throws CertprofileException {
    Asn1Oid extType = ExtensionOIDs.basicConstraints;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    CertLevel certLevel = certprofile.certLevel();

    // Level EE
    if (certLevel == CertLevel.EndEntity) {
      CertprofileUtil.addExtension(values, extType, extControl,
          CaUtil.createBasicConstraints(CertLevel.EndEntity, null));
      return;
    }

    // Level CA+
    Integer pathLen = certprofile.pathLenBasicConstraint();
    Extension requestedExtn = requestedExtns.get(extType);

    if (requestedExtn != null) {
      BasicConstraints requested = requestedExtn.getBasicConstraints();
      boolean requestedIsCa = requested.isCA();
      Integer requestedPathLen = requested.pathLenConstraint();

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
      ExtensionValues values, List<Asn1Oid> types, ExtensionsControl controls,
      Map<Asn1Oid, Extension> requestedExtns, KeySpec keySpec)
      throws CertprofileException {
    Asn1Oid extType = ExtensionOIDs.keyUsage;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    Set<KeyUsage> usages = new HashSet<>();
    // have a copy
    Set<KeySingleUsage> thisKeyUsage = certprofile.keyUsage(keySpec);
    if (thisKeyUsage == null || thisKeyUsage.isEmpty()) {
      throw new CertprofileException("KeyUsage does not allow empty usages.");
    }

    Set<KeySingleUsage> usageOccs = new HashSet<>(thisKeyUsage);

    // Signature only key specs
    if (keySpec.isMldsa() || keySpec.isEdwardsEC() || keySpec.isCompositeMLDSA()) {
      removeKeyUsage(keySpec, usageOccs, KeyUsage.keyAgreement,
          KeyUsage.dataEncipherment, KeyUsage.keyEncipherment,
          KeyUsage.decipherOnly,     KeyUsage.encipherOnly);
    } else if (keySpec.isMlkem() || keySpec.isCompositeMLKEM()) {
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

    CertLevel certLevel = certprofile.certLevel();
    CertDomain certDomain = certprofile.certDomain();
    if (certLevel == CertLevel.EndEntity) {
      // make sure the EE certificate does not contain CA-only usages
      if (containsKeyusage(usageOccs, KeyUsage.keyCertSign)) {
        throw new CertprofileException(
            "EndEntity profile must not contain CA-only keyUsage keyCertSign");
      }
    } else {
      // make sure the CA certificate contains usage keyCertSign and cRLSign
      boolean containsCaUsage = containsKeyusage(usageOccs, KeyUsage.keyCertSign)
              || containsKeyusage(usageOccs, KeyUsage.cRLSign);
      if (!containsCaUsage) {
        throw new CertprofileException(
            "CA profile does not contain any of keyCertSign and cRLSign, ");
      }
    }

    if (certDomain == CertDomain.CABForumBR) {
      if (certLevel == CertLevel.RootCA || certLevel == CertLevel.SubCA) {
        if (!containsKeyusage(usageOccs, KeyUsage.cRLSign)) {
          throw new CertprofileException("CA profile does contain keyUsage cRLSign");
        }
      } else if (certLevel == CertLevel.EndEntity) {
        if (containsKeyusage(usageOccs, KeyUsage.cRLSign)) {
          throw new CertprofileException("EndEntity profile must not contain keyUsage cRLSign");
        }
      }
    }

    for (KeySingleUsage k : usageOccs) {
      if (k.isRequired()) {
        usages.add(k.keyUsage());
      }
    }

    // the optional KeyUsage will only be set if requested explicitly
    CertprofileUtil.addRequestedKeyusage(usages, requestedExtns, usageOccs);

    if (usages.isEmpty()) {
      throw new CertprofileException("KeyUsage does not allow empty usages.");
    }

    CertprofileUtil.addExtension(values, extType, extControl, X509Util.createKeyUsage(usages));
  }

  private static void removeKeyUsage(
      KeySpec keySpec, Set<KeySingleUsage> usageControls, KeyUsage... usages)
      throws CertprofileException {
    for (KeyUsage usage : usages) {
      KeySingleUsage singleUsage = null;
      for (KeySingleUsage control : usageControls) {
        if (usage == control.keyUsage()) {
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

  private static boolean containsKeyusage(Set<KeySingleUsage> usageControls, KeyUsage usage) {
    for (KeySingleUsage entry : usageControls) {
      if (usage == entry.keyUsage()) {
        return true;
      }
    }
    return false;
  }

  private void addExtnExtendedKeyUsage(
      ExtensionValues values, List<Asn1Oid> types, ExtensionsControl controls,
      Map<Asn1Oid, Extension> requestedExtns) throws CertprofileException {
    Asn1Oid extType = ExtensionOIDs.extendedKeyUsage;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    List<Asn1Oid> usages = new LinkedList<>();
    Set<ExtKeyUsageControl> usageOccs = certprofile.extendedKeyUsages();
    for (ExtKeyUsageControl k : usageOccs) {
      if (k.isRequired()) {
        usages.add(k.extKeyUsage());
      }
    }

    // the optional ExtKeyUsage will only be set if requested explicitly
    CertprofileUtil.addRequestedExtKeyusage(usages, requestedExtns, usageOccs);

    if (extControl.isCritical() && usages.contains(KeyPurposeOIDs.anyExtendedKeyUsage)) {
      extControl = new ExtensionControl(extControl.type(), false,
          extControl.isRequired(), extControl.inRequest());
    }

    if (!extControl.isCritical() && usages.contains(KeyPurposeOIDs.id_kp_timeStamping)) {
      extControl = new ExtensionControl(extControl.type(), true,
          extControl.isRequired(), extControl.inRequest());
    }

    CertprofileUtil.addExtension(values, extType, extControl, X509Util.createExtendedUsage(usages));
  }

  private void addExtnPkixOcspNoCheck(
      ExtensionValues values, List<Asn1Oid> types, ExtensionsControl controls)
      throws CertprofileException {
    Asn1Oid extType = ExtensionOIDs.id_pkix_ocsp_nocheck;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    // the extension ocsp-nocheck will only be set if requested explicitly
    CertprofileUtil.addExtension(values, extType, extControl, Asn1Null.INSTANCE);
  }

  private void addExtnSubjectInfoAccess(
      ExtensionValues values, List<Asn1Oid> types,
      ExtensionsControl controls, Map<Asn1Oid, Extension> requestedExtns)
      throws BadCertTemplateException, CertprofileException {
    Asn1Oid extType = ExtensionOIDs.subjectInfoAccess;
    types.remove(extType);
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    SubjectInfoAccessSyntax value = CertprofileUtil.createSubjectInfoAccess(
        requestedExtns, certprofile.subjectInfoAccessModes());
    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void addExtnCertificatePolicies(
      ExtensionValues values, List<Asn1Oid> types, ExtensionsControl controls)
      throws CertprofileException {
    Asn1Oid extType = ExtensionOIDs.certificatePolicies;
    ExtensionControl extControl = controls.getControl(extType);
    if (extControl == null) {
      return;
    }

    types.remove(extType);
    CertificatePolicies value = certprofile.certificatePolicies();
    CertprofileUtil.addExtension(values, extType, extControl, value);
  }

  private void assertCommonNameInSAN(X500Name subject, ExtensionValues values)
      throws BadCertTemplateException {
    // Make sure that the commonName is included in SubjectAltName
    String commonName = X509Util.getCommonName(subject);
    boolean commonNameInSan = commonName == null;

    ExtensionValue extValue = values.getExtensionValue(ExtensionOIDs.subjectAlternativeName);

    // No private IP address is permitted
    GeneralNames x509Names;
    try {
      x509Names = GeneralNames.fromAsn1(extValue.value().asSequence());
    } catch (CodecException e) {
      throw new BadCertTemplateException(
          "could not parsing extension value of subjectAlternativeName", e);
    }

    for (GeneralName m : x509Names) {
      String domain = null;
      byte[] ipAddress = null;
      if (GeneralName.tag_dNSName == m.getTagNo()) {
        domain = m.getDNSName().getString();
      } else if (GeneralName.tag_iPAddress == m.getTagNo()) {
        ipAddress = m.getIPAddress().getOctets();
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
            if (ipAddressText.equalsIgnoreCase(commonName)) {
              commonNameInSan = true;
            }
          }

          //if (!ExtensionSpec.isValidPublicIPv4Address(octets)) {
          //  throw new BadCertTemplateException(
          //      "invalid IPv4Address " + ipAddressText);
          //}
        } else if (ipAddress.length == 16) { // IPv6 address
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
                blocks[i + 1] = commonName.substring(positions.get(i) + 1, positions.get(i + 1));
              }
              blocks[7] = commonName.substring(positions.get(6) + 1);

              byte[] commonNameBytes = new byte[16];
              for (int i = 0; i < 8; i++) {
                String block = blocks[i];
                int blen = block.length();
                if (blen == 1 | blen == 2) {
                  commonNameBytes[i * 2 + 1] = (byte) Integer.parseInt(block, 16);
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
          throw new BadCertTemplateException("invalid IP address " + Hex.encode(ipAddress));
        }
      }
    }

    if (!commonNameInSan) {
      throw new BadCertTemplateException("content of subject:commonName " +
          "is not included in extension:SubjectAlternativeNames");
    }
  }

}
