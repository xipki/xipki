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

package org.xipki.ca.server;

import java.io.Closeable;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.BadFormatException;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.MgmtEntry;
import org.xipki.ca.api.profile.BaseCertprofile;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.Certprofile.AuthorityInfoAccessControl;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.Certprofile.ExtKeyUsageControl;
import org.xipki.ca.api.profile.Certprofile.ExtensionControl;
import org.xipki.ca.api.profile.Certprofile.GeneralNameMode;
import org.xipki.ca.api.profile.Certprofile.KeyUsageControl;
import org.xipki.ca.api.profile.Certprofile.SubjectInfo;
import org.xipki.ca.api.profile.Certprofile.X509CertVersion;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.KeypairGenControl;
import org.xipki.ca.api.profile.SubjectDnSpec;
import org.xipki.security.ExtensionExistence;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.Validity;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class IdentifiedCertprofile implements Closeable {

  private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> CA_CRITICAL_ONLY_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> NONCRITICAL_ONLY_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> CA_ONLY_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> NONE_REQUEST_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> REQUIRED_CA_EXTENSION_TYPES;

  private static final Set<ASN1ObjectIdentifier> REQUIRED_EE_EXTENSION_TYPES;

  static {
    CRITICAL_ONLY_EXTENSION_TYPES = new HashSet<>();
    CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.keyUsage);
    CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.policyMappings);
    CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.nameConstraints);
    CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.policyConstraints);
    CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.inhibitAnyPolicy);
    CRITICAL_ONLY_EXTENSION_TYPES.add(ObjectIdentifiers.id_pe_tlsfeature);

    CA_CRITICAL_ONLY_EXTENSION_TYPES = new HashSet<>();
    CA_CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.basicConstraints);

    NONCRITICAL_ONLY_EXTENSION_TYPES = new HashSet<>();
    NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.authorityKeyIdentifier);
    NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.subjectKeyIdentifier);
    NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.issuerAlternativeName);
    NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.subjectDirectoryAttributes);
    NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.freshestCRL);
    NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.authorityInfoAccess);
    NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.subjectInfoAccess);

    CA_ONLY_EXTENSION_TYPES = new HashSet<>();
    CA_ONLY_EXTENSION_TYPES.add(Extension.policyMappings);
    CA_ONLY_EXTENSION_TYPES.add(Extension.nameConstraints);
    CA_ONLY_EXTENSION_TYPES.add(Extension.policyConstraints);
    CA_ONLY_EXTENSION_TYPES.add(Extension.inhibitAnyPolicy);

    NONE_REQUEST_EXTENSION_TYPES = new HashSet<ASN1ObjectIdentifier>();
    NONE_REQUEST_EXTENSION_TYPES.add(Extension.subjectKeyIdentifier);
    NONE_REQUEST_EXTENSION_TYPES.add(Extension.authorityKeyIdentifier);
    NONE_REQUEST_EXTENSION_TYPES.add(Extension.issuerAlternativeName);
    NONE_REQUEST_EXTENSION_TYPES.add(Extension.cRLDistributionPoints);
    NONE_REQUEST_EXTENSION_TYPES.add(Extension.freshestCRL);
    NONE_REQUEST_EXTENSION_TYPES.add(Extension.basicConstraints);
    NONE_REQUEST_EXTENSION_TYPES.add(Extension.inhibitAnyPolicy);

    REQUIRED_CA_EXTENSION_TYPES = new HashSet<>();
    REQUIRED_CA_EXTENSION_TYPES.add(Extension.basicConstraints);
    REQUIRED_CA_EXTENSION_TYPES.add(Extension.subjectKeyIdentifier);
    REQUIRED_CA_EXTENSION_TYPES.add(Extension.keyUsage);

    REQUIRED_EE_EXTENSION_TYPES = new HashSet<>();
    REQUIRED_EE_EXTENSION_TYPES.add(Extension.authorityKeyIdentifier);
    REQUIRED_EE_EXTENSION_TYPES.add(Extension.subjectKeyIdentifier);
  } // end static

  private final MgmtEntry.Certprofile dbEntry;
  private final Certprofile certprofile;

  IdentifiedCertprofile(MgmtEntry.Certprofile dbEntry, Certprofile certprofile)
      throws CertprofileException {
    this.dbEntry = Args.notNull(dbEntry, "dbEntry");
    this.certprofile = Args.notNull(certprofile, "certprofile");

    this.certprofile.initialize(dbEntry.getConf());
  } // constructor

  public NameId getIdent() {
    return dbEntry.getIdent();
  }

  public MgmtEntry.Certprofile getDbEntry() {
    return dbEntry;
  }

  public X509CertVersion getVersion() {
    return certprofile.getVersion();
  }

  public List<String> getSignatureAlgorithms() {
    return certprofile.getSignatureAlgorithms();
  }

  public Date getNotBefore(Date notBefore) {
    return certprofile.getNotBefore(notBefore);
  }

  public Validity getValidity() {
    return certprofile.getValidity();
  }

  public SubjectInfo getSubject(X500Name requestedSubject)
      throws CertprofileException, BadCertTemplateException {
    SubjectInfo subjectInfo = certprofile.getSubject(requestedSubject);
    RDN[] countryRdns = subjectInfo.getGrantedSubject().getRDNs(ObjectIdentifiers.DN_C);
    if (countryRdns != null) {
      for (RDN rdn : countryRdns) {
        String textValue = IETFUtils.valueToString(rdn.getFirst().getValue());
        if (!SubjectDnSpec.isValidCountryAreaCode(textValue)) {
          throw new BadCertTemplateException("invalid country/area code '" + textValue + "'");
        }
      }
    }
    return subjectInfo;
  }

  /**
   * TODO.
   * @param requestedSubject
   *          Subject requested subject. Must not be {@code null}.
   * @param grantedSubject
   *          Granted subject. Must not be {@code null}.
   * @param requestedExtensions
   *          Extensions requested by the requestor. Could be {@code null}.
   * @param publicKeyInfo
   *          Subject public key. Must not be {@code null}.
   * @param publicCaInfo
   *          CA information. Must not be {@code null}.
   * @param crlSignerCert
   *          CRL signer certificate. Could be {@code null}.
   * @param notBefore
   *          NotBefore. Must not be {@code null}.
   * @param notAfter
   *          NotAfter. Must not be {@code null}.
   * @param caInfo
   *          CA information.
   * @return the extensions of the certificate to be issued.
   */
  public ExtensionValues getExtensions(X500Name requestedSubject, X500Name grantedSubject,
      Extensions requestedExtensions, SubjectPublicKeyInfo publicKeyInfo, PublicCaInfo publicCaInfo,
      X509Certificate crlSignerCert, Date notBefore, Date notAfter)
      throws CertprofileException, BadCertTemplateException {
    Args.notNull(publicKeyInfo, "publicKeyInfo");
    ExtensionValues values = new ExtensionValues();

    Map<ASN1ObjectIdentifier, ExtensionControl> controls
        = new HashMap<>(certprofile.getExtensionControls());

    Set<ASN1ObjectIdentifier> neededExtTypes = new HashSet<>(2);
    Set<ASN1ObjectIdentifier> wantedExtTypes = new HashSet<>(2);
    if (requestedExtensions != null) {
      Extension reqExtension = requestedExtensions.getExtension(
          ObjectIdentifiers.id_xipki_ext_cmpRequestExtensions);
      if (reqExtension != null) {
        ExtensionExistence ee = ExtensionExistence.getInstance(reqExtension.getParsedValue());
        neededExtTypes.addAll(ee.getNeedExtensions());
        wantedExtTypes.addAll(ee.getWantExtensions());
      }

      for (ASN1ObjectIdentifier oid : neededExtTypes) {
        if (wantedExtTypes.contains(oid)) {
          wantedExtTypes.remove(oid);
        }

        if (!controls.containsKey(oid)) {
          throw new BadCertTemplateException("could not add needed extension " + oid.getId());
        }
      }
    }

    // SubjectKeyIdentifier
    ASN1ObjectIdentifier extType = Extension.subjectKeyIdentifier;
    ExtensionControl extControl = controls.remove(extType);
    if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
      byte[] encodedSpki = publicKeyInfo.getPublicKeyData().getBytes();
      byte[] skiValue = HashAlgo.SHA1.hash(encodedSpki);
      SubjectKeyIdentifier value = new SubjectKeyIdentifier(skiValue);
      addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
    }

    // Authority key identifier
    extType = Extension.authorityKeyIdentifier;
    extControl = controls.remove(extType);
    if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
      byte[] ikiValue = publicCaInfo.getSubjectKeyIdentifer();
      AuthorityKeyIdentifier value = null;
      if (ikiValue != null) {
        if (certprofile.includesIssuerAndSerialInAki()) {
          GeneralNames x509CaSubject = new GeneralNames(
              new GeneralName(publicCaInfo.getX500Subject()));
          value = new AuthorityKeyIdentifier(ikiValue, x509CaSubject,
              publicCaInfo.getSerialNumber());
        } else {
          value = new AuthorityKeyIdentifier(ikiValue);
        }
      }

      addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
    }

    // IssuerAltName
    extType = Extension.issuerAlternativeName;
    extControl = controls.remove(extType);
    if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
      GeneralNames value = publicCaInfo.getSubjectAltName();
      addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
    }

    // AuthorityInfoAccess
    extType = Extension.authorityInfoAccess;
    extControl = controls.remove(extType);
    CaUris caUris = publicCaInfo.getCaUris();

    if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
      AuthorityInfoAccessControl aiaControl = certprofile.getAiaControl();

      List<String> caIssuers = null;
      if (aiaControl == null || aiaControl.isIncludesCaIssuers()) {
        caIssuers = caUris.getCacertUris();
      }

      List<String> ocspUris = null;
      if (aiaControl == null || aiaControl.isIncludesOcsp()) {
        ocspUris = caUris.getOcspUris();
      }

      AuthorityInformationAccess value = null;
      if (CollectionUtil.isNonEmpty(caIssuers) || CollectionUtil.isNonEmpty(ocspUris)) {
        value = CaUtil.createAuthorityInformationAccess(
            caIssuers, ocspUris);
      }
      addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
    }

    if (controls.containsKey(Extension.cRLDistributionPoints)
        || controls.containsKey(Extension.freshestCRL)) {
      X500Name crlSignerSubject = (crlSignerCert == null) ? null
          : X500Name.getInstance(crlSignerCert.getSubjectX500Principal().getEncoded());
      X500Name x500CaPrincipal = publicCaInfo.getX500Subject();

      // CRLDistributionPoints
      extType = Extension.cRLDistributionPoints;
      extControl = controls.remove(extType);
      if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
        CRLDistPoint value = null;
        if (CollectionUtil.isNonEmpty(caUris.getCrlUris())) {
          value = CaUtil.createCrlDistributionPoints(caUris.getCrlUris(),
              x500CaPrincipal, crlSignerSubject);
        }
        addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
      }

      // FreshestCRL
      extType = Extension.freshestCRL;
      extControl = controls.remove(extType);
      if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
        CRLDistPoint value = null;
        if (CollectionUtil.isNonEmpty(caUris.getDeltaCrlUris())) {
          value = CaUtil.createCrlDistributionPoints(caUris.getDeltaCrlUris(),
              x500CaPrincipal, crlSignerSubject);
        }
        addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
      }
    }

    // BasicConstraints
    extType = Extension.basicConstraints;
    extControl = controls.remove(extType);
    if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
      BasicConstraints value = CaUtil.createBasicConstraints(certprofile.getCertLevel(),
          certprofile.getPathLenBasicConstraint());
      addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
    }

    // KeyUsage
    extType = Extension.keyUsage;
    extControl = controls.remove(extType);
    if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
      Set<KeyUsage> usages = new HashSet<>();
      Set<KeyUsageControl> usageOccs = certprofile.getKeyUsage();
      for (KeyUsageControl k : usageOccs) {
        if (k.isRequired()) {
          usages.add(k.getKeyUsage());
        }
      }

      // the optional KeyUsage will only be set if requested explicitly
      if (requestedExtensions != null && extControl.isRequest()) {
        addRequestedKeyusage(usages, requestedExtensions, usageOccs);
      }

      org.bouncycastle.asn1.x509.KeyUsage value = X509Util.createKeyUsage(usages);
      addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
    }

    // ExtendedKeyUsage
    extType = Extension.extendedKeyUsage;
    extControl = controls.remove(extType);
    if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
      List<ASN1ObjectIdentifier> usages = new LinkedList<>();
      Set<ExtKeyUsageControl> usageOccs = certprofile.getExtendedKeyUsages();
      for (ExtKeyUsageControl k : usageOccs) {
        if (k.isRequired()) {
          usages.add(k.getExtKeyUsage());
        }
      }

      // the optional ExtKeyUsage will only be set if requested explicitly
      if (requestedExtensions != null && extControl.isRequest()) {
        addRequestedExtKeyusage(usages, requestedExtensions, usageOccs);
      }

      if (extControl.isCritical()
          && usages.contains(ObjectIdentifiers.id_anyExtendedKeyUsage)) {
        extControl = new ExtensionControl(false, extControl.isRequired(),
            extControl.isRequest());
      }

      ExtendedKeyUsage value = X509Util.createExtendedUsage(usages);
      addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
    }

    // ocsp-nocheck
    extType = ObjectIdentifiers.id_extension_pkix_ocsp_nocheck;
    extControl = controls.remove(extType);
    if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
      // the extension ocsp-nocheck will only be set if requested explicitly
      addExtension(values, extType, DERNull.INSTANCE, extControl, neededExtTypes, wantedExtTypes);
    }

    // SubjectInfoAccess
    extType = Extension.subjectInfoAccess;
    extControl = controls.remove(extType);
    if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
      ASN1Sequence value = null;
      if (requestedExtensions != null && extControl.isRequest()) {
        value = createSubjectInfoAccess(requestedExtensions,
            certprofile.getSubjectInfoAccessModes());
      }
      addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
    }

    // remove extensions that are not required from the list
    List<ASN1ObjectIdentifier> listToRm = null;
    for (ASN1ObjectIdentifier extnType : controls.keySet()) {
      ExtensionControl ctrl = controls.get(extnType);
      if (ctrl.isRequired()) {
        continue;
      }

      if (neededExtTypes.contains(extnType) || wantedExtTypes.contains(extnType)) {
        continue;
      }

      if (listToRm == null) {
        listToRm = new LinkedList<>();
      }
      listToRm.add(extnType);
    }

    if (listToRm != null) {
      for (ASN1ObjectIdentifier extnType : listToRm) {
        controls.remove(extnType);
      }
    }

    ExtensionValues subvalues = certprofile.getExtensions(Collections.unmodifiableMap(controls),
        requestedSubject, grantedSubject, requestedExtensions, notBefore, notAfter,
        publicCaInfo);

    Set<ASN1ObjectIdentifier> extTypes = new HashSet<>(controls.keySet());
    for (ASN1ObjectIdentifier type : extTypes) {
      extControl = controls.remove(type);
      boolean addMe = addMe(type, extControl, neededExtTypes, wantedExtTypes);
      if (addMe) {
        ExtensionValue value = null;
        if (requestedExtensions != null && extControl.isRequest()) {
          Extension reqExt = requestedExtensions.getExtension(type);
          if (reqExt != null) {
            value = new ExtensionValue(extControl.isCritical(), reqExt.getParsedValue());
          }
        }

        if (value == null) {
          value = subvalues.getExtensionValue(type);
        }

        addExtension(values, type, value, extControl, neededExtTypes, wantedExtTypes);
      }
    }

    Set<ASN1ObjectIdentifier> unprocessedExtTypes = new HashSet<>();
    for (ASN1ObjectIdentifier type : controls.keySet()) {
      if (controls.get(type).isRequired()) {
        unprocessedExtTypes.add(type);
      }
    }

    if (CollectionUtil.isNonEmpty(unprocessedExtTypes)) {
      throw new CertprofileException(
          "could not add required extensions " + toString(unprocessedExtTypes));
    }

    if (CollectionUtil.isNonEmpty(neededExtTypes)) {
      throw new BadCertTemplateException(
          "could not add requested extensions " + toString(neededExtTypes));
    }

    return values;
  } // method getExtensions

  public CertLevel getCertLevel() {
    return certprofile.getCertLevel();
  }

  public KeypairGenControl getKeypairGenControl() {
    return certprofile.getKeypairGenControl();
  }

  public boolean isOnlyForRa() {
    return certprofile.isOnlyForRa();
  }

  public SubjectPublicKeyInfo checkPublicKey(SubjectPublicKeyInfo publicKey)
      throws CertprofileException, BadCertTemplateException {
    return certprofile.checkPublicKey(Args.notNull(publicKey, "publicKey"));
  }

  public boolean incSerialNumberIfSubjectExists() {
    return certprofile.incSerialNumberIfSubjectExists();
  }

  @Override
  public void close() {
    if (certprofile != null) {
      certprofile.close();
    }
  }

  public boolean includeIssuerAndSerialInAki() {
    return certprofile.includesIssuerAndSerialInAki();
  }

  public String incSerialNumber(String currentSerialNumber) throws BadFormatException {
    return certprofile.incSerialNumber(currentSerialNumber);
  }

  public boolean isSerialNumberInReqPermitted() {
    return certprofile.isSerialNumberInReqPermitted();
  }

  public Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls() {
    return certprofile.getExtensionControls();
  }

  public Set<KeyUsageControl> getKeyUsage() {
    return certprofile.getKeyUsage();
  }

  public Integer getPathLenBasicConstraint() {
    return certprofile.getPathLenBasicConstraint();
  }

  public Set<ExtKeyUsageControl> getExtendedKeyUsages() {
    return certprofile.getExtendedKeyUsages();
  }

  public int getMaxCertSize() {
    return certprofile.getMaxCertSize();
  }

  public void validate() throws CertprofileException {
    StringBuilder msg = new StringBuilder();

    Map<ASN1ObjectIdentifier, ExtensionControl> controls = getExtensionControls();

    // make sure that non-request extensions are not permitted in requests
    Set<ASN1ObjectIdentifier> set = new HashSet<>();
    for (ASN1ObjectIdentifier type : NONE_REQUEST_EXTENSION_TYPES) {
      ExtensionControl control = controls.get(type);
      if (control != null && control.isRequest()) {
        set.add(type);
      }
    }

    if (CollectionUtil.isNonEmpty(set)) {
      msg.append("extensions ").append(toString(set)).append(" may not be contained in request, ");
    }

    CertLevel level = getCertLevel();
    boolean ca = (level == CertLevel.RootCA) || (level == CertLevel.SubCA);

    // make sure that CA-only extensions are not permitted in EE certificate
    set.clear();
    if (!ca) {
      set.clear();
      for (ASN1ObjectIdentifier type : CA_ONLY_EXTENSION_TYPES) {
        if (controls.containsKey(type)) {
          set.add(type);
        }
      }

      if (CollectionUtil.isNonEmpty(set)) {
        msg.append("EE profile contains CA-only extensions ").append(toString(set)).append(", ");
      }
    }

    // make sure that critical only extensions are not marked as non-critical.
    set.clear();
    for (ASN1ObjectIdentifier type : controls.keySet()) {
      ExtensionControl control = controls.get(type);
      if (CRITICAL_ONLY_EXTENSION_TYPES.contains(type)) {
        if (!control.isCritical()) {
          set.add(type);
        }
      }

      if (ca && CA_CRITICAL_ONLY_EXTENSION_TYPES.contains(type)) {
        if (!control.isCritical()) {
          set.add(type);
        }
      }
    }

    if (CollectionUtil.isNonEmpty(set)) {
      msg.append("critical only extensions are marked as non-critical ")
        .append(toString(set)).append(", ");
    }

    // make sure that non-critical only extensions are not marked as critical.
    set.clear();
    for (ASN1ObjectIdentifier type : controls.keySet()) {
      ExtensionControl control = controls.get(type);
      if (NONCRITICAL_ONLY_EXTENSION_TYPES.contains(type)) {
        if (control.isCritical()) {
          set.add(type);
        }
      }
    }

    if (CollectionUtil.isNonEmpty(set)) {
      msg.append("non-critical extensions are marked as critical ").append(toString(set))
        .append(", ");
    }

    // make sure that required extensions are present
    set.clear();
    Set<ASN1ObjectIdentifier> requiredTypes = ca ? REQUIRED_CA_EXTENSION_TYPES
        : REQUIRED_EE_EXTENSION_TYPES;

    for (ASN1ObjectIdentifier type : requiredTypes) {
      ExtensionControl extCtrl = controls.get(type);
      if (extCtrl == null || !extCtrl.isRequired()) {
        set.add(type);
      }
    }

    if (level == CertLevel.SubCA) {
      ASN1ObjectIdentifier type = Extension.authorityKeyIdentifier;
      ExtensionControl extCtrl = controls.get(type);
      if (extCtrl == null || !extCtrl.isRequired()) {
        set.add(type);
      }
    }

    if (!set.isEmpty()) {
      msg.append("required extensions are not marked as required ")
        .append(toString(set)).append(", ");
    }

    // KeyUsage
    Set<KeyUsageControl> usages = getKeyUsage();

    if (ca) {
      // make sure the CA certificate contains usage keyCertSign
      if (!containsKeyusage(usages, KeyUsage.keyCertSign)) {
        msg.append("CA profile does not contain keyUsage ")
          .append(KeyUsage.keyCertSign).append(", ");
      }
    } else {
      // make sure the EE certificate does not contain CA-only usages
      KeyUsage[] caOnlyUsages = {KeyUsage.keyCertSign, KeyUsage.cRLSign};

      Set<KeyUsage> setUsages = new HashSet<>();
      for (KeyUsage caOnlyUsage : caOnlyUsages) {
        if (containsKeyusage(usages, caOnlyUsage)) {
          setUsages.add(caOnlyUsage);
        }
      }

      if (CollectionUtil.isNonEmpty(set)) {
        msg.append("EE profile contains CA-only keyUsage ").append(setUsages).append(", ");
      }
    }

    final int len = msg.length();
    if (len > 2) {
      msg.delete(len - 2, len);
      throw new CertprofileException(msg.toString());
    }
  } // method validate

  private static String toString(Set<ASN1ObjectIdentifier> oids) {
    if (oids == null) {
      return "null";
    }

    StringBuilder sb = new StringBuilder();
    sb.append("[");

    for (ASN1ObjectIdentifier oid : oids) {
      String name = ObjectIdentifiers.getName(oid);
      if (name != null) {
        sb.append(name);
        sb.append(" (").append(oid.getId()).append(")");
      } else {
        sb.append(oid.getId());
      }
      sb.append(", ");
    }

    if (CollectionUtil.isNonEmpty(oids)) {
      int len = sb.length();
      sb.delete(len - 2, len);
    }
    sb.append("]");

    return sb.toString();
  } // method toString

  private static boolean containsKeyusage(Set<KeyUsageControl> usageControls, KeyUsage usage) {
    for (KeyUsageControl entry : usageControls) {
      if (usage == entry.getKeyUsage()) {
        return true;
      }
    }
    return false;
  }

  private static boolean addMe(ASN1ObjectIdentifier extType, ExtensionControl extControl,
      Set<ASN1ObjectIdentifier> neededExtTypes, Set<ASN1ObjectIdentifier> wantedExtTypes) {
    boolean addMe = extControl.isRequired();
    if (addMe) {
      return true;
    }

    return neededExtTypes.contains(extType) || wantedExtTypes.contains(extType);
  } // method addMe

  private static void addRequestedKeyusage(Set<KeyUsage> usages, Extensions requestedExtensions,
      Set<KeyUsageControl> usageOccs) {
    Extension extension = requestedExtensions.getExtension(Extension.keyUsage);
    if (extension == null) {
      return;
    }

    org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
        org.bouncycastle.asn1.x509.KeyUsage.getInstance(extension.getParsedValue());
    for (KeyUsageControl k : usageOccs) {
      if (k.isRequired()) {
        continue;
      }

      if (reqKeyUsage.hasUsages(k.getKeyUsage().getBcUsage())) {
        usages.add(k.getKeyUsage());
      }
    }
  } // method addRequestedKeyusage

  private static void addRequestedExtKeyusage(List<ASN1ObjectIdentifier> usages,
      Extensions requestedExtensions, Set<ExtKeyUsageControl> usageOccs) {
    Extension extension = requestedExtensions.getExtension(Extension.extendedKeyUsage);
    if (extension == null) {
      return;
    }

    ExtendedKeyUsage reqKeyUsage = ExtendedKeyUsage.getInstance(extension.getParsedValue());
    for (ExtKeyUsageControl k : usageOccs) {
      if (k.isRequired()) {
        continue;
      }

      if (reqKeyUsage.hasKeyPurposeId(KeyPurposeId.getInstance(k.getExtKeyUsage()))) {
        usages.add(k.getExtKeyUsage());
      }
    }
  } // method addRequestedExtKeyusage

  private static ASN1Sequence createSubjectInfoAccess(Extensions requestedExtensions,
      Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> modes) throws BadCertTemplateException {
    if (modes == null) {
      return null;
    }

    ASN1Encodable extValue = requestedExtensions.getExtensionParsedValue(
        Extension.subjectInfoAccess);
    if (extValue == null) {
      return null;
    }

    ASN1Sequence reqSeq = ASN1Sequence.getInstance(extValue);
    int size = reqSeq.size();

    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (int i = 0; i < size; i++) {
      AccessDescription ad = AccessDescription.getInstance(reqSeq.getObjectAt(i));
      ASN1ObjectIdentifier accessMethod = ad.getAccessMethod();
      Set<GeneralNameMode> generalNameModes = modes.get(accessMethod);

      if (generalNameModes == null) {
        throw new BadCertTemplateException("subjectInfoAccess.accessMethod "
            + accessMethod.getId() + " is not allowed");
      }

      GeneralName accessLocation = BaseCertprofile.createGeneralName(
          ad.getAccessLocation(), generalNameModes);
      vec.add(new AccessDescription(accessMethod, accessLocation));
    } // end for

    return vec.size() > 0 ? new DERSequence(vec) : null;
  } // method createSubjectInfoAccess

  private static void addExtension(ExtensionValues values, ASN1ObjectIdentifier extType,
      ExtensionValue extValue, ExtensionControl extControl,
      Set<ASN1ObjectIdentifier> neededExtensionTypes,
      Set<ASN1ObjectIdentifier> wantedExtensionTypes) throws CertprofileException {
    if (extValue != null) {
      values.addExtension(extType, extValue);
      neededExtensionTypes.remove(extType);
      wantedExtensionTypes.remove(extType);
    } else if (extControl.isRequired()) {
      String description = ObjectIdentifiers.getName(extType);
      if (description == null) {
        description = extType.getId();
      }
      throw new CertprofileException("could not add required extension " + description);
    }
  } // method addExtension

  private static void addExtension(ExtensionValues values, ASN1ObjectIdentifier extType,
      ASN1Encodable extValue, ExtensionControl extControl,
      Set<ASN1ObjectIdentifier> neededExtensionTypes,
      Set<ASN1ObjectIdentifier> wantedExtensionTypes) throws CertprofileException {
    if (extValue != null) {
      values.addExtension(extType, extControl.isCritical(), extValue);
      neededExtensionTypes.remove(extType);
      wantedExtensionTypes.remove(extType);
    } else if (extControl.isRequired()) {
      String description = ObjectIdentifiers.getName(extType);
      if (description == null) {
        description = extType.getId();
      }
      throw new CertprofileException("could not add required extension " + description);
    }
  } // method addExtension

}
