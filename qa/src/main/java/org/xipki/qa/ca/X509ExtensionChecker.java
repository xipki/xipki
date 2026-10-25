// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.AbstractAsn1String;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.DiceOIDs;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.PolicyQualifierOIDs;
import org.xipki.codec.asn1.oid.X509OIDs;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.*;
import org.xipki.pkix.asn1.x509.qualified.Iso4217CurrencyCode;
import org.xipki.pkix.asn1.x509.qualified.MonetaryValue;
import org.xipki.pkix.asn1.x509.qualified.PdsLocation;
import org.xipki.pkix.asn1.x509.qualified.PdsLocations;
import org.xipki.pkix.asn1.x509.qualified.QCStatement;
import org.xipki.pkix.asn1.x509.qualified.QCStatements;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ProfileUtil;
import org.xipki.ca.api.profile.ctrl.AuthorityInfoAccessControl;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.ExtKeyUsageControl;
import org.xipki.ca.api.profile.ctrl.ExtensionControl;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.api.profile.id.QCStatementID;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.XijsonExtensions;
import org.xipki.ca.certprofile.xijson.conf.ExtensionValueConf;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.qa.CheckerUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.exception.BadCertTemplateException;
import org.xipki.pkix.asn1.cert.CtLog;
import org.xipki.pkix.cert.KeyUsage;
import org.xipki.pkix.util.X509Util;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.pkix.util.misc.LogUtil;
import org.xipki.pkix.util.conf.Validity;

import java.time.Instant;
import java.util.*;

import static org.xipki.qa.CheckerUtil.addViolation;

/**
 * Extension checker.
 *
 * @author Lijun Liao (xipki)
 */
class X509ExtensionChecker {

  private static final byte[] DER_NULL = new byte[] {5, 0};

  // TODO. delete me
  private static final List<String> ALL_USAGES = Arrays.asList(
      KeyUsage.digitalSignature.getName(), // 0
      KeyUsage.contentCommitment.getName(), // 1
      KeyUsage.keyEncipherment.getName(), // 2
      KeyUsage.dataEncipherment.getName(), // 3
      KeyUsage.keyAgreement.getName(), // 4
      KeyUsage.keyCertSign.getName(), // 5
      KeyUsage.cRLSign.getName(), // 6
      KeyUsage.encipherOnly.getName(), // 7
      KeyUsage.decipherOnly.getName()); // 8

  private final Logger log;

  private final X509ExtensionsChecker caller;

  X509ExtensionChecker(X509ExtensionsChecker caller) {
    this.caller = caller;
    this.log = LoggerFactory.getLogger(getClass());
  }

  protected XijsonCertprofile getCertprofile() {
    return caller.getCertprofile();
  }

  private static Extension getExtension(Extensions extensions, Asn1Oid extensionId) {
    return extensions == null ? null : extensions.getExtension(extensionId);
  }

  void checkExtnAuthorityInfoAccess(
      StringBuilder failureMsg, Extension extn, IssuerInfo issuerInfo) {
    AuthorityInfoAccessControl aiaControl = getCertprofile().aiaControl();
    Set<String> expCaIssuerUris = (aiaControl == null || aiaControl.isIncludesCaIssuers())
            ? issuerInfo.getCaIssuerUrls() : Collections.emptySet();

    Set<String> expOcspUris = (aiaControl == null || aiaControl.isIncludesOcsp())
            ? issuerInfo.getOcspUrls() : Collections.emptySet();

    if (CollectionUtil.isEmpty(expCaIssuerUris) && CollectionUtil.isEmpty(expOcspUris)) {
      failureMsg.append("AIA is present but expected is 'none'; ");
      return;
    }

    AuthorityInfoAccessSyntax isAia = extn.getAuthorityInfoAccess();

    checkAia(failureMsg, isAia, X509OIDs.id_ad_caIssuers, expCaIssuerUris);
    checkAia(failureMsg, isAia, X509OIDs.id_ad_ocsp, expOcspUris);
  } // method checkExtnAuthorityInfoAccess

  void checkExtnAuthorityKeyId(StringBuilder failureMsg, Extension extn,
                               IssuerInfo issuerInfo) {
    byte[] keyIdentifier = extn.getAuthorityKeyIdentifier().getKeyIdentifierOctets();

    if (keyIdentifier == null) {
      failureMsg.append("keyIdentifier is 'absent', but expected 'present'; ");
    } else {
      if (!Arrays.equals(issuerInfo.getSubjectKeyIdentifier(), keyIdentifier)) {
        addViolation(failureMsg, "keyIdentifier",
            Hex.encode(keyIdentifier), Hex.encode(issuerInfo.getSubjectKeyIdentifier()));
      }
    }
  } // method checkExtnAuthorityKeyId

  void checkExtnBasicConstraints(StringBuilder failureMsg, Extension extn) {
    XijsonCertprofile certprofile = getCertprofile();
    BasicConstraints bc = extn.getBasicConstraints();

    CertLevel certLevel = certprofile.certLevel();
    boolean ca = CertLevel.EndEntity != certLevel;
    if (ca != bc.isCA()) {
      addViolation(failureMsg, "ca", bc.isCA(), ca);
    }

    if (!bc.isCA()) {
      return;
    }

    Integer tmpPathLen = bc.pathLenConstraint();
    Integer pathLen = certprofile.extensions().pathLen();
    if (pathLen == null) {
      if (tmpPathLen != null) {
        addViolation(failureMsg, "pathLen", tmpPathLen, "absent");
      }
    } else {
      if (tmpPathLen == null) {
        addViolation(failureMsg, "pathLen", "null", pathLen);
      } else if (!Objects.equals(pathLen, tmpPathLen)) {
        addViolation(failureMsg, "pathLen", tmpPathLen, pathLen);
      }
    }
  } // method checkExtnBasicConstraints

  void checkExtnCertificatePolicies(
      StringBuilder failureMsg, Extension extn,
      Extensions requestedExtns, ExtensionControl extnControl) {
    ExtensionValueConf.CertificatePolicies certificatePolicies = caller.getCertificatePolicies();
    if (certificatePolicies == null) {
      caller.checkConstantExtnValue(ExtensionOIDs.certificatePolicies, failureMsg,
          extn, requestedExtns, extnControl);
      return;
    }

    Map<String, ExtensionValueConf.CertificatePolicyInformationType> expPoliciesMap =
        new HashMap<>();

    for (ExtensionValueConf.CertificatePolicyInformationType cp
        : caller.getCertificatePolicies().certificatePolicyInformations()) {
      expPoliciesMap.put(cp.policyIdentifier().oid().getId(), cp);
    }

    Set<String> expPolicyIds = new HashSet<>(expPoliciesMap.keySet());

    CertificatePolicies isPolicyInformations = extn.getCertificatePolicies();

    for (PolicyInformation isPolicyInformation : isPolicyInformations) {
      String isPolicyId = isPolicyInformation.getPolicyIdentifier().getId();
      expPolicyIds.remove(isPolicyId);
      ExtensionValueConf.CertificatePolicyInformationType expCp = expPoliciesMap.get(isPolicyId);
      if (expCp == null) {
        failureMsg.append("certificate policy '").append(isPolicyId).append("' is not expected; ");
        continue;
      }

      List<ExtensionValueConf.PolicyQualifier> expCpPq = expCp.policyQualifiers();
      if (CollectionUtil.isEmpty(expCpPq)) {
        continue;
      }

      PolicyQualifierInfo.Seq1 isPolicyQualifiers = isPolicyInformation.getPolicyQualifiers();
      List<String> isCpsUris = new LinkedList<>();
      List<String> isUserNotices = new LinkedList<>();

      int size = isPolicyQualifiers.size();
      for (int i = 0; i < size; i++) {
        PolicyQualifierInfo isPolicyQualifierInfo = isPolicyQualifiers.get(i);

        Asn1Oid isPolicyQualifierId = isPolicyQualifierInfo.getPolicyQualifierId();
        if (PolicyQualifierOIDs.id_qt_cps.equals(isPolicyQualifierId)) {
          String isCpsUri = isPolicyQualifierInfo.cps();
          isCpsUris.add(isCpsUri);
        } else if (PolicyQualifierOIDs.id_qt_unotice.equals(isPolicyQualifierId)) {
          UserNotice isUserNotice = isPolicyQualifierInfo.getUserNotice();
          String explicitText = isUserNotice.explicitText();
          if (explicitText != null) {
            isUserNotices.add(explicitText);
          }
        }
      }

      for (ExtensionValueConf.PolicyQualifier qualifierInfo : expCpPq) {
        String value = qualifierInfo.value();
        switch (qualifierInfo.type()) {
          case cpsUri:
            if (!isCpsUris.contains(value)) {
              failureMsg.append("CPSUri '").append(value).append("' is absent but is required; ");
            }
            continue;
          case userNotice:
            if (!isUserNotices.contains(value)) {
              failureMsg.append("userNotice '").append(value)
                  .append("' is absent but is required; ");
            }
            continue;
          default:
            throw new IllegalStateException("should not reach here");
        }
      }
    }

    for (String policyId : expPolicyIds) {
      failureMsg.append("certificate policy '").append(policyId)
          .append("' is absent but is required; ");
    }
  } // method checkExtnCertificatePolicies

  void checkExtnDeltaCrlDistributionPoints(
      StringBuilder failureMsg, Extension extn, IssuerInfo issuerInfo) {
    checkExtnCrlDistributionPoints(true, failureMsg, extn, issuerInfo);
  }

  void checkExtnCrlDistributionPoints(
      StringBuilder failureMsg, Extension extn, IssuerInfo issuerInfo) {
    checkExtnCrlDistributionPoints(false, failureMsg, extn, issuerInfo);
  }

  private void checkExtnCrlDistributionPoints(
      boolean deltaCrl, StringBuilder failureMsg, Extension extn, IssuerInfo issuerInfo) {
    CRLDistributionPoints isDistributionPoints = deltaCrl ?
        extn.getFreshestCRL() : extn.getCRLDistributionPoints();

    String type = deltaCrl ? "deltaCRL" : "CRL";

    if (isDistributionPoints == null) {
      addViolation(failureMsg, "size of DistributionPoints of " + type, 0, 1);
      return;
    } else {
      int len = isDistributionPoints.size();
      if (len != 1) {
        addViolation(failureMsg, "size of DistributionPoints of " + type, len, 1);
        return;
      }
    }

    Set<String> isCrlUrls = new HashSet<>();
    for (DistributionPoint entry : isDistributionPoints) {
      int asn1Type = entry.getDistributionPoint().getTagNo();
      if (asn1Type != DistributionPointName.tag_fullName) {
        addViolation(failureMsg,
            "tag of DistributionPointName of CRLDistributionPoints of " + type,
            asn1Type, DistributionPointName.tag_fullName);
        continue;
      }

      GeneralNames isDistributionPointNames = entry.getDistributionPoint().getFullName();

      for (GeneralName name : isDistributionPointNames) {
        if (name.getTagNo() != GeneralName.tag_uri) {
          addViolation(failureMsg, "tag of URL of " + type, name.getTagNo(), GeneralName.tag_uri);
        } else {
          String uri = ((AbstractAsn1String) name.getChoiceData()).getString();
          isCrlUrls.add(uri);
        }
      }

      Set<String> expCrlUrls = deltaCrl ? issuerInfo.getDeltaCrlUrls()
          : issuerInfo.getCrlUrls();

      Set<String> diffs = CheckerUtil.elementInBnotInA(expCrlUrls, isCrlUrls);
      if (CollectionUtil.isNotEmpty(diffs)) {
        failureMsg.append("URLs of ").append(type).append(" ").append(diffs)
            .append(" are present but not expected; ");
      }

      diffs = CheckerUtil.elementInBnotInA(isCrlUrls, expCrlUrls);
      if (CollectionUtil.isNotEmpty(diffs)) {
        failureMsg.append("URLs of ").append(type).append(" ").append(diffs)
            .append(" are absent but are required; ");
      }
    }
  } // method checkExtnCrlDistributionPoints

  void checkExtnExtendedKeyUsage(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns,
      ExtensionControl extnControl) {
    Set<String> isUsages = new HashSet<>();
    ExtendedKeyUsage usages = extn.getExtendedKeyUsage();

    if (usages != null) {
      for (Asn1Oid usage : usages) {
        isUsages.add(usage.getId());
      }
    }

    Set<String> expectedUsages = new HashSet<>();
    Set<ExtKeyUsageControl> requiredExtKeyusage = caller.getExtKeyusage(true);
    if (requiredExtKeyusage != null) {
      for (ExtKeyUsageControl usage : requiredExtKeyusage) {
        expectedUsages.add(usage.extKeyUsage().getId());
      }
    }

    Set<ExtKeyUsageControl> optionalExtKeyusage = caller.getExtKeyusage(false);
    if (requestedExtns != null && extnControl.isPermittedInRequest()
        && CollectionUtil.isNotEmpty(optionalExtKeyusage)) {
      Extension extension = getExtension(requestedExtns, ExtensionOIDs.extendedKeyUsage);

      if (extension != null) {
        ExtendedKeyUsage reqKeyUsage = extension.getExtendedKeyUsage();
        for (ExtKeyUsageControl k : optionalExtKeyusage) {
          if (reqKeyUsage.hasKeyPurposeId(k.extKeyUsage())) {
            expectedUsages.add(k.extKeyUsage().getId());
          }
        }
      }
    }

    if (CollectionUtil.isEmpty(expectedUsages)) {
      byte[] constantExtValue = caller.getConstantExtensionValue(ExtensionOIDs.extendedKeyUsage);
      if (constantExtValue != null) {
        try {
          expectedUsages = getExtKeyUsage(constantExtValue);
        } catch (CodecException e) {
          failureMsg.append("error parsing the expected extendedKeyUsage " +
              "from encoded constant extension value; ");
          return;
        }
      }
    }

    Set<String> diffs = CheckerUtil.elementInBnotInA(expectedUsages, isUsages);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs).append(" are present but not expected; ");
    }

    diffs = CheckerUtil.elementInBnotInA(isUsages, expectedUsages);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs).append(" are absent but are required; ");
    }
  } // method checkExtnExtendedKeyUsage

  void checkExtnInhibitAnyPolicy(
      StringBuilder failureMsg, Extension extn,
      Extensions requestedExtns, ExtensionControl extControl) {
    ExtensionValueConf.InhibitAnyPolicy conf = caller.getInhibitAnyPolicy();
    if (conf == null) {
      caller.checkConstantExtnValue(ExtensionOIDs.inhibitAnyPolicy, failureMsg,
          extn, requestedExtns, extControl);
      return;
    }

    Asn1Integer asn1Int = extn.getInhibitAnyPolicy();
    int isSkipCerts = asn1Int.intValueExact();
    if (isSkipCerts != conf.skipCerts()) {
      addViolation(failureMsg, "skipCerts", isSkipCerts, conf.skipCerts());
    }
  } // method checkExtnInhibitAnyPolicy

  void checkExtnIssuerAltNames(
      StringBuilder failureMsg, Extension extn, IssuerInfo issuerInfo) {
    Extension tExtn = issuerInfo.getCert().getCert().getExtension(
                        ExtensionOIDs.subjectAlternativeName);
    byte[] caSubjectAltExtensionValue = (tExtn == null) ? null : tExtn.extnValue();
    if (caSubjectAltExtensionValue == null) {
      failureMsg.append("issuerAlternativeName is present but expected 'none'; ");
      return;
    }

    byte[] extnValue = extn.extnValue();
    if (!Arrays.equals(caSubjectAltExtensionValue, extnValue)) {
      addViolation(failureMsg, "issuerAltNames",
          Hex.encode(extnValue), Hex.encode(caSubjectAltExtensionValue));
    }
  } // method checkExtnIssuerAltNames

  void checkExtnKeyUsage(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns,
      ExtensionControl extnControl, KeySpec keySpec) {
    boolean[] usages = extn.getKeyUsage().toBooleans();
    int len = usages.length;

    if (len > 9) {
      failureMsg.append("invalid syntax: size of valid bits is larger than 9: ")
          .append(len).append("; ");
    }

    Set<String> isUsages = new HashSet<>();
    for (int i = 0; i < len; i++) {
      if (usages[i]) {
        isUsages.add(ALL_USAGES.get(i));
      }
    }

    Set<String> expectedUsages = new HashSet<>();
    Set<KeySingleUsage> requiredKeyusage = getKeyusage(true, keySpec);
    for (KeySingleUsage usage : requiredKeyusage) {
      expectedUsages.add(usage.keyUsage().getName());
    }

    Set<KeySingleUsage> optionalKeyusage = getKeyusage(false, keySpec);
    if (requestedExtns != null && extnControl.isPermittedInRequest()
        && CollectionUtil.isNotEmpty(optionalKeyusage)) {
      Extension extension = getExtension(requestedExtns, ExtensionOIDs.keyUsage);
      if (extension != null) {
        org.xipki.pkix.asn1.x509.KeyUsage reqKeyUsage = extension.getKeyUsage();
        for (KeySingleUsage k : optionalKeyusage) {
          if (reqKeyUsage.hasFlag(k.keyUsage().asn1())) {
            expectedUsages.add(k.keyUsage().getName());
          }
        }
      }
    }

    if (CollectionUtil.isEmpty(expectedUsages)) {
      byte[] constantExtValue = caller.getConstantExtensionValue(ExtensionOIDs.keyUsage);
      if (constantExtValue != null) {
        expectedUsages = getKeyUsage(constantExtValue);
      }
    }

    Set<String> diffs = CheckerUtil.elementInBnotInA(expectedUsages, isUsages);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs).append(" are present but not expected; ");
    }

    diffs = CheckerUtil.elementInBnotInA(isUsages, expectedUsages);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs).append(" are absent but are required; ");
    }
  } // method checkExtnKeyUsage

  Set<KeySingleUsage> getKeyusage(boolean required, KeySpec keySpec) {
    Set<KeySingleUsage> ret = new HashSet<>();

    Set<KeySingleUsage> controls = getCertprofile().extensions().getKeyUsage(keySpec);
    if (controls != null) {
      for (KeySingleUsage control : controls) {
        if (control.isRequired() == required) {
          ret.add(control);
        }
      }
    }
    return ret;
  } // method getKeyusage

  void checkExtnNameConstraints(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns,
      ExtensionControl extnControl) {
    ExtensionValueConf.NameConstraints nameConstraints = caller.getNameConstraints();

    if (nameConstraints == null) {
      caller.checkConstantExtnValue(ExtensionOIDs.nameConstraints,
          failureMsg, extn, requestedExtns, extnControl);
      return;
    }

    NameConstraints tmpNameConstraints = extn.getNameConstraints();
    checkExtnNameConstraintsSubtrees(failureMsg, "PermittedSubtrees",
        tmpNameConstraints.getPermittedSubtrees(), nameConstraints.permittedSubtrees());
    checkExtnNameConstraintsSubtrees(failureMsg, "ExcludedSubtrees",
        tmpNameConstraints.getExcludedSubtrees(), nameConstraints.excludedSubtrees());
  } // method checkExtnNameConstraints

  private void checkExtnNameConstraintsSubtrees(
      StringBuilder failureMsg, String description, GeneralSubtrees subtrees,
      List<GeneralSubtreeType> expectedSubtrees) {
    int isSize = (subtrees == null) ? 0 : subtrees.size();
    int expSize = (expectedSubtrees == null) ? 0 : expectedSubtrees.size();
    if (isSize != expSize) {
      addViolation(failureMsg, "size of " + description, isSize, expSize);
      return;
    }

    if (subtrees == null || expectedSubtrees == null) {
      return;
    }

    for (int i = 0; i < isSize; i++) {
      GeneralSubtree isSubtree = subtrees.get(i);
      GeneralSubtreeType expSubtree = expectedSubtrees.get(i);
      String desc = description + " [" + i + "]";

      GeneralName isBase = isSubtree.getBase();

      GeneralName expBase;
      if (expSubtree.directoryName() != null) {
        expBase = GeneralName.ofDirectoryName(X509Util.reverse(
                    new X500Name(expSubtree.directoryName())));
      } else if (expSubtree.dnsName() != null) {
        expBase = GeneralName.ofDnsName(expSubtree.dnsName());
      } else if (expSubtree.ipAddress() != null) {
        expBase = GeneralName.ofIPAddress(expSubtree.ipAddress());
      } else if (expSubtree.rfc822Name() != null) {
        expBase = GeneralName.ofRfc822Name(expSubtree.rfc822Name());
      } else if (expSubtree.uri() != null) {
        expBase = GeneralName.ofUri(expSubtree.uri());
      } else {
        throw new IllegalStateException("should not reach here, unknown child of GeneralName");
      }

      if (!isBase.equals(expBase)) {
        addViolation(failureMsg, "base of " + desc, isBase, expBase);
      }
    }
  } // method checkExtnNameConstraintsSubtrees

  void checkExtnOcspNocheck(StringBuilder failureMsg, Extension extn) {
    checkExtnNullValue(failureMsg, extn);
  }

  void checkExtnPolicyConstraints(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns,
      ExtensionControl extnControl) {
    ExtensionValueConf.PolicyConstraints conf = caller.getPolicyConstraints();
    if (conf == null) {
      caller.checkConstantExtnValue(ExtensionOIDs.policyConstraints,
          failureMsg, extn, requestedExtns, extnControl);
      return;
    }

    PolicyConstraints isPolicyConstraints = extn.getPolicyConstraints();

    Integer expRequireExplicitPolicy = conf.requireExplicitPolicy();
    Integer isRequireExplicitPolicy = isPolicyConstraints.requireExplicitPolicyMapping();

    boolean match = true;
    if (expRequireExplicitPolicy == null) {
      if (isRequireExplicitPolicy != null) {
        match = false;
      }
    } else if (!expRequireExplicitPolicy.equals(isRequireExplicitPolicy)) {
      match = false;
    }

    if (!match) {
      addViolation(failureMsg, "requireExplicitPolicy",
          isRequireExplicitPolicy, expRequireExplicitPolicy);
    }

    Integer expInhibitPolicyMapping = conf.inhibitPolicyMapping();
    Integer isInhibitPolicyMapping = isPolicyConstraints.inhibitPolicyMapping();

    match = true;
    if (expInhibitPolicyMapping == null) {
      if (isInhibitPolicyMapping != null) {
        match = false;
      }
    } else if (!expInhibitPolicyMapping.equals(isInhibitPolicyMapping)) {
      match = false;
    }

    if (!match) {
      addViolation(failureMsg, "inhibitPolicyMapping",
          isInhibitPolicyMapping, expInhibitPolicyMapping);
    }
  } // method checkExtnPolicyConstraints

  void checkExtnPolicyMappings(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns,
      ExtensionControl extnControl) {
    ExtensionValueConf.PolicyMappings conf = caller.getPolicyMappings();
    if (conf == null) {
      caller.checkConstantExtnValue(ExtensionOIDs.policyMappings, failureMsg,
          extn, requestedExtns, extnControl);
      return;
    }

    PolicyMappings isPolicyMappings = extn.getPolicyMappings();

    Map<String, String> isMap = new HashMap<>();
    int size = isPolicyMappings.size();
    for (int i = 0; i < size; i++) {
      PolicyMapping m = isPolicyMappings.get(i);
      Asn1Oid issuerDomainPolicy = m.getIssuerDomainPolicy();
      Asn1Oid subjectDomainPolicy = m.getSubjectDomainPolicy();
      isMap.put(issuerDomainPolicy.getId(), subjectDomainPolicy.getId());
    }

    for (ExtensionValueConf.PolicyIdMappingType m : conf.mappings()) {
      String expIssuerDomainPolicy = m.issuerDomainPolicy().textOid();
      String expSubjectDomainPolicy = m.subjectDomainPolicy().textOid();

      String isSubjectDomainPolicy = isMap.remove(expIssuerDomainPolicy);
      if (isSubjectDomainPolicy == null) {
        failureMsg.append("issuerDomainPolicy '").append(expIssuerDomainPolicy)
            .append("' is absent but is required; ");
      } else if (!isSubjectDomainPolicy.equals(expSubjectDomainPolicy)) {
        addViolation(failureMsg, "subjectDomainPolicy for issuerDomainPolicy",
            isSubjectDomainPolicy, expSubjectDomainPolicy);
      }
    }

    if (CollectionUtil.isNotEmpty(isMap)) {
      failureMsg.append("issuerDomainPolicies '").append(isMap.keySet())
          .append("' are present but not expected; ");
    }
  } // method checkExtnMappings

  void checkSmimeCapabilities(StringBuilder failureMsg, Extension extn) {
    byte[] expected = caller.smimeCapabilities().getValue();
    byte[] extnValue = extn.extnValue();
    if (!Arrays.equals(expected, extnValue)) {
      addViolation(failureMsg, "extension valus", Hex.encode(extnValue), Hex.encode(expected));
    }
  } // method checkSmimeCapabilities

  void checkScts(StringBuilder failureMsg, Extension extn) {
    // just check the syntax
    try {
      CtLog.SignedCertificateTimestampList sctList =
          CtLog.SignedCertificateTimestampList.getInstance(
              extn.signedCertificateTimestampList());
      int size = sctList.sctList().size();
      for (int i = 0; i < size; i++) {
        CtLog.getSignatureObject(sctList.sctList().get(i).digitallySigned());
      }
    } catch (Exception ex) {
      failureMsg.append("invalid syntax: ").append(ex.getMessage()).append("; ");
    }
  } // method checkScts

  void checkExtnPrivateKeyUsagePeriod(
      StringBuilder failureMsg, Extension extn, Instant certNotBefore, Instant certNotAfter) {
    Asn1GeneralizedTime notBefore = new Asn1GeneralizedTime(certNotBefore);
    Instant dateNotAfter;
    Validity privateKeyUsagePeriod = getCertprofile().extensions().privateKeyUsagePeriod();
    if (privateKeyUsagePeriod == null) {
      dateNotAfter = certNotAfter;
    } else {
      dateNotAfter = privateKeyUsagePeriod.add(certNotBefore);
      if (dateNotAfter.isAfter(certNotAfter)) {
        dateNotAfter = certNotAfter;
      }
    }
    Asn1GeneralizedTime notAfter = new Asn1GeneralizedTime(dateNotAfter);

    PrivateKeyUsagePeriod extValue = extn.getPrivateKeyUsagePeriod();

    Asn1GeneralizedTime time = extValue.getNotBefore();
    if (time == null) {
      failureMsg.append("notBefore is absent but expected present; ");
    } else if (!time.equals(notBefore)) {
      addViolation(failureMsg, "notBefore", time.getText(), notBefore.getText());
    }

    time = extValue.getNotAfter();
    if (time == null) {
      failureMsg.append("notAfter is absent but expected present; ");
    } else if (!time.equals(notAfter)) {
      addViolation(failureMsg, "notAfter", time.getText(), notAfter.getText());
    }
  } // method checkExtnPrivateKeyUsagePeriod

  void checkExtnQcStatements(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns,
      ExtensionControl extnControl) {
    ExtensionValueConf.QcStatements qcStatements = caller.getQcStatements();
    if (qcStatements == null) {
      caller.checkConstantExtnValue(ExtensionOIDs.qCStatements, failureMsg,
          extn, requestedExtns, extnControl);
      return;
    }

    final int expSize = qcStatements.qcStatements().size();
    QCStatements extValue = extn.getQCStatements();
    final int isSize = extValue.size();
    if (isSize != expSize) {
      addViolation(failureMsg, "number of statements", isSize, expSize);
      return;
    }

    // extract the euLimit and pdsLocations data from request
    Map<String, int[]> reqQcEuLimits = new HashMap<>();
    Extension reqExtension = getExtension(requestedExtns, ExtensionOIDs.qCStatements);
    if (reqExtension != null) {
      QCStatements seq = reqExtension.getQCStatements();

      final int n = seq.size();
      for (int j = 0; j < n; j++) {
        QCStatement stmt = seq.get(j);
        if (QCStatementID.etsi_qcs_QcLimitValue.oid().equals(stmt.getStatementId())) {

          MonetaryValue monetaryValue = stmt.getQcLimitValue();
          int amount = monetaryValue.amount();
          int exponent = monetaryValue.exponent();
          Iso4217CurrencyCode currency = monetaryValue.getCurrency();
          String currencyS = currency.isAlphabetic()
              ? currency.alphabetic().toUpperCase()
              : currency.numeric().toString();
          reqQcEuLimits.put(currencyS, new int[]{amount, exponent});
        }
      }
    }

    for (int i = 0; i < expSize; i++) {
      QCStatement is = extValue.get(i);
      ExtensionValueConf.QcStatementType exp = qcStatements.qcStatements().get(i);
      if (!is.getStatementId().equals(exp.statementId().oid())) {
        addViolation(failureMsg, "statementId[" + i + "]",
            is.getStatementId().getId(), exp.statementId().oid());
        continue;
      }

      if (exp.statementValue() == null) {
        if (is.getStatementInfo() != null) {
          addViolation(failureMsg, "statementInfo[" + i + "]", "present", "absent");
        }
        continue;
      }

      if (is.getStatementInfo() == null) {
        addViolation(failureMsg, "statementInfo[" + i + "]", "absent", "present");
        continue;
      }

      ExtensionValueConf.QcStatementValueType expStatementValue = exp.statementValue();

      try {
        if (expStatementValue.constant() != null) {
          byte[] expValue = expStatementValue.constant().toASN1().getEncoded();
          byte[] isValue = is.getStatementInfo().getEncoded();

          if (!Arrays.equals(isValue, expValue)) {
            addViolation(failureMsg, "statementInfo[" + i + "]",
                Hex.encode(isValue), Hex.encode(expValue));
          }
        } else if (expStatementValue.qcRetentionPeriod() != null) {
          String isValue = ((Asn1Integer) is.getStatementInfo()).getValue().toString();

          String expValue = expStatementValue.qcRetentionPeriod().toString();
          if (!isValue.equals(expValue)) {
            addViolation(failureMsg, "statementInfo[" + i + "]", isValue, expValue);
          }
        } else if (expStatementValue.pdsLocations() != null) {
          PdsLocations pdsLocs = is.getQcPDS();
          Set<String> pdsLocations = new HashSet<>();

          int size = pdsLocs.size();
          for (int k = 0; k < size; k++) {
            PdsLocation pdsLoc = pdsLocs.get(k);

            String url = pdsLoc.url();
            String lang = pdsLoc.language();
            pdsLocations.add("url=" + url + ",lang=" + lang);
          }

          Set<String> expectedPdsLocations = new HashSet<>();
          for (ExtensionValueConf.PdsLocationType m : expStatementValue.pdsLocations()) {
            expectedPdsLocations.add("url=" + m.url() + ",lang=" + m.language());
          }

          Set<String> diffs = CheckerUtil.elementInBnotInA(expectedPdsLocations, pdsLocations);

          if (CollectionUtil.isNotEmpty(diffs)) {
            failureMsg.append("statementInfo[").append(i).append("]: ")
                .append(diffs).append(" are present but not expected; ");
          }

          diffs = CheckerUtil.elementInBnotInA(pdsLocations, expectedPdsLocations);
          if (CollectionUtil.isNotEmpty(diffs)) {
            failureMsg.append("statementInfo[").append(i).append("]: ")
                .append(diffs).append(" are absent but are required; ");
          }
        } else if (expStatementValue.qcEuLimitValue() != null) {
          ExtensionValueConf.QcEuLimitValueType euLimitConf = expStatementValue.qcEuLimitValue();
          String expCurrency = euLimitConf.currency().toUpperCase();
          int[] expAmountExp = reqQcEuLimits.get(expCurrency);

          ExtensionValueConf.Range2Type range = euLimitConf.amount();
          int value;
          if (range.min() == range.max()) {
            value = range.min();
          } else if (expAmountExp != null) {
            value = expAmountExp[0];
          } else {
            failureMsg.append("found no QcEuLimit for currency '")
                .append(expCurrency).append("'; ");
            return;
          }
          String expAmount = Integer.toString(value);

          range = euLimitConf.exponent();
          if (range.min() == range.max()) {
            value = range.min();
          } else if (expAmountExp != null) {
            value = expAmountExp[1];
          } else {
            failureMsg.append("found no QcEuLimit for currency '")
                .append(expCurrency).append("'; ");
            return;
          }
          String expExponent = Integer.toString(value);

          MonetaryValue monterayValue = is.getQcLimitValue();
          Iso4217CurrencyCode currency = monterayValue.getCurrency();
          String isCurrency = currency.isAlphabetic()
              ? currency.alphabetic() : Integer.toString(currency.numeric());
          String isAmount = monterayValue.getAmount().toString();
          String isExponent = monterayValue.getExponent().toString();
          if (!isCurrency.equals(expCurrency)) {
            addViolation(failureMsg, "statementInfo[" + i +
                    "].qcEuLimit.currency", isCurrency, expCurrency);
          }
          if (!isAmount.equals(expAmount)) {
            addViolation(failureMsg, "statementInfo[" + i +
                    "].qcEuLimit.amount", isAmount, expAmount);
          }
          if (!isExponent.equals(expExponent)) {
            addViolation(failureMsg, "statementInfo[" + i +
                    "].qcEuLimit.exponent", isExponent, expExponent);
          }
        } else {
          throw new IllegalStateException("statementInfo[" + i + "]should not reach here");
        }
      } catch (CodecException ex) {
        failureMsg.append("statementInfo[").append(i).append("] has incorrect syntax; ");
      }
    }
  } // method checkExtnQcStatements

  void checkExtnSubjectAltNames(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns,
      X500Name requestedSubject) {
    XijsonCertprofile certprofile = getCertprofile();
    Set<GeneralNameTag> conf = certprofile.subjectAltNameModes();
    Set<Asn1Oid> sanOtherNameTypes =
        certprofile.extensions().subjectAltNameOtherNameTypes();

    GeneralNames requested;
    try {
      Extension rExtn = getExtension(requestedExtns, ExtensionOIDs.subjectAlternativeName);
      GeneralNames sanExtnValue = (rExtn == null) ? null : rExtn.getSubjectAlternativeName();
      requested = XijsonExtensions.createRequestedSubjectAltNames(
          requestedSubject, sanExtnValue, certprofile.subjectAltNameModes(),
          certprofile.extensions().subjectToSubjectAltNameModes(),
          certprofile.extensions().subjectAltNameOtherNameTypes());
    } catch (BadCertTemplateException ex) {
      String msg = "error while derive grantedSubject from requestedSubject";
      LogUtil.warn(log, ex, msg);
      failureMsg.append(msg);
      return;
    }

    if (requested == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    GeneralNames is = extn.getSubjectAlternativeName();

    List<GeneralName> expected = new ArrayList<>(requested.size());
    for (int i = 0; i < is.size(); i++) {
      try {
        expected.add(createGeneralName(is.get(i), conf, sanOtherNameTypes));
      } catch (BadCertTemplateException | CodecException ex) {
        failureMsg.append("could not process ").append(i + 1)
            .append("-th name: ").append(ex.getMessage()).append("; ");
        return;
      }
    }

    if (is.size() != expected.size()) {
      addViolation(failureMsg, "size of GeneralNames", is.size(), expected.size());
      return;
    }

    for (int i = 0; i < is.size(); i++) {
      if (!is.get(i).equals(expected.get(i))) {
        failureMsg.append(i + 1).append("-th name does not match the requested one; ");
      }
    }
  } // method checkExtnSubjectAltNames

  void checkExtnSubjectDirectoryAttributes(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns) {
    XijsonCertprofile certprofile = getCertprofile();
    List<Asn1Oid> profileAttrTypes = certprofile.extensions().subjectDirectoryAttributes();

    SubjectDirectoryAttributes sdAttrs = extn.getSubjectDirectoryAttributes();

    Map<Asn1Oid, Attribute> certAttrsMap = new HashMap<>();
    for (Attribute attr : sdAttrs) {
      certAttrsMap.put(attr.getAttrType(), attr);
    }

    List<Asn1Oid> unpermittedAttrTypes = new ArrayList<>();
    for (Asn1Oid attrTypeInCert : certAttrsMap.keySet()) {
      if (!profileAttrTypes.contains(attrTypeInCert)) {
        unpermittedAttrTypes.add(attrTypeInCert);
      }
    }

    List<Asn1Oid> missingAttrTypes = new ArrayList<>();
    for (Asn1Oid profileAttrType : profileAttrTypes) {
      if (!certAttrsMap.containsKey(profileAttrType)) {
        missingAttrTypes.add(profileAttrType);
      }
    }

    if (! (unpermittedAttrTypes.isEmpty() && missingAttrTypes.isEmpty())) {
      if (!unpermittedAttrTypes.isEmpty()) {
        failureMsg.append("attributes ").append(unpermittedAttrTypes)
            .append(" present but not permitted; ");
      }

      if (!missingAttrTypes.isEmpty()) {
        failureMsg.append("attributes ").append(unpermittedAttrTypes)
            .append(" required but not present; ");
      }
      return;
    }

    Extension reqExtn = getExtension(requestedExtns, ExtensionOIDs.subjectDirectoryAttributes);
    if (reqExtn == null) {
      failureMsg.append("extension is required in request but not present; ");
      return;
    }

    SubjectDirectoryAttributes reqSdAttrs = reqExtn.getSubjectDirectoryAttributes();

    Map<Asn1Oid, Attribute> reqCertAttrsMap = new HashMap<>();
    for (Attribute attr : reqSdAttrs) {
      reqCertAttrsMap.put(attr.getAttrType(), attr);
    }

    for (Map.Entry<Asn1Oid, Attribute> m : certAttrsMap.entrySet()) {
      Asn1Oid attrType = m.getKey();
      Attribute reqAttr = reqCertAttrsMap.get(attrType);
      if (reqAttr == null) {
        failureMsg.append("attribute ").append(attrType)
            .append(" is present in cert but not in request; ");
      } else {
        byte[] expected, is;
        try {
          Attribute expectedAttr = ProfileUtil.canonicalizeSubjectDirectoryAttribute(reqAttr);
          expected = expectedAttr.getAttrValues().getEncoded();
          is = m.getValue().getAttrValues().getEncoded();
        } catch (Exception e) {
          failureMsg.append("attribute ").append(attrType)
              .append(" error encoding attribute value; ");
          continue;
        }

        if (!Arrays.equals(expected, is)) {
          CheckerUtil.addViolation(failureMsg, "attribute value", Hex.encode(is),
              Hex.encode(expected));
        }
      }
    }
  } // method checkExtnSubjectDirectoryAttributes

  void checkExtnSubjectInfoAccess(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns) {
    Map<Asn1Oid, Set<GeneralNameTag>> conf = getCertprofile().subjectInfoAccessModes();
    if (conf == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    SubjectInfoAccessSyntax requestSeq = null;
    Extension extension = getExtension(requestedExtns, ExtensionOIDs.subjectInfoAccess);
    if (extension != null) {
      requestSeq = extension.getSubjectInfoAccess();
    }

    if (requestSeq == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    SubjectInfoAccessSyntax certSeq = extn.getSubjectInfoAccess();
    int size = requestSeq.size();

    if (certSeq.size() != size) {
      addViolation(failureMsg, "size of GeneralNames", certSeq.size(), size);
      return;
    }

    for (int i = 0; i < size; i++) {
      AccessDescription ad = requestSeq.get(i);
      Asn1Oid accessMethod = ad.getAccessMethod();
      Set<GeneralNameTag> generalNameModes = conf.get(accessMethod);

      if (generalNameModes == null) {
        failureMsg.append("accessMethod in requestedExtension ")
            .append(accessMethod.getId()).append(" is not allowed; ");
        continue;
      }

      AccessDescription certAccessDesc = certSeq.get(i);
      Asn1Oid certAccessMethod = certAccessDesc.getAccessMethod();

      boolean bo = Objects.equals(accessMethod, certAccessMethod);

      if (!bo) {
        addViolation(failureMsg, "accessMethod",
            (certAccessMethod == null) ? "null" : certAccessMethod.getId(),
            (accessMethod == null) ? "null" : accessMethod.getId());
        continue;
      }

      GeneralName accessLocation;
      try {
        accessLocation = createGeneralName(ad.getAccessLocation(), generalNameModes, null);
      } catch (BadCertTemplateException | CodecException ex) {
        failureMsg.append("invalid requestedExtension: ").append(ex.getMessage()).append("; ");
        continue;
      }

      GeneralName certAccessLocation = certAccessDesc.getAccessLocation();
      if (!certAccessLocation.equals(accessLocation)) {
        failureMsg.append("accessLocation does not match the requested one; ");
      }
    }
  } // method checkExtnSUbjectInfoAccess

  void checkExtnSubjectKeyIdentifier(
      StringBuilder failureMsg, Extension extn, SubjectPublicKeyInfo subjectPublicKeyInfo) {
    SubjectKeyIdentifier asn1 = extn.getSubjectKeyIdentifier();

    byte[] ski = asn1.getKeyIdentifier();

    byte[] expectedSki = getCertprofile().subjectKeyIdentifier(subjectPublicKeyInfo);

    if (!Arrays.equals(expectedSki, ski)) {
      addViolation(failureMsg, "SKI", Hex.encode(ski), Hex.encode(expectedSki));
    }
  } // method checkExtnSubjectKeyIdentifier

  void checkExtnTlsFeature(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns,
      ExtensionControl extnControl) {
    ExtensionValueConf.TlsFeature tlsFeature = caller.getTlsFeature();
    if (tlsFeature == null) {
      caller.checkConstantExtnValue(ExtensionOIDs.id_pe_tlsfeature,
          failureMsg, extn, requestedExtns, extnControl);
      return;
    }

    Set<Integer> isFeatures = new HashSet<>();
    for (Asn1Integer asn1Feature : extn.getTlsFeatures()) {
      isFeatures.add(asn1Feature.intValueExact());
    }

    Set<Integer> expFeatures = new HashSet<>(tlsFeature.features());

    Set<Integer> diffs = CheckerUtil.elementInBnotInA(expFeatures, isFeatures);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("features ").append(diffs).append(" are present but not expected; ");
    }

    diffs = CheckerUtil.elementInBnotInA(isFeatures, expFeatures);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("features ").append(diffs).append(" are absent but are required; ");
    }
  } // method checkExtnTlsFeature

  void checkExtnMicrosoftCertificateTemplateName(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns,
      ExtensionControl extnControl) {
    ExtensionValueConf.MicrosoftCertificateTemplateName template =
        caller.getMicrosoftCertificateTemplateName();
    if (template == null) {
      caller.checkConstantExtnValue(ExtensionOIDs.id_microsoft_CertificateTemplateName,
          failureMsg, extn, requestedExtns, extnControl);
      return;
    }

    Asn1Primitive expectedExtnValue = template.toExtensionValue();

    checkExpectedAsn1(failureMsg, extn.extnValue(), expectedExtnValue);
  } // method checkExtnMicrosoftCertificateTemplateName

  void checkExtnMicrosoftCertificateTemplateInformation(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns,
      ExtensionControl extnControl) {
    ExtensionValueConf.MicrosoftCertificateTemplateInformation template =
        caller.getMicrosoftCertificateTemplateInformation();
    if (template == null) {
      caller.checkConstantExtnValue(ExtensionOIDs.id_microsoft_CertificateTemplateInformation,
          failureMsg, extn, requestedExtns, extnControl);
      return;
    }

    checkExpectedAsn1(failureMsg, extn.extnValue(), template.toExtensionValue());
  } // method checkExtnMicrosoftCertificateTemplateInformation

  void checkExtnMicrosoftSid(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns) {
    ExtensionValueConf.MicrosoftSID template = caller.getCertprofile().extensions().microsoftSID();
    if (template == null) {
      return;
    }

    Extension rExtn = getExtension(requestedExtns, ExtensionOIDs.id_microsoft_SecurityIdentifier);
    checkExpectedAsn1(failureMsg, extn.extnValue(), rExtn.extnValue());
  } // method checkExtnMicrosoftSid

  void checkExtnStirTNAuthList(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns) {
    try {
      Extension rExtn = getExtension(requestedExtns, ExtensionOIDs.id_pe_TNAuthList);
      checkExpectedAsn1(failureMsg, extn.extnValue(), rExtn.extnValue());
    } catch (RuntimeException ex) {
      CheckerUtil.addViolation(failureMsg, "extension value",
          ex.getMessage(), "profile conform");
    }
  } // method checkExtnMicrosoftSid

  void checkExtnRpkiAsIdentifiers(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns) {
    try {
      Extension rExtn = getExtension(requestedExtns, extn.getExtnId());
      byte[] rExtnValue = (rExtn == null) ? null : rExtn.extnValue();
      checkExpectedAsn1(failureMsg, extn.extnValue(), rExtnValue);
    } catch (RuntimeException ex) {
      CheckerUtil.addViolation(failureMsg, "extension value",
          ex.getMessage(), "profile conform");
    }
  } // method checkExtnRpkiAsIdentifiers

  void checkExtnRpkiIPAddrBlocks(
      StringBuilder failureMsg, Extension extn, Extensions requestedExtns) {
    try {
      Extension rExtn = getExtension(requestedExtns, extn.getExtnId());
      byte[] rExtnValue = (rExtn == null) ? null : rExtn.extnValue();

      checkExpectedAsn1(failureMsg, extn.extnValue(), rExtnValue);
    } catch (RuntimeException ex) {
      CheckerUtil.addViolation(failureMsg, "extension value",
          ex.getMessage(), "profile conform");
    }
  } // method checkExtnRpkiIPAddrBlocks

  void checkExtnStirJWTClaimConstraints(StringBuilder failureMsg, Extension extn) {
    try {
      ExtensionValue expectedExtnValue =
          caller.getCertprofile().extensions().stirJWTClaimPermittedValues();
      checkExpectedAsn1(failureMsg, extn.extnValue(), expectedExtnValue.value());
    } catch (RuntimeException ex) {
      CheckerUtil.addViolation(failureMsg, "extension value",
          ex.getMessage(), "profile conform");
    }
  } // method checkExtnStirJWTClaimConstraints

  void checkExtnSpdmCertOids(StringBuilder failureMsg, Extension extn) {
    try {
      ExtensionValue expectedExtnValue = caller.getCertprofile().extensions().spdmCertOids();
      checkExpectedAsn1(failureMsg, extn.extnValue(), expectedExtnValue.value());
    } catch (RuntimeException ex) {
      CheckerUtil.addViolation(failureMsg, "extension value",
          ex.getMessage(), "profile conform");
    }
  } // method checkExtnSpdmCertOids

  void checkExtnNoRevAvail(StringBuilder failureMsg, Extension extn) {
    checkExtnNullValue(failureMsg, extn);
  }

  void checkExtnMasaUrl(StringBuilder failureMsg, Extension extn, Extensions requestedExtns) {
    try {
      Asn1Primitive expExtValue = caller.getCertprofile().extensions().masaUrl().value();
      if (expExtValue == null) {
        Extension rExtn = getExtension(requestedExtns, ExtensionID.masaUrl.oid());
        String str = (rExtn == null) ? null : rExtn.masaUrl();

        expExtValue = new Asn1IA5String(str);
      }
      checkExpectedAsn1(failureMsg, extn.extnValue(), expExtValue);
    } catch (RuntimeException ex) {
      CheckerUtil.addViolation(failureMsg, "extension value",
          ex.getMessage(), "profile conform");
    }
  } // method checkExtnMasaUrl

  void checkExtnMrtdNameChange(StringBuilder failureMsg, Extension extn) {
    checkExtnNullValue(failureMsg, extn);
  }

  void checkExtnMrtdDocumentTypeList(StringBuilder failureMsg, Extension extn) {
    try {
      Asn1Primitive expExtValue = caller.getCertprofile().extensions().mrtdDocumentTypes().value();
      checkExpectedAsn1(failureMsg, extn.extnValue(), expExtValue);
    } catch (RuntimeException ex) {
      CheckerUtil.addViolation(failureMsg, "extension value",
          ex.getMessage(), "profile conform");
    }
  } // method checkExtnMasaUrl

  private void checkExtnNullValue(StringBuilder failureMsg, Extension extn) {
    if (!Arrays.equals(DER_NULL, extn.extnValue())) {
      failureMsg.append("value is not DER NULL; ");
    }
  }

  void checkExtnDiceUeid(StringBuilder failureMsg, Extension extn, Extensions requestedExtns) {
    try {
      Extension rExtn = getExtension(requestedExtns, DiceOIDs.tcg_dice_ueid);
      checkExpectedAsn1(failureMsg, extn.extnValue(), rExtn.getTcgDiceUeid().getEncoded());
    } catch (RuntimeException ex) {
      CheckerUtil.addViolation(failureMsg, "extension value",
          ex.getMessage(), "profile conform");
    }
  } // method checkExtnRpkiIPAddrBlocks

  private static void checkExpectedAsn1(
      StringBuilder failureMsg, byte[] extnValue, Asn1Primitive expectedAsn1) {
    checkExpectedAsn1(failureMsg, extnValue, expectedAsn1.getEncoded());
  }

  private static void checkExpectedAsn1(
      StringBuilder failureMsg, byte[] extnValue, byte[] expectedEncoded) {
    if (!Arrays.equals(expectedEncoded, extnValue)) {
      CheckerUtil.addViolation(failureMsg, "extension values", Hex.encode(extnValue),
          Hex.encode(expectedEncoded));
    }
  }

  static Set<String> getKeyUsage(byte[] extensionValue) {
    Set<String> usages = new HashSet<>();
    org.xipki.pkix.asn1.x509.KeyUsage reqKeyUsage;
    try {
      reqKeyUsage = org.xipki.pkix.asn1.x509.KeyUsage.fromEncoded(extensionValue);
    } catch (CodecException e) {
      throw new RuntimeException("could not parse key usage");
    }

    for (KeyUsage k : KeyUsage.values()) {
      if (reqKeyUsage.hasFlag(k.asn1())) {
        usages.add(k.getName());
      }
    }

    return usages;
  } // method getKeyUsage

  static Set<String> getExtKeyUsage(byte[] extensionValue) throws CodecException {
    Set<String> usages = new HashSet<>();
    ExtendedKeyUsage reqKeyUsage = ExtendedKeyUsage.fromEncoded(extensionValue);
    for (Asn1Oid usage : reqKeyUsage) {
      usages.add(usage.getId());
    }
    return usages;
  } // method getExtKeyUsage

  static void checkAia(
      StringBuilder failureMsg, AuthorityInfoAccessSyntax aia,
      Asn1Oid accessMethod, Set<String> expectedUris) {
    String typeDesc;
    if (X509OIDs.id_ad_ocsp.equals(accessMethod)) {
      typeDesc = "OCSP";
    } else if (X509OIDs.id_ad_caIssuers.equals(accessMethod)) {
      typeDesc = "caIssuer";
    } else {
      typeDesc = accessMethod.getId();
    }

    List<AccessDescription> isAccessDescriptions = new LinkedList<>();
    for (AccessDescription accessDescription : aia) {
      if (accessMethod.equals(accessDescription.getAccessMethod())) {
        isAccessDescriptions.add(accessDescription);
      }
    }

    int size = isAccessDescriptions.size();
    if (size != expectedUris.size()) {
      CheckerUtil.addViolation(failureMsg,
          "number of AIA " + typeDesc + " URIs", size, expectedUris.size());
      return;
    }

    Set<String> isUris = new HashSet<>();
    for (AccessDescription isAccessDescription : isAccessDescriptions) {
      GeneralName isAccessLocation = isAccessDescription.getAccessLocation();
      if (isAccessLocation.getTagNo() != GeneralName.tag_uri) {
        CheckerUtil.addViolation(failureMsg, "tag of accessLocation of AIA ",
            isAccessLocation.getTagNo(), GeneralName.tag_uri);
      } else {
        isUris.add(isAccessLocation.uri());
      }
    }

    Set<String> diffs = CheckerUtil.elementInBnotInA(expectedUris, isUris);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append(typeDesc).append(" URIs ").append(diffs);
      failureMsg.append(" are present but not expected; ");
    }

    diffs = CheckerUtil.elementInBnotInA(isUris, expectedUris);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append(typeDesc).append(" URIs ").append(diffs);
      failureMsg.append(" are absent but are required; ");
    }
  } // method checkAia

  static GeneralName createGeneralName(
      GeneralName reqName, Set<GeneralNameTag> modes, Set<Asn1Oid> otherNameTypes)
          throws BadCertTemplateException, CodecException {
    int tag = reqName.getTagNo();
    GeneralNameTag mode = null;
    if (modes != null) {
      for (GeneralNameTag m : modes) {
        if (m.tag() == tag) {
          mode = m;
          break;
        }
      }

      if (mode == null) {
        throw new BadCertTemplateException("generalName tag " + tag + " is not allowed");
      }
    }

    switch (tag) {
      case GeneralName.tag_rfc822Name:
        return GeneralName.ofRfc822Name(reqName.getRfc822Name());
      case GeneralName.tag_dNSName:
        return GeneralName.ofDnsName(reqName.getDNSName());
      case GeneralName.tag_uri:
        return GeneralName.ofUri(reqName.getUri());
      case GeneralName.tag_iPAddress:
        return GeneralName.ofIPAddress(reqName.getIPAddress());
      case GeneralName.tag_registeredID:
        return GeneralName.ofRegisteredID(reqName.getRegisteredID());
      case GeneralName.tag_directoryName:
        return GeneralName.ofDirectoryName(reqName.getDirectoryName());
      case GeneralName.tag_otherName: {
        OtherName reqSeq = reqName.getOtherName();
        Asn1Oid type = reqSeq.getTypeID();
        if (otherNameTypes != null && !otherNameTypes.contains(type)) {
          throw new BadCertTemplateException("otherName.type " + type.getId() +
              " is not permitted");
        }

        reqSeq.parseValue();
        OtherName newOtherName = OtherName.create(type, reqSeq.getValue());
        return GeneralName.ofOtherName(newOtherName);
      }
      case GeneralName.tag_ediPartyName: {
        EDIPartyName reqSeq = reqName.getEdiPartyName();
        return GeneralName.ofEdiPartyName(new EDIPartyName(
            reqSeq.nameAssigner(), reqSeq.partyName()));
      }
      default:
        throw new IllegalStateException("should not reach here, unknown GeneralName tag " + tag);
    } // end switch
  } // method createGeneralName

}
