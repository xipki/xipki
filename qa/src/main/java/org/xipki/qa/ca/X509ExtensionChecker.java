// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.ctrl.AuthorityInfoAccessControl;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.ExtKeyUsageControl;
import org.xipki.ca.api.profile.ctrl.ExtensionControl;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.XijsonExtensions;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.ca.certprofile.xijson.conf.extn.CertificatePolicies;
import org.xipki.ca.certprofile.xijson.conf.extn.InhibitAnyPolicy;
import org.xipki.ca.certprofile.xijson.conf.extn.NameConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyMappings;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements;
import org.xipki.ca.certprofile.xijson.conf.extn.TlsFeature;
import org.xipki.qa.CheckerUtil;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.security.pkix.CtLog;
import org.xipki.security.pkix.KeyUsage;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.type.Validity;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import static org.xipki.qa.CheckerUtil.addViolation;

/**
 * Extension checker.
 * @author Lijun Liao
 */
class X509ExtensionChecker {

  private static final byte[] DER_NULL = new byte[] {5, 0};

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

  void checkExtnAuthorityInfoAccess(
      StringBuilder failureMsg, byte[] extnValue, IssuerInfo issuerInfo) {
    AuthorityInfoAccessControl aiaControl = getCertprofile().aiaControl();
    Set<String> expCaIssuerUris =
        (aiaControl == null || aiaControl.isIncludesCaIssuers())
            ? issuerInfo.getCaIssuerUrls() : Collections.emptySet();

    Set<String> expOcspUris =
        (aiaControl == null || aiaControl.isIncludesOcsp())
            ? issuerInfo.getOcspUrls() : Collections.emptySet();

    if (CollectionUtil.isEmpty(expCaIssuerUris)
        && CollectionUtil.isEmpty(expOcspUris)) {
      failureMsg.append("AIA is present but expected is 'none'; ");
      return;
    }

    AuthorityInformationAccess isAia =
        AuthorityInformationAccess.getInstance(extnValue);
    checkAia(failureMsg, isAia, OIDs.X509.id_ad_caIssuers, expCaIssuerUris);
    checkAia(failureMsg, isAia, OIDs.X509.id_ad_ocsp, expOcspUris);
  } // method checkExtnAuthorityInfoAccess

  void checkExtnAuthorityKeyId(StringBuilder failureMsg, byte[] extnValue,
                               IssuerInfo issuerInfo) {
    AuthorityKeyIdentifier asn1 = AuthorityKeyIdentifier.getInstance(extnValue);
    byte[] keyIdentifier = asn1.getKeyIdentifierOctets();

    if (keyIdentifier == null) {
      failureMsg.append("keyIdentifier is 'absent', but expected 'present'; ");
    } else {
      if (!Arrays.equals(issuerInfo.getSubjectKeyIdentifier(), keyIdentifier)) {
        addViolation(failureMsg, "keyIdentifier",
            Hex.encode(keyIdentifier),
            Hex.encode(issuerInfo.getSubjectKeyIdentifier()));
      }
    }
  } // method checkExtnAuthorityKeyId

  void checkExtnBasicConstraints(StringBuilder failureMsg, byte[] extnValue) {
    XijsonCertprofile certprofile = getCertprofile();
    BasicConstraints bc = BasicConstraints.getInstance(extnValue);
    CertLevel certLevel = certprofile.certLevel();
    boolean ca = CertLevel.EndEntity != certLevel;
    if (ca != bc.isCA()) {
      addViolation(failureMsg, "ca", bc.isCA(), ca);
    }

    if (!bc.isCA()) {
      return;
    }

    BigInteger tmpPathLen = bc.getPathLenConstraint();
    Integer pathLen = certprofile.extensions().pathLen();
    if (pathLen == null) {
      if (tmpPathLen != null) {
        addViolation(failureMsg, "pathLen", tmpPathLen, "absent");
      }
    } else {
      if (tmpPathLen == null) {
        addViolation(failureMsg, "pathLen", "null", pathLen);
      } else if (!BigInteger.valueOf(pathLen).equals(tmpPathLen)) {
        addViolation(failureMsg, "pathLen", tmpPathLen, pathLen);
      }
    }
  } // method checkExtnBasicConstraints

  void checkExtnCertificatePolicies(
      StringBuilder failureMsg, byte[] extnValue,
      Extensions requestedExtns, ExtensionControl extnControl) {
    CertificatePolicies certificatePolicies = caller.getCertificatePolicies();
    if (certificatePolicies == null) {
      caller.checkConstantExtnValue(OIDs.Extn.certificatePolicies, failureMsg,
          extnValue, requestedExtns, extnControl);
      return;
    }

    Map<String, CertificatePolicies.CertificatePolicyInformationType>
        expPoliciesMap = new HashMap<>();

    for (CertificatePolicies.CertificatePolicyInformationType cp
        : caller.getCertificatePolicies().certificatePolicyInformations()) {
      expPoliciesMap.put(cp.policyIdentifier().oid().getId(), cp);
    }

    Set<String> expPolicyIds = new HashSet<>(expPoliciesMap.keySet());

    org.bouncycastle.asn1.x509.CertificatePolicies asn1 =
        org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(extnValue);
    PolicyInformation[] isPolicyInformations = asn1.getPolicyInformation();

    for (PolicyInformation isPolicyInformation : isPolicyInformations) {
      String isPolicyId = isPolicyInformation.getPolicyIdentifier().getId();
      expPolicyIds.remove(isPolicyId);
      CertificatePolicies.CertificatePolicyInformationType expCp =
          expPoliciesMap.get(isPolicyId);
      if (expCp == null) {
        failureMsg.append("certificate policy '").append(isPolicyId)
            .append("' is not expected; ");
        continue;
      }

      List<CertificatePolicies.PolicyQualifier> expCpPq =
          expCp.policyQualifiers();
      if (CollectionUtil.isEmpty(expCpPq)) {
        continue;
      }

      ASN1Sequence isPolicyQualifiers =
          isPolicyInformation.getPolicyQualifiers();
      List<String> isCpsUris = new LinkedList<>();
      List<String> isUserNotices = new LinkedList<>();

      int size = isPolicyQualifiers.size();
      for (int i = 0; i < size; i++) {
        PolicyQualifierInfo isPolicyQualifierInfo =
            PolicyQualifierInfo.getInstance(isPolicyQualifiers.getObjectAt(i));

        ASN1ObjectIdentifier isPolicyQualifierId =
            isPolicyQualifierInfo.getPolicyQualifierId();
        ASN1Encodable isQualifier = isPolicyQualifierInfo.getQualifier();
        if (PolicyQualifierId.id_qt_cps.equals(isPolicyQualifierId)) {
          String isCpsUri = ASN1IA5String.getInstance(isQualifier).getString();
          isCpsUris.add(isCpsUri);
        } else if (PolicyQualifierId.id_qt_unotice.equals(
            isPolicyQualifierId)) {
          UserNotice isUserNotice = UserNotice.getInstance(isQualifier);
          if (isUserNotice.getExplicitText() != null) {
            isUserNotices.add(isUserNotice.getExplicitText().getString());
          }
        }
      }

      for (CertificatePolicies.PolicyQualifier qualifierInfo : expCpPq) {
        String value = qualifierInfo.value();
        switch (qualifierInfo.type()) {
          case cpsUri:
            if (!isCpsUris.contains(value)) {
              failureMsg.append("CPSUri '").append(value)
                  .append("' is absent but is required; ");
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
      StringBuilder failureMsg, byte[] extnValue, IssuerInfo issuerInfo) {
    checkExtnCrlDistributionPoints(true, failureMsg,
        extnValue, issuerInfo);
  }

  void checkExtnCrlDistributionPoints(
      StringBuilder failureMsg, byte[] extnValue, IssuerInfo issuerInfo) {
    checkExtnCrlDistributionPoints(false, failureMsg,
        extnValue, issuerInfo);
  }

  private void checkExtnCrlDistributionPoints(
      boolean deltaCrl, StringBuilder failureMsg, byte[] extnValue,
      IssuerInfo issuerInfo) {
    CRLDistPoint isCrlDistPoints = CRLDistPoint.getInstance(extnValue);
    DistributionPoint[] isDistributionPoints =
        isCrlDistPoints.getDistributionPoints();

    String type = deltaCrl ? "deltaCRL" : "CRL";

    if (isDistributionPoints == null) {
      addViolation(failureMsg, "size of DistributionPoints of " + type, 0, 1);
      return;
    } else {
      int len = isDistributionPoints.length;
      if (len != 1) {
        addViolation(failureMsg, "size of DistributionPoints of " + type,
            len, 1);
        return;
      }
    }

    Set<String> isCrlUrls = new HashSet<>();
    for (DistributionPoint entry : isDistributionPoints) {
      int asn1Type = entry.getDistributionPoint().getType();
      if (asn1Type != DistributionPointName.FULL_NAME) {
        addViolation(failureMsg,
            "tag of DistributionPointName of CRLDistributionPoints of " + type,
            asn1Type, DistributionPointName.FULL_NAME);
        continue;
      }

      GeneralNames isDistributionPointNames =
          GeneralNames.getInstance(entry.getDistributionPoint().getName());
      GeneralName[] names = isDistributionPointNames.getNames();

      for (GeneralName name : names) {
        if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
          addViolation(failureMsg, "tag of URL of " + type, name.getTagNo(),
              GeneralName.uniformResourceIdentifier);
        } else {
          String uri = ((ASN1String) name.getName()).getString();
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
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns,
      ExtensionControl extnControl) {
    Set<String> isUsages = new HashSet<>();
    org.bouncycastle.asn1.x509.ExtendedKeyUsage keyusage =
        org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extnValue);
    KeyPurposeId[] usages = keyusage.getUsages();
    if (usages != null) {
      for (KeyPurposeId usage : usages) {
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
    if (requestedExtns != null
        && extnControl.isPermittedInRequest()
        && CollectionUtil.isNotEmpty(optionalExtKeyusage)) {
      Extension extension =
          requestedExtns.getExtension(OIDs.Extn.extendedKeyUsage);

      if (extension != null) {
        org.bouncycastle.asn1.x509.ExtendedKeyUsage reqKeyUsage =
            org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(
                extension.getParsedValue());
        for (ExtKeyUsageControl k : optionalExtKeyusage) {
          if (reqKeyUsage.hasKeyPurposeId(
              KeyPurposeId.getInstance(k.extKeyUsage()))) {
            expectedUsages.add(k.extKeyUsage().getId());
          }
        }
      }
    }

    if (CollectionUtil.isEmpty(expectedUsages)) {
      byte[] constantExtValue =
          caller.getConstantExtensionValue(OIDs.Extn.extendedKeyUsage);
      if (constantExtValue != null) {
        expectedUsages = getExtKeyUsage(constantExtValue);
      }
    }

    Set<String> diffs = CheckerUtil.elementInBnotInA(expectedUsages, isUsages);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs)
          .append(" are present but not expected; ");
    }

    diffs = CheckerUtil.elementInBnotInA(isUsages, expectedUsages);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs)
          .append(" are absent but are required; ");
    }
  } // method checkExtnExtendedKeyUsage

  void checkExtnInhibitAnyPolicy(
      StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    InhibitAnyPolicy conf = caller.getInhibitAnyPolicy();
    if (conf == null) {
      caller.checkConstantExtnValue(OIDs.Extn.inhibitAnyPolicy, failureMsg,
          extensionValue, requestedExtns, extControl);
      return;
    }

    ASN1Integer asn1Int = ASN1Integer.getInstance(extensionValue);
    int isSkipCerts = asn1Int.getPositiveValue().intValue();
    if (isSkipCerts != conf.skipCerts()) {
      addViolation(failureMsg, "skipCerts", isSkipCerts, conf.skipCerts());
    }
  } // method checkExtnInhibitAnyPolicy

  void checkExtnIssuerAltNames(
      StringBuilder failureMsg, byte[] extensionValue, IssuerInfo issuerInfo) {
    byte[] caSubjectAltExtensionValue =
        issuerInfo.getCert().getExtensionCoreValue(
            OIDs.Extn.subjectAlternativeName);
    if (caSubjectAltExtensionValue == null) {
      failureMsg.append(
          "issuerAlternativeName is present but expected 'none'; ");
      return;
    }

    if (!Arrays.equals(caSubjectAltExtensionValue, extensionValue)) {
      addViolation(failureMsg, "issuerAltNames",
          Hex.encode(extensionValue), Hex.encode(caSubjectAltExtensionValue));
    }
  } // method checkExtnIssuerAltNames

  void checkExtnKeyUsage(
      StringBuilder failureMsg, boolean[] usages, Extensions requestedExtns,
      ExtensionControl extnControl, KeySpec keySpec) {
    int len = usages.length;

    if (len > 9) {
      failureMsg
          .append("invalid syntax: size of valid bits is larger than 9: ")
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
      Extension extension = requestedExtns.getExtension(OIDs.Extn.keyUsage);
      if (extension != null) {
        org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
            org.bouncycastle.asn1.x509.KeyUsage.getInstance(
                extension.getParsedValue());
        for (KeySingleUsage k : optionalKeyusage) {
          if (reqKeyUsage.hasUsages(k.keyUsage().bcUsage())) {
            expectedUsages.add(k.keyUsage().getName());
          }
        }
      }
    }

    if (CollectionUtil.isEmpty(expectedUsages)) {
      byte[] constantExtValue =
          caller.getConstantExtensionValue(OIDs.Extn.keyUsage);
      if (constantExtValue != null) {
        expectedUsages = getKeyUsage(constantExtValue);
      }
    }

    Set<String> diffs = CheckerUtil.elementInBnotInA(expectedUsages, isUsages);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs)
          .append(" are present but not expected; ");
    }

    diffs = CheckerUtil.elementInBnotInA(isUsages, expectedUsages);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs)
          .append(" are absent but are required; ");
    }
  } // method checkExtnKeyUsage

  Set<KeySingleUsage> getKeyusage(boolean required, KeySpec keySpec) {
    Set<KeySingleUsage> ret = new HashSet<>();

    Set<KeySingleUsage> controls =
        getCertprofile().extensions().getKeyUsage(keySpec);
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
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns,
      ExtensionControl extnControl) {
    NameConstraints nameConstraints = caller.getNameConstraints();

    if (nameConstraints == null) {
      caller.checkConstantExtnValue(OIDs.Extn.nameConstraints,
          failureMsg, extnValue, requestedExtns, extnControl);
      return;
    }

    org.bouncycastle.asn1.x509.NameConstraints tmpNameConstraints =
        org.bouncycastle.asn1.x509.NameConstraints.getInstance(extnValue);

    checkExtnNameConstraintsSubtrees(failureMsg, "PermittedSubtrees",
        tmpNameConstraints.getPermittedSubtrees(),
        nameConstraints.permittedSubtrees());
    checkExtnNameConstraintsSubtrees(failureMsg, "ExcludedSubtrees",
        tmpNameConstraints.getExcludedSubtrees(),
        nameConstraints.excludedSubtrees());
  } // method checkExtnNameConstraints

  private void checkExtnNameConstraintsSubtrees(
      StringBuilder failureMsg, String description, GeneralSubtree[] subtrees,
      List<GeneralSubtreeType> expectedSubtrees) {
    int isSize = (subtrees == null) ? 0 : subtrees.length;
    int expSize = (expectedSubtrees == null) ? 0 : expectedSubtrees.size();
    if (isSize != expSize) {
      addViolation(failureMsg, "size of " + description, isSize, expSize);
      return;
    }

    if (subtrees == null || expectedSubtrees == null) {
      return;
    }

    for (int i = 0; i < isSize; i++) {
      GeneralSubtree isSubtree = subtrees[i];
      GeneralSubtreeType expSubtree = expectedSubtrees.get(i);
      String desc = description + " [" + i + "]";

      GeneralName isBase = isSubtree.getBase();

      GeneralName expBase;
      if (expSubtree.directoryName() != null) {
        expBase = new GeneralName(X509Util.reverse(
            new X500Name(expSubtree.directoryName())));
      } else if (expSubtree.dnsName() != null) {
        expBase = new GeneralName(GeneralName.dNSName,
            expSubtree.dnsName());
      } else if (expSubtree.ipAddress() != null) {
        expBase = new GeneralName(GeneralName.iPAddress,
            expSubtree.ipAddress());
      } else if (expSubtree.rfc822Name() != null) {
        expBase = new GeneralName(GeneralName.rfc822Name,
            expSubtree.rfc822Name());
      } else if (expSubtree.uri() != null) {
        expBase = new GeneralName(GeneralName.uniformResourceIdentifier,
            expSubtree.uri());
      } else {
        throw new IllegalStateException(
            "should not reach here, unknown child of GeneralName");
      }

      if (!isBase.equals(expBase)) {
        addViolation(failureMsg, "base of " + desc, isBase, expBase);
      }
    }
  } // method checkExtnNameConstraintsSubtrees

  void checkExtnOcspNocheck(StringBuilder failureMsg, byte[] extnValue) {
    if (!Arrays.equals(DER_NULL, extnValue)) {
      failureMsg.append("value is not DER NULL; ");
    }
  }

  void checkExtnPolicyConstraints(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns,
      ExtensionControl extnControl) {
    PolicyConstraints conf = caller.getPolicyConstraints();
    if (conf == null) {
      caller.checkConstantExtnValue(OIDs.Extn.policyConstraints,
          failureMsg, extnValue, requestedExtns, extnControl);
      return;
    }

    org.bouncycastle.asn1.x509.PolicyConstraints isPolicyConstraints =
        org.bouncycastle.asn1.x509.PolicyConstraints.getInstance(extnValue);
    Integer expRequireExplicitPolicy = conf.requireExplicitPolicy();
    BigInteger bigInt = isPolicyConstraints.getRequireExplicitPolicyMapping();
    Integer isRequireExplicitPolicy = (bigInt == null) ? null
        : bigInt.intValue();

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
    bigInt = isPolicyConstraints.getInhibitPolicyMapping();
    Integer isInhibitPolicyMapping = (bigInt == null) ? null
        : bigInt.intValue();

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
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns,
      ExtensionControl extnControl) {
    PolicyMappings conf = caller.getPolicyMappings();
    if (conf == null) {
      caller.checkConstantExtnValue(OIDs.Extn.policyMappings, failureMsg,
          extnValue, requestedExtns, extnControl);
      return;
    }

    ASN1Sequence isPolicyMappings = DERSequence.getInstance(extnValue);
    Map<String, String> isMap = new HashMap<>();
    int size = isPolicyMappings.size();
    for (int i = 0; i < size; i++) {
      ASN1Sequence seq = ASN1Sequence.getInstance(
          isPolicyMappings.getObjectAt(i));
      CertPolicyId issuerDomainPolicy = CertPolicyId.getInstance(
          seq.getObjectAt(0));
      CertPolicyId subjectDomainPolicy = CertPolicyId.getInstance(
          seq.getObjectAt(1));
      isMap.put(issuerDomainPolicy.getId(), subjectDomainPolicy.getId());
    }

    for (PolicyMappings.PolicyIdMappingType m : conf.mappings()) {
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

  void checkSmimeCapabilities(StringBuilder failureMsg, byte[] extnValue) {
    byte[] expected = caller.getSmimeCapabilities().getValue();
    if (!Arrays.equals(expected, extnValue)) {
      addViolation(failureMsg, "extension valus",
          Hex.encode(extnValue), Hex.encode(expected));
    }
  } // method checkSmimeCapabilities

  void checkScts(StringBuilder failureMsg, byte[] extensionValue) {
    // just check the syntax
    try {
      ASN1OctetString octet = DEROctetString.getInstance(extensionValue);
      CtLog.SignedCertificateTimestampList sctList =
          CtLog.SignedCertificateTimestampList.getInstance(octet.getOctets());
      int size = sctList.sctList().size();
      for (int i = 0; i < size; i++) {
        CtLog.getSignatureObject(
            sctList.sctList().get(i).digitallySigned());
      }
    } catch (Exception ex) {
      failureMsg.append("invalid syntax: ").append(ex.getMessage())
          .append("; ");
    }
  } // method checkScts

  void checkExtnPrivateKeyUsagePeriod(
      StringBuilder failureMsg, byte[] extnValue,
      Date certNotBefore, Date certNotAfter) {
    ASN1GeneralizedTime notBefore = new ASN1GeneralizedTime(certNotBefore);
    Date dateNotAfter;
    Validity privateKeyUsagePeriod =
        getCertprofile().extensions().privateKeyUsagePeriod();
    if (privateKeyUsagePeriod == null) {
      dateNotAfter = certNotAfter;
    } else {
      dateNotAfter = Date.from(
          privateKeyUsagePeriod.add(certNotBefore.toInstant()));

      if (dateNotAfter.after(certNotAfter)) {
        dateNotAfter = certNotAfter;
      }
    }
    ASN1GeneralizedTime notAfter = new ASN1GeneralizedTime(dateNotAfter);

    org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod extValue =
        org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod.getInstance(extnValue);

    ASN1GeneralizedTime time = extValue.getNotBefore();
    if (time == null) {
      failureMsg.append("notBefore is absent but expected present; ");
    } else if (!time.equals(notBefore)) {
      addViolation(failureMsg, "notBefore", time.getTimeString(),
          notBefore.getTimeString());
    }

    time = extValue.getNotAfter();
    if (time == null) {
      failureMsg.append("notAfter is absent but expected present; ");
    } else if (!time.equals(notAfter)) {
      addViolation(failureMsg, "notAfter", time.getTimeString(),
          notAfter.getTimeString());
    }
  } // method checkExtnPrivateKeyUsagePeriod

  void checkExtnQcStatements(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns,
      ExtensionControl extnControl) {
    QcStatements qcStatements = caller.getQcStatements();
    if (qcStatements == null) {
      caller.checkConstantExtnValue(OIDs.Extn.qCStatements, failureMsg,
          extnValue, requestedExtns, extnControl);
      return;
    }

    final int expSize = qcStatements.qcStatements().size();
    ASN1Sequence extValue = ASN1Sequence.getInstance(extnValue);
    final int isSize = extValue.size();
    if (isSize != expSize) {
      addViolation(failureMsg, "number of statements", isSize, expSize);
      return;
    }

    // extract the euLimit and pdsLocations data from request
    Map<String, int[]> reqQcEuLimits = new HashMap<>();
    Extension reqExtension = (requestedExtns == null) ? null
        : requestedExtns.getExtension(OIDs.Extn.qCStatements);
    if (reqExtension != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(
          reqExtension.getParsedValue());

      final int n = seq.size();
      for (int j = 0; j < n; j++) {
        QCStatement stmt = QCStatement.getInstance(seq.getObjectAt(j));
        if (OIDs.QCS.id_etsi_qcs_QcLimitValue.equals(stmt.getStatementId())) {
          MonetaryValue monetaryValue =
              MonetaryValue.getInstance(stmt.getStatementInfo());
          int amount = monetaryValue.getAmount().intValue();
          int exponent = monetaryValue.getExponent().intValue();
          Iso4217CurrencyCode currency = monetaryValue.getCurrency();
          String currencyS = currency.isAlphabetic()
              ? currency.getAlphabetic().toUpperCase()
              : Integer.toString(currency.getNumeric());
          reqQcEuLimits.put(currencyS, new int[]{amount, exponent});
        }
      }
    }

    for (int i = 0; i < expSize; i++) {
      QCStatement is = QCStatement.getInstance(extValue.getObjectAt(i));
      QcStatements.QcStatementType exp = qcStatements.qcStatements().get(i);
      if (!is.getStatementId().equals(exp.statementId().oid())) {
        addViolation(failureMsg, "statmentId[" + i + "]",
            is.getStatementId().getId(), exp.statementId().oid());
        continue;
      }

      if (exp.statementValue() == null) {
        if (is.getStatementInfo() != null) {
          addViolation(failureMsg, "statmentInfo[" + i + "]",
              "present", "absent");
        }
        continue;
      }

      if (is.getStatementInfo() == null) {
        addViolation(failureMsg, "statmentInfo[" + i + "]",
            "absent", "present");
        continue;
      }

      QcStatements.QcStatementValueType expStatementValue =
          exp.statementValue();

      try {
        if (expStatementValue.constant() != null) {
          byte[] expValue = expStatementValue.constant().toASN1()
              .toASN1Primitive().getEncoded();
          byte[] isValue = is.getStatementInfo().toASN1Primitive().getEncoded();

          if (!Arrays.equals(isValue, expValue)) {
            addViolation(failureMsg, "statementInfo[" + i + "]",
                Hex.encode(isValue), Hex.encode(expValue));
          }
        } else if (expStatementValue.qcRetentionPeriod() != null) {
          String isValue = ASN1Integer.getInstance(
              is.getStatementInfo()).toString();

          String expValue = expStatementValue.qcRetentionPeriod().toString();
          if (!isValue.equals(expValue)) {
            addViolation(failureMsg, "statementInfo[" + i + "]",
                isValue, expValue);
          }
        } else if (expStatementValue.pdsLocations() != null) {
          Set<String> pdsLocations = new HashSet<>();
          ASN1Sequence pdsLocsSeq =
              ASN1Sequence.getInstance(is.getStatementInfo());

          int size = pdsLocsSeq.size();
          for (int k = 0; k < size; k++) {
            ASN1Sequence pdsLocSeq =
                ASN1Sequence.getInstance(pdsLocsSeq.getObjectAt(k));

            int size2 = pdsLocSeq.size();
            if (size2 != 2) {
              throw new IllegalArgumentException(
                  "sequence size is " + size2 + " but expected 2");
            }
            String url = ASN1IA5String.getInstance(
                pdsLocSeq.getObjectAt(0)).getString();

            String lang = ASN1PrintableString.getInstance(
                pdsLocSeq.getObjectAt(1)).getString();

            pdsLocations.add("url=" + url + ",lang=" + lang);
          }

          Set<String> expectedPdsLocations = new HashSet<>();
          for (QcStatements.PdsLocationType m
              : expStatementValue.pdsLocations()) {
            expectedPdsLocations.add("url=" + m.url() +
                ",lang=" + m.language());
          }

          Set<String> diffs = CheckerUtil.elementInBnotInA(
              expectedPdsLocations, pdsLocations);

          if (CollectionUtil.isNotEmpty(diffs)) {
            failureMsg.append("statementInfo[").append(i).append("]: ")
                .append(diffs).append(" are present but not expected; ");
          }

          diffs = CheckerUtil.elementInBnotInA(
              pdsLocations, expectedPdsLocations);
          if (CollectionUtil.isNotEmpty(diffs)) {
            failureMsg.append("statementInfo[").append(i).append("]: ")
                .append(diffs).append(" are absent but are required; ");
          }
        } else if (expStatementValue.qcEuLimitValue() != null) {
          QcStatements.QcEuLimitValueType euLimitConf =
              expStatementValue.qcEuLimitValue();
          String expCurrency = euLimitConf.currency().toUpperCase();
          int[] expAmountExp = reqQcEuLimits.get(expCurrency);

          QcStatements.Range2Type range = euLimitConf.amount();
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

          MonetaryValue monterayValue =
              MonetaryValue.getInstance(is.getStatementInfo());
          Iso4217CurrencyCode currency = monterayValue.getCurrency();
          String isCurrency = currency.isAlphabetic()
              ? currency.getAlphabetic()
              : Integer.toString(currency.getNumeric());
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
          throw new IllegalStateException("statementInfo[" + i +
              "]should not reach here");
        }
      } catch (IOException ex) {
        failureMsg.append("statementInfo[").append(i)
            .append("] has incorrect syntax; ");
      }
    }
  } // method checkExtnQcStatements

  void checkExtnSubjectAltNames(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns,
      X500Name requestedSubject) {
    XijsonCertprofile certprofile = getCertprofile();
    Set<GeneralNameTag> conf = certprofile.subjectAltNameModes();

    GeneralName[] requested;
    try {
      GeneralNames sanExtnValue = (requestedExtns == null)
          ? null
          : GeneralNames.getInstance(requestedExtns.getExtensionParsedValue(
              OIDs.Extn.subjectAlternativeName));
      GeneralNames gns = XijsonExtensions.createRequestedSubjectAltNames(
          requestedSubject, sanExtnValue, certprofile.subjectAltNameModes(),
          certprofile.extensions().subjectToSubjectAltNameModes());
      requested = (gns == null) ? new GeneralName[0] : gns.getNames();
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

    GeneralName[] is = GeneralNames.getInstance(extnValue).getNames();

    GeneralName[] expected = new GeneralName[requested.length];
    for (int i = 0; i < is.length; i++) {
      try {
        expected[i] = createGeneralName(is[i], conf);
      } catch (BadCertTemplateException ex) {
        failureMsg.append("could not process ").append(i + 1)
            .append("-th name: ").append(ex.getMessage()).append("; ");
        return;
      }
    }

    if (is.length != expected.length) {
      addViolation(failureMsg, "size of GeneralNames",
          is.length, expected.length);
      return;
    }

    for (int i = 0; i < is.length; i++) {
      if (!is[i].equals(expected[i])) {
        failureMsg.append(i + 1)
            .append("-th name does not match the requested one; ");
      }
    }
  } // method checkExtnSubjectAltNames

  void checkExtnSubjectInfoAccess(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns) {
    Map<ASN1ObjectIdentifier, Set<GeneralNameTag>> conf
        = getCertprofile().subjectInfoAccessModes();
    if (conf == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    ASN1Encodable requestExtValue = null;
    if (requestedExtns != null) {
      requestExtValue = requestedExtns.getExtensionParsedValue(
          OIDs.Extn.subjectInfoAccess);
    }
    if (requestExtValue == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    ASN1Sequence requestSeq = ASN1Sequence.getInstance(requestExtValue);
    ASN1Sequence certSeq = ASN1Sequence.getInstance(extnValue);

    int size = requestSeq.size();

    if (certSeq.size() != size) {
      addViolation(failureMsg, "size of GeneralNames",
          certSeq.size(), size);
      return;
    }

    for (int i = 0; i < size; i++) {
      AccessDescription ad = AccessDescription.getInstance(
          requestSeq.getObjectAt(i));
      ASN1ObjectIdentifier accessMethod = ad.getAccessMethod();
      Set<GeneralNameTag> generalNameModes = conf.get(accessMethod);

      if (generalNameModes == null) {
        failureMsg.append("accessMethod in requestedExtension ")
            .append(accessMethod.getId()).append(" is not allowed; ");
        continue;
      }

      AccessDescription certAccessDesc =
          AccessDescription.getInstance(certSeq.getObjectAt(i));
      ASN1ObjectIdentifier certAccessMethod = certAccessDesc.getAccessMethod();

      boolean bo = Objects.equals(accessMethod, certAccessMethod);

      if (!bo) {
        addViolation(failureMsg, "accessMethod",
            (certAccessMethod == null) ? "null" : certAccessMethod.getId(),
            (accessMethod == null) ? "null" : accessMethod.getId());
        continue;
      }

      GeneralName accessLocation;
      try {
        accessLocation = createGeneralName(ad.getAccessLocation(),
            generalNameModes);
      } catch (BadCertTemplateException ex) {
        failureMsg.append("invalid requestedExtension: ")
            .append(ex.getMessage()).append("; ");
        continue;
      }

      GeneralName certAccessLocation = certAccessDesc.getAccessLocation();
      if (!certAccessLocation.equals(accessLocation)) {
        failureMsg.append("accessLocation does not match the requested one; ");
      }
    }
  } // method checkExtnSUbjectInfoAccess

  void checkExtnSubjectKeyIdentifier(
      StringBuilder failureMsg, byte[] extnValue,
      SubjectPublicKeyInfo subjectPublicKeyInfo) {
    // subjectKeyIdentifier
    SubjectKeyIdentifier asn1 = SubjectKeyIdentifier.getInstance(extnValue);
    byte[] ski = asn1.getKeyIdentifier();

    byte[] expectedSki;
    try {
      expectedSki = getCertprofile().subjectKeyIdentifier(
          subjectPublicKeyInfo);
    } catch (CertprofileException e) {
      failureMsg.append("error computing expected SubjectKeyIdentifier");
      return;
    }

    if (!Arrays.equals(expectedSki, ski)) {
      addViolation(failureMsg, "SKI", Hex.encode(ski),
          Hex.encode(expectedSki));
    }
  } // method checkExtnSubjectKeyIdentifier

  void checkExtnTlsFeature(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns,
      ExtensionControl extnControl) {
    TlsFeature tlsFeature = caller.getTlsFeature();
    if (tlsFeature == null) {
      caller.checkConstantExtnValue(OIDs.Extn.id_pe_tlsfeature,
          failureMsg, extnValue, requestedExtns, extnControl);
      return;
    }

    Set<Integer> isFeatures = new HashSet<>();
    ASN1Sequence seq = ASN1Sequence.getInstance(extnValue);
    final int n = seq.size();
    for (int i = 0; i < n; i++) {
      ASN1Integer asn1Feature = ASN1Integer.getInstance(seq.getObjectAt(i));
      isFeatures.add(asn1Feature.intValueExact());
    }

    Set<Integer> expFeatures = new HashSet<>(tlsFeature.features());

    Set<Integer> diffs = CheckerUtil.elementInBnotInA(expFeatures, isFeatures);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("features ").append(diffs)
          .append(" are present but not expected; ");
    }

    diffs = CheckerUtil.elementInBnotInA(isFeatures, expFeatures);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("features ").append(diffs)
          .append(" are absent but are required; ");
    }
  } // method checkExtnTlsFeature

  static Set<String> getKeyUsage(byte[] extensionValue) {
    Set<String> usages = new HashSet<>();
    org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
        org.bouncycastle.asn1.x509.KeyUsage.getInstance(extensionValue);
    for (KeyUsage k : KeyUsage.values()) {
      if (reqKeyUsage.hasUsages(k.bcUsage())) {
        usages.add(k.getName());
      }
    }

    return usages;
  } // method getKeyUsage

  static Set<String> getExtKeyUsage(byte[] extensionValue) {
    Set<String> usages = new HashSet<>();
    org.bouncycastle.asn1.x509.ExtendedKeyUsage reqKeyUsage =
        org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extensionValue);
    for (KeyPurposeId usage : reqKeyUsage.getUsages()) {
      usages.add(usage.getId());
    }
    return usages;
  } // method getExtKeyUsage

  static void checkAia(
      StringBuilder failureMsg, AuthorityInformationAccess aia,
      ASN1ObjectIdentifier accessMethod, Set<String> expectedUris) {
    String typeDesc;
    if (OIDs.X509.id_ad_ocsp.equals(accessMethod)) {
      typeDesc = "OCSP";
    } else if (OIDs.X509.id_ad_caIssuers.equals(accessMethod)) {
      typeDesc = "caIssuer";
    } else {
      typeDesc = accessMethod.getId();
    }

    List<AccessDescription> isAccessDescriptions = new LinkedList<>();
    for (AccessDescription accessDescription : aia.getAccessDescriptions()) {
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
      if (isAccessLocation.getTagNo() !=
          GeneralName.uniformResourceIdentifier) {
        CheckerUtil.addViolation(failureMsg, "tag of accessLocation of AIA ",
            isAccessLocation.getTagNo(), GeneralName.uniformResourceIdentifier);
      } else {
        String isOcspUri =
            ((ASN1String) isAccessLocation.getName()).getString();
        isUris.add(isOcspUri);
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
      GeneralName reqName, Set<GeneralNameTag> modes)
      throws BadCertTemplateException {
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
        throw new BadCertTemplateException(
            "generalName tag " + tag + " is not allowed");
      }
    }

    switch (tag) {
      case GeneralName.rfc822Name:
      case GeneralName.dNSName:
      case GeneralName.uniformResourceIdentifier:
      case GeneralName.iPAddress:
      case GeneralName.registeredID:
      case GeneralName.directoryName:
        return new GeneralName(tag, reqName.getName());
      case GeneralName.otherName: {
        ASN1Sequence reqSeq = ASN1Sequence.getInstance(reqName.getName());
        ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(
            reqSeq.getObjectAt(0));

        ASN1Encodable value = ASN1TaggedObject.getInstance(
            reqSeq.getObjectAt(1)).getBaseObject();

        String text;
        if (!(value instanceof ASN1String)) {
          throw new BadCertTemplateException("otherName.value is not a String");
        } else {
          text = ((ASN1String) value).getString();
        }

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(type);
        vector.add(new DERTaggedObject(true, 0, new DERUTF8String(text)));

        return new GeneralName(GeneralName.otherName, new DERSequence(vector));
      }
      case GeneralName.ediPartyName: {
        ASN1Sequence reqSeq = ASN1Sequence.getInstance(reqName.getName());

        int size = reqSeq.size();
        String nameAssigner = null;
        int idx = 0;
        if (size > 1) {
          DirectoryString ds = DirectoryString.getInstance(
              ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx++))
                  .getBaseObject());
          nameAssigner = ds.getString();
        }

        DirectoryString ds = DirectoryString.getInstance(
            ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx))
                .getBaseObject());
        String partyName = ds.getString();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (nameAssigner != null) {
          vector.add(new DERTaggedObject(false, 0,
              new DirectoryString(nameAssigner)));
        }
        vector.add(new DERTaggedObject(false, 1,
            new DirectoryString(partyName)));
        return new GeneralName(GeneralName.ediPartyName,
            new DERSequence(vector));
      }
      default:
        throw new IllegalStateException(
            "should not reach here, unknown GeneralName tag " + tag);
    } // end switch
  } // method createGeneralName

}
