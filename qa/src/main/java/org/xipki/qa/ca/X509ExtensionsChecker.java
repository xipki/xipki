// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.pkix.asn1.ccc.SimpleExtensionSchema;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.OIDs;
import org.xipki.pkix.asn1.smime.SMIMECapabilities;
import org.xipki.pkix.asn1.smime.SMIMECapability;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.Extensions;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ctrl.ExtKeyUsageControl;
import org.xipki.ca.api.profile.ctrl.ExtensionControl;
import org.xipki.ca.api.profile.ctrl.ExtensionsControl;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.ExtensionValueConf;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.qa.CheckerUtil;
import org.xipki.qa.ValidationIssue;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.ca.api.CertprofileException;
import org.xipki.pkix.util.misc.CollectionUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * X509 Extensions Checker.
 *
 * @author Lijun Liao (xipki)
 */
public class X509ExtensionsChecker {

  private static final Logger LOG = LoggerFactory.getLogger(X509ExtensionsChecker.class);

  private ExtensionValueConf.CertificatePolicies certificatePolicies;

  private ExtensionValueConf.PolicyMappings policyMappings;

  private ExtensionValueConf.NameConstraints nameConstraints;

  private ExtensionValueConf.PolicyConstraints policyConstraints;

  private ExtensionValueConf.InhibitAnyPolicy inhibitAnyPolicy;

  private ExtensionValueConf.QcStatements qcStatements;

  private ExtensionValueConf.TlsFeature tlsFeature;

  private QaExtensionValue smimeCapabilities;

  private ExtensionValueConf.MicrosoftCertificateTemplateName microsoftCertificateTemplateName;

  private ExtensionValueConf.MicrosoftCertificateTemplateInformation
      microsoftCertificateTemplateInformation;

  private Asn1Oid cccExtensionSchemaType;

  private byte[] cccExtensionSchemaValue;

  private final Map<Asn1Oid, QaExtensionValue> constantExtensions;

  private final XijsonCertprofile certprofile;

  private final X509ExtensionChecker extnChecker;

  public X509ExtensionsChecker(XijsonCertprofileType conf, XijsonCertprofile certprofile)
      throws CertprofileException {
    this.certprofile = Args.notNull(certprofile, "certprofile");

    // Extensions
    Map<String, ExtensionType> extensions = Args.notNull(conf, "conf").buildExtensions();

    // Extension controls
    ExtensionsControl extensionControls = certprofile.extensionsControl();

    // Certificate Policies
    Asn1Oid type = ExtensionID.certificatePolicies.oid();
    if (extensionControls.containsID(type)) {
      this.certificatePolicies = extensions.get(type.getId()).certificatePolicies();
    }

    // Policy Mappings
    type = ExtensionID.policyMappings.oid();
    if (extensionControls.containsID(type)) {
      this.policyMappings = extensions.get(type.getId()).policyMappings();
    }

    // Name Constraints
    type = ExtensionID.nameConstraints.oid();
    if (extensionControls.containsID(type)) {
      this.nameConstraints = extensions.get(type.getId()).nameConstraints();
    }

    // Policy Constraints
    type = ExtensionID.policyConstraints.oid();
    if (extensionControls.containsID(type)) {
      this.policyConstraints = extensions.get(type.getId()).policyConstraints();
    }

    // Inhibit anyPolicy
    type = ExtensionID.inhibitAnyPolicy.oid();
    if (extensionControls.containsID(type)) {
      this.inhibitAnyPolicy = extensions.get(type.getId()).inhibitAnyPolicy();
    }

    type = ExtensionID.qcStatements.oid();
    if (extensionControls.containsID(type)) {
      this.qcStatements = extensions.get(type.getId()).qcStatements();
    }

    // tlsFeature
    type = ExtensionID.tlsFeature.oid();
    if (extensionControls.containsID(type)) {
      this.tlsFeature = extensions.get(type.getId()).tlsFeature();
    }

    // SMIMECapabilities
    type = ExtensionID.smimeCapabilities.oid();
    if (extensionControls.containsID(type)) {
      List<ExtensionValueConf.SmimeCapability> list =
          extensions.get(type.getId()).smimeCapabilities().capabilities();

      List<SMIMECapability> vec = new LinkedList<>();
      for (ExtensionValueConf.SmimeCapability m : list) {
        Asn1Oid oid = m.capabilityId();
        Asn1Primitive params = null;
        Integer capParam = m.parameter();
        if (capParam != null) {
          params = new Asn1Integer(capParam);
        }
        SMIMECapability cap = new SMIMECapability(oid, params);
        vec.add(cap);
      }

      SMIMECapabilities extValue = new SMIMECapabilities(vec);
      smimeCapabilities = new QaExtensionValue(
          extensionControls.getControl(type).isCritical(), extValue.getEncoded());
    }

    // CCC
    initCCCExtensionSchemas(extensions);

    // Microsoft
    type = ExtensionID.microsoft_CertificateTemplateName.oid();
    if (extensionControls.containsID(type)) {
      this.microsoftCertificateTemplateName =
          extensions.get(type.getId()).microsoftCertificateTemplateName();
    }

    type = ExtensionID.microsoft_CertificateTemplateInformation.oid();
    if (extensionControls.containsID(type)) {
      this.microsoftCertificateTemplateInformation =
          extensions.get(type.getId()).microsoftCertificateTemplateInformation();
    }

    // constant extensions
    Map<Asn1Oid, ExtensionValue> constExtns = certprofile.constantExtensions();
    this.constantExtensions = new HashMap<>();
    if (constExtns != null) {
      for (Map.Entry<Asn1Oid, ExtensionValue> m : constExtns.entrySet()) {
        ExtensionValue v = m.getValue();
        byte[] encoded = v.value().getEncoded();
        QaExtensionValue value = new QaExtensionValue(v.isCritical(), encoded);
        this.constantExtensions.put(m.getKey(), value);
      }
    }

    this.extnChecker = new X509ExtensionChecker(this);
  } // constructor

  private void initCCCExtensionSchemas(Map<String, ExtensionType> extensions)
      throws CertprofileException {
    Set<String> extnIds = extensions.keySet();
    Asn1Oid type = null;
    for (String m : extnIds) {
      Asn1Oid mOid = new Asn1Oid(m);
      if (mOid.on(ExtensionOIDs.id_ccc_extn)) {
        if (type != null) {
          throw new CertprofileException(
              "Maximal one CCC Extension is allowed, but configured at least 2.");
        }
        type = mOid;
      }
    }

    if (type == null) {
      return;
    }

    ExtensionType ex = extensions.get(type.getId());
    if (!ex.isCritical()) {
      throw new CertprofileException(
          "CCC Extension must be set to critical, but configured non-critical.");
    }

    List<Asn1Oid> simpleSchemaTypes = Arrays.asList(
        ExtensionID.CCC_K_VehicleCert.oid(),
        ExtensionID.CCC_F_External_CACert.oid(),
        ExtensionID.CCC_P_VehicleOEMEncCert.oid(),
        ExtensionID.CCC_Q_VehicleOEMSigCert.oid(),
        ExtensionID.CCC_DeviceEncCert.oid(),
        ExtensionID.CCC_VehicleIntermediateCert.oid(),
        ExtensionID.CCC_J_VehicleOEMCACert.oid(),
        ExtensionID.CCC_M_VehicleOEMCACert.oid());

    if (!simpleSchemaTypes.contains(type)) {
      return;
    }

    int schemaVersion = ex.cccExtensionSchema() != null ?
        ex.cccExtensionSchema().version() : 1;

    SimpleExtensionSchema schema = new SimpleExtensionSchema(schemaVersion);
    this.cccExtensionSchemaType = type;
    this.cccExtensionSchemaValue = schema.getEncoded();
  }

  ExtensionValueConf.CertificatePolicies getCertificatePolicies() {
    return certificatePolicies;
  }

  ExtensionValueConf.PolicyMappings getPolicyMappings() {
    return policyMappings;
  }

  ExtensionValueConf.NameConstraints getNameConstraints() {
    return nameConstraints;
  }

  ExtensionValueConf.PolicyConstraints getPolicyConstraints() {
    return policyConstraints;
  }

  ExtensionValueConf.InhibitAnyPolicy getInhibitAnyPolicy() {
    return inhibitAnyPolicy;
  }

  ExtensionValueConf.QcStatements getQcStatements() {
    return qcStatements;
  }

  ExtensionValueConf.TlsFeature getTlsFeature() {
    return tlsFeature;
  }

  QaExtensionValue smimeCapabilities() {
    return smimeCapabilities;
  }

  ExtensionValueConf.MicrosoftCertificateTemplateName getMicrosoftCertificateTemplateName() {
    return microsoftCertificateTemplateName;
  }

  ExtensionValueConf.MicrosoftCertificateTemplateInformation
      getMicrosoftCertificateTemplateInformation() {
    return microsoftCertificateTemplateInformation;
  }

  XijsonCertprofile getCertprofile() {
    return certprofile;
  }

  public List<ValidationIssue> checkExtensions(
      Certificate cert, IssuerInfo issuerInfo, Extensions requestedExtns,
      X500Name requestedSubject, KeySpec keySpec) {
    Args.notNull(issuerInfo, "issuerInfo");

    List<ValidationIssue> result = new LinkedList<>();

    try {
      new X509Cert(Args.notNull(cert, "cert"));
    } catch (CodecException e) {
      ValidationIssue issue = new ValidationIssue("X509.CERT", "certificate parsing");
      result.add(issue);
      issue.setFailureMessage("could not parse certificate: " + e.getMessage());
      return result;
    }

    // detect the list of extension types in certificate
    Set<Asn1Oid> expectedExtensionTypes = getExtensionTypes(
        cert, issuerInfo, requestedExtns, requestedSubject, keySpec);

    Extensions extensions = cert.getExtensions();
    Set<Asn1Oid> certExtnOids = extensions.getExtensionIds();

    if (certExtnOids == null) {
      ValidationIssue issue = new ValidationIssue("X509.EXT.GEN", "extension general");
      result.add(issue);
      issue.setFailureMessage("no extension is present");
      return result;
    }

    List<Asn1Oid> certExtnTypes = new ArrayList<>(certExtnOids);

    for (Asn1Oid extType : expectedExtensionTypes) {
      if (!certExtnTypes.contains(extType)) {
        ValidationIssue issue = createExtensionIssue(extType);
        result.add(issue);
        issue.setFailureMessage("extension is absent but is required");
      }
    }

    ExtensionsControl extnControls = certprofile.extensionsControl();
    for (Asn1Oid oid : certExtnTypes) {
      ValidationIssue issue = createExtensionIssue(oid);
      result.add(issue);
      if (!expectedExtensionTypes.contains(oid)) {
        issue.setFailureMessage("extension is present but is not permitted");
        continue;
      }

      Extension ext = extensions.getExtension(oid);
      StringBuilder failureMsg = new StringBuilder();
      ExtensionControl extnControl = extnControls.getControl(oid);

      if (extnControl.isCritical() != ext.isCritical()) {
        CheckerUtil.addViolation(failureMsg, "critical",
            ext.isCritical(), extnControl.isCritical());
      }

      try {
        if (ExtensionID.authorityKeyIdentifier.oid().equals(oid)) {
          extnChecker.checkExtnAuthorityKeyId(failureMsg, ext, issuerInfo);
        } else if (ExtensionID.subjectKeyIdentifier.oid().equals(oid)) {
          extnChecker.checkExtnSubjectKeyIdentifier(failureMsg, ext,
              cert.getSubjectPublicKeyInfo());
        } else if (ExtensionID.keyUsage.oid().equals(oid)) {
          extnChecker.checkExtnKeyUsage(failureMsg, ext, requestedExtns, extnControl, keySpec);
        } else if (ExtensionID.certificatePolicies.oid().equals(oid)) {
          extnChecker.checkExtnCertificatePolicies(failureMsg, ext, requestedExtns, extnControl);
        } else if (ExtensionID.policyMappings.oid().equals(oid)) {
          extnChecker.checkExtnPolicyMappings(failureMsg, ext, requestedExtns, extnControl);
        } else if (ExtensionID.subjectAlternativeName.oid().equals(oid)) {
          extnChecker.checkExtnSubjectAltNames(failureMsg, ext, requestedExtns, requestedSubject);
        } else if (ExtensionID.subjectDirectoryAttributes.oid().equals(oid)) {
          extnChecker.checkExtnSubjectDirectoryAttributes(failureMsg, ext, requestedExtns);
        } else if (ExtensionID.issuerAltName.oid().equals(oid)) {
          extnChecker.checkExtnIssuerAltNames(failureMsg, ext, issuerInfo);
        } else if (ExtensionID.basicConstraints.oid().equals(oid)) {
          extnChecker.checkExtnBasicConstraints(failureMsg, ext);
        } else if (ExtensionID.nameConstraints.oid().equals(oid)) {
          extnChecker.checkExtnNameConstraints(failureMsg, ext, requestedExtns, extnControl);
        } else if (ExtensionID.policyConstraints.oid().equals(oid)) {
          extnChecker.checkExtnPolicyConstraints(failureMsg, ext, requestedExtns, extnControl);
        } else if (ExtensionID.extendedKeyUsage.oid().equals(oid)) {
          extnChecker.checkExtnExtendedKeyUsage(failureMsg, ext, requestedExtns, extnControl);
        } else if (ExtensionID.crlDistributionPoints.oid().equals(oid)) {
          extnChecker.checkExtnCrlDistributionPoints(failureMsg, ext, issuerInfo);
        } else if (ExtensionID.inhibitAnyPolicy.oid().equals(oid)) {
          extnChecker.checkExtnInhibitAnyPolicy(failureMsg, ext, extensions, extnControl);
        } else if (ExtensionID.freshestCRL.oid().equals(oid)) {
          extnChecker.checkExtnDeltaCrlDistributionPoints(failureMsg, ext, issuerInfo);
        } else if (ExtensionID.authorityInfoAccess.oid().equals(oid)) {
          extnChecker.checkExtnAuthorityInfoAccess(failureMsg, ext, issuerInfo);
        } else if (ExtensionID.subjectInfoAccess.oid().equals(oid)) {
          extnChecker.checkExtnSubjectInfoAccess(failureMsg, ext, requestedExtns);
        } else if (ExtensionID.ocspNoCheck.oid().equals(oid)) {
          extnChecker.checkExtnOcspNocheck(failureMsg, ext);
        } else if (ExtensionID.tlsFeature.oid().equals(oid)) {
          extnChecker.checkExtnTlsFeature(failureMsg, ext, requestedExtns, extnControl);
        } else if (ExtensionID.smimeCapabilities.oid().equals(oid)) {
          extnChecker.checkSmimeCapabilities(failureMsg, ext);
        } else if (ExtensionID.signedCertificateTimestampList.oid().equals(oid)) {
          extnChecker.checkScts(failureMsg, ext);
        } else if (oid.equals(cccExtensionSchemaType)) {
          byte[] expected = cccExtensionSchemaValue;
          byte[] extnValue = ext.extnValue();
          if (!Arrays.equals(cccExtensionSchemaValue, extnValue)) {
            CheckerUtil.addViolation(failureMsg, "extension value", Hex.encode(extnValue),
                (expected == null) ? "not present" : Hex.encode(expected));
          }
        } else if (ExtensionID.privateKeyUsagePeriod.oid().equals(oid)) {
          extnChecker.checkExtnPrivateKeyUsagePeriod(failureMsg, ext,
              cert.notBefore(), cert.notAfter());
        } else if (ExtensionID.qcStatements.oid().equals(oid)) {
          extnChecker.checkExtnQcStatements(failureMsg, ext, requestedExtns, extnControl);
        } else if (ExtensionID.microsoft_CertificateTemplateName.oid().equals(oid)) {
          extnChecker.checkExtnMicrosoftCertificateTemplateName(failureMsg, ext,
              requestedExtns, extnControl);
        } else if (ExtensionID.microsoft_CertificateTemplateInformation.oid().equals(oid)) {
          extnChecker.checkExtnMicrosoftCertificateTemplateInformation(failureMsg, ext,
              requestedExtns, extnControl);
        } else if (ExtensionID.microsoft_SID.oid().equals(oid)) {
          extnChecker.checkExtnMicrosoftSid(failureMsg, ext, requestedExtns);
        } else if (ExtensionID.STIR_TNAuthList.oid().equals(oid)) {
          extnChecker.checkExtnStirTNAuthList(failureMsg, ext, requestedExtns);
        } else if (ExtensionID.STIR_JWTClaimConstraints.oid().equals(oid)) {
          extnChecker.checkExtnStirJWTClaimConstraints(failureMsg, ext);
        } else if (ExtensionID.SPDM_Extension.oid().equals(oid)) {
          extnChecker.checkExtnSpdmCertOids(failureMsg, ext);
        } else if (ExtensionID.ASIdentifiers.oid().equals(oid)
            || ExtensionID.ASIdentifiersV2.oid().equals(oid)) {
          extnChecker.checkExtnRpkiAsIdentifiers(failureMsg, ext, requestedExtns);
        } else if (ExtensionID.IPAddrBlocks.oid().equals(oid)
            || ExtensionID.IPAddrBlocks.oid().equals(oid)) {
          extnChecker.checkExtnRpkiIPAddrBlocks(failureMsg, ext, requestedExtns);
        } else if (ExtensionID.masaUrl.oid().equals(oid)) {
          extnChecker.checkExtnMasaUrl(failureMsg, ext, requestedExtns);
        } else if (ExtensionID.MRTD_NameChange.oid().equals(oid)) {
          extnChecker.checkExtnMrtdNameChange(failureMsg, ext);
        } else if (ExtensionID.MRTD_DocumentTypeList.oid().equals(oid)) {
          extnChecker.checkExtnMrtdDocumentTypeList(failureMsg, ext);
        } else if (ExtensionID.dice_ueid.oid().equals(oid)) {
          extnChecker.checkExtnDiceUeid(failureMsg, ext, requestedExtns);
        } else {
          byte[] expected = getExpectedExtValue(oid, requestedExtns, extnControl);
          byte[] extnValue = ext.extnValue();
          if (!Arrays.equals(expected, extnValue)) {
            CheckerUtil.addViolation(failureMsg, "extension value", Hex.encode(extnValue),
                (expected == null) ? "not present" : Hex.encode(expected));
          }
        }

        if (failureMsg.length() > 0) {
          issue.setFailureMessage(failureMsg.toString());
        }
      } catch (RuntimeException ex) {
        LOG.debug("extension value does not have correct syntax", ex);
        issue.setFailureMessage("extension value does not have correct syntax");
      }
    }

    return result;
  } // method checkExtensions

  private byte[] getExpectedExtValue(Asn1Oid type, Extensions requestedExtns,
                                     ExtensionControl extControl) {
    if (constantExtensions != null && constantExtensions.containsKey(type)) {
      return constantExtensions.get(type).getValue();
    } else if (requestedExtns != null && extControl.isPermittedInRequest()) {
      Extension reqExt = requestedExtns.getExtension(type);
      if (reqExt != null) {
        if (ExtensionID.CN_residentIdCardNumber.oid().equals(type)
          || ExtensionID.CN_passportNumber.oid().equals(type)
          || ExtensionID.CN_socialInsuranceNumber.oid().equals(type)
          || ExtensionID.CN_UnifiedSocialCreditCode.oid().equals(type)) {
          String str;
          if (ExtensionID.CN_residentIdCardNumber.oid().equals(type)) {
            str = reqExt.CN_ResidentIdCardNumber();
          } else if (ExtensionID.CN_passportNumber.oid().equals(type)) {
            str = reqExt.CN_PassportNumber();
          } else if (ExtensionID.CN_socialInsuranceNumber.oid().equals(type)) {
            str = reqExt.CN_SocialInsuranceNumber();
          } else {
            str = reqExt.CN_UnifiedSocialCreditCode();
          }

          Asn1Primitive extnValue = ExtensionID.CN_passportNumber.oid().equals(type)
              ? new Asn1Utf8String(str) : new Asn1PrintableString(str);

          return extnValue.getEncoded();
        }

        return reqExt.extnValue();
      }
    }

    return null;
  } // getExpectedExtValue

  private Set<Asn1Oid> getExtensionTypes(
      Certificate cert, IssuerInfo issuerInfo, Extensions requestedExtns,
      X500Name requestedSubject, KeySpec keySpec) {
    Set<Asn1Oid> types = new HashSet<>();
    // profile required extension types
    ExtensionsControl extensionControls = certprofile.extensionsControl();

    for (Asn1Oid oid : extensionControls.types()) {
      ExtensionControl entry = extensionControls.getControl(oid);
      if (entry.isRequired()) {
        types.add(oid);
      } else if ((requestedExtns != null && requestedExtns.getExtension(oid) != null)) {
        types.add(oid);
      }
    }

    // Authority key identifier
    Asn1Oid type = ExtensionID.authorityKeyIdentifier.oid();
    if (extensionControls.containsID(type)) {
      addIfNotIn(types, type);
    }

    // Subject key identifier, Subject Ke
    type = ExtensionID.subjectKeyIdentifier.oid();
    if (extensionControls.containsID(type)) {
      addIfNotIn(types, type);
    }

    // KeyUsage
    type = ExtensionID.keyUsage.oid();
    if (extensionControls.containsID(type)) {
      boolean required = requestedExtns != null && requestedExtns.getExtension(type) != null;

      if (!required) {
        Set<KeySingleUsage> requiredKeyusage = extnChecker.getKeyusage(true, keySpec);
        if (CollectionUtil.isNotEmpty(requiredKeyusage)) {
          required = true;
        }
      }

      if (required) {
        addIfNotIn(types, type);
      }
    }

    // CertificatePolicies
    type = ExtensionID.certificatePolicies.oid();
    if (extensionControls.containsID(type)) {
      if (certificatePolicies != null) {
        addIfNotIn(types, type);
      }
    }

    // Policy Mappings
    type = ExtensionID.policyMappings.oid();
    if (extensionControls.containsID(type)) {
      if (policyMappings != null) {
        addIfNotIn(types, type);
      }
    }

    // SubjectAltNames
    type = ExtensionID.subjectAlternativeName.oid();
    if (extensionControls.containsID(type)) {
      if (requestedExtns != null && requestedExtns.getExtension(type) != null) {
        addIfNotIn(types, type);
      } else if (requestedSubject != null) {
        Map<Asn1Oid, GeneralNameTag> toSanModes =
            certprofile.extensions().subjectToSubjectAltNameModes();
        if (toSanModes != null) {
          for (Asn1Oid rdnType : requestedSubject.getAttributeTypes()) {
            if (toSanModes.containsKey(rdnType)) {
              addIfNotIn(types, type);
            }
          }
        }
      }
    }

    // IssuerAltName
    type = ExtensionID.issuerAltName.oid();
    if (extensionControls.containsID(type)) {
      if (cert.getTBSCertificate().getExtensions().getExtension(
          ExtensionID.subjectAlternativeName.oid()) != null) {
        addIfNotIn(types, type);
      }
    }

    // SubjectDirectoryAttributes
    type = ExtensionID.subjectDirectoryAttributes.oid();
    if (extensionControls.containsID(type)) {
      if (requestedExtns != null && requestedExtns.getExtension(type) != null) {
        addIfNotIn(types, type);
      }
    }

    // BasicConstraints
    type = ExtensionID.basicConstraints.oid();
    if (extensionControls.containsID(type)) {
      addIfNotIn(types, type);
    }

    // Name Constraints
    type = ExtensionID.nameConstraints.oid();
    if (extensionControls.containsID(type)) {
      if (nameConstraints != null) {
        addIfNotIn(types, type);
      }
    }

    // PolicyConstraints
    type = ExtensionID.policyConstraints.oid();
    if (extensionControls.containsID(type)) {
      if (policyConstraints != null) {
        addIfNotIn(types, type);
      }
    }

    // ExtendedKeyUsage
    type = ExtensionID.extendedKeyUsage.oid();
    if (extensionControls.containsID(type)) {
      boolean required = requestedExtns != null && requestedExtns.getExtension(type) != null;

      if (!required) {
        Set<ExtKeyUsageControl> requiredExtKeyusage = getExtKeyusage(true);
        if (CollectionUtil.isNotEmpty(requiredExtKeyusage)) {
          required = true;
        }
      }

      if (required) {
        addIfNotIn(types, type);
      }
    }

    // CRLDistributionPoints
    type = ExtensionID.crlDistributionPoints.oid();
    if (extensionControls.containsID(type)) {
      if (issuerInfo.getCrlUrls() != null) {
        addIfNotIn(types, type);
      }
    }

    // Inhibit anyPolicy
    type = ExtensionID.inhibitAnyPolicy.oid();
    if (extensionControls.containsID(type)) {
      if (inhibitAnyPolicy != null) {
        addIfNotIn(types, type);
      }
    }

    // FreshestCRL
    type = ExtensionID.freshestCRL.oid();
    if (extensionControls.containsID(type)) {
      if (issuerInfo.getDeltaCrlUrls() != null) {
        addIfNotIn(types, type);
      }
    }

    // AuthorityInfoAccess
    type = ExtensionID.authorityInfoAccess.oid();
    if (extensionControls.containsID(type)) {
      if (issuerInfo.getOcspUrls() != null) {
        addIfNotIn(types, type);
      }
    }

    // SubjectInfoAccess
    type = ExtensionID.subjectInfoAccess.oid();
    if (extensionControls.containsID(type)) {
      if (requestedExtns != null && requestedExtns.getExtension(type) != null) {
        addIfNotIn(types, type);
      }
    }

    // ocsp-nocheck
    type = ExtensionID.ocspNoCheck.oid();
    if (extensionControls.containsID(type)) {
      addIfNotIn(types, type);
    }

    if (requestedExtns != null) {
      Set<Asn1Oid> extOids = requestedExtns.getExtensionIds();
      for (Asn1Oid oid : extOids) {
        if (extensionControls.containsID(oid)) {
          addIfNotIn(types, oid);
        }
      }
    }

    return types;
  } // method getExtensionTypes

  private ValidationIssue createExtensionIssue(Asn1Oid extId) {
    String extName = OIDs.getName(extId);
    return new ValidationIssue("X509.EXT." + extName,
        "extension " + extName + " (" + extId.getId() + ")");
  } // method createExtensionIssue

  Set<ExtKeyUsageControl> getExtKeyusage(boolean required) {
    Set<ExtKeyUsageControl> ret = new HashSet<>();

    Set<ExtKeyUsageControl> controls = certprofile.extensions().extendedKeyusages();
    if (controls != null) {
      for (ExtKeyUsageControl control : controls) {
        if (control.isRequired() == required) {
          ret.add(control);
        }
      }
    }
    return ret;
  } // method getExtKeyusage

  byte[] getConstantExtensionValue(Asn1Oid type) {
    return (constantExtensions == null) ? null : constantExtensions.get(type).getValue();
  }

  void checkConstantExtnValue(
      Asn1Oid extnType, StringBuilder failureMsg,
      Extension extn, Extensions requestedExtns, ExtensionControl extControl) {
    byte[] expected = getExpectedExtValue(extnType, requestedExtns, extControl);
    byte[] extnValue = extn.extnValue();
    if (!Arrays.equals(expected, extnValue)) {
      CheckerUtil.addViolation(failureMsg, "extension values", Hex.encode(extnValue),
          (expected == null) ? "not present" : Hex.encode(expected));
    }
  } // method checkConstantExtnValue

  static void addIfNotIn(Set<Asn1Oid> set, Asn1Oid oid) {
    set.add(oid);
  }

}
