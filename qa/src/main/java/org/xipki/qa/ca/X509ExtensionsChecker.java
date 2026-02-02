// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ctrl.ExtKeyUsageControl;
import org.xipki.ca.api.profile.ctrl.ExtensionControl;
import org.xipki.ca.api.profile.ctrl.ExtensionsControl;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.ca.certprofile.xijson.conf.extn.CCCSimpleExtensionSchema;
import org.xipki.ca.certprofile.xijson.conf.extn.CertificatePolicies;
import org.xipki.ca.certprofile.xijson.conf.extn.InhibitAnyPolicy;
import org.xipki.ca.certprofile.xijson.conf.extn.NameConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyMappings;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements;
import org.xipki.ca.certprofile.xijson.conf.extn.SmimeCapabilities;
import org.xipki.ca.certprofile.xijson.conf.extn.TlsFeature;
import org.xipki.qa.CheckerUtil;
import org.xipki.qa.ValidationIssue;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.pkix.X509Cert;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.misc.CollectionUtil;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Extensions checker.
 *
 * @author Lijun Liao
 */

public class X509ExtensionsChecker {

  private static final Logger LOG =
      LoggerFactory.getLogger(X509ExtensionsChecker.class);

  private CertificatePolicies certificatePolicies;

  private PolicyMappings policyMappings;

  private NameConstraints nameConstraints;

  private PolicyConstraints policyConstraints;

  private InhibitAnyPolicy inhibitAnyPolicy;

  private QcStatements qcStatements;

  private TlsFeature tlsFeature;

  private QaExtensionValue smimeCapabilities;

  private ASN1ObjectIdentifier cccExtensionSchemaType;

  private byte[] cccExtensionSchemaValue;

  private final Map<ASN1ObjectIdentifier, QaExtensionValue> constantExtensions;

  private final XijsonCertprofile certprofile;

  private final X509ExtensionChecker extnChecker;

  public X509ExtensionsChecker(XijsonCertprofileType conf,
                               XijsonCertprofile certprofile)
      throws CertprofileException {
    this.certprofile = Args.notNull(certprofile, "certprofile");

    // Extensions
    Map<String, ExtensionType> extensions =
        Args.notNull(conf, "conf").buildExtensions();

    // Extension controls
    ExtensionsControl extensionControls = certprofile.extensionsControl();

    // Certificate Policies
    ASN1ObjectIdentifier type = OIDs.Extn.certificatePolicies;
    if (extensionControls.containsID(type)) {
      this.certificatePolicies =
          extensions.get(type.getId()).certificatePolicies();
    }

    // Policy Mappings
    type = OIDs.Extn.policyMappings;
    if (extensionControls.containsID(type)) {
      this.policyMappings = extensions.get(type.getId()).policyMappings();
    }

    // Name Constraints
    type = OIDs.Extn.nameConstraints;
    if (extensionControls.containsID(type)) {
      this.nameConstraints = extensions.get(type.getId()).nameConstraints();
    }

    // Policy Constraints
    type = OIDs.Extn.policyConstraints;
    if (extensionControls.containsID(type)) {
      this.policyConstraints =
          extensions.get(type.getId()).policyConstraints();
    }

    // Inhibit anyPolicy
    type = OIDs.Extn.inhibitAnyPolicy;
    if (extensionControls.containsID(type)) {
      this.inhibitAnyPolicy =
          extensions.get(type.getId()).inhibitAnyPolicy();
    }

    type = OIDs.Extn.qCStatements;
    if (extensionControls.containsID(type)) {
      this.qcStatements = extensions.get(type.getId()).qcStatements();
    }

    // tlsFeature
    type = OIDs.Extn.id_pe_tlsfeature;
    if (extensionControls.containsID(type)) {
      this.tlsFeature = extensions.get(type.getId()).tlsFeature();
    }

    // SMIMECapabilities
    type = OIDs.Extn.id_smimeCapabilities;
    if (extensionControls.containsID(type)) {
      List<SmimeCapabilities.SmimeCapability> list =
          extensions.get(type.getId()).smimeCapabilities().capabilities();

      ASN1EncodableVector vec = new ASN1EncodableVector();
      for (SmimeCapabilities.SmimeCapability m : list) {
        ASN1ObjectIdentifier oid = m.capabilityId();
        ASN1Object params = null;
        Integer capParam = m.parameter();
        if (capParam != null) {
          params = new ASN1Integer(capParam);
        }
        org.bouncycastle.asn1.smime.SMIMECapability cap =
            new org.bouncycastle.asn1.smime.SMIMECapability(oid, params);
        vec.add(cap);
      }

      DERSequence extValue = new DERSequence(vec);
      try {
        smimeCapabilities = new QaExtensionValue(
            extensionControls.getControl(type).isCritical(),
            extValue.getEncoded());
      } catch (IOException ex) {
        throw new CertprofileException("Cannot encode SMIMECapabilities: "
            + ex.getMessage());
      }
    }

    // CCC
    initCCCExtensionSchemas(extensions);

    // constant extensions
    Map<ASN1ObjectIdentifier, ExtensionValue> constExtns =
        certprofile.constantExtensions();
    this.constantExtensions = new HashMap<>();
    if (constExtns != null) {
      for (Map.Entry<ASN1ObjectIdentifier, ExtensionValue> m
          : constExtns.entrySet()) {
        ExtensionValue v = m.getValue();
        byte[] encoded;
        try {
          encoded = v.value().toASN1Primitive().getEncoded();
        } catch (IOException e) {
          throw new CertprofileException(
              "Cannot encode extension: " + OIDs.getName(m.getKey()));
        }
        QaExtensionValue value = new QaExtensionValue(v.isCritical(), encoded);
        this.constantExtensions.put(m.getKey(), value);
      }
    }

    this.extnChecker = new X509ExtensionChecker(this);
  } // constructor

  private void initCCCExtensionSchemas(Map<String, ExtensionType> extensions)
      throws CertprofileException {
    Set<String> extnIds = extensions.keySet();
    ASN1ObjectIdentifier type = null;
    for (String m : extnIds) {
      ASN1ObjectIdentifier mOid = new ASN1ObjectIdentifier(m);
      if (mOid.on(OIDs.Extn.id_ccc_extn)) {
        if (type != null) {
          throw new CertprofileException("Maximal one CCC Extension is " +
              "allowed, but configured at least 2.");
        }
        type = mOid;
      }
    }

    if (type == null) {
      return;
    }

    ExtensionType ex = extensions.get(type.getId());
    if (!ex.isCritical()) {
      throw new CertprofileException("CCC Extension must be set to critical, " +
          "but configured non-critical.");
    }

    List<ASN1ObjectIdentifier> simpleSchemaTypes = Arrays.asList(
        OIDs.Extn.id_ccc_K_Vehicle_Cert,
        OIDs.Extn.id_ccc_F_External_CA_Cert,
        OIDs.Extn.id_ccc_P_VehicleOEM_Enc_Cert,
        OIDs.Extn.id_ccc_Q_VehicleOEM_Sig_Cert,
        OIDs.Extn.id_ccc_Device_Enc_Cert,
        OIDs.Extn.id_ccc_Vehicle_Intermediate_Cert,
        OIDs.Extn.id_ccc_J_VehicleOEM_CA_Cert,
        OIDs.Extn.id_ccc_M_VehicleOEM_CA_Cert);

    if (!simpleSchemaTypes.contains(type)) {
      return;
    }

    CCCSimpleExtensionSchema schema = ex.cccExtensionSchema();
    if (schema == null) {
      throw new CertprofileException(
          "ccExtensionSchema is not set for " + type);
    }

    ASN1Sequence seq = new DERSequence(new ASN1Integer(schema.version()));
    this.cccExtensionSchemaType = type;
    try {
      this.cccExtensionSchemaValue = seq.getEncoded();
    } catch (IOException e) {
      throw new CertprofileException("error encoding CCC extensionSchemaValue");
    }
  }

  CertificatePolicies getCertificatePolicies() {
    return certificatePolicies;
  }

  PolicyMappings getPolicyMappings() {
    return policyMappings;
  }

  NameConstraints getNameConstraints() {
    return nameConstraints;
  }

  PolicyConstraints getPolicyConstraints() {
    return policyConstraints;
  }

  InhibitAnyPolicy getInhibitAnyPolicy() {
    return inhibitAnyPolicy;
  }

  QcStatements getQcStatements() {
    return qcStatements;
  }

  TlsFeature getTlsFeature() {
    return tlsFeature;
  }

  QaExtensionValue getSmimeCapabilities() {
    return smimeCapabilities;
  }

  XijsonCertprofile getCertprofile() {
    return certprofile;
  }

  public List<ValidationIssue> checkExtensions(
      Certificate cert, IssuerInfo issuerInfo, Extensions requestedExtns,
      X500Name requestedSubject, KeySpec keySpec) {
    Args.notNull(issuerInfo, "issuerInfo");

    X509Cert jceCert = new X509Cert(Args.notNull(cert, "cert"));
    List<ValidationIssue> result = new LinkedList<>();

    // detect the list of extension types in certificate
    Set<ASN1ObjectIdentifier> expectedExtensionTypes = getExtensionTypes(
        cert, issuerInfo, requestedExtns, requestedSubject, keySpec);

    Extensions extensions = cert.getTBSCertificate().getExtensions();
    ASN1ObjectIdentifier[] certExtnOids = extensions.getExtensionOIDs();

    if (certExtnOids == null) {
      ValidationIssue issue = new ValidationIssue(
          "X509.EXT.GEN", "extension general");
      result.add(issue);
      issue.setFailureMessage("no extension is present");
      return result;
    }

    List<ASN1ObjectIdentifier> certExtnTypes = Arrays.asList(certExtnOids);

    for (ASN1ObjectIdentifier extType : expectedExtensionTypes) {
      if (!certExtnTypes.contains(extType)) {
        ValidationIssue issue = createExtensionIssue(extType);
        result.add(issue);
        issue.setFailureMessage("extension is absent but is required");
      }
    }

    ExtensionsControl extnControls = certprofile.extensionsControl();
    for (ASN1ObjectIdentifier oid : certExtnTypes) {
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

      byte[] extnValue = ext.getExtnValue().getOctets();
      try {
        if (OIDs.Extn.authorityKeyIdentifier.equals(oid)) {
          extnChecker.checkExtnAuthorityKeyId(
              failureMsg, extnValue, issuerInfo);
        } else if (OIDs.Extn.subjectKeyIdentifier.equals(oid)) {
          // SubjectKeyIdentifier
          extnChecker.checkExtnSubjectKeyIdentifier(failureMsg, extnValue,
              cert.getSubjectPublicKeyInfo());
        } else if (OIDs.Extn.keyUsage.equals(oid)) {
          extnChecker.checkExtnKeyUsage(failureMsg, jceCert.keyUsage(),
              requestedExtns, extnControl, keySpec);
        } else if (OIDs.Extn.certificatePolicies.equals(oid)) {
          extnChecker.checkExtnCertificatePolicies(
              failureMsg, extnValue, requestedExtns, extnControl);
        } else if (OIDs.Extn.policyMappings.equals(oid)) {
          extnChecker.checkExtnPolicyMappings(failureMsg, extnValue,
              requestedExtns, extnControl);
        } else if (OIDs.Extn.subjectAlternativeName.equals(oid)) {
          extnChecker.checkExtnSubjectAltNames(
              failureMsg, extnValue, requestedExtns, requestedSubject);
        } else if (OIDs.Extn.issuerAlternativeName.equals(oid)) {
          extnChecker.checkExtnIssuerAltNames(failureMsg, extnValue,
              issuerInfo);
        } else if (OIDs.Extn.basicConstraints.equals(oid)) {
          extnChecker.checkExtnBasicConstraints(failureMsg, extnValue);
        } else if (OIDs.Extn.nameConstraints.equals(oid)) {
          extnChecker.checkExtnNameConstraints(
              failureMsg, extnValue, requestedExtns, extnControl);
        } else if (OIDs.Extn.policyConstraints.equals(oid)) {
          extnChecker.checkExtnPolicyConstraints(
              failureMsg, extnValue, requestedExtns, extnControl);
        } else if (OIDs.Extn.extendedKeyUsage.equals(oid)) {
          extnChecker.checkExtnExtendedKeyUsage(
              failureMsg, extnValue, requestedExtns, extnControl);
        } else if (OIDs.Extn.cRLDistributionPoints.equals(oid)) {
          extnChecker.checkExtnCrlDistributionPoints(failureMsg, extnValue,
              issuerInfo);
        } else if (OIDs.Extn.inhibitAnyPolicy.equals(oid)) {
          extnChecker.checkExtnInhibitAnyPolicy(failureMsg, extnValue,
              extensions, extnControl);
        } else if (OIDs.Extn.freshestCRL.equals(oid)) {
          extnChecker.checkExtnDeltaCrlDistributionPoints(failureMsg,
              extnValue, issuerInfo);
        } else if (OIDs.Extn.authorityInfoAccess.equals(oid)) {
          extnChecker.checkExtnAuthorityInfoAccess(failureMsg, extnValue,
              issuerInfo);
        } else if (OIDs.Extn.subjectInfoAccess.equals(oid)) {
          extnChecker.checkExtnSubjectInfoAccess(failureMsg, extnValue,
              requestedExtns);
        } else if (OIDs.Extn.id_pkix_ocsp_nocheck.equals(oid)) {
          extnChecker.checkExtnOcspNocheck(failureMsg, extnValue);
        } else if (OIDs.Extn.id_pe_tlsfeature.equals(oid)) {
          extnChecker.checkExtnTlsFeature(failureMsg, extnValue,
              requestedExtns, extnControl);
        } else if (OIDs.Extn.id_smimeCapabilities.equals(oid)) {
          extnChecker.checkSmimeCapabilities(failureMsg, extnValue);
        } else if (OIDs.Extn.id_SignedCertificateTimestampList.equals(oid)) {
          extnChecker.checkScts(failureMsg, extnValue);
        } else if (oid.equals(cccExtensionSchemaType)) {
          byte[] expected = cccExtensionSchemaValue;
          if (!Arrays.equals(cccExtensionSchemaValue, extnValue)) {
            CheckerUtil.addViolation(failureMsg, "extension value",
                Hex.encode(extnValue),
                (expected == null) ? "not present" : Hex.encode(expected));
          }
        } else if (OIDs.Extn.privateKeyUsagePeriod.equals(oid)) {
          extnChecker.checkExtnPrivateKeyUsagePeriod(failureMsg, extnValue,
              cert.getTBSCertificate().getStartDate().getDate(),
              cert.getTBSCertificate().getEndDate().getDate());
        } else if (OIDs.Extn.qCStatements.equals(oid)) {
          extnChecker.checkExtnQcStatements(failureMsg, extnValue,
              requestedExtns, extnControl);
        } else {
          byte[] expected = getExpectedExtValue(oid, requestedExtns,
              extnControl);
          if (!Arrays.equals(expected, extnValue)) {
            CheckerUtil.addViolation(failureMsg, "extension value",
                Hex.encode(extnValue),
                (expected == null) ? "not present" : Hex.encode(expected));
          }
        }

        if (failureMsg.length() > 0) {
          issue.setFailureMessage(failureMsg.toString());
        }

      } catch (IllegalArgumentException | ClassCastException
               | ArrayIndexOutOfBoundsException ex) {
        LOG.debug("extension value does not have correct syntax", ex);
        issue.setFailureMessage("extension value does not have correct syntax");
      }
    }

    return result;
  } // method checkExtensions

  private byte[] getExpectedExtValue(
      ASN1ObjectIdentifier type, Extensions requestedExtns,
      ExtensionControl extControl) {
    if (constantExtensions != null && constantExtensions.containsKey(type)) {
      return constantExtensions.get(type).getValue();
    } else if (requestedExtns != null && extControl.isPermittedInRequest()) {
      Extension reqExt = requestedExtns.getExtension(type);
      if (reqExt != null) {
        return reqExt.getExtnValue().getOctets();
      }
    }

    return null;
  } // getExpectedExtValue

  private Set<ASN1ObjectIdentifier> getExtensionTypes(
      Certificate cert, IssuerInfo issuerInfo, Extensions requestedExtns,
      X500Name requestedSubject, KeySpec keySpec) {
    Set<ASN1ObjectIdentifier> types = new HashSet<>();
    // profile required extension types
    ExtensionsControl extensionControls = certprofile.extensionsControl();

    for (ASN1ObjectIdentifier oid : extensionControls.types()) {
      ExtensionControl entry = extensionControls.getControl(oid);
      if (entry.isRequired()) {
        types.add(oid);
      } else if ((requestedExtns != null
          && requestedExtns.getExtension(oid) != null)) {
        types.add(oid);
      }
    }

    // Authority key identifier
    ASN1ObjectIdentifier type = OIDs.Extn.authorityKeyIdentifier;
    if (extensionControls.containsID(type)) {
      addIfNotIn(types, type);
    }

    // Subject key identifier, Subject Ke
    type = OIDs.Extn.subjectKeyIdentifier;
    if (extensionControls.containsID(type)) {
      addIfNotIn(types, type);
    }

    // KeyUsage
    type = OIDs.Extn.keyUsage;
    if (extensionControls.containsID(type)) {
      boolean required = requestedExtns != null
          && requestedExtns.getExtension(type) != null;

      if (!required) {
        Set<KeySingleUsage> requiredKeyusage =
            extnChecker.getKeyusage(true, keySpec);
        if (CollectionUtil.isNotEmpty(requiredKeyusage)) {
          required = true;
        }
      }

      if (required) {
        addIfNotIn(types, type);
      }
    }

    // CertificatePolicies
    type = OIDs.Extn.certificatePolicies;
    if (extensionControls.containsID(type)) {
      if (certificatePolicies != null) {
        addIfNotIn(types, type);
      }
    }

    // Policy Mappings
    type = OIDs.Extn.policyMappings;
    if (extensionControls.containsID(type)) {
      if (policyMappings != null) {
        addIfNotIn(types, type);
      }
    }

    // SubjectAltNames
    type = OIDs.Extn.subjectAlternativeName;
    if (extensionControls.containsID(type)) {
      if (requestedExtns != null && requestedExtns.getExtension(type) != null) {
        addIfNotIn(types, type);
      } else if (requestedSubject != null) {
        Map<ASN1ObjectIdentifier, GeneralNameTag> toSanModes =
            certprofile.extensions().subjectToSubjectAltNameModes();
        if (toSanModes != null) {
          for (ASN1ObjectIdentifier rdnType
              : requestedSubject.getAttributeTypes()) {
            if (toSanModes.containsKey(rdnType)) {
              addIfNotIn(types, type);
            }
          }
        }
      }
    }

    // IssuerAltName
    type = OIDs.Extn.issuerAlternativeName;
    if (extensionControls.containsID(type)) {
      if (cert.getTBSCertificate().getExtensions().getExtension(
          OIDs.Extn.subjectAlternativeName) != null) {
        addIfNotIn(types, type);
      }
    }

    // BasicConstraints
    type = OIDs.Extn.basicConstraints;
    if (extensionControls.containsID(type)) {
      addIfNotIn(types, type);
    }

    // Name Constraints
    type = OIDs.Extn.nameConstraints;
    if (extensionControls.containsID(type)) {
      if (nameConstraints != null) {
        addIfNotIn(types, type);
      }
    }

    // PolicyConstraints
    type = OIDs.Extn.policyConstraints;
    if (extensionControls.containsID(type)) {
      if (policyConstraints != null) {
        addIfNotIn(types, type);
      }
    }

    // ExtendedKeyUsage
    type = OIDs.Extn.extendedKeyUsage;
    if (extensionControls.containsID(type)) {
      boolean required = requestedExtns != null
          && requestedExtns.getExtension(type) != null;

      if (!required) {
        Set<ExtKeyUsageControl> requiredExtKeyusage =
            getExtKeyusage(true);
        if (CollectionUtil.isNotEmpty(requiredExtKeyusage)) {
          required = true;
        }
      }

      if (required) {
        addIfNotIn(types, type);
      }
    }

    // CRLDistributionPoints
    type = OIDs.Extn.cRLDistributionPoints;
    if (extensionControls.containsID(type)) {
      if (issuerInfo.getCrlUrls() != null) {
        addIfNotIn(types, type);
      }
    }

    // Inhibit anyPolicy
    type = OIDs.Extn.inhibitAnyPolicy;
    if (extensionControls.containsID(type)) {
      if (inhibitAnyPolicy != null) {
        addIfNotIn(types, type);
      }
    }

    // FreshestCRL
    type = OIDs.Extn.freshestCRL;
    if (extensionControls.containsID(type)) {
      if (issuerInfo.getDeltaCrlUrls() != null) {
        addIfNotIn(types, type);
      }
    }

    // AuthorityInfoAccess
    type = OIDs.Extn.authorityInfoAccess;
    if (extensionControls.containsID(type)) {
      if (issuerInfo.getOcspUrls() != null) {
        addIfNotIn(types, type);
      }
    }

    // SubjectInfoAccess
    type = OIDs.Extn.subjectInfoAccess;
    if (extensionControls.containsID(type)) {
      if (requestedExtns != null && requestedExtns.getExtension(type) != null) {
        addIfNotIn(types, type);
      }
    }

    // ocsp-nocheck
    type = OIDs.Extn.id_pkix_ocsp_nocheck;
    if (extensionControls.containsID(type)) {
      addIfNotIn(types, type);
    }

    if (requestedExtns != null) {
      ASN1ObjectIdentifier[] extOids = requestedExtns.getExtensionOIDs();
      for (ASN1ObjectIdentifier oid : extOids) {
        if (extensionControls.containsID(oid)) {
          addIfNotIn(types, oid);
        }
      }
    }

    return types;
  } // method getExensionTypes

  private ValidationIssue createExtensionIssue(ASN1ObjectIdentifier extId) {
    String extName = OIDs.getName(extId);
    if (extName == null) {
      extName = extId.getId().replace('.', '_');
      return new ValidationIssue("X509.EXT." + extName,
          "extension " + extId.getId());
    } else {
      return new ValidationIssue("X509.EXT." + extName,
          "extension " + extName + " (" + extId.getId() + ")");
    }
  } // method createExtensionIssue

  Set<ExtKeyUsageControl> getExtKeyusage(boolean required) {
    Set<ExtKeyUsageControl> ret = new HashSet<>();

    Set<ExtKeyUsageControl> controls =
        certprofile.extensions().extendedKeyusages();
    if (controls != null) {
      for (ExtKeyUsageControl control : controls) {
        if (control.isRequired() == required) {
          ret.add(control);
        }
      }
    }
    return ret;
  } // method getExtKeyusage

  byte[] getConstantExtensionValue(ASN1ObjectIdentifier type) {
    return (constantExtensions == null) ? null
        : constantExtensions.get(type).getValue();
  }

  void checkConstantExtnValue(
      ASN1ObjectIdentifier extnType, StringBuilder failureMsg,
      byte[] extensionValue, Extensions requestedExtns,
      ExtensionControl extControl) {
    byte[] expected = getExpectedExtValue(extnType, requestedExtns, extControl);
    if (!Arrays.equals(expected, extensionValue)) {
      CheckerUtil.addViolation(failureMsg, "extension values",
          Hex.encode(extensionValue),
          (expected == null) ? "not present" : Hex.encode(expected));
    }
  } // method checkConstantExtnValue

  static void addIfNotIn(Set<ASN1ObjectIdentifier> set,
                         ASN1ObjectIdentifier oid) {
    set.add(oid);
  }

}
