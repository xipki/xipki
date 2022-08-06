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

package org.xipki.qa.ca.extn;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.exception.BadCertTemplateException;
import org.xipki.ca.api.profile.Certprofile.ExtKeyUsageControl;
import org.xipki.ca.api.profile.Certprofile.ExtensionControl;
import org.xipki.ca.api.profile.Certprofile.KeyUsageControl;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.certprofile.xijson.DirectoryStringType;
import org.xipki.ca.certprofile.xijson.ExtensionSyntaxChecker;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.*;
import org.xipki.ca.certprofile.xijson.conf.SmimeCapabilities.SmimeCapability;
import org.xipki.ca.certprofile.xijson.conf.SmimeCapabilities.SmimeCapabilityParameter;
import org.xipki.qa.ValidationIssue;
import org.xipki.qa.ca.IssuerInfo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.X509Cert;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import static org.xipki.qa.ca.extn.CheckerUtil.*;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.CollectionUtil.isNotEmpty;

/**
 * Extensions checker.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ExtensionsChecker {

  private static final Logger LOG = LoggerFactory.getLogger(ExtensionsChecker.class);

  private CertificatePolicies certificatePolicies;

  private PolicyMappings policyMappings;

  private NameConstraints nameConstraints;

  private PolicyConstraints policyConstraints;

  private InhibitAnyPolicy inhibitAnyPolicy;

  private Restriction restriction;

  private AdditionalInformation additionalInformation;

  private ASN1ObjectIdentifier validityModelId;

  private QcStatements qcStatements;

  private TlsFeature tlsFeature;

  private QaExtensionValue smimeCapabilities;

  private Map<ASN1ObjectIdentifier, QaExtensionValue> constantExtensions;

  private Map<ASN1ObjectIdentifier, ExtnSyntax> extensionSyntaxes;

  private XijsonCertprofile certprofile;

  private final A2gChecker a2gChecker;
  private final H2nChecker h2nChecker;
  private final O2tChecker o2tChecker;
  private final U2zChecker u2zChecker;

  public ExtensionsChecker(X509ProfileType conf, XijsonCertprofile certprofile)
      throws CertprofileException {
    this.certprofile = notNull(certprofile, "certprofile");

    notNull(conf, "conf");

    // Extensions
    Map<String, ExtensionType> extensions = conf.buildExtensions();

    // Extension controls
    Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls =
        certprofile.getExtensionControls();

    // Certificate Policies
    ASN1ObjectIdentifier type = Extension.certificatePolicies;
    if (extensionControls.containsKey(type)) {
      this.certificatePolicies = extensions.get(type.getId()).getCertificatePolicies();
    }

    // Policy Mappings
    type = Extension.policyMappings;
    if (extensionControls.containsKey(type)) {
      this.policyMappings = extensions.get(type.getId()).getPolicyMappings();
    }

    // Name Constrains
    type = Extension.nameConstraints;
    if (extensionControls.containsKey(type)) {
      this.nameConstraints = extensions.get(type.getId()).getNameConstraints();
    }

    // Policy Constraints
    type = Extension.policyConstraints;
    if (extensionControls.containsKey(type)) {
      this.policyConstraints = extensions.get(type.getId()).getPolicyConstraints();
    }

    // Inhibit anyPolicy
    type = Extension.inhibitAnyPolicy;
    if (extensionControls.containsKey(type)) {
      this.inhibitAnyPolicy = extensions.get(type.getId()).getInhibitAnyPolicy();
    }

    // restriction
    type = Extn.id_extension_restriction;
    if (extensionControls.containsKey(type)) {
      this.restriction = extensions.get(type.getId()).getRestriction();
    }

    // additionalInformation
    type = Extn.id_extension_additionalInformation;
    if (extensionControls.containsKey(type)) {
      this.additionalInformation = extensions.get(type.getId()).getAdditionalInformation();
    }

    // validityModel
    type = Extn.id_extension_validityModel;
    if (extensionControls.containsKey(type)) {
      this.validityModelId = extensions.get(type.getId()).getValidityModel().getModelId().toXiOid();
    }

    // QCStatements
    type = Extension.qCStatements;
    if (extensionControls.containsKey(type)) {
      this.qcStatements = extensions.get(type.getId()).getQcStatements();
    }

    // tlsFeature
    type = Extn.id_pe_tlsfeature;
    if (extensionControls.containsKey(type)) {
      this.tlsFeature = extensions.get(type.getId()).getTlsFeature();
    }

    // SMIMECapabilities
    type = Extn.id_smimeCapabilities;
    if (extensionControls.containsKey(type)) {
      List<SmimeCapability> list =
          extensions.get(type.getId()).getSmimeCapabilities().getCapabilities();

      ASN1EncodableVector vec = new ASN1EncodableVector();
      for (SmimeCapability m : list) {
        ASN1ObjectIdentifier oid = m.getCapabilityId().toXiOid();
        ASN1Encodable params = null;
        SmimeCapabilityParameter capParam = m.getParameter();
        if (capParam != null) {
          if (capParam.getInteger() != null) {
            params = new ASN1Integer(capParam.getInteger());
          } else if (capParam.getBinary() != null) {
            params = readAsn1Encodable(capParam.getBinary().getValue());
          }
        }
        org.bouncycastle.asn1.smime.SMIMECapability cap =
            new org.bouncycastle.asn1.smime.SMIMECapability(oid, params);
        vec.add(cap);
      }

      DERSequence extValue = new DERSequence(vec);
      try {
        smimeCapabilities = new QaExtensionValue(
            extensionControls.get(type).isCritical(), extValue.getEncoded());
      } catch (IOException ex) {
        throw new CertprofileException("Cannot encode SMIMECapabilities: " + ex.getMessage());
      }
    }

    // constant extensions
    this.constantExtensions = buildConstantExtesions(extensions);

    // extensions with syntax
    this.extensionSyntaxes = buildExtesionSyntaxes(extensions);

    this.a2gChecker = new A2gChecker(this);
    this.h2nChecker = new H2nChecker(this);
    this.o2tChecker = new O2tChecker(this);
    this.u2zChecker = new U2zChecker(this);
  } // constructor

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

  Restriction getRestriction() {
    return restriction;
  }

  AdditionalInformation getAdditionalInformation() {
    return additionalInformation;
  }

  ASN1ObjectIdentifier getValidityModelId() {
    return validityModelId;
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

  Map<ASN1ObjectIdentifier, QaExtensionValue> getConstantExtensions() {
    return constantExtensions;
  }

  XijsonCertprofile getCertprofile() {
    return certprofile;
  }

  public List<ValidationIssue> checkExtensions(Certificate cert, IssuerInfo issuerInfo,
      Extensions requestedExtns, X500Name requestedSubject) {
    notNull(cert, "cert");
    notNull(issuerInfo, "issuerInfo");

    X509Cert jceCert = new X509Cert(cert);

    List<ValidationIssue> result = new LinkedList<>();

    // detect the list of extension types in certificate
    Set<ASN1ObjectIdentifier> presentExtenionTypes =
        getExensionTypes(cert, issuerInfo, requestedExtns);

    Extensions extensions = cert.getTBSCertificate().getExtensions();
    ASN1ObjectIdentifier[] oids = extensions.getExtensionOIDs();

    if (oids == null) {
      ValidationIssue issue = new ValidationIssue("X509.EXT.GEN", "extension general");
      result.add(issue);
      issue.setFailureMessage("no extension is present");
      return result;
    }

    List<ASN1ObjectIdentifier> certExtTypes = Arrays.asList(oids);

    for (ASN1ObjectIdentifier extType : presentExtenionTypes) {
      if (!certExtTypes.contains(extType)) {
        ValidationIssue issue = createExtensionIssue(extType);
        result.add(issue);
        issue.setFailureMessage("extension is absent but is required");
      }
    }

    Map<ASN1ObjectIdentifier, ExtensionControl> extnControls =
        certprofile.getExtensionControls();
    for (ASN1ObjectIdentifier oid : certExtTypes) {
      ValidationIssue issue = createExtensionIssue(oid);
      result.add(issue);
      if (!presentExtenionTypes.contains(oid)) {
        issue.setFailureMessage("extension is present but is not permitted");
        continue;
      }

      Extension ext = extensions.getExtension(oid);
      StringBuilder failureMsg = new StringBuilder();
      ExtensionControl extnControl = extnControls.get(oid);

      if (extnControl.isCritical() != ext.isCritical()) {
        addViolation(failureMsg, "critical", ext.isCritical(), extnControl.isCritical());
      }

      byte[] extnValue = ext.getExtnValue().getOctets();
      try {
        if (extensionSyntaxes != null && extensionSyntaxes.containsKey(oid)) {
          Extension requestedExtn = requestedExtns.getExtension(oid);
          if (!Arrays.equals(requestedExtn.getExtnValue().getOctets(), extnValue)) {
            failureMsg.append(
                "extension in certificate does not equal the one contained in the request");
          } else {
            ExtnSyntax syntax = extensionSyntaxes.get(oid);
            String extnName = "extension " + ObjectIdentifiers.oidToDisplayName(oid);
            try {
              ExtensionSyntaxChecker.checkExtension(extnName, ext.getParsedValue(), syntax);
            } catch (BadCertTemplateException ex) {
              failureMsg.append(ex.getMessage());
            }
          }
        } else if (Extension.authorityKeyIdentifier.equals(oid)) {
          a2gChecker.checkExtnAuthorityKeyId(failureMsg, extnValue, issuerInfo);
        } else if (Extension.subjectKeyIdentifier.equals(oid)) {
          // SubjectKeyIdentifier
          o2tChecker.checkExtnSubjectKeyIdentifier(
                      failureMsg, extnValue, cert.getSubjectPublicKeyInfo());
        } else if (Extension.keyUsage.equals(oid)) {
          h2nChecker.checkExtnKeyUsage(
                      failureMsg, jceCert.getKeyUsage(), requestedExtns, extnControl);
        } else if (Extension.certificatePolicies.equals(oid)) {
          a2gChecker.checkExtnCertificatePolicies(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.policyMappings.equals(oid)) {
          o2tChecker.checkExtnPolicyMappings(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.subjectAlternativeName.equals(oid)) {
          o2tChecker.checkExtnSubjectAltNames(
                      failureMsg, extnValue, requestedExtns, extnControl, requestedSubject);
        } else if (Extension.subjectDirectoryAttributes.equals(oid)) {
          o2tChecker.checkExtnSubjectDirAttrs(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.issuerAlternativeName.equals(oid)) {
          h2nChecker.checkExtnIssuerAltNames(
                      failureMsg, extnValue, issuerInfo);
        } else if (Extension.basicConstraints.equals(oid)) {
          a2gChecker.checkExtnBasicConstraints(
                      failureMsg, extnValue);
        } else if (Extension.nameConstraints.equals(oid)) {
          h2nChecker.checkExtnNameConstraints(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.policyConstraints.equals(oid)) {
          o2tChecker.checkExtnPolicyConstraints(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.extendedKeyUsage.equals(oid)) {
          a2gChecker.checkExtnExtendedKeyUsage(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.cRLDistributionPoints.equals(oid)) {
          a2gChecker.checkExtnCrlDistributionPoints(
                      failureMsg, extnValue, issuerInfo);
        } else if (Extension.inhibitAnyPolicy.equals(oid)) {
          h2nChecker.checkExtnInhibitAnyPolicy(
                      failureMsg, extnValue, extensions, extnControl);
        } else if (Extension.freshestCRL.equals(oid)) {
          a2gChecker.checkExtnDeltaCrlDistributionPoints(
                      failureMsg, extnValue, issuerInfo);
        } else if (Extension.authorityInfoAccess.equals(oid)) {
          a2gChecker.checkExtnAuthorityInfoAccess(
                      failureMsg, extnValue, issuerInfo);
        } else if (Extension.subjectInfoAccess.equals(oid)) {
          o2tChecker.checkExtnSubjectInfoAccess(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extn.id_extension_admission.equals(oid)) {
          a2gChecker.checkExtnAdmission(
                      failureMsg, extnValue, requestedExtns, requestedSubject, extnControl);
        } else if (Extn.id_extension_pkix_ocsp_nocheck.equals(oid)) {
          o2tChecker.checkExtnOcspNocheck(
                      failureMsg, extnValue);
        } else if (Extn.id_extension_restriction.equals(oid)) {
          o2tChecker.checkExtnRestriction(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extn.id_extension_additionalInformation.equals(oid)) {
          a2gChecker.checkExtnAdditionalInformation(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extn.id_extension_validityModel.equals(oid)) {
          u2zChecker.checkExtnValidityModel(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.privateKeyUsagePeriod.equals(oid)) {
          o2tChecker.checkExtnPrivateKeyUsagePeriod(
                      failureMsg, extnValue, jceCert.getNotBefore(), jceCert.getNotAfter());
        } else if (Extension.qCStatements.equals(oid)) {
          o2tChecker.checkExtnQcStatements(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.biometricInfo.equals(oid)) {
          a2gChecker.checkExtnBiometricInfo(
                      failureMsg, extnValue, requestedExtns);
        } else if (Extn.id_pe_tlsfeature.equals(oid)) {
          o2tChecker.checkExtnTlsFeature(
                      failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extn.id_smimeCapabilities.equals(oid)) {
          o2tChecker.checkSmimeCapabilities(
                      failureMsg, extnValue, extnControl);
        } else if (Extn.id_SCTs.equals(oid)) {
          o2tChecker.checkScts(failureMsg, extnValue, extnControl);
        } else if (Extn.id_GMT_0015_ICRegistrationNumber.equals(oid)
            || Extn.id_GMT_0015_InsuranceNumber.equals(oid)
            || Extn.id_GMT_0015_OrganizationCode.equals(oid)
            || Extn.id_GMT_0015_TaxationNumber.equals(oid)
            || Extn.id_GMT_0015_IdentityCode.equals(oid)) {
          a2gChecker.checkExtnGmt0015(failureMsg, extnValue, requestedExtns, extnControl,
              oid, requestedSubject);
        } else {
          byte[] expected = getExpectedExtValue(oid, requestedExtns, extnControl);
          if (!Arrays.equals(expected, extnValue)) {
            addViolation(failureMsg, "extension value", hex(extnValue),
                (expected == null) ? "not present" : hex(expected));
          }
        }

        if (failureMsg.length() > 0) {
          issue.setFailureMessage(failureMsg.toString());
        }

      } catch (IllegalArgumentException | ClassCastException | IOException
          | ArrayIndexOutOfBoundsException ex) {
        LOG.debug("extension value does not have correct syntax", ex);
        issue.setFailureMessage("extension value does not have correct syntax");
      }
    }

    return result;
  } // method checkExtensions

  private byte[] getExpectedExtValue(ASN1ObjectIdentifier type, Extensions requestedExtns,
      ExtensionControl extControl) {
    if (constantExtensions != null && constantExtensions.containsKey(type)) {
      return constantExtensions.get(type).getValue();
    } else if (requestedExtns != null && extControl.isRequest()) {
      Extension reqExt = requestedExtns.getExtension(type);
      if (reqExt != null) {
        return reqExt.getExtnValue().getOctets();
      }
    }

    return null;
  } // getExpectedExtValue

  private Set<ASN1ObjectIdentifier> getExensionTypes(Certificate cert,
      IssuerInfo issuerInfo, Extensions requestedExtns) {
    Set<ASN1ObjectIdentifier> types = new HashSet<>();
    // profile required extension types
    Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls =
        certprofile.getExtensionControls();

    for (Entry<ASN1ObjectIdentifier, ExtensionControl> entry : extensionControls.entrySet()) {
      ASN1ObjectIdentifier oid = entry.getKey();
      if (entry.getValue().isRequired()) {
        types.add(oid);
      } else if ((requestedExtns != null && requestedExtns.getExtension(oid) != null)
          && (extensionSyntaxes != null && extensionSyntaxes.containsKey(oid))) {
        types.add(oid);
      }
    }

    // Authority key identifier
    ASN1ObjectIdentifier type = Extension.authorityKeyIdentifier;
    if (extensionControls.containsKey(type)) {
      addIfNotIn(types, type);
    }

    // Subject key identifier, Subject Ke
    type = Extension.subjectKeyIdentifier;
    if (extensionControls.containsKey(type)) {
      addIfNotIn(types, type);
    }

    // KeyUsage
    type = Extension.keyUsage;
    if (extensionControls.containsKey(type)) {
      boolean required = false;
      if (requestedExtns != null && requestedExtns.getExtension(type) != null) {
        required = true;
      }

      if (!required) {
        Set<KeyUsageControl> requiredKeyusage = h2nChecker.getKeyusage(true);
        if (isNotEmpty(requiredKeyusage)) {
          required = true;
        }
      }

      if (required) {
        addIfNotIn(types, type);
      }
    }

    // CertificatePolicies
    type = Extension.certificatePolicies;
    if (extensionControls.containsKey(type)) {
      if (certificatePolicies != null) {
        addIfNotIn(types, type);
      }
    }

    // Policy Mappings
    type = Extension.policyMappings;
    if (extensionControls.containsKey(type)) {
      if (policyMappings != null) {
        addIfNotIn(types, type);
      }
    }

    // SubjectAltNames
    type = Extension.subjectAlternativeName;
    if (extensionControls.containsKey(type)) {
      if (requestedExtns != null && requestedExtns.getExtension(type) != null) {
        addIfNotIn(types, type);
      }
    }

    // IssuerAltName
    type = Extension.issuerAlternativeName;
    if (extensionControls.containsKey(type)) {
      if (cert.getTBSCertificate().getExtensions().getExtension(Extension.subjectAlternativeName)
          != null) {
        addIfNotIn(types, type);
      }
    }

    // BasicConstraints
    type = Extension.basicConstraints;
    if (extensionControls.containsKey(type)) {
      addIfNotIn(types, type);
    }

    // Name Constraints
    type = Extension.nameConstraints;
    if (extensionControls.containsKey(type)) {
      if (nameConstraints != null) {
        addIfNotIn(types, type);
      }
    }

    // PolicyConstrains
    type = Extension.policyConstraints;
    if (extensionControls.containsKey(type)) {
      if (policyConstraints != null) {
        addIfNotIn(types, type);
      }
    }

    // ExtendedKeyUsage
    type = Extension.extendedKeyUsage;
    if (extensionControls.containsKey(type)) {
      boolean required = false;
      if (requestedExtns != null && requestedExtns.getExtension(type) != null) {
        required = true;
      }

      if (!required) {
        Set<ExtKeyUsageControl> requiredExtKeyusage = getExtKeyusage(true);
        if (isNotEmpty(requiredExtKeyusage)) {
          required = true;
        }
      }

      if (required) {
        addIfNotIn(types, type);
      }
    }

    // CRLDistributionPoints
    type = Extension.cRLDistributionPoints;
    if (extensionControls.containsKey(type)) {
      if (issuerInfo.getCrlUrls() != null) {
        addIfNotIn(types, type);
      }
    }

    // Inhibit anyPolicy
    type = Extension.inhibitAnyPolicy;
    if (extensionControls.containsKey(type)) {
      if (inhibitAnyPolicy != null) {
        addIfNotIn(types, type);
      }
    }

    // FreshestCRL
    type = Extension.freshestCRL;
    if (extensionControls.containsKey(type)) {
      if (issuerInfo.getDeltaCrlUrls() != null) {
        addIfNotIn(types, type);
      }
    }

    // AuthorityInfoAccess
    type = Extension.authorityInfoAccess;
    if (extensionControls.containsKey(type)) {
      if (issuerInfo.getOcspUrls() != null) {
        addIfNotIn(types, type);
      }
    }

    // SubjectInfoAccess
    type = Extension.subjectInfoAccess;
    if (extensionControls.containsKey(type)) {
      if (requestedExtns != null && requestedExtns.getExtension(type) != null) {
        addIfNotIn(types, type);
      }
    }

    // Admission
    type = Extn.id_extension_admission;
    if (extensionControls.containsKey(type)) {
      if (certprofile.extensions().getAdmission() != null) {
        addIfNotIn(types, type);
      }
    }

    // ocsp-nocheck
    type = Extn.id_extension_pkix_ocsp_nocheck;
    if (extensionControls.containsKey(type)) {
      addIfNotIn(types, type);
    }

    if (requestedExtns != null) {
      ASN1ObjectIdentifier[] extOids = requestedExtns.getExtensionOIDs();
      for (ASN1ObjectIdentifier oid : extOids) {
        if (extensionControls.containsKey(oid)) {
          addIfNotIn(types, oid);
        }
      }
    }

    return types;
  } // method getExensionTypes

  private ValidationIssue createExtensionIssue(ASN1ObjectIdentifier extId) {
    String extName = ObjectIdentifiers.getName(extId);
    if (extName == null) {
      extName = extId.getId().replace('.', '_');
      return new ValidationIssue("X509.EXT." + extName, "extension " + extId.getId());
    } else {
      return new ValidationIssue("X509.EXT." + extName, "extension " + extName
          + " (" + extId.getId() + ")");
    }
  } // method createExtensionIssue

  void checkDirectoryString(ASN1ObjectIdentifier extnType,
      DirectoryStringType type, String text,
      StringBuilder failureMsg, byte[] extensionValue, Extensions requestedExtns,
      ExtensionControl extControl) {
    if (type == null) {
      checkConstantExtnValue(extnType, failureMsg, extensionValue, requestedExtns, extControl);
      return;
    }

    ASN1Primitive asn1;
    try {
      asn1 = ASN1Primitive.fromByteArray(extensionValue);
    } catch (IOException ex) {
      failureMsg.append("invalid syntax of extension value; ");
      return;
    }

    boolean correctStringType;

    switch (type) {
      case bmpString:
        correctStringType = (asn1 instanceof DERBMPString);
        break;
      case printableString:
        correctStringType = (asn1 instanceof DERPrintableString);
        break;
      case teletexString:
        correctStringType = (asn1 instanceof DERT61String);
        break;
      case utf8String:
        correctStringType = (asn1 instanceof DERUTF8String);
        break;
      default:
        throw new IllegalStateException("should not reach here, unknown DirectoryStringType "
            + type);
    } // end switch

    if (!correctStringType) {
      failureMsg.append("extension value is not of type DirectoryString.")
        .append(text).append("; ");
      return;
    }

    String extTextValue = ((ASN1String) asn1).getString();
    if (!text.equals(extTextValue)) {
      addViolation(failureMsg, "content", extTextValue, text);
    }
  } // method checkDirectoryString

  Set<ExtKeyUsageControl> getExtKeyusage(boolean required) {
    Set<ExtKeyUsageControl> ret = new HashSet<>();

    Set<ExtKeyUsageControl> controls = certprofile.extensions().getExtendedKeyusages();
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
    return (constantExtensions == null) ? null : constantExtensions.get(type).getValue();
  }

  void checkConstantExtnValue(ASN1ObjectIdentifier extnType,
      StringBuilder failureMsg, byte[] extensionValue, Extensions requestedExtns,
      ExtensionControl extControl) {
    byte[] expected = getExpectedExtValue(extnType, requestedExtns, extControl);
    if (!Arrays.equals(expected, extensionValue)) {
      addViolation(failureMsg, "extension values", hex(extensionValue),
          (expected == null) ? "not present" : hex(expected));
    }
  } // method checkConstantExtnValue

}
