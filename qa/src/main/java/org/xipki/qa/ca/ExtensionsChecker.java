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

package org.xipki.qa.ca;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.CollectionUtil.isEmpty;
import static org.xipki.util.CollectionUtil.isNotEmpty;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.profile.Certprofile.AuthorityInfoAccessControl;
import org.xipki.ca.api.profile.Certprofile.CertLevel;
import org.xipki.ca.api.profile.Certprofile.ExtKeyUsageControl;
import org.xipki.ca.api.profile.Certprofile.ExtensionControl;
import org.xipki.ca.api.profile.Certprofile.GeneralNameMode;
import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.api.profile.Certprofile.KeyUsageControl;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.TextVadidator;
import org.xipki.ca.certprofile.xijson.AdmissionExtension;
import org.xipki.ca.certprofile.xijson.BiometricInfoOption;
import org.xipki.ca.certprofile.xijson.DirectoryStringType;
import org.xipki.ca.certprofile.xijson.ExtensionSyntaxChecker;
import org.xipki.ca.certprofile.xijson.SubjectDirectoryAttributesControl;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.AdditionalInformation;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicies;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicies.CertificatePolicyInformationType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicies.PolicyQualifier;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.ExtnSyntax;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType.Base;
import org.xipki.ca.certprofile.xijson.conf.InhibitAnyPolicy;
import org.xipki.ca.certprofile.xijson.conf.NameConstraints;
import org.xipki.ca.certprofile.xijson.conf.PolicyConstraints;
import org.xipki.ca.certprofile.xijson.conf.PolicyMappings;
import org.xipki.ca.certprofile.xijson.conf.PolicyMappings.PolicyIdMappingType;
import org.xipki.ca.certprofile.xijson.conf.QcStatements;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.PdsLocationType;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.QcEuLimitValueType;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.QcStatementType;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.QcStatementValueType;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.Range2Type;
import org.xipki.ca.certprofile.xijson.conf.Restriction;
import org.xipki.ca.certprofile.xijson.conf.SmimeCapabilities.SmimeCapability;
import org.xipki.ca.certprofile.xijson.conf.SmimeCapabilities.SmimeCapabilityParameter;
import org.xipki.ca.certprofile.xijson.conf.TlsFeature;
import org.xipki.ca.certprofile.xijson.conf.X509ProfileType;
import org.xipki.qa.ValidationIssue;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.X509Cert;
import org.xipki.security.ctlog.CtLog.SignedCertificateTimestampList;
import org.xipki.security.util.X509Util;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.Hex;
import org.xipki.util.InvalidConfException;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.TripleState;
import org.xipki.util.Validity;

/**
 * Extensions checker.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ExtensionsChecker {

  private static final byte[] DER_NULL = new byte[]{5, 0};

  private static final Logger LOG = LoggerFactory.getLogger(ExtensionsChecker.class);

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
  } // constructor

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
          // AuthorityKeyIdentifier
          checkExtnAuthorityKeyIdentifier(failureMsg, extnValue, issuerInfo);
        } else if (Extension.subjectKeyIdentifier.equals(oid)) {
          // SubjectKeyIdentifier
          checkExtnSubjectKeyIdentifier(failureMsg, extnValue, cert.getSubjectPublicKeyInfo());
        } else if (Extension.keyUsage.equals(oid)) {
          // KeyUsage
          checkExtnKeyUsage(failureMsg, extnValue, jceCert.getKeyUsage(),
              requestedExtns, extnControl);
        } else if (Extension.certificatePolicies.equals(oid)) {
          // CertificatePolicies
          checkExtnCertificatePolicies(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.policyMappings.equals(oid)) {
          // Policy Mappings
          checkExtnPolicyMappings(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.subjectAlternativeName.equals(oid)) {
          // SubjectAltName
          checkExtnSubjectAltName(failureMsg, extnValue, requestedExtns,
              extnControl, requestedSubject);
        } else if (Extension.subjectDirectoryAttributes.equals(oid)) {
          // SubjectDirectoryAttributes
          checkExtnSubjectDirAttrs(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.issuerAlternativeName.equals(oid)) {
          // IssuerAltName
          checkExtnIssuerAltNames(failureMsg, extnValue, issuerInfo);
        } else if (Extension.basicConstraints.equals(oid)) {
          // Basic Constraints
          checkExtnBasicConstraints(failureMsg, extnValue);
        } else if (Extension.nameConstraints.equals(oid)) {
          // Name Constraints
          checkExtnNameConstraints(failureMsg, extnValue, extensions, extnControl);
        } else if (Extension.policyConstraints.equals(oid)) {
          // PolicyConstrains
          checkExtnPolicyConstraints(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.extendedKeyUsage.equals(oid)) {
          // ExtendedKeyUsage
          checkExtnExtendedKeyUsage(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.cRLDistributionPoints.equals(oid)) {
          // CRL Distribution Points
          checkExtnCrlDistributionPoints(failureMsg, extnValue, issuerInfo);
        } else if (Extension.inhibitAnyPolicy.equals(oid)) {
          // Inhibit anyPolicy
          checkExtnInhibitAnyPolicy(failureMsg, extnValue, extensions, extnControl);
        } else if (Extension.freshestCRL.equals(oid)) {
          // Freshest CRL
          checkExtnDeltaCrlDistributionPoints(failureMsg, extnValue, issuerInfo);
        } else if (Extension.authorityInfoAccess.equals(oid)) {
          // Authority Information Access
          checkExtnAuthorityInfoAccess(failureMsg, extnValue, issuerInfo);
        } else if (Extension.subjectInfoAccess.equals(oid)) {
          // SubjectInfoAccess
          checkExtnSubjectInfoAccess(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extn.id_extension_admission.equals(oid)) {
          // Admission
          checkExtnAdmission(failureMsg, extnValue, requestedExtns, requestedSubject, extnControl);
        } else if (Extn.id_extension_pkix_ocsp_nocheck.equals(oid)) {
          // ocsp-nocheck
          checkExtnOcspNocheck(failureMsg, extnValue);
        } else if (Extn.id_extension_restriction.equals(oid)) {
          // restriction
          checkExtnRestriction(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extn.id_extension_additionalInformation.equals(oid)) {
          // additionalInformation
          checkExtnAdditionalInformation(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extn.id_extension_validityModel.equals(oid)) {
          // validityModel
          checkExtnValidityModel(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.privateKeyUsagePeriod.equals(oid)) {
          // privateKeyUsagePeriod
          checkExtnPrivateKeyUsagePeriod(failureMsg, extnValue,
              jceCert.getNotBefore(), jceCert.getNotAfter());
        } else if (Extension.qCStatements.equals(oid)) {
          // qCStatements
          checkExtnQcStatements(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extension.biometricInfo.equals(oid)) {
          // biometricInfo
          checkExtnBiometricInfo(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extn.id_pe_tlsfeature.equals(oid)) {
          // tlsFeature
          checkExtnTlsFeature(failureMsg, extnValue, requestedExtns, extnControl);
        } else if (Extn.id_smimeCapabilities.equals(oid)) {
          byte[] expected = smimeCapabilities.getValue();
          if (!Arrays.equals(expected, extnValue)) {
            addViolation(failureMsg, "extension valus", hex(extnValue),
                (expected == null) ? "not present" : hex(expected));
          }
        } else if (Extn.id_SCTs.equals(oid)) {
          checkScts(failureMsg, extnValue, extnControl);
        } else if (Extn.id_GMT_0015_ICRegistrationNumber.equals(oid)
            || Extn.id_GMT_0015_InsuranceNumber.equals(oid)
            || Extn.id_GMT_0015_OrganizationCode.equals(oid)
            || Extn.id_GMT_0015_TaxationNumber.equals(oid)) {
          String expStr = null;
          Extension extension = requestedExtns == null ? null : requestedExtns.getExtension(oid);
          if (extension != null) {
            // extract from the extension
            expStr = ((ASN1String) extension.getParsedValue()).getString();
          } else {
            // extract from the subject
            RDN[] rdns = requestedSubject.getRDNs(oid);
            if (rdns != null && rdns.length > 0) {
              expStr = X509Util.rdnValueToString(rdns[0].getFirst().getValue());
            }
          }

          if (!(ext.getParsedValue() instanceof DERPrintableString)) {
            failureMsg.append("exension value is not of type PrintableString; ");
          } else {
            String isStr = ((DERPrintableString) ext.getParsedValue()).getString();
            if (!CompareUtil.equalsObject(expStr, isStr)) {
              addViolation(failureMsg, "extension value", isStr, expStr);
            }
          }
        } else if (Extn.id_GMT_0015_IdentityCode.equals(oid)) {
          int tag = -1;
          String extnStr = null;

          Extension extension = requestedExtns == null ? null : requestedExtns.getExtension(oid);

          if (extension != null) {
            // extract from extension
            ASN1Encodable reqExtnValue = extension.getParsedValue();
            if (reqExtnValue instanceof ASN1TaggedObject) {
              ASN1TaggedObject tagged = (ASN1TaggedObject) reqExtnValue;
              tag = tagged.getTagNo();
              // we allow the EXPLICIT in request
              if (tagged.isExplicit()) {
                extnStr = ((ASN1String) tagged.getObject()).getString();
              } else {
                // we also allow the IMPLICIT in request
                if (tag == 0 || tag == 2) {
                  extnStr = DERPrintableString.getInstance(tagged, false).getString();
                } else if (tag == 1) {
                  extnStr = DERUTF8String.getInstance(tagged, false).getString();
                }
              }
            }
          } else {
            String str = null;
            // extract from the subject
            RDN[] rdns = requestedSubject.getRDNs(oid);
            if (rdns != null && rdns.length > 0) {
              str = X509Util.rdnValueToString(rdns[0].getFirst().getValue());
            }

            // [tag]value where tag is only one digit 0, 1 or 2
            if (str.length() > 3 && str.charAt(0) == '[' && str.charAt(2) == ']') {
              tag = Integer.parseInt(str.substring(1, 2));
              extnStr = str.substring(3);
            }
          }

          byte[] expected = null;
          if (StringUtil.isNotBlank(extnStr)) {
            final boolean explicit = true;
            if (tag == 0 || tag == 2) {
              expected =
                  new DERTaggedObject(explicit, tag, new DERPrintableString(extnStr)).getEncoded();
            } else if (tag == 1) {
              expected =
                  new DERTaggedObject(explicit, tag, new DERUTF8String(extnStr)).getEncoded();
            }
          }

          if (!Arrays.equals(expected, extnValue)) {
            addViolation(failureMsg, "extension value", hex(extnValue),
                (expected == null) ? "not present" : hex(expected));
          }
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
    for (ASN1ObjectIdentifier oid : extensionControls.keySet()) {
      if (extensionControls.get(oid).isRequired()) {
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
        Set<KeyUsageControl> requiredKeyusage = getKeyusage(true);
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

  private static void addIfNotIn(Set<ASN1ObjectIdentifier> set, ASN1ObjectIdentifier oid) {
    if (!set.contains(oid)) {
      set.add(oid);
    }
  }

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

  private void checkExtnBasicConstraints(StringBuilder failureMsg, byte[] extensionValue) {
    BasicConstraints bc = BasicConstraints.getInstance(extensionValue);
    CertLevel certLevel = certprofile.getCertLevel();
    boolean ca = (CertLevel.RootCA == certLevel) || (CertLevel.SubCA == certLevel);
    if (ca != bc.isCA()) {
      addViolation(failureMsg, "ca", bc.isCA(), ca);
    }

    if (!bc.isCA()) {
      return;
    }

    BigInteger tmpPathLen = bc.getPathLenConstraint();
    Integer pathLen = certprofile.extensions().getPathLen();
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

  private void checkExtnSubjectKeyIdentifier(StringBuilder failureMsg,
      byte[] extensionValue, SubjectPublicKeyInfo subjectPublicKeyInfo) {
    // subjectKeyIdentifier
    SubjectKeyIdentifier asn1 = SubjectKeyIdentifier.getInstance(extensionValue);
    byte[] ski = asn1.getKeyIdentifier();
    byte[] pkData = subjectPublicKeyInfo.getPublicKeyData().getBytes();
    byte[] expectedSki = HashAlgo.SHA1.hash(pkData);
    if (!Arrays.equals(expectedSki, ski)) {
      addViolation(failureMsg, "SKI", hex(ski), hex(expectedSki));
    }
  } // method checkExtnSubjectKeyIdentifier

  private void checkExtnAuthorityKeyIdentifier(StringBuilder failureMsg,
      byte[] extensionValue, IssuerInfo issuerInfo) {
    AuthorityKeyIdentifier asn1 = AuthorityKeyIdentifier.getInstance(extensionValue);
    byte[] keyIdentifier = asn1.getKeyIdentifier();
    BigInteger authorityCertSerialNumber = asn1.getAuthorityCertSerialNumber();
    GeneralNames authorityCertIssuer = asn1.getAuthorityCertIssuer();

    if (certprofile.useIssuerAndSerialInAki()) {
      if (authorityCertIssuer == null) {
        failureMsg.append("authorityCertIssuer is 'absent', but expected 'present'; ");
      } else {
        GeneralName[] genNames = authorityCertIssuer.getNames();
        X500Name x500GenName = null;
        for (GeneralName genName : genNames) {
          if (genName.getTagNo() != GeneralName.directoryName) {
            continue;
          }

          if (x500GenName != null) {
            failureMsg.append("authorityCertIssuer contains at least two directoryName "
                + "but expected one; ");
            break;
          } else {
            x500GenName = (X500Name) genName.getName();
          }
        }

        if (x500GenName == null) {
          failureMsg.append(
              "authorityCertIssuer does not contain directoryName but expected one; ");
        } else {
          X500Name caIssuer = issuerInfo.getCert().getIssuer();
          if (!caIssuer.equals(x500GenName)) {
            addViolation(failureMsg, "authorityCertIssuer", x500GenName, caIssuer);
          }
        }
      }

      if (authorityCertSerialNumber == null) {
        failureMsg.append("authorityCertSerialNumber is 'absent', but expected 'present'; ");
      } else {
        BigInteger issuerSn = issuerInfo.getCert().getSerialNumber();
        if (!issuerSn.equals(authorityCertSerialNumber)) {
          addViolation(failureMsg, "authorityCertSerialNumber",
              authorityCertSerialNumber, issuerSn);
        }
      }

      if (keyIdentifier != null) {
        failureMsg.append("keyIdentifier is 'present', but expected 'absent'; ");
      }

    } else {
      if (keyIdentifier == null) {
        failureMsg.append("keyIdentifier is 'absent', but expected 'present'; ");
      } else {
        if (!Arrays.equals(issuerInfo.getSubjectKeyIdentifier(), keyIdentifier)) {
          addViolation(failureMsg, "keyIdentifier", hex(keyIdentifier),
              hex(issuerInfo.getSubjectKeyIdentifier()));
        }
      }

      if (authorityCertIssuer != null) {
        failureMsg.append("authorityCertIssuer is 'present', but expected 'absent'; ");
      }

      if (authorityCertSerialNumber != null) {
        failureMsg.append("authorityCertSerialNumber is 'present', but expected 'absent'; ");
      }
    }

  } // method checkExtnIssuerKeyIdentifier

  private void checkExtnNameConstraints(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    NameConstraints conf = nameConstraints;
    if (conf == null) {
      checkConstantExtnValue(Extension.nameConstraints, failureMsg, extensionValue, requestedExtns,
          extControl);
      return;
    }

    org.bouncycastle.asn1.x509.NameConstraints tmpNameConstraints =
        org.bouncycastle.asn1.x509.NameConstraints.getInstance(extensionValue);

    checkExtnNameConstraintsSubtrees(failureMsg, "PermittedSubtrees",
        tmpNameConstraints.getPermittedSubtrees(),  conf.getPermittedSubtrees());
    checkExtnNameConstraintsSubtrees(failureMsg, "ExcludedSubtrees",
        tmpNameConstraints.getExcludedSubtrees(), conf.getExcludedSubtrees());
  } // method checkExtnNameConstraints

  private void checkExtnNameConstraintsSubtrees(StringBuilder failureMsg, String description,
      GeneralSubtree[] subtrees, List<GeneralSubtreeType> expectedSubtrees) {
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
      BigInteger bigInt = isSubtree.getMinimum();
      int isMinimum = (bigInt == null) ? 0 : bigInt.intValue();
      Integer minimum = expSubtree.getMinimum();
      int expMinimum = (minimum == null) ? 0 : minimum.intValue();
      String desc = description + " [" + i + "]";
      if (isMinimum != expMinimum) {
        addViolation(failureMsg, "minimum of " + desc, isMinimum, expMinimum);
      }

      bigInt = isSubtree.getMaximum();
      Integer isMaximum = (bigInt == null) ? null : bigInt.intValue();
      Integer expMaximum = expSubtree.getMaximum();
      if (!CompareUtil.equalsObject(isMaximum, expMaximum)) {
        addViolation(failureMsg, "maxmum of " + desc, isMaximum, expMaximum);
      }

      GeneralName isBase = isSubtree.getBase();

      Base expBase0 = expSubtree.getBase();

      GeneralName expBase;
      if (expSubtree.getBase().getDirectoryName() != null) {
        expBase = new GeneralName(
            X509Util.reverse(
                new X500Name(expBase0.getDirectoryName())));
      } else if (expBase0.getDnsName() != null) {
        expBase = new GeneralName(GeneralName.dNSName, expBase0.getDnsName());
      } else if (expBase0.getIpAddress() != null) {
        expBase = new GeneralName(GeneralName.iPAddress, expBase0.getIpAddress());
      } else if (expBase0.getRfc822Name() != null) {
        expBase = new GeneralName(GeneralName.rfc822Name, expBase0.getRfc822Name());
      } else if (expBase0.getUri() != null) {
        expBase = new GeneralName(GeneralName.uniformResourceIdentifier, expBase0.getUri());
      } else {
        throw new IllegalStateException("should not reach here, unknown child of GeneralName");
      }

      if (!isBase.equals(expBase)) {
        addViolation(failureMsg, "base of " + desc, isBase, expBase);
      }
    }
  } // method checkExtnNameConstraintsSubtrees

  private void checkExtnPolicyConstraints(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    PolicyConstraints conf = policyConstraints;
    if (conf == null) {
      checkConstantExtnValue(Extension.policyConstraints, failureMsg, extensionValue,
          requestedExtns, extControl);
      return;
    }

    org.bouncycastle.asn1.x509.PolicyConstraints isPolicyConstraints =
        org.bouncycastle.asn1.x509.PolicyConstraints.getInstance(extensionValue);
    Integer expRequireExplicitPolicy = conf.getRequireExplicitPolicy();
    BigInteger bigInt = isPolicyConstraints.getRequireExplicitPolicyMapping();
    Integer isRequireExplicitPolicy = (bigInt == null) ? null : bigInt.intValue();

    boolean match = true;
    if (expRequireExplicitPolicy == null) {
      if (isRequireExplicitPolicy != null) {
        match = false;
      }
    } else if (!expRequireExplicitPolicy.equals(isRequireExplicitPolicy)) {
      match = false;
    }

    if (!match) {
      addViolation(failureMsg, "requireExplicitPolicy", isRequireExplicitPolicy,
          expRequireExplicitPolicy);
    }

    Integer expInhibitPolicyMapping = conf.getInhibitPolicyMapping();
    bigInt = isPolicyConstraints.getInhibitPolicyMapping();
    Integer isInhibitPolicyMapping = (bigInt == null) ? null : bigInt.intValue();

    match = true;
    if (expInhibitPolicyMapping == null) {
      if (isInhibitPolicyMapping != null) {
        match = false;
      }
    } else if (!expInhibitPolicyMapping.equals(isInhibitPolicyMapping)) {
      match = false;
    }

    if (!match) {
      addViolation(failureMsg, "inhibitPolicyMapping", isInhibitPolicyMapping,
          expInhibitPolicyMapping);
    }
  } // method checkExtnPolicyConstraints

  private void checkExtnKeyUsage(StringBuilder failureMsg, byte[] extensionValue,
      boolean[] usages, Extensions requestedExtns, ExtensionControl extControl) {
    int len = usages.length;

    if (len > 9) {
      failureMsg.append("invalid syntax: size of valid bits is larger than 9: ").append(len);
      failureMsg.append("; ");
    }

    Set<String> isUsages = new HashSet<>();
    for (int i = 0; i < len; i++) {
      if (usages[i]) {
        isUsages.add(ALL_USAGES.get(i));
      }
    }

    Set<String> expectedUsages = new HashSet<>();
    Set<KeyUsageControl> requiredKeyusage = getKeyusage(true);
    for (KeyUsageControl usage : requiredKeyusage) {
      expectedUsages.add(usage.getKeyUsage().getName());
    }

    Set<KeyUsageControl> optionalKeyusage = getKeyusage(false);
    if (requestedExtns != null && extControl.isRequest()
        && isNotEmpty(optionalKeyusage)) {
      Extension extension = requestedExtns.getExtension(Extension.keyUsage);
      if (extension != null) {
        org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
            org.bouncycastle.asn1.x509.KeyUsage.getInstance(extension.getParsedValue());
        for (KeyUsageControl k : optionalKeyusage) {
          if (reqKeyUsage.hasUsages(k.getKeyUsage().getBcUsage())) {
            expectedUsages.add(k.getKeyUsage().getName());
          }
        }
      }
    }

    if (isEmpty(expectedUsages)) {
      byte[] constantExtValue = getConstantExtensionValue(Extension.keyUsage);
      if (constantExtValue != null) {
        expectedUsages = getKeyUsage(constantExtValue);
      }
    }

    Set<String> diffs = strInBnotInA(expectedUsages, isUsages);
    if (isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs).append(" are present but not expected; ");
    }

    diffs = strInBnotInA(isUsages, expectedUsages);
    if (isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs).append(" are absent but are required; ");
    }
  } // method checkExtnKeyUsage

  private void checkExtnExtendedKeyUsage(StringBuilder failureMsg,
      byte[] extensionValue, Extensions requestedExtns, ExtensionControl extControl) {
    Set<String> isUsages = new HashSet<>();
    org.bouncycastle.asn1.x509.ExtendedKeyUsage keyusage =
        org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extensionValue);
    KeyPurposeId[] usages = keyusage.getUsages();
    if (usages != null) {
      for (KeyPurposeId usage : usages) {
        isUsages.add(usage.getId());
      }
    }

    Set<String> expectedUsages = new HashSet<>();
    Set<ExtKeyUsageControl> requiredExtKeyusage = getExtKeyusage(true);
    if (requiredExtKeyusage != null) {
      for (ExtKeyUsageControl usage : requiredExtKeyusage) {
        expectedUsages.add(usage.getExtKeyUsage().getId());
      }
    }

    Set<ExtKeyUsageControl> optionalExtKeyusage = getExtKeyusage(false);
    if (requestedExtns != null && extControl.isRequest()
        && isNotEmpty(optionalExtKeyusage)) {
      Extension extension = requestedExtns.getExtension(Extension.extendedKeyUsage);
      if (extension != null) {
        org.bouncycastle.asn1.x509.ExtendedKeyUsage reqKeyUsage =
            org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extension.getParsedValue());
        for (ExtKeyUsageControl k : optionalExtKeyusage) {
          if (reqKeyUsage.hasKeyPurposeId(KeyPurposeId.getInstance(k.getExtKeyUsage()))) {
            expectedUsages.add(k.getExtKeyUsage().getId());
          }
        }
      }
    }

    if (isEmpty(expectedUsages)) {
      byte[] constantExtValue = getConstantExtensionValue(Extension.extendedKeyUsage);
      if (constantExtValue != null) {
        expectedUsages = getExtKeyUsage(constantExtValue);
      }
    }

    Set<String> diffs = strInBnotInA(expectedUsages, isUsages);
    if (isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs).append(" are present but not expected; ");
    }

    diffs = strInBnotInA(isUsages, expectedUsages);
    if (isNotEmpty(diffs)) {
      failureMsg.append("usages ").append(diffs).append(" are absent but are required; ");
    }
  } // method checkExtnExtendedKeyUsage

  private void checkExtnTlsFeature(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    TlsFeature conf = tlsFeature;
    if (tlsFeature == null) {
      checkConstantExtnValue(Extn.id_pe_tlsfeature, failureMsg, extensionValue,
          requestedExtns, extControl);
      return;
    }

    Set<String> isFeatures = new HashSet<>();
    ASN1Sequence seq = ASN1Sequence.getInstance(extensionValue);
    final int n = seq.size();
    for (int i = 0; i < n; i++) {
      ASN1Integer asn1Feature = ASN1Integer.getInstance(seq.getObjectAt(i));
      isFeatures.add(asn1Feature.getPositiveValue().toString());
    }

    Set<String> expFeatures = new HashSet<>();
    for (DescribableInt m : conf.getFeatures()) {
      expFeatures.add(Integer.toString(m.getValue()));
    }

    Set<String> diffs = strInBnotInA(expFeatures, isFeatures);
    if (isNotEmpty(diffs)) {
      failureMsg.append("features ").append(diffs).append(" are present but not expected; ");
    }

    diffs = strInBnotInA(isFeatures, expFeatures);
    if (isNotEmpty(diffs)) {
      failureMsg.append("features ").append(diffs).append(" are absent but are required; ");
    }
  } // method checkExtnTlsFeature

  private void checkExtnCertificatePolicies(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    CertificatePolicies conf = certificatePolicies;
    if (conf == null) {
      checkConstantExtnValue(Extension.certificatePolicies, failureMsg, extensionValue,
          requestedExtns, extControl);
      return;
    }

    Map<String, CertificatePolicyInformationType> expPoliciesMap = new HashMap<>();
    for (CertificatePolicyInformationType cp : conf.getCertificatePolicyInformations()) {
      expPoliciesMap.put(cp.getPolicyIdentifier().getOid(), cp);
    }
    Set<String> expPolicyIds = new HashSet<>(expPoliciesMap.keySet());

    org.bouncycastle.asn1.x509.CertificatePolicies asn1 =
        org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(extensionValue);
    PolicyInformation[] isPolicyInformations = asn1.getPolicyInformation();

    for (PolicyInformation isPolicyInformation : isPolicyInformations) {
      ASN1ObjectIdentifier isPolicyId = isPolicyInformation.getPolicyIdentifier();
      expPolicyIds.remove(isPolicyId.getId());
      CertificatePolicyInformationType expCp = expPoliciesMap.get(isPolicyId.getId());
      if (expCp == null) {
        failureMsg.append("certificate policy '").append(isPolicyId).append("' is not expected; ");
        continue;
      }

      List<PolicyQualifier> expCpPq = expCp.getPolicyQualifiers();
      if (isEmpty(expCpPq)) {
        continue;
      }

      ASN1Sequence isPolicyQualifiers = isPolicyInformation.getPolicyQualifiers();
      List<String> isCpsUris = new LinkedList<>();
      List<String> isUserNotices = new LinkedList<>();

      int size = isPolicyQualifiers.size();
      for (int i = 0; i < size; i++) {
        PolicyQualifierInfo isPolicyQualifierInfo =
            PolicyQualifierInfo.getInstance(isPolicyQualifiers.getObjectAt(i));
        ASN1ObjectIdentifier isPolicyQualifierId = isPolicyQualifierInfo.getPolicyQualifierId();
        ASN1Encodable isQualifier = isPolicyQualifierInfo.getQualifier();
        if (PolicyQualifierId.id_qt_cps.equals(isPolicyQualifierId)) {
          String isCpsUri = DERIA5String.getInstance(isQualifier).getString();
          isCpsUris.add(isCpsUri);
        } else if (PolicyQualifierId.id_qt_unotice.equals(isPolicyQualifierId)) {
          UserNotice isUserNotice = UserNotice.getInstance(isQualifier);
          if (isUserNotice.getExplicitText() != null) {
            isUserNotices.add(isUserNotice.getExplicitText().getString());
          }
        }
      }

      for (PolicyQualifier qualifierInfo : expCpPq) {
        String value = qualifierInfo.getValue();
        switch (qualifierInfo.getType()) {
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

  private void checkExtnPolicyMappings(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    PolicyMappings conf = policyMappings;
    if (conf == null) {
      checkConstantExtnValue(Extension.policyMappings, failureMsg, extensionValue,
          requestedExtns, extControl);
      return;
    }

    ASN1Sequence isPolicyMappings = DERSequence.getInstance(extensionValue);
    Map<String, String> isMap = new HashMap<>();
    int size = isPolicyMappings.size();
    for (int i = 0; i < size; i++) {
      ASN1Sequence seq = ASN1Sequence.getInstance(isPolicyMappings.getObjectAt(i));
      CertPolicyId issuerDomainPolicy = CertPolicyId.getInstance(seq.getObjectAt(0));
      CertPolicyId subjectDomainPolicy = CertPolicyId.getInstance(seq.getObjectAt(1));
      isMap.put(issuerDomainPolicy.getId(), subjectDomainPolicy.getId());
    }

    for (PolicyIdMappingType m : conf.getMappings()) {
      String expIssuerDomainPolicy = m.getIssuerDomainPolicy().getOid();
      String expSubjectDomainPolicy = m.getSubjectDomainPolicy().getOid();

      String isSubjectDomainPolicy = isMap.remove(expIssuerDomainPolicy);
      if (isSubjectDomainPolicy == null) {
        failureMsg.append("issuerDomainPolicy '").append(expIssuerDomainPolicy)
          .append("' is absent but is required; ");
      } else if (!isSubjectDomainPolicy.equals(expSubjectDomainPolicy)) {
        addViolation(failureMsg, "subjectDomainPolicy for issuerDomainPolicy",
            isSubjectDomainPolicy, expSubjectDomainPolicy);
      }
    }

    if (isNotEmpty(isMap)) {
      failureMsg.append("issuerDomainPolicies '").append(isMap.keySet())
        .append("' are present but not expected; ");
    }
  } // method checkExtnPolicyMappings

  private void checkExtnInhibitAnyPolicy(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    InhibitAnyPolicy conf = inhibitAnyPolicy;
    if (conf == null) {
      checkConstantExtnValue(Extension.inhibitAnyPolicy, failureMsg, extensionValue,
          requestedExtns, extControl);
      return;
    }

    ASN1Integer asn1Int = ASN1Integer.getInstance(extensionValue);
    int isSkipCerts = asn1Int.getPositiveValue().intValue();
    if (isSkipCerts != conf.getSkipCerts()) {
      addViolation(failureMsg, "skipCerts", isSkipCerts, conf.getSkipCerts());
    }
  } // method checkExtnInhibitAnyPolicy

  private void checkExtnSubjectDirAttrs(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    SubjectDirectoryAttributesControl conf = certprofile.extensions().getSubjectDirAttrsControl();
    if (conf == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    ASN1Encodable extInRequest = null;
    if (requestedExtns != null) {
      extInRequest = requestedExtns.getExtensionParsedValue(
          Extension.subjectDirectoryAttributes);
    }

    if (extInRequest == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    SubjectDirectoryAttributes requested = SubjectDirectoryAttributes.getInstance(extInRequest);
    Vector<?> reqSubDirAttrs = requested.getAttributes();
    ASN1GeneralizedTime expDateOfBirth = null;
    String expPlaceOfBirth = null;
    String expGender = null;
    Set<String> expCountryOfCitizenshipList = new HashSet<>();
    Set<String> expCountryOfResidenceList = new HashSet<>();
    Map<ASN1ObjectIdentifier, Set<ASN1Encodable>> expOtherAttrs = new HashMap<>();

    final int expN = reqSubDirAttrs.size();
    for (int i = 0; i < expN; i++) {
      Attribute attr = Attribute.getInstance(reqSubDirAttrs.get(i));
      ASN1ObjectIdentifier attrType = attr.getAttrType();
      ASN1Encodable attrVal = attr.getAttributeValues()[0];

      if (ObjectIdentifiers.DN.dateOfBirth.equals(attrType)) {
        expDateOfBirth = ASN1GeneralizedTime.getInstance(attrVal);
      } else if (ObjectIdentifiers.DN.placeOfBirth.equals(attrType)) {
        expPlaceOfBirth = DirectoryString.getInstance(attrVal).getString();
      } else if (ObjectIdentifiers.DN.gender.equals(attrType)) {
        expGender = DERPrintableString.getInstance(attrVal).getString();
      } else if (ObjectIdentifiers.DN.countryOfCitizenship.equals(attrType)) {
        String country = DERPrintableString.getInstance(attrVal).getString();
        expCountryOfCitizenshipList.add(country);
      } else if (ObjectIdentifiers.DN.countryOfResidence.equals(attrType)) {
        String country = DERPrintableString.getInstance(attrVal).getString();
        expCountryOfResidenceList.add(country);
      } else {
        Set<ASN1Encodable> otherAttrVals = expOtherAttrs.get(attrType);
        if (otherAttrVals == null) {
          otherAttrVals = new HashSet<>();
          expOtherAttrs.put(attrType, otherAttrVals);
        }
        otherAttrVals.add(attrVal);
      }
    }

    SubjectDirectoryAttributes ext = SubjectDirectoryAttributes.getInstance(extensionValue);
    Vector<?> subDirAttrs = ext.getAttributes();
    ASN1GeneralizedTime dateOfBirth = null;
    String placeOfBirth = null;
    String gender = null;
    Set<String> countryOfCitizenshipList = new HashSet<>();
    Set<String> countryOfResidenceList = new HashSet<>();
    Map<ASN1ObjectIdentifier, Set<ASN1Encodable>> otherAttrs = new HashMap<>();

    List<ASN1ObjectIdentifier> attrTypes = new LinkedList<>(conf.getTypes());
    final int n = subDirAttrs.size();
    for (int i = 0; i < n; i++) {
      Attribute attr = Attribute.getInstance(subDirAttrs.get(i));
      ASN1ObjectIdentifier attrType = attr.getAttrType();
      if (!attrTypes.contains(attrType)) {
        failureMsg.append("attribute of type " + attrType.getId())
          .append(" is present but not expected; ");
        continue;
      }

      ASN1Encodable[] attrs = attr.getAttributeValues();
      if (attrs.length != 1) {
        failureMsg.append("attribute of type ").append(attrType.getId())
          .append(" does not single-value value: ").append(attrs.length).append("; ");
        continue;
      }

      ASN1Encodable attrVal = attrs[0];

      if (ObjectIdentifiers.DN.dateOfBirth.equals(attrType)) {
        dateOfBirth = ASN1GeneralizedTime.getInstance(attrVal);
      } else if (ObjectIdentifiers.DN.placeOfBirth.equals(attrType)) {
        placeOfBirth = DirectoryString.getInstance(attrVal).getString();
      } else if (ObjectIdentifiers.DN.gender.equals(attrType)) {
        gender = DERPrintableString.getInstance(attrVal).getString();
      } else if (ObjectIdentifiers.DN.countryOfCitizenship.equals(attrType)) {
        String country = DERPrintableString.getInstance(attrVal).getString();
        countryOfCitizenshipList.add(country);
      } else if (ObjectIdentifiers.DN.countryOfResidence.equals(attrType)) {
        String country = DERPrintableString.getInstance(attrVal).getString();
        countryOfResidenceList.add(country);
      } else {
        Set<ASN1Encodable> otherAttrVals = otherAttrs.get(attrType);
        if (otherAttrVals == null) {
          otherAttrVals = new HashSet<>();
          otherAttrs.put(attrType, otherAttrVals);
        }
        otherAttrVals.add(attrVal);
      }
    }

    if (dateOfBirth != null) {
      attrTypes.remove(ObjectIdentifiers.DN.dateOfBirth);
    }

    if (placeOfBirth != null) {
      attrTypes.remove(ObjectIdentifiers.DN.placeOfBirth);
    }

    if (gender != null) {
      attrTypes.remove(ObjectIdentifiers.DN.gender);
    }

    if (!countryOfCitizenshipList.isEmpty()) {
      attrTypes.remove(ObjectIdentifiers.DN.countryOfCitizenship);
    }

    if (!countryOfResidenceList.isEmpty()) {
      attrTypes.remove(ObjectIdentifiers.DN.countryOfResidence);
    }

    attrTypes.removeAll(otherAttrs.keySet());

    if (!attrTypes.isEmpty()) {
      List<String> attrTypeTexts = new LinkedList<>();
      for (ASN1ObjectIdentifier oid : attrTypes) {
        attrTypeTexts.add(oid.getId());
      }
      failureMsg.append("required attributes of types ").append(attrTypeTexts)
        .append(" are not present; ");
    }

    if (dateOfBirth != null) {
      String timeStirng = dateOfBirth.getTimeString();
      if (!TextVadidator.DATE_OF_BIRTH.isValid(timeStirng)) {
        failureMsg.append("invalid dateOfBirth: " + timeStirng + "; ");
      }

      String exp = (expDateOfBirth == null) ? null : expDateOfBirth.getTimeString();
      if (!timeStirng.equalsIgnoreCase(exp)) {
        addViolation(failureMsg, "dateOfBirth", timeStirng, exp);
      }
    }

    if (gender != null) {
      if (!(gender.equalsIgnoreCase("F") || gender.equalsIgnoreCase("M"))) {
        failureMsg.append("invalid gender: ").append(gender).append("; ");
      }
      if (!gender.equalsIgnoreCase(expGender)) {
        addViolation(failureMsg, "gender", gender, expGender);
      }
    }

    if (placeOfBirth != null) {
      if (!placeOfBirth.equals(expPlaceOfBirth)) {
        addViolation(failureMsg, "placeOfBirth", placeOfBirth, expPlaceOfBirth);
      }
    }

    if (!countryOfCitizenshipList.isEmpty()) {
      Set<String> diffs = strInBnotInA(expCountryOfCitizenshipList, countryOfCitizenshipList);
      if (isNotEmpty(diffs)) {
        failureMsg.append("countryOfCitizenship ").append(diffs)
          .append(" are present but not expected; ");
      }

      diffs = strInBnotInA(countryOfCitizenshipList, expCountryOfCitizenshipList);
      if (isNotEmpty(diffs)) {
        failureMsg.append("countryOfCitizenship ").append(diffs)
          .append(" are absent but are required; ");
      }
    }

    if (!countryOfResidenceList.isEmpty()) {
      Set<String> diffs = strInBnotInA(expCountryOfResidenceList, countryOfResidenceList);
      if (isNotEmpty(diffs)) {
        failureMsg.append("countryOfResidence ").append(diffs)
          .append(" are present but not expected; ");
      }

      diffs = strInBnotInA(countryOfResidenceList, expCountryOfResidenceList);
      if (isNotEmpty(diffs)) {
        failureMsg.append("countryOfResidence ").append(diffs)
          .append(" are absent but are required; ");
      }
    }

    if (!otherAttrs.isEmpty()) {
      for (ASN1ObjectIdentifier attrType : otherAttrs.keySet()) {
        Set<ASN1Encodable> expAttrValues = expOtherAttrs.get(attrType);
        if (expAttrValues == null) {
          failureMsg.append("attribute of type ").append(attrType.getId())
              .append(" is present but not requested; ");
          continue;
        }

        Set<ASN1Encodable> attrValues = otherAttrs.get(attrType);
        if (!attrValues.equals(expAttrValues)) {
          failureMsg.append("attribute of type ").append(attrType.getId())
            .append(" differs from the requested one; ");
          continue;
        }
      }
    }
  } // method checkExtnSubjectDirectoryAttributes

  private void checkExtnSubjectAltName(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl, X500Name requestedSubject) {
    Set<GeneralNameMode> conf = certprofile.getSubjectAltNameModes();

    GeneralName[] requested;
    try {
      requested = getRequestedSubjectAltNames(requestedSubject, requestedExtns);
    } catch (CertprofileException | BadCertTemplateException ex) {
      String msg = "error while derive grantedSubject from requestedSubject";
      LogUtil.warn(LOG, ex, msg);
      failureMsg.append(msg);
      return;
    }

    if (requested == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    GeneralName[] is = GeneralNames.getInstance(extensionValue).getNames();

    GeneralName[] expected = new GeneralName[requested.length];
    for (int i = 0; i < is.length; i++) {
      try {
        expected[i] = createGeneralName(is[i], conf);
      } catch (BadCertTemplateException ex) {
        failureMsg.append("could not process ").append(i + 1).append("-th name: ")
          .append(ex.getMessage()).append("; ");
        return;
      }
    }

    if (is.length != expected.length) {
      addViolation(failureMsg, "size of GeneralNames", is.length, expected.length);
      return;
    }

    for (int i = 0; i < is.length; i++) {
      if (!is[i].equals(expected[i])) {
        failureMsg.append(i + 1).append("-th name does not match the requested one; ");
      }
    }
  } // method checkExtnSubjectAltName

  private GeneralName[] getRequestedSubjectAltNames(X500Name requestedSubject,
      Extensions requestedExtns)
          throws CertprofileException, BadCertTemplateException {
    ASN1Encodable extValue = (requestedExtns == null) ? null
        : requestedExtns.getExtensionParsedValue(Extension.subjectAlternativeName);

    Map<ASN1ObjectIdentifier, GeneralNameTag> subjectToSubjectAltNameModes =
        certprofile.extensions().getSubjectToSubjectAltNameModes();
    if (extValue == null && subjectToSubjectAltNameModes == null) {
      return null;
    }

    GeneralNames reqNames = (extValue == null) ? null : GeneralNames.getInstance(extValue);

    Set<GeneralNameMode> subjectAltNameModes = certprofile.getSubjectAltNameModes();
    if (subjectAltNameModes == null && subjectToSubjectAltNameModes == null) {
      return (reqNames == null) ? null : reqNames.getNames();
    }

    List<GeneralName> grantedNames = new LinkedList<>();
    // copy the required attributes of Subject
    if (subjectToSubjectAltNameModes != null) {
      X500Name grantedSubject = certprofile.getSubject(requestedSubject).getGrantedSubject();

      for (ASN1ObjectIdentifier attrType : subjectToSubjectAltNameModes.keySet()) {
        GeneralNameTag tag = subjectToSubjectAltNameModes.get(attrType);

        RDN[] rdns = grantedSubject.getRDNs(attrType);
        if (rdns == null || rdns.length == 0) {
          rdns = requestedSubject.getRDNs(attrType);
        }

        if (rdns == null || rdns.length == 0) {
          continue;
        }

        for (RDN rdn : rdns) {
          String rdnValue = X509Util.rdnValueToString(rdn.getFirst().getValue());
          switch (tag) {
            case rfc822Name:
              grantedNames.add(new GeneralName(tag.getTag(), rdnValue.toLowerCase()));
              break;
            case DNSName:
            case uniformResourceIdentifier:
            case IPAddress:
            case directoryName:
            case registeredID:
              grantedNames.add(new GeneralName(tag.getTag(), rdnValue));
              break;
            default:
              throw new IllegalStateException(
                  "should not reach here, unknown GeneralName tag " + tag);
          } // end switch (tag)
        }
      }
    }

    // copy the requested SubjectAltName entries
    if (reqNames != null) {
      GeneralName[] reqL = reqNames.getNames();
      for (int i = 0; i < reqL.length; i++) {
        grantedNames.add(reqL[i]);
      }
    }

    return grantedNames.isEmpty() ? null : grantedNames.toArray(new GeneralName[0]);
  } // getRequestedSubjectAltNames

  private void checkExtnSubjectInfoAccess(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> conf =
        certprofile.getSubjectInfoAccessModes();
    if (conf == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    ASN1Encodable requestExtValue = null;
    if (requestedExtns != null) {
      requestExtValue = requestedExtns.getExtensionParsedValue(Extension.subjectInfoAccess);
    }
    if (requestExtValue == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    ASN1Sequence requestSeq = ASN1Sequence.getInstance(requestExtValue);
    ASN1Sequence certSeq = ASN1Sequence.getInstance(extensionValue);

    int size = requestSeq.size();

    if (certSeq.size() != size) {
      addViolation(failureMsg, "size of GeneralNames", certSeq.size(), size);
      return;
    }

    for (int i = 0; i < size; i++) {
      AccessDescription ad = AccessDescription.getInstance(requestSeq.getObjectAt(i));
      ASN1ObjectIdentifier accessMethod = ad.getAccessMethod();
      Set<GeneralNameMode> generalNameModes = conf.get(accessMethod);

      if (generalNameModes == null) {
        failureMsg.append("accessMethod in requestedExtension ")
          .append(accessMethod.getId()).append(" is not allowed; ");
        continue;
      }

      AccessDescription certAccessDesc = AccessDescription.getInstance(
          certSeq.getObjectAt(i));
      ASN1ObjectIdentifier certAccessMethod = certAccessDesc.getAccessMethod();

      boolean bo = (accessMethod == null) ? (certAccessMethod == null)
          : accessMethod.equals(certAccessMethod);

      if (!bo) {
        addViolation(failureMsg, "accessMethod",
            (certAccessMethod == null) ? "null" : certAccessMethod.getId(),
            (accessMethod == null) ? "null" : accessMethod.getId());
        continue;
      }

      GeneralName accessLocation;
      try {
        accessLocation = createGeneralName(ad.getAccessLocation(), generalNameModes);
      } catch (BadCertTemplateException ex) {
        failureMsg.append("invalid requestedExtension: ").append(ex.getMessage()).append("; ");
        continue;
      }

      GeneralName certAccessLocation = certAccessDesc.getAccessLocation();
      if (!certAccessLocation.equals(accessLocation)) {
        failureMsg.append("accessLocation does not match the requested one; ");
      }
    }
  } // method checkExtnSubjectInfoAccess

  private void checkExtnIssuerAltNames(StringBuilder failureMsg, byte[] extensionValue,
      IssuerInfo issuerInfo) {
    byte[] caSubjectAltExtensionValue = issuerInfo.getCert().getExtensionCoreValue(
        Extension.subjectAlternativeName);
    if (caSubjectAltExtensionValue == null) {
      failureMsg.append("issuerAlternativeName is present but expected 'none'; ");
      return;
    }

    if (!Arrays.equals(caSubjectAltExtensionValue, extensionValue)) {
      addViolation(failureMsg, "issuerAltNames", hex(extensionValue),
          hex(caSubjectAltExtensionValue));
    }
  } // method checkExtnIssuerAltNames

  private void checkExtnCrlDistributionPoints(StringBuilder failureMsg,
      byte[] extensionValue, IssuerInfo issuerInfo) {
    CRLDistPoint isCrlDistPoints = CRLDistPoint.getInstance(extensionValue);
    DistributionPoint[] isDistributionPoints = isCrlDistPoints.getDistributionPoints();
    if (isDistributionPoints == null) {
      addViolation(failureMsg, "size of CRLDistributionPoints", 0, 1);
      return;
    } else {
      int len = isDistributionPoints.length;
      if (len != 1) {
        addViolation(failureMsg, "size of CRLDistributionPoints", len, 1);
        return;
      }
    }

    Set<String> isCrlUrls = new HashSet<>();
    for (DistributionPoint entry : isDistributionPoints) {
      int asn1Type = entry.getDistributionPoint().getType();
      if (asn1Type != DistributionPointName.FULL_NAME) {
        addViolation(failureMsg, "tag of DistributionPointName of CRLDistibutionPoints",
            asn1Type, DistributionPointName.FULL_NAME);
        continue;
      }

      GeneralNames isDistributionPointNames =
          GeneralNames.getInstance(entry.getDistributionPoint().getName());
      GeneralName[] names = isDistributionPointNames.getNames();

      for (int i = 0; i < names.length; i++) {
        GeneralName name = names[i];
        if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
          addViolation(failureMsg, "tag of CRL URL", name.getTagNo(),
              GeneralName.uniformResourceIdentifier);
        } else {
          String uri = ((ASN1String) name.getName()).getString();
          isCrlUrls.add(uri);
        }
      }

      Set<String> expCrlUrls = issuerInfo.getCrlUrls();
      Set<String> diffs = strInBnotInA(expCrlUrls, isCrlUrls);
      if (isNotEmpty(diffs)) {
        failureMsg.append("CRL URLs ").append(diffs).append(" are present but not expected; ");
      }

      diffs = strInBnotInA(isCrlUrls, expCrlUrls);
      if (isNotEmpty(diffs)) {
        failureMsg.append("CRL URLs ").append(diffs).append(" are absent but are required; ");
      }
    }
  } // method checkExtnCrlDistributionPoints

  private void checkExtnDeltaCrlDistributionPoints(StringBuilder failureMsg,
      byte[] extensionValue, IssuerInfo issuerInfo) {
    CRLDistPoint isCrlDistPoints = CRLDistPoint.getInstance(extensionValue);
    DistributionPoint[] isDistributionPoints = isCrlDistPoints.getDistributionPoints();
    if (isDistributionPoints == null) {
      addViolation(failureMsg, "size of CRLDistributionPoints (deltaCRL)", 0, 1);
      return;
    } else {
      int len = isDistributionPoints.length;
      if (len != 1) {
        addViolation(failureMsg, "size of CRLDistributionPoints (deltaCRL)", len, 1);
        return;
      }
    }

    Set<String> isCrlUrls = new HashSet<>();
    for (DistributionPoint entry : isDistributionPoints) {
      int asn1Type = entry.getDistributionPoint().getType();
      if (asn1Type != DistributionPointName.FULL_NAME) {
        addViolation(failureMsg, "tag of DistributionPointName of CRLDistibutionPoints (deltaCRL)",
            asn1Type, DistributionPointName.FULL_NAME);
        continue;
      }

      GeneralNames isDistributionPointNames =
          GeneralNames.getInstance(entry.getDistributionPoint().getName());
      GeneralName[] names = isDistributionPointNames.getNames();

      for (int i = 0; i < names.length; i++) {
        GeneralName name = names[i];
        if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
          addViolation(failureMsg, "tag of deltaCRL URL", name.getTagNo(),
              GeneralName.uniformResourceIdentifier);
        } else {
          String uri = ((ASN1String) name.getName()).getString();
          isCrlUrls.add(uri);
        }
      }

      Set<String> expCrlUrls = issuerInfo.getDeltaCrlUrls();
      Set<String> diffs = strInBnotInA(expCrlUrls, isCrlUrls);
      if (isNotEmpty(diffs)) {
        failureMsg.append("deltaCRL URLs ").append(diffs).append(" are present but not expected; ");
      }

      diffs = strInBnotInA(isCrlUrls, expCrlUrls);
      if (isNotEmpty(diffs)) {
        failureMsg.append("deltaCRL URLs ").append(diffs).append(" are absent but are required; ");
      }
    }
  } // method checkExtnDeltaCrlDistributionPoints

  private void checkExtnAdmission(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, X500Name requestedSubject, ExtensionControl extControl) {
    AdmissionExtension.AdmissionSyntaxOption conf = certprofile.extensions().getAdmission();
    ASN1ObjectIdentifier type = Extn.id_extension_admission;
    if (conf == null) {
      checkConstantExtnValue(type, failureMsg, extensionValue, requestedExtns, extControl);
      return;
    }

    List<List<String>> reqRegNumsList = null;
    if (requestedSubject != null && conf.isInputFromRequestRequired()) {

      RDN[] admissionRdns = requestedSubject.getRDNs(type);
      if (admissionRdns != null && admissionRdns.length == 0) {
        failureMsg.append("no subject RDN Admission is contained in the request;");
        return;
      }

      reqRegNumsList = new LinkedList<>();
      for (RDN m : admissionRdns) {
        String str = X509Util.rdnValueToString(m.getFirst().getValue());
        ConfPairs pairs = new ConfPairs(str);
        for (String name : pairs.names()) {
          if ("registrationNumber".equalsIgnoreCase(name)) {
            reqRegNumsList.add(StringUtil.split(pairs.value(name), " ,;:"));
          }
        }
      }
    }

    try {
      byte[] expected =
          conf.getExtensionValue(reqRegNumsList).getValue().toASN1Primitive().getEncoded();
      if (!Arrays.equals(expected, extensionValue)) {
        addViolation(failureMsg, "extension valus", hex(extensionValue), hex(expected));
      }
    } catch (IOException ex) {
      LogUtil.error(LOG, ex);
      failureMsg.append("IOException while computing the expected extension value;");
    } catch (BadCertTemplateException ex) {
      LogUtil.error(LOG, ex);
      failureMsg.append("BadCertTemplateException while computing the expected extension value;");
    }

  } // method checkExtnAdmission

  private void checkExtnAuthorityInfoAccess(StringBuilder failureMsg,
      byte[] extensionValue, IssuerInfo issuerInfo) {
    AuthorityInfoAccessControl aiaControl = certprofile.getAiaControl();
    Set<String> expCaIssuerUris = (aiaControl == null || aiaControl.isIncludesCaIssuers())
        ? issuerInfo.getCaIssuerUrls() : Collections.emptySet();

    Set<String> expOcspUris = (aiaControl == null || aiaControl.isIncludesOcsp())
        ? issuerInfo.getOcspUrls() : Collections.emptySet();

    if (isEmpty(expCaIssuerUris) && isEmpty(expOcspUris)) {
      failureMsg.append("AIA is present but expected is 'none'; ");
      return;
    }

    AuthorityInformationAccess isAia = AuthorityInformationAccess.getInstance(extensionValue);
    checkAia(failureMsg, isAia, X509ObjectIdentifiers.id_ad_caIssuers, expCaIssuerUris);
    checkAia(failureMsg, isAia, X509ObjectIdentifiers.id_ad_ocsp, expOcspUris);
  } // method checkExtnAuthorityInfoAccess

  private void checkExtnOcspNocheck(StringBuilder failureMsg, byte[] extensionValue) {
    if (!Arrays.equals(DER_NULL, extensionValue)) {
      failureMsg.append("value is not DER NULL; ");
    }
  }

  private void checkExtnRestriction(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    checkDirectoryString(Extn.id_extension_restriction,
        restriction.getType(), restriction.getText(),
        failureMsg, extensionValue, requestedExtns, extControl);
  }

  private void checkExtnAdditionalInformation(StringBuilder failureMsg,
      byte[] extensionValue, Extensions requestedExtns, ExtensionControl extControl) {
    checkDirectoryString(Extn.id_extension_additionalInformation,
        additionalInformation.getType(), additionalInformation.getText(),
        failureMsg, extensionValue, requestedExtns, extControl);
  }

  private void checkDirectoryString(ASN1ObjectIdentifier extnType,
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

  private void checkExtnValidityModel(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    ASN1ObjectIdentifier conf = validityModelId;
    if (conf == null) {
      checkConstantExtnValue(Extn.id_extension_validityModel,
          failureMsg, extensionValue, requestedExtns, extControl);
    } else {
      ASN1Sequence seq = ASN1Sequence.getInstance(extensionValue);
      ASN1ObjectIdentifier extValue = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      if (!conf.equals(extValue)) {
        addViolation(failureMsg, "content", extValue, conf);
      }
    }
  } // method checkExtnValidityModel

  private void checkExtnPrivateKeyUsagePeriod(StringBuilder failureMsg,
      byte[] extensionValue, Date certNotBefore, Date certNotAfter) {
    ASN1GeneralizedTime notBefore = new ASN1GeneralizedTime(certNotBefore);
    Date dateNotAfter;
    Validity privateKeyUsagePeriod = certprofile.extensions().getPrivateKeyUsagePeriod();
    if (privateKeyUsagePeriod == null) {
      dateNotAfter = certNotAfter;
    } else {
      dateNotAfter = privateKeyUsagePeriod.add(certNotBefore);
      if (dateNotAfter.after(certNotAfter)) {
        dateNotAfter = certNotAfter;
      }
    }
    ASN1GeneralizedTime notAfter = new ASN1GeneralizedTime(dateNotAfter);

    org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod extValue =
        org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod.getInstance(extensionValue);

    ASN1GeneralizedTime time = extValue.getNotBefore();
    if (time == null) {
      failureMsg.append("notBefore is absent but expected present; ");
    } else if (!time.equals(notBefore)) {
      addViolation(failureMsg, "notBefore", time.getTimeString(), notBefore.getTimeString());
    }

    time = extValue.getNotAfter();
    if (time == null) {
      failureMsg.append("notAfter is absent but expected present; ");
    } else if (!time.equals(notAfter)) {
      addViolation(failureMsg, "notAfter", time.getTimeString(), notAfter.getTimeString());
    }
  } // method checkExtnPrivateKeyUsagePeriod

  private void checkExtnQcStatements(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    QcStatements conf = qcStatements;
    if (conf == null) {
      checkConstantExtnValue(Extension.qCStatements, failureMsg, extensionValue,
          requestedExtns, extControl);
      return;
    }

    final int expSize = conf.getQcStatements().size();
    ASN1Sequence extValue = ASN1Sequence.getInstance(extensionValue);
    final int isSize = extValue.size();
    if (isSize != expSize) {
      addViolation(failureMsg, "number of statements", isSize, expSize);
      return;
    }

    // extract the euLimit and pdsLocations data from request
    Map<String, int[]> reqQcEuLimits = new HashMap<>();
    Extension reqExtension = (requestedExtns == null) ? null
        : requestedExtns.getExtension(Extension.qCStatements);
    if (reqExtension != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(reqExtension.getParsedValue());

      final int n = seq.size();
      for (int j = 0; j < n; j++) {
        QCStatement stmt = QCStatement.getInstance(seq.getObjectAt(j));
        if (Extn.id_etsi_qcs_QcLimitValue.equals(stmt.getStatementId())) {
          MonetaryValue monetaryValue = MonetaryValue.getInstance(stmt.getStatementInfo());
          int amount = monetaryValue.getAmount().intValue();
          int exponent = monetaryValue.getExponent().intValue();
          Iso4217CurrencyCode currency = monetaryValue.getCurrency();
          String currencyS = currency.isAlphabetic()
              ? currency.getAlphabetic().toUpperCase() : Integer.toString(currency.getNumeric());
          reqQcEuLimits.put(currencyS, new int[]{amount, exponent});
        }
      }
    }

    for (int i = 0; i < expSize; i++) {
      QCStatement is = QCStatement.getInstance(extValue.getObjectAt(i));
      QcStatementType exp = conf.getQcStatements().get(i);
      if (!is.getStatementId().getId().equals(exp.getStatementId().getOid())) {
        addViolation(failureMsg, "statmentId[" + i + "]",
            is.getStatementId().getId(), exp.getStatementId().getOid());
        continue;
      }

      if (exp.getStatementValue() == null) {
        if (is.getStatementInfo() != null) {
          addViolation(failureMsg, "statmentInfo[" + i + "]", "present", "absent");
        }
        continue;
      }

      if (is.getStatementInfo() == null) {
        addViolation(failureMsg, "statmentInfo[" + i + "]", "absent", "present");
        continue;
      }

      QcStatementValueType expStatementValue = exp.getStatementValue();
      try {
        if (expStatementValue.getConstant() != null) {
          byte[] expValue = expStatementValue.getConstant().getValue();
          byte[] isValue = is.getStatementInfo().toASN1Primitive().getEncoded();
          if (!Arrays.equals(isValue, expValue)) {
            addViolation(failureMsg, "statementInfo[" + i + "]", hex(isValue), hex(expValue));
          }
        } else if (expStatementValue.getQcRetentionPeriod() != null) {
          String isValue = ASN1Integer.getInstance(is.getStatementInfo()).toString();
          String expValue = expStatementValue.getQcRetentionPeriod().toString();
          if (!isValue.equals(expValue)) {
            addViolation(failureMsg, "statementInfo[" + i + "]", isValue, expValue);
          }
        } else if (expStatementValue.getPdsLocations() != null) {
          Set<String> pdsLocations = new HashSet<>();
          ASN1Sequence pdsLocsSeq = ASN1Sequence.getInstance(is.getStatementInfo());
          int size = pdsLocsSeq.size();
          for (int k = 0; k < size; k++) {
            ASN1Sequence pdsLocSeq = ASN1Sequence.getInstance(pdsLocsSeq.getObjectAt(k));
            int size2 = pdsLocSeq.size();
            if (size2 != 2) {
              throw new IllegalArgumentException("sequence size is " + size2 + " but expected 2");
            }
            String url = DERIA5String.getInstance(pdsLocSeq.getObjectAt(0)).getString();
            String lang = DERPrintableString.getInstance(pdsLocSeq.getObjectAt(1)).getString();
            pdsLocations.add("url=" + url + ",lang=" + lang);
          }

          Set<String> expectedPdsLocations = new HashSet<>();
          for (PdsLocationType m : expStatementValue.getPdsLocations()) {
            expectedPdsLocations.add("url=" + m.getUrl() + ",lang=" + m.getLanguage());
          }

          Set<String> diffs = strInBnotInA(expectedPdsLocations, pdsLocations);
          if (isNotEmpty(diffs)) {
            failureMsg.append("statementInfo[").append(i).append("]: ").append(diffs)
              .append(" are present but not expected; ");
          }

          diffs = strInBnotInA(pdsLocations, expectedPdsLocations);
          if (isNotEmpty(diffs)) {
            failureMsg.append("statementInfo[").append(i).append("]: ").append(diffs)
              .append(" are absent but are required; ");
          }
        } else if (expStatementValue.getQcEuLimitValue() != null) {
          QcEuLimitValueType euLimitConf = expStatementValue.getQcEuLimitValue();
          String expCurrency = euLimitConf.getCurrency().toUpperCase();
          int[] expAmountExp = reqQcEuLimits.get(expCurrency);

          Range2Type range = euLimitConf.getAmount();
          int value;
          if (range.getMin() == range.getMax()) {
            value = range.getMin();
          } else if (expAmountExp != null) {
            value = expAmountExp[0];
          } else {
            failureMsg.append("found no QcEuLimit for currency '").append(expCurrency)
              .append("'; ");
            return;
          }
          // CHECKSTYLE:SKIP
          String expAmount = Integer.toString(value);

          range = euLimitConf.getExponent();
          if (range.getMin() == range.getMax()) {
            value = range.getMin();
          } else if (expAmountExp != null) {
            value = expAmountExp[1];
          } else {
            failureMsg.append("found no QcEuLimit for currency '").append(expCurrency)
            .append("'; ");
            return;
          }
          String expExponent = Integer.toString(value);

          MonetaryValue monterayValue = MonetaryValue.getInstance(is.getStatementInfo());
          Iso4217CurrencyCode currency = monterayValue.getCurrency();
          String isCurrency = currency.isAlphabetic() ? currency.getAlphabetic()
              : Integer.toString(currency.getNumeric());
          String isAmount = monterayValue.getAmount().toString();
          String isExponent = monterayValue.getExponent().toString();
          if (!isCurrency.equals(expCurrency)) {
            addViolation(failureMsg, "statementInfo[" + i + "].qcEuLimit.currency",
                isCurrency, expCurrency);
          }
          if (!isAmount.equals(expAmount)) {
            addViolation(failureMsg, "statementInfo[" + i + "].qcEuLimit.amount",
                isAmount, expAmount);
          }
          if (!isExponent.equals(expExponent)) {
            addViolation(failureMsg, "statementInfo[" + i + "].qcEuLimit.exponent",
                isExponent, expExponent);
          }
        } else {
          throw new IllegalStateException("statementInfo[" + i + "]should not reach here");
        }
      } catch (IOException ex) {
        failureMsg.append("statementInfo[").append(i).append("] has incorrect syntax; ");
      }
    }
  } // method checkExtnQcStatements

  private void checkExtnBiometricInfo(StringBuilder failureMsg, byte[] extensionValue,
      Extensions requestedExtns, ExtensionControl extControl) {
    BiometricInfoOption conf = certprofile.extensions().getBiometricInfo();

    if (conf == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    ASN1Encodable extInRequest = null;
    if (requestedExtns != null) {
      extInRequest = requestedExtns.getExtensionParsedValue(Extension.biometricInfo);
    }

    if (extInRequest == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    ASN1Sequence extValueInReq = ASN1Sequence.getInstance(extInRequest);
    final int expSize = extValueInReq.size();

    ASN1Sequence extValue = ASN1Sequence.getInstance(extensionValue);
    final int isSize = extValue.size();
    if (isSize != expSize) {
      addViolation(failureMsg, "number of biometricData", isSize, expSize);
      return;
    }

    for (int i = 0; i < expSize; i++) {
      BiometricData isData = BiometricData.getInstance(extValue.getObjectAt(i));
      BiometricData expData = BiometricData.getInstance(extValueInReq.getObjectAt(i));

      TypeOfBiometricData isType = isData.getTypeOfBiometricData();
      TypeOfBiometricData expType = expData.getTypeOfBiometricData();
      if (!isType.equals(expType)) {
        String isStr = isType.isPredefined()
            ? Integer.toString(isType.getPredefinedBiometricType())
            : isType.getBiometricDataOid().getId();
        String expStr = expType.isPredefined()
            ? Integer.toString(expType.getPredefinedBiometricType())
            : expType.getBiometricDataOid().getId();

        addViolation(failureMsg, "biometricData[" + i + "].typeOfBiometricData", isStr, expStr);
      }

      ASN1ObjectIdentifier is = isData.getHashAlgorithm().getAlgorithm();
      ASN1ObjectIdentifier exp = expData.getHashAlgorithm().getAlgorithm();
      if (!is.equals(exp)) {
        addViolation(failureMsg, "biometricData[" + i + "].hashAlgorithm", is.getId(), exp.getId());
      }

      ASN1Encodable isHashAlgoParam = isData.getHashAlgorithm().getParameters();
      if (isHashAlgoParam == null) {
        failureMsg.append("biometricData[").append(i)
          .append("].hashAlgorithm.parameters is 'present' but expected 'absent'; ");
      } else {
        try {
          byte[] isBytes = isHashAlgoParam.toASN1Primitive().getEncoded();
          if (!Arrays.equals(isBytes, DER_NULL)) {
            addViolation(failureMsg, "biometricData[" + i + "].biometricDataHash.parameters",
                hex(isBytes), hex(DER_NULL));
          }
        } catch (IOException ex) {
          failureMsg.append("biometricData[").append(i)
            .append("].biometricDataHash.parameters has incorrect syntax; ");
        }
      }

      byte[] isBytes = isData.getBiometricDataHash().getOctets();
      byte[] expBytes = expData.getBiometricDataHash().getOctets();
      if (!Arrays.equals(isBytes, expBytes)) {
        addViolation(failureMsg, "biometricData[" + i + "].biometricDataHash",
            hex(isBytes), hex(expBytes));
      }

      DERIA5String str = isData.getSourceDataUri();
      String isSourceDataUri = (str == null) ? null : str.getString();

      String expSourceDataUri = null;
      if (conf.getSourceDataUriOccurrence() != TripleState.forbidden) {
        str = expData.getSourceDataUri();
        expSourceDataUri = (str == null) ? null : str.getString();
      }

      if (expSourceDataUri == null) {
        if (isSourceDataUri != null) {
          addViolation(failureMsg, "biometricData[" + i + "].sourceDataUri", "present", "absent");
        }
      } else {
        if (isSourceDataUri == null) {
          failureMsg.append("biometricData[").append(i).append("].sourceDataUri is 'absent'");
          failureMsg.append(" but expected 'present'; ");
        } else if (!isSourceDataUri.equals(expSourceDataUri)) {
          addViolation(failureMsg, "biometricData[" + i + "].sourceDataUri",
              isSourceDataUri, expSourceDataUri);
        }
      }
    }
  } // method checkExtnBiometricInfo

  private void checkScts(StringBuilder failureMsg,
      byte[] extensionValue, ExtensionControl extControl) {
    // just check the syntax
    try {
      ASN1OctetString octet = DEROctetString.getInstance(extensionValue);
      SignedCertificateTimestampList sctList =
          SignedCertificateTimestampList.getInstance(octet.getOctets());
      int size = sctList.getSctList().size();
      for (int i = 0; i < size; i++) {
        sctList.getSctList().get(i).getDigitallySigned().getSignatureObject();
      }
    } catch (Exception ex) {
      failureMsg.append("invalid syntax: ").append(ex.getMessage()).append("; ");
    }
  } // method checkScts

  private Set<KeyUsageControl> getKeyusage(boolean required) {
    Set<KeyUsageControl> ret = new HashSet<>();

    Set<KeyUsageControl> controls = certprofile.extensions().getKeyusages();
    if (controls != null) {
      for (KeyUsageControl control : controls) {
        if (control.isRequired() == required) {
          ret.add(control);
        }
      }
    }
    return ret;
  } // method getKeyusage

  private Set<ExtKeyUsageControl> getExtKeyusage(boolean required) {
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

  private byte[] getConstantExtensionValue(ASN1ObjectIdentifier type) {
    return (constantExtensions == null) ? null : constantExtensions.get(type).getValue();
  }

  private static Map<ASN1ObjectIdentifier, QaExtensionValue> buildConstantExtesions(
      Map<String, ExtensionType> extensions)
          throws CertprofileException {
    if (extensions == null) {
      return null;
    }

    Map<ASN1ObjectIdentifier, QaExtensionValue> map = new HashMap<>();

    for (String type : extensions.keySet()) {
      ExtensionType extn = extensions.get(type);
      if (extn.getConstant() == null) {
        continue;
      }

      ASN1ObjectIdentifier oid = extn.getType().toXiOid();
      if (Extension.subjectAlternativeName.equals(oid)
          || Extension.subjectInfoAccess.equals(oid)
          || Extension.biometricInfo.equals(oid)) {
        continue;
      }

      byte[] encodedValue;
      try {
        encodedValue = extn.getConstant().toASN1Encodable().toASN1Primitive().getEncoded();
      } catch (IOException | InvalidConfException ex) {
        throw new CertprofileException(
            "could not parse the constant extension value of type" + type, ex);
      }

      QaExtensionValue extension = new QaExtensionValue(extn.isCritical(), encodedValue);
      map.put(oid, extension);
    }

    if (isEmpty(map)) {
      return null;
    }

    return Collections.unmodifiableMap(map);
  } // method buildConstantExtesions

  private static Map<ASN1ObjectIdentifier, ExtnSyntax> buildExtesionSyntaxes(
      Map<String, ExtensionType> extensions)
          throws CertprofileException {
    if (extensions == null) {
      return null;
    }

    Map<ASN1ObjectIdentifier, ExtnSyntax> map = new HashMap<>();

    for (String type : extensions.keySet()) {
      ExtensionType extn = extensions.get(type);
      if (extn.getSyntax() != null) {
        map.put(extn.getType().toXiOid(), extn.getSyntax());
      }
    }

    if (isEmpty(map)) {
      return null;
    }

    return Collections.unmodifiableMap(map);
  } // method buildExtesionSyntaxes

  private static ASN1Encodable readAsn1Encodable(byte[] encoded)
      throws CertprofileException {
    ASN1StreamParser parser = new ASN1StreamParser(encoded);
    try {
      return parser.readObject();
    } catch (IOException ex) {
      throw new CertprofileException("could not parse the constant extension value", ex);
    }
  } // method readAsn1Encodable

  private static String hex(byte[] bytes) {
    return Hex.encode(bytes);
  }

  private static Set<String> strInBnotInA(Collection<String> collectionA,
      Collection<String> collectionB) {
    if (collectionB == null) {
      return Collections.emptySet();
    }

    Set<String> result = new HashSet<>();
    for (String entry : collectionB) {
      if (collectionA == null || !collectionA.contains(entry)) {
        result.add(entry);
      }
    }
    return result;
  } // method strInBnotInA

  private static GeneralName createGeneralName(GeneralName reqName, Set<GeneralNameMode> modes)
      throws BadCertTemplateException {
    int tag = reqName.getTagNo();
    GeneralNameMode mode = null;
    if (modes != null) {
      for (GeneralNameMode m : modes) {
        if (m.getTag().getTag() == tag) {
          mode = m;
          break;
        }
      }

      if (mode == null) {
        throw new BadCertTemplateException("generalName tag " + tag + " is not allowed");
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
      case GeneralName.otherName:
        ASN1Sequence reqSeq = ASN1Sequence.getInstance(reqName.getName());
        ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(reqSeq.getObjectAt(0));
        if (mode != null && !mode.getAllowedTypes().contains(type)) {
          throw new BadCertTemplateException("otherName.type " + type.getId() + " is not allowed");
        }

        ASN1Encodable value = ASN1TaggedObject.getInstance(reqSeq.getObjectAt(1)).getObject();
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
      case GeneralName.ediPartyName:
        reqSeq = ASN1Sequence.getInstance(reqName.getName());

        int size = reqSeq.size();
        String nameAssigner = null;
        int idx = 0;
        if (size > 1) {
          DirectoryString ds = DirectoryString.getInstance(
              ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx++)).getObject());
          nameAssigner = ds.getString();
        }

        DirectoryString ds = DirectoryString.getInstance(
            ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx++)).getObject());
        String partyName = ds.getString();

        vector = new ASN1EncodableVector();
        if (nameAssigner != null) {
          vector.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
        }
        vector.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
        return new GeneralName(GeneralName.ediPartyName, new DERSequence(vector));
      default:
        throw new IllegalStateException("should not reach here, unknown GeneralName tag " + tag);
    } // end switch
  } // method createGeneralName

  private static Set<String> getKeyUsage(byte[] extensionValue) {
    Set<String> usages = new HashSet<>();
    org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
        org.bouncycastle.asn1.x509.KeyUsage.getInstance(extensionValue);
    for (KeyUsage k : KeyUsage.values()) {
      if (reqKeyUsage.hasUsages(k.getBcUsage())) {
        usages.add(k.getName());
      }
    }

    return usages;
  } // method getKeyUsage

  private static Set<String> getExtKeyUsage(byte[] extensionValue) {
    Set<String> usages = new HashSet<>();
    org.bouncycastle.asn1.x509.ExtendedKeyUsage reqKeyUsage =
        org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extensionValue);
    for (KeyPurposeId usage : reqKeyUsage.getUsages()) {
      usages.add(usage.getId());
    }
    return usages;
  } // method getExtKeyUsage

  private static void checkAia(StringBuilder failureMsg, AuthorityInformationAccess aia,
      ASN1ObjectIdentifier accessMethod, Set<String> expectedUris) {
    String typeDesc;
    if (X509ObjectIdentifiers.id_ad_ocsp.equals(accessMethod)) {
      typeDesc = "OCSP";
    } else if (X509ObjectIdentifiers.id_ad_caIssuers.equals(accessMethod)) {
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
      addViolation(failureMsg, "number of AIA " + typeDesc + " URIs", size, expectedUris.size());
      return;
    }

    Set<String> isUris = new HashSet<>();
    for (int i = 0; i < size; i++) {
      GeneralName isAccessLocation = isAccessDescriptions.get(i).getAccessLocation();
      if (isAccessLocation.getTagNo() != GeneralName.uniformResourceIdentifier) {
        addViolation(failureMsg, "tag of accessLocation of AIA ",
            isAccessLocation.getTagNo(), GeneralName.uniformResourceIdentifier);
      } else {
        String isOcspUri = ((ASN1String) isAccessLocation.getName()).getString();
        isUris.add(isOcspUri);
      }
    }

    Set<String> diffs = strInBnotInA(expectedUris, isUris);
    if (isNotEmpty(diffs)) {
      failureMsg.append(typeDesc).append(" URIs ").append(diffs);
      failureMsg.append(" are present but not expected; ");
    }

    diffs = strInBnotInA(isUris, expectedUris);
    if (isNotEmpty(diffs)) {
      failureMsg.append(typeDesc).append(" URIs ").append(diffs);
      failureMsg.append(" are absent but are required; ");
    }
  } // method checkAia

  private void checkConstantExtnValue(ASN1ObjectIdentifier extnType,
      StringBuilder failureMsg, byte[] extensionValue, Extensions requestedExtns,
      ExtensionControl extControl) {
    byte[] expected = getExpectedExtValue(extnType, requestedExtns, extControl);
    if (!Arrays.equals(expected, extensionValue)) {
      addViolation(failureMsg, "extension values", hex(extensionValue),
          (expected == null) ? "not present" : hex(expected));
    }
  } // method checkConstantExtnValue

  private static void addViolation(StringBuilder failureMsg, String field,
      Object is, Object expected) {
    failureMsg.append(field).append(" is '").append(is)
      .append("' but expected '").append(expected).append("';");
  } // method addViolation

}
