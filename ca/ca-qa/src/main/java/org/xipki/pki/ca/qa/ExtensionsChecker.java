/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.qa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
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
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.qa.ValidationIssue;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.CompareUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.ExtensionExistence;
import org.xipki.commons.security.HashAlgoType;
import org.xipki.commons.security.KeyUsage;
import org.xipki.commons.security.ObjectIdentifiers;
import org.xipki.commons.security.util.X509Util;
import org.xipki.pki.ca.api.BadCertTemplateException;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.api.profile.CertprofileException;
import org.xipki.pki.ca.api.profile.ExtensionControl;
import org.xipki.pki.ca.api.profile.GeneralNameMode;
import org.xipki.pki.ca.api.profile.GeneralNameTag;
import org.xipki.pki.ca.api.profile.Range;
import org.xipki.pki.ca.api.profile.x509.AuthorityInfoAccessControl;
import org.xipki.pki.ca.api.profile.x509.ExtKeyUsageControl;
import org.xipki.pki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.pki.ca.api.profile.x509.SubjectDirectoryAttributesControl;
import org.xipki.pki.ca.api.profile.x509.SubjectDnSpec;
import org.xipki.pki.ca.api.profile.x509.X509CertLevel;
import org.xipki.pki.ca.certprofile.BiometricInfoOption;
import org.xipki.pki.ca.certprofile.XmlX509Certprofile;
import org.xipki.pki.ca.certprofile.XmlX509CertprofileUtil;
import org.xipki.pki.ca.certprofile.commonpki.AdmissionSyntaxOption;
import org.xipki.pki.ca.certprofile.x509.jaxb.AdditionalInformation;
import org.xipki.pki.ca.certprofile.x509.jaxb.AuthorizationTemplate;
import org.xipki.pki.ca.certprofile.x509.jaxb.ConstantExtValue;
import org.xipki.pki.ca.certprofile.x509.jaxb.ExtensionType;
import org.xipki.pki.ca.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.pki.ca.certprofile.x509.jaxb.InhibitAnyPolicy;
import org.xipki.pki.ca.certprofile.x509.jaxb.PdsLocationType;
import org.xipki.pki.ca.certprofile.x509.jaxb.PdsLocationsType;
import org.xipki.pki.ca.certprofile.x509.jaxb.PolicyConstraints;
import org.xipki.pki.ca.certprofile.x509.jaxb.PolicyMappings;
import org.xipki.pki.ca.certprofile.x509.jaxb.QcEuLimitValueType;
import org.xipki.pki.ca.certprofile.x509.jaxb.QcStatementType;
import org.xipki.pki.ca.certprofile.x509.jaxb.QcStatementValueType;
import org.xipki.pki.ca.certprofile.x509.jaxb.QcStatements;
import org.xipki.pki.ca.certprofile.x509.jaxb.Range2Type;
import org.xipki.pki.ca.certprofile.x509.jaxb.RangeType;
import org.xipki.pki.ca.certprofile.x509.jaxb.RangesType;
import org.xipki.pki.ca.certprofile.x509.jaxb.Restriction;
import org.xipki.pki.ca.certprofile.x509.jaxb.SMIMECapabilities;
import org.xipki.pki.ca.certprofile.x509.jaxb.SMIMECapability;
import org.xipki.pki.ca.certprofile.x509.jaxb.TlsFeature;
import org.xipki.pki.ca.certprofile.x509.jaxb.TripleState;
import org.xipki.pki.ca.certprofile.x509.jaxb.ValidityModel;
import org.xipki.pki.ca.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.pki.ca.qa.internal.QaAuthorizationTemplate;
import org.xipki.pki.ca.qa.internal.QaCertificatePolicies;
import org.xipki.pki.ca.qa.internal.QaCertificatePolicies.QaCertificatePolicyInformation;
import org.xipki.pki.ca.qa.internal.QaDirectoryString;
import org.xipki.pki.ca.qa.internal.QaExtensionValue;
import org.xipki.pki.ca.qa.internal.QaGeneralSubtree;
import org.xipki.pki.ca.qa.internal.QaInhibitAnyPolicy;
import org.xipki.pki.ca.qa.internal.QaNameConstraints;
import org.xipki.pki.ca.qa.internal.QaPolicyConstraints;
import org.xipki.pki.ca.qa.internal.QaPolicyMappingsOption;
import org.xipki.pki.ca.qa.internal.QaPolicyQualifierInfo;
import org.xipki.pki.ca.qa.internal.QaPolicyQualifierInfo.QaCpsUriPolicyQualifier;
import org.xipki.pki.ca.qa.internal.QaPolicyQualifierInfo.QaUserNoticePolicyQualifierInfo;
import org.xipki.pki.ca.qa.internal.QaPolicyQualifiers;
import org.xipki.pki.ca.qa.internal.QaTlsFeature;

/**
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
            KeyUsage.decipherOnly.getName() // 8
        );

    private QaCertificatePolicies certificatePolicies;

    private QaPolicyMappingsOption policyMappings;

    private QaNameConstraints nameConstraints;

    private QaPolicyConstraints policyConstraints;

    private QaInhibitAnyPolicy inhibitAnyPolicy;

    private QaDirectoryString restriction;

    private QaDirectoryString additionalInformation;

    private ASN1ObjectIdentifier validityModelId;

    private QcStatements qcStatements;

    private QaAuthorizationTemplate authorizationTemplate;

    private QaTlsFeature tlsFeature;

    private QaExtensionValue smimeCapabilities;

    private Map<ASN1ObjectIdentifier, QaExtensionValue> constantExtensions;

    private XmlX509Certprofile certProfile;

    public ExtensionsChecker(final X509ProfileType conf, final XmlX509Certprofile certProfile)
    throws CertprofileException {
        this.certProfile = ParamUtil.requireNonNull("certProfile", certProfile);

        ParamUtil.requireNonNull("conf", conf);

        // Extensions
        ExtensionsType extensionsType = conf.getExtensions();

        // Extension controls
        Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls =
                certProfile.getExtensionControls();

        // Certificate Policies
        ASN1ObjectIdentifier type = Extension.certificatePolicies;
        if (extensionControls.containsKey(type)) {
            org.xipki.pki.ca.certprofile.x509.jaxb.CertificatePolicies extConf =
                (org.xipki.pki.ca.certprofile.x509.jaxb.CertificatePolicies)
                    getExtensionValue(type, extensionsType,
                        org.xipki.pki.ca.certprofile.x509.jaxb.CertificatePolicies.class);
            if (extConf != null) {
                this.certificatePolicies = new QaCertificatePolicies(extConf);
            }
        }

        // Policy Mappings
        type = Extension.policyMappings;
        if (extensionControls.containsKey(type)) {
            PolicyMappings extConf = (PolicyMappings) getExtensionValue(
                    type, extensionsType, PolicyMappings.class);
            if (extConf != null) {
                this.policyMappings = new QaPolicyMappingsOption(extConf);
            }
        }

        // Name Constrains
        type = Extension.nameConstraints;
        if (extensionControls.containsKey(type)) {
            org.xipki.pki.ca.certprofile.x509.jaxb.NameConstraints extConf =
                (org.xipki.pki.ca.certprofile.x509.jaxb.NameConstraints) getExtensionValue(
                        type, extensionsType,
                        org.xipki.pki.ca.certprofile.x509.jaxb.NameConstraints.class);
            if (extConf != null) {
                this.nameConstraints = new QaNameConstraints(extConf);
            }
        }

        // Policy Constraints
        type = Extension.policyConstraints;
        if (extensionControls.containsKey(type)) {
            PolicyConstraints extConf = (PolicyConstraints) getExtensionValue(
                    type, extensionsType, PolicyConstraints.class);
            if (extConf != null) {
                this.policyConstraints = new QaPolicyConstraints(extConf);
            }
        }

        // Inhibit anyPolicy
        type = Extension.inhibitAnyPolicy;
        if (extensionControls.containsKey(type)) {
            InhibitAnyPolicy extConf = (InhibitAnyPolicy) getExtensionValue(
                    type, extensionsType, InhibitAnyPolicy.class);
            if (extConf != null) {
                this.inhibitAnyPolicy = new QaInhibitAnyPolicy(extConf);
            }
        }

        // restriction
        type = ObjectIdentifiers.id_extension_restriction;
        if (extensionControls.containsKey(type)) {
            Restriction extConf = (Restriction) getExtensionValue(
                    type, extensionsType, Restriction.class);
            if (extConf != null) {
                restriction = new QaDirectoryString(
                        XmlX509CertprofileUtil.convertDirectoryStringType(extConf.getType()),
                        extConf.getText());
            }
        }

        // additionalInformation
        type = ObjectIdentifiers.id_extension_additionalInformation;
        if (extensionControls.containsKey(type)) {
            AdditionalInformation extConf = (AdditionalInformation) getExtensionValue(
                    type, extensionsType, AdditionalInformation.class);
            if (extConf != null) {
                additionalInformation = new QaDirectoryString(
                        XmlX509CertprofileUtil.convertDirectoryStringType(extConf.getType()),
                        extConf.getText());
            }
        }

        // validityModel
        type = ObjectIdentifiers.id_extension_validityModel;
        if (extensionControls.containsKey(type)) {
            ValidityModel extConf = (ValidityModel) getExtensionValue(
                    type, extensionsType, ValidityModel.class);
            if (extConf != null) {
                validityModelId = new ASN1ObjectIdentifier(extConf.getModelId().getValue());
            }
        }

        // QCStatements
        type = Extension.qCStatements;
        if (extensionControls.containsKey(type)) {
            QcStatements extConf = (QcStatements) getExtensionValue(
                    type, extensionsType, QcStatements.class);
            if (extConf != null) {
                qcStatements = extConf;
            }
        }

        // tlsFeature
        type = ObjectIdentifiers.id_pe_tlsfeature;
        if (extensionControls.containsKey(type)) {
            TlsFeature extConf = (TlsFeature) getExtensionValue(
                    type, extensionsType, TlsFeature.class);
            if (extConf != null) {
                tlsFeature = new QaTlsFeature(extConf);
            }
        }

        // AuthorizationTemplate
        type = ObjectIdentifiers.id_xipki_ext_authorizationTemplate;
        if (extensionControls.containsKey(type)) {
            AuthorizationTemplate extConf = (AuthorizationTemplate) getExtensionValue(
                    type, extensionsType, AuthorizationTemplate.class);
            if (extConf != null) {
                authorizationTemplate = new QaAuthorizationTemplate(extConf);
            }
        }

        // SMIMECapabilities
        type = ObjectIdentifiers.id_smimeCapabilities;
        if (extensionControls.containsKey(type)) {
            SMIMECapabilities extConf = (SMIMECapabilities) getExtensionValue(
                    type, extensionsType, SMIMECapabilities.class);
            List<SMIMECapability> list = extConf.getSMIMECapability();

            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (SMIMECapability m : list) {
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(
                        m.getCapabilityID().getValue());
                ASN1Encodable params = null;
                org.xipki.pki.ca.certprofile.x509.jaxb.SMIMECapability.Parameters capParams =
                        m.getParameters();
                if (capParams != null) {
                    if (capParams.getInteger() != null) {
                        params = new ASN1Integer(capParams.getInteger());
                    } else if (capParams.getBase64Binary() != null) {
                        params = readAsn1Encodable(capParams.getBase64Binary().getValue());
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
                throw new CertprofileException(
                        "Cannot encode SMIMECapabilities: " + ex.getMessage());
            }
        }

        // constant extensions
        this.constantExtensions = buildConstantExtesions(extensionsType);
    } // constructor

    public List<ValidationIssue> checkExtensions(final Certificate cert,
            final X509IssuerInfo issuerInfo, final Extensions requestedExtensions,
            final X500Name requestedSubject) {
        ParamUtil.requireNonNull("cert", cert);
        ParamUtil.requireNonNull("issuerInfo", issuerInfo);

        X509Certificate jceCert;
        try {
            jceCert = new X509CertificateObject(cert);
        } catch (CertificateParsingException ex) {
            throw new IllegalArgumentException("invalid cert: " + ex.getMessage());
        }

        List<ValidationIssue> result = new LinkedList<>();

        // detect the list of extension types in certificate
        Set<ASN1ObjectIdentifier> presentExtenionTypes =
                getExensionTypes(cert, issuerInfo, requestedExtensions);

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

        Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls =
                certProfile.getExtensionControls();
        for (ASN1ObjectIdentifier oid : certExtTypes) {
            ValidationIssue issue = createExtensionIssue(oid);
            result.add(issue);
            if (!presentExtenionTypes.contains(oid)) {
                issue.setFailureMessage("extension is present but is not permitted");
                continue;
            }

            Extension ext = extensions.getExtension(oid);
            StringBuilder failureMsg = new StringBuilder();
            ExtensionControl extControl = extensionControls.get(oid);

            if (extControl.isCritical() != ext.isCritical()) {
                addViolation(failureMsg, "critical", ext.isCritical(), extControl.isCritical());
            }

            byte[] extensionValue = ext.getExtnValue().getOctets();
            try {
                if (Extension.authorityKeyIdentifier.equals(oid)) {
                    // AuthorityKeyIdentifier
                    checkExtensionIssuerKeyIdentifier(failureMsg, extensionValue, issuerInfo);
                } else if (Extension.subjectKeyIdentifier.equals(oid)) {
                    // SubjectKeyIdentifier
                    checkExtensionSubjectKeyIdentifier(failureMsg, extensionValue,
                            cert.getSubjectPublicKeyInfo());
                } else if (Extension.keyUsage.equals(oid)) {
                    // KeyUsage
                    checkExtensionKeyUsage(failureMsg, extensionValue, jceCert.getKeyUsage(),
                            requestedExtensions, extControl);
                } else if (Extension.certificatePolicies.equals(oid)) {
                    // CertificatePolicies
                    checkExtensionCertificatePolicies(failureMsg, extensionValue,
                            requestedExtensions, extControl);
                } else if (Extension.policyMappings.equals(oid)) {
                    // Policy Mappings
                    checkExtensionPolicyMappings(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (Extension.subjectAlternativeName.equals(oid)) {
                    // SubjectAltName
                    checkExtensionSubjectAltName(failureMsg, extensionValue, requestedExtensions,
                            extControl, requestedSubject);
                } else if (Extension.subjectDirectoryAttributes.equals(oid)) {
                    // SubjectDirectoryAttributes
                    checkExtensionSubjectDirAttrs(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (Extension.issuerAlternativeName.equals(oid)) {
                    // IssuerAltName
                    checkExtensionIssuerAltNames(failureMsg, extensionValue, issuerInfo);
                } else if (Extension.basicConstraints.equals(oid)) {
                    // Basic Constraints
                    checkExtensionBasicConstraints(failureMsg, extensionValue);
                } else if (Extension.nameConstraints.equals(oid)) {
                    // Name Constraints
                    checkExtensionNameConstraints(failureMsg, extensionValue, extensions,
                            extControl);
                } else if (Extension.policyConstraints.equals(oid)) {
                    // PolicyConstrains
                    checkExtensionPolicyConstraints(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (Extension.extendedKeyUsage.equals(oid)) {
                    // ExtendedKeyUsage
                    checkExtensionExtendedKeyUsage(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (Extension.cRLDistributionPoints.equals(oid)) {
                    // CRL Distribution Points
                    checkExtensionCrlDistributionPoints(failureMsg, extensionValue, issuerInfo);
                } else if (Extension.inhibitAnyPolicy.equals(oid)) {
                    // Inhibit anyPolicy
                    checkExtensionInhibitAnyPolicy(failureMsg, extensionValue, extensions,
                            extControl);
                } else if (Extension.freshestCRL.equals(oid)) {
                    // Freshest CRL
                    checkExtensionDeltaCrlDistributionPoints(failureMsg, extensionValue,
                            issuerInfo);
                } else if (Extension.authorityInfoAccess.equals(oid)) {
                    // Authority Information Access
                    checkExtensionAuthorityInfoAccess(failureMsg, extensionValue, issuerInfo);
                } else if (Extension.subjectInfoAccess.equals(oid)) {
                    // SubjectInfoAccess
                    checkExtensionSubjectInfoAccess(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (ObjectIdentifiers.id_extension_admission.equals(oid)) {
                    // Admission
                    checkExtensionAdmission(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (ObjectIdentifiers.id_extension_pkix_ocsp_nocheck.equals(oid)) {
                    // ocsp-nocheck
                    checkExtensionOcspNocheck(failureMsg, extensionValue);
                } else if (ObjectIdentifiers.id_extension_restriction.equals(oid)) {
                    // restriction
                    checkExtensionRestriction(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (ObjectIdentifiers.id_extension_additionalInformation.equals(oid)) {
                    // additionalInformation
                    checkExtensionAdditionalInformation(failureMsg, extensionValue,
                            requestedExtensions, extControl);
                } else if (ObjectIdentifiers.id_extension_validityModel.equals(oid)) {
                    // validityModel
                    checkExtensionValidityModel(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (Extension.privateKeyUsagePeriod.equals(oid)) {
                    // privateKeyUsagePeriod
                    checkExtensionPrivateKeyUsagePeriod(failureMsg, extensionValue,
                            jceCert.getNotBefore(), jceCert.getNotAfter());
                } else if (Extension.qCStatements.equals(oid)) {
                    // qCStatements
                    checkExtensionQcStatements(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (Extension.biometricInfo.equals(oid)) {
                    // biometricInfo
                    checkExtensionBiometricInfo(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (ObjectIdentifiers.id_pe_tlsfeature.equals(oid)) {
                    // tlsFeature
                    checkExtensionTlsFeature(failureMsg, extensionValue, requestedExtensions,
                            extControl);
                } else if (ObjectIdentifiers.id_xipki_ext_authorizationTemplate.equals(oid)) {
                    // authorizationTemplate
                    checkExtensionAuthorizationTemplate(failureMsg, extensionValue,
                            requestedExtensions, extControl);
                } else {
                    byte[] expected;
                    if (ObjectIdentifiers.id_smimeCapabilities.equals(oid)) {
                        // SMIMECapabilities
                        expected = smimeCapabilities.getValue();
                    } else {
                        expected = getExpectedExtValue(oid, requestedExtensions, extControl);
                    }

                    if (!Arrays.equals(expected, extensionValue)) {
                        addViolation(failureMsg, "extension valus", hex(extensionValue),
                                (expected == null) ? "not present" : hex(expected));
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

    private byte[] getExpectedExtValue(final ASN1ObjectIdentifier type,
            final Extensions requestedExtensions, final ExtensionControl extControl) {
        if (constantExtensions != null && constantExtensions.containsKey(type)) {
            return constantExtensions.get(type).getValue();
        } else if (requestedExtensions != null && extControl.isRequest()) {
            Extension reqExt = requestedExtensions.getExtension(type);
            if (reqExt != null) {
                return reqExt.getExtnValue().getOctets();
            }
        }

        return null;
    } // getExpectedExtValue

    private Set<ASN1ObjectIdentifier> getExensionTypes(final Certificate cert,
            final X509IssuerInfo issuerInfo, final Extensions requestedExtensions) {
        Set<ASN1ObjectIdentifier> types = new HashSet<>();
        // profile required extension types
        Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls =
                certProfile.getExtensionControls();
        for (ASN1ObjectIdentifier oid : extensionControls.keySet()) {
            if (extensionControls.get(oid).isRequired()) {
                types.add(oid);
            }
        }

        Set<ASN1ObjectIdentifier> wantedExtensionTypes = new HashSet<>();

        if (requestedExtensions != null) {
            Extension reqExtension = requestedExtensions.getExtension(
                    ObjectIdentifiers.id_xipki_ext_cmpRequestExtensions);
            if (reqExtension != null) {
                ExtensionExistence ee = ExtensionExistence.getInstance(
                        reqExtension.getParsedValue());
                types.addAll(ee.getNeedExtensions());
                wantedExtensionTypes.addAll(ee.getWantExtensions());
            }
        }

        if (CollectionUtil.isEmpty(wantedExtensionTypes)) {
            return types;
        }

        // wanted extension types
        // Authority key identifier
        ASN1ObjectIdentifier type = Extension.authorityKeyIdentifier;
        if (wantedExtensionTypes.contains(type)) {
            types.add(type);
        }

        // Subject key identifier
        type = Extension.subjectKeyIdentifier;
        if (wantedExtensionTypes.contains(type)) {
            types.add(type);
        }

        // KeyUsage
        type = Extension.keyUsage;
        if (wantedExtensionTypes.contains(type)) {
            boolean required = false;
            if (requestedExtensions != null && requestedExtensions.getExtension(type) != null) {
                required = true;
            }

            if (!required) {
                Set<KeyUsageControl> requiredKeyusage = getKeyusage(true);
                if (CollectionUtil.isNonEmpty(requiredKeyusage)) {
                    required = true;
                }
            }

            if (required) {
                types.add(type);
            }
        }

        // CertificatePolicies
        type = Extension.certificatePolicies;
        if (wantedExtensionTypes.contains(type)) {
            if (certificatePolicies != null) {
                types.add(type);
            }
        }

        // Policy Mappings
        type = Extension.policyMappings;
        if (wantedExtensionTypes.contains(type)) {
            if (policyMappings != null) {
                types.add(type);
            }
        }

        // SubjectAltNames
        type = Extension.subjectAlternativeName;
        if (wantedExtensionTypes.contains(type)) {
            if (requestedExtensions != null && requestedExtensions.getExtension(type) != null) {
                types.add(type);
            }
        }

        // IssuerAltName
        type = Extension.issuerAlternativeName;
        if (wantedExtensionTypes.contains(type)) {
            if (cert.getTBSCertificate().getExtensions().getExtension(
                    Extension.subjectAlternativeName) != null) {
                types.add(type);
            }
        }

        // BasicConstraints
        type = Extension.basicConstraints;
        if (wantedExtensionTypes.contains(type)) {
            types.add(type);
        }

        // Name Constraints
        type = Extension.nameConstraints;
        if (wantedExtensionTypes.contains(type)) {
            if (nameConstraints != null) {
                types.add(type);
            }
        }

        // PolicyConstrains
        type = Extension.policyConstraints;
        if (wantedExtensionTypes.contains(type)) {
            if (policyConstraints != null) {
                types.add(type);
            }
        }

        // ExtendedKeyUsage
        type = Extension.extendedKeyUsage;
        if (wantedExtensionTypes.contains(type)) {
            boolean required = false;
            if (requestedExtensions != null && requestedExtensions.getExtension(type) != null) {
                required = true;
            }

            if (!required) {
                Set<ExtKeyUsageControl> requiredExtKeyusage = getExtKeyusage(true);
                if (CollectionUtil.isNonEmpty(requiredExtKeyusage)) {
                    required = true;
                }
            }

            if (required) {
                types.add(type);
            }
        }

        // CRLDistributionPoints
        type = Extension.cRLDistributionPoints;
        if (wantedExtensionTypes.contains(type)) {
            if (issuerInfo.getCrlUrls() != null) {
                types.add(type);
            }
        }

        // Inhibit anyPolicy
        type = Extension.inhibitAnyPolicy;
        if (wantedExtensionTypes.contains(type)) {
            if (inhibitAnyPolicy != null) {
                types.add(type);
            }
        }

        // FreshestCRL
        type = Extension.freshestCRL;
        if (wantedExtensionTypes.contains(type)) {
            if (issuerInfo.getDeltaCrlUrls() != null) {
                types.add(type);
            }
        }

        // AuthorityInfoAccess
        type = Extension.authorityInfoAccess;
        if (wantedExtensionTypes.contains(type)) {
            if (issuerInfo.getOcspUrls() != null) {
                types.add(type);
            }
        }

        // SubjectInfoAccess
        type = Extension.subjectInfoAccess;
        if (wantedExtensionTypes.contains(type)) {
            if (requestedExtensions != null && requestedExtensions.getExtension(type) != null) {
                types.add(type);
            }
        }

        // Admission
        type = ObjectIdentifiers.id_extension_admission;
        if (wantedExtensionTypes.contains(type)) {
            if (certProfile.getAdmission() != null) {
                types.add(type);
            }
        }

        // ocsp-nocheck
        type = ObjectIdentifiers.id_extension_pkix_ocsp_nocheck;
        if (wantedExtensionTypes.contains(type)) {
            types.add(type);
        }

        wantedExtensionTypes.removeAll(types);

        for (ASN1ObjectIdentifier oid : wantedExtensionTypes) {
            if (requestedExtensions != null && requestedExtensions.getExtension(oid) != null) {
                if (constantExtensions.containsKey(oid)) {
                    types.add(oid);
                }
            }
        }

        return types;
    } // method getExensionTypes

    private ValidationIssue createExtensionIssue(final ASN1ObjectIdentifier extId) {
        ValidationIssue issue;
        String extName = ObjectIdentifiers.getName(extId);
        if (extName == null) {
            extName = extId.getId().replace('.', '_');
            issue = new ValidationIssue("X509.EXT." + extName, "extension " + extId.getId());
        } else {
            issue = new ValidationIssue("X509.EXT." + extName, "extension " + extName
                    + " (" + extId.getId() + ")");
        }
        return issue;
    } // method createExtensionIssue

    private void checkExtensionBasicConstraints(final StringBuilder failureMsg,
            final byte[] extensionValue) {
        BasicConstraints bc = BasicConstraints.getInstance(extensionValue);
        X509CertLevel certLevel = certProfile.getCertLevel();
        boolean ca = (X509CertLevel.RootCA == certLevel) || (X509CertLevel.SubCA == certLevel);
        if (ca != bc.isCA()) {
            addViolation(failureMsg, "ca", bc.isCA(), ca);
        }

        if (bc.isCA()) {
            BigInteger tmpPathLen = bc.getPathLenConstraint();
            Integer pathLen = certProfile.getPathLen();
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
        }
    } // method checkExtensionBasicConstraints

    private void checkExtensionSubjectKeyIdentifier(final StringBuilder failureMsg,
            final byte[] extensionValue, final SubjectPublicKeyInfo subjectPublicKeyInfo) {
        // subjectKeyIdentifier
        SubjectKeyIdentifier asn1 = SubjectKeyIdentifier.getInstance(extensionValue);
        byte[] ski = asn1.getKeyIdentifier();
        byte[] pkData = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        byte[] expectedSki = HashAlgoType.SHA1.hash(pkData);
        if (!Arrays.equals(expectedSki, ski)) {
            addViolation(failureMsg, "SKI", hex(ski), hex(expectedSki));
        }
    } // method checkExtensionSubjectKeyIdentifier

    private void checkExtensionIssuerKeyIdentifier(final StringBuilder failureMsg,
            final byte[] extensionValue, final X509IssuerInfo issuerInfo) {
        AuthorityKeyIdentifier asn1 = AuthorityKeyIdentifier.getInstance(extensionValue);
        byte[] keyIdentifier = asn1.getKeyIdentifier();
        if (keyIdentifier == null) {
            failureMsg.append("keyIdentifier is 'absent' but expected 'present'; ");
        } else if (!Arrays.equals(issuerInfo.getSubjectKeyIdentifier(), keyIdentifier)) {
            addViolation(failureMsg, "keyIdentifier", hex(keyIdentifier),
                hex(issuerInfo.getSubjectKeyIdentifier()));
        }

        BigInteger serialNumber = asn1.getAuthorityCertSerialNumber();
        GeneralNames names = asn1.getAuthorityCertIssuer();

        if (certProfile.isIncludeIssuerAndSerialInAki()) {
            if (serialNumber == null) {
                failureMsg.append("authorityCertSerialNumber is 'absent' but expected 'present'; ");
            } else {
                if (!issuerInfo.getCert().getSerialNumber().equals(serialNumber)) {
                    addViolation(failureMsg, "authorityCertSerialNumber",
                            LogUtil.formatCsn(serialNumber),
                            LogUtil.formatCsn(issuerInfo.getCert().getSerialNumber()));
                }
            }

            if (names == null) {
                failureMsg.append("authorityCertIssuer is 'absent' but expected 'present'; ");
            } else {
                GeneralName[] genNames = names.getNames();
                X500Name x500GenName = null;
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() != GeneralName.directoryName) {
                        continue;
                    }

                    if (x500GenName != null) {
                        failureMsg.append("authorityCertIssuer contains at least two ");
                        failureMsg.append("directoryName but expected one; ");
                        break;
                    } else {
                        x500GenName = (X500Name) genName.getName();
                    }
                }

                if (x500GenName == null) {
                    failureMsg.append(
                        "authorityCertIssuer does not contain directoryName but expected one; ");
                } else {
                    X500Name caSubject = issuerInfo.getBcCert().getTBSCertificate().getSubject();
                    if (!caSubject.equals(x500GenName)) {
                        addViolation(failureMsg, "authorityCertIssuer", x500GenName, caSubject);
                    }
                }
            }
        } else {
            if (serialNumber != null) {
                failureMsg.append("authorityCertSerialNumber is 'absent' but expected 'present'; ");
            }

            if (names != null) {
                failureMsg.append("authorityCertIssuer is 'absent' but expected 'present'; ");
            }
        }
    } // method checkExtensionIssuerKeyIdentifier

    private void checkExtensionNameConstraints(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        QaNameConstraints conf = nameConstraints;

        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.nameConstraints, requestedExtensions,
                    extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", hex(extensionValue),
                        (expected == null) ? "not present" : hex(expected));
            }
            return;
        }

        org.bouncycastle.asn1.x509.NameConstraints tmpNameConstraints =
                org.bouncycastle.asn1.x509.NameConstraints.getInstance(extensionValue);

        checkExtensionNameConstraintsSubtrees(failureMsg, "PermittedSubtrees",
                tmpNameConstraints.getPermittedSubtrees(),  conf.getPermittedSubtrees());
        checkExtensionNameConstraintsSubtrees(failureMsg, "ExcludedSubtrees",
                tmpNameConstraints.getExcludedSubtrees(), conf.getExcludedSubtrees());
    } // method checkExtensionNameConstraints

    private void checkExtensionNameConstraintsSubtrees(final StringBuilder failureMsg,
            final String description, final GeneralSubtree[] subtrees,
            final List<QaGeneralSubtree> expectedSubtrees) {
        int isSize = (subtrees == null) ? 0 : subtrees.length;
        int expSize = (expectedSubtrees == null) ? 0 : expectedSubtrees.size();
        if (isSize != expSize) {
            addViolation(failureMsg, "size of " + description, isSize, expSize);
            return;
        }

        for (int i = 0; i < isSize; i++) {
            GeneralSubtree isSubtree = subtrees[i];
            QaGeneralSubtree expSubtree = expectedSubtrees.get(i);
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

            GeneralName expBase;
            if (expSubtree.getDirectoryName() != null) {
                expBase = new GeneralName(X509Util.reverse(
                        new X500Name(expSubtree.getDirectoryName())));
            } else if (expSubtree.getDnsName() != null) {
                expBase = new GeneralName(GeneralName.dNSName, expSubtree.getDnsName());
            } else if (expSubtree.getIpAddress() != null) {
                expBase = new GeneralName(GeneralName.iPAddress, expSubtree.getIpAddress());
            } else if (expSubtree.getRfc822Name() != null) {
                expBase = new GeneralName(GeneralName.rfc822Name, expSubtree.getRfc822Name());
            } else if (expSubtree.getUri() != null) {
                expBase = new GeneralName(GeneralName.uniformResourceIdentifier,
                        expSubtree.getUri());
            } else {
                throw new RuntimeException("should not reach here, unknown child of GeneralName");
            }

            if (!isBase.equals(expBase)) {
                addViolation(failureMsg, "base of " + desc, isBase, expBase);
            }
        }
    } // method checkExtensionNameConstraintsSubtrees

    private void checkExtensionPolicyConstraints(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        QaPolicyConstraints conf = policyConstraints;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.policyConstraints,
                    requestedExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", hex(extensionValue),
                        (expected == null) ? "not present" : hex(expected));
            }
            return;
        }

        org.bouncycastle.asn1.x509.PolicyConstraints isPolicyConstraints =
                org.bouncycastle.asn1.x509.PolicyConstraints.getInstance(extensionValue);
        Integer expRequireExplicitPolicy = conf.getRequireExplicitPolicy();
        BigInteger bigInt = isPolicyConstraints.getRequireExplicitPolicyMapping();
        Integer isRequreExplicitPolicy = (bigInt == null) ? null : bigInt.intValue();

        boolean match = true;
        if (expRequireExplicitPolicy == null) {
            if (isRequreExplicitPolicy != null) {
                match = false;
            }
        } else if (!expRequireExplicitPolicy.equals(isRequreExplicitPolicy)) {
            match = false;
        }

        if (!match) {
            addViolation(failureMsg, "requreExplicitPolicy", isRequreExplicitPolicy,
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
    } // method checkExtensionPolicyConstraints

    private void checkExtensionKeyUsage(final StringBuilder failureMsg, final byte[] extensionValue,
            final boolean[] usages, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
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
        if (requestedExtensions != null && extControl.isRequest()
                && CollectionUtil.isNonEmpty(optionalKeyusage)) {
            Extension extension = requestedExtensions.getExtension(Extension.keyUsage);
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

        if (CollectionUtil.isEmpty(expectedUsages)) {
            byte[] constantExtValue = getConstantExtensionValue(Extension.keyUsage);
            if (constantExtValue != null) {
                expectedUsages = getKeyUsage(constantExtValue);
            }
        }

        Set<String> diffs = strInBnotInA(expectedUsages, isUsages);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("usages ").append(diffs.toString())
                .append(" are present but not expected; ");
        }

        diffs = strInBnotInA(isUsages, expectedUsages);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("usages ").append(diffs.toString())
                .append(" are absent but are required; ");
        }
    } // method checkExtensionKeyUsage

    private void checkExtensionExtendedKeyUsage(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
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
        if (requestedExtensions != null && extControl.isRequest()
                && CollectionUtil.isNonEmpty(optionalExtKeyusage)) {
            Extension extension = requestedExtensions.getExtension(Extension.extendedKeyUsage);
            if (extension != null) {
                org.bouncycastle.asn1.x509.ExtendedKeyUsage reqKeyUsage =
                        org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(
                                extension.getParsedValue());
                for (ExtKeyUsageControl k : optionalExtKeyusage) {
                    if (reqKeyUsage.hasKeyPurposeId(KeyPurposeId.getInstance(k.getExtKeyUsage()))) {
                        expectedUsages.add(k.getExtKeyUsage().getId());
                    }
                }
            }
        }

        if (CollectionUtil.isEmpty(expectedUsages)) {
            byte[] constantExtValue = getConstantExtensionValue(Extension.keyUsage);
            if (constantExtValue != null) {
                expectedUsages = getExtKeyUsage(constantExtValue);
            }
        }

        Set<String> diffs = strInBnotInA(expectedUsages, isUsages);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("usages ").append(diffs.toString())
                .append(" are present but not expected; ");
        }

        diffs = strInBnotInA(isUsages, expectedUsages);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("usages ").append(diffs.toString())
                .append(" are absent but are required; ");
        }
    } // method checkExtensionExtendedKeyUsage

    private void checkExtensionTlsFeature(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        QaTlsFeature conf = tlsFeature;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(ObjectIdentifiers.id_pe_tlsfeature,
                    requestedExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", hex(extensionValue),
                        (expected == null) ? "not present" : hex(expected));
            }
            return;
        }

        Set<String> isFeatures = new HashSet<>();
        ASN1Sequence seq =
                ASN1Sequence.getInstance(extensionValue);
        final int n = seq.size();
        for (int i = 0; i < n; i++) {
            ASN1Integer asn1Feature = ASN1Integer.getInstance(seq.getObjectAt(i));
            isFeatures.add(asn1Feature.getPositiveValue().toString());
        }

        Set<String> expFeatures = new HashSet<>();
        for (Integer m : conf.getFeatures()) {
            expFeatures.add(m.toString());
        }

        Set<String> diffs = strInBnotInA(expFeatures, isFeatures);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("features ").append(diffs.toString())
                .append(" are present but not expected; ");
        }

        diffs = strInBnotInA(isFeatures, expFeatures);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("features ").append(diffs.toString())
                .append(" are absent but are required; ");
        }
    } // method checkExtensionTlsFeature

    private void checkExtensionCertificatePolicies(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        QaCertificatePolicies conf = certificatePolicies;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.certificatePolicies,
                    requestedExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", hex(extensionValue),
                        (expected == null) ? "not present" : hex(expected));
            }
            return;
        }

        org.bouncycastle.asn1.x509.CertificatePolicies asn1 =
                org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(extensionValue);
        PolicyInformation[] isPolicyInformations = asn1.getPolicyInformation();

        for (PolicyInformation isPolicyInformation : isPolicyInformations) {
            ASN1ObjectIdentifier isPolicyId = isPolicyInformation.getPolicyIdentifier();
            QaCertificatePolicyInformation expCp = conf.getPolicyInformation(isPolicyId.getId());
            if (expCp == null) {
                failureMsg.append("certificate policy '").append(isPolicyId);
                failureMsg.append("' is not expected; ");
                continue;
            }

            QaPolicyQualifiers expCpPq = expCp.getPolicyQualifiers();
            if (expCpPq == null) {
                continue;
            }

            ASN1Sequence isPolicyQualifiers = isPolicyInformation.getPolicyQualifiers();
            List<String> isCpsUris = new LinkedList<>();
            List<String> isUserNotices = new LinkedList<>();

            int size = isPolicyQualifiers.size();
            for (int i = 0; i < size; i++) {
                PolicyQualifierInfo isPolicyQualifierInfo =
                        (PolicyQualifierInfo) isPolicyQualifiers.getObjectAt(i);
                ASN1ObjectIdentifier isPolicyQualifierId =
                        isPolicyQualifierInfo.getPolicyQualifierId();
                ASN1Encodable isQualifier = isPolicyQualifierInfo.getQualifier();
                if (PolicyQualifierId.id_qt_cps.equals(isPolicyQualifierId)) {
                    String isCpsUri = ((DERIA5String) isQualifier).getString();
                    isCpsUris.add(isCpsUri);
                } else if (PolicyQualifierId.id_qt_unotice.equals(isPolicyQualifierId)) {
                    UserNotice isUserNotice = UserNotice.getInstance(isQualifier);
                    if (isUserNotice.getExplicitText() != null) {
                        isUserNotices.add(isUserNotice.getExplicitText().getString());
                    }
                }
            }

            List<QaPolicyQualifierInfo> qualifierInfos = expCpPq.getPolicyQualifiers();
            for (QaPolicyQualifierInfo qualifierInfo : qualifierInfos) {
                if (qualifierInfo instanceof QaCpsUriPolicyQualifier) {
                    String value = ((QaCpsUriPolicyQualifier) qualifierInfo).getCpsUri();
                    if (!isCpsUris.contains(value)) {
                        failureMsg.append("CPSUri '").append(value);
                        failureMsg.append("' is absent but is required; ");
                    }
                } else if (qualifierInfo instanceof QaUserNoticePolicyQualifierInfo) {
                    String value =
                            ((QaUserNoticePolicyQualifierInfo) qualifierInfo).getUserNotice();
                    if (!isUserNotices.contains(value)) {
                        failureMsg.append("userNotice '").append(value);
                        failureMsg.append("' is absent but is required; ");
                    }
                } else {
                    throw new RuntimeException("should not reach here");
                }
            }
        }

        for (QaCertificatePolicyInformation cp : conf.getPolicyInformations()) {
            boolean present = false;
            for (PolicyInformation isPolicyInformation : isPolicyInformations) {
                if (isPolicyInformation.getPolicyIdentifier().getId().equals(cp.getPolicyId())) {
                    present = true;
                    break;
                }
            }

            if (present) {
                continue;
            }

            failureMsg.append("certificate policy '").append(cp.getPolicyId());
            failureMsg.append("' is absent but is required; ");
        }
    } // method checkExtensionCertificatePolicies

    private void checkExtensionPolicyMappings(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        QaPolicyMappingsOption conf = policyMappings;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.policyMappings, requestedExtensions,
                    extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", hex(extensionValue),
                        (expected == null) ? "not present" : hex(expected));
            }
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

        Set<String> expIssuerDomainPolicies = conf.getIssuerDomainPolicies();
        for (String expIssuerDomainPolicy : expIssuerDomainPolicies) {
            String expSubjectDomainPolicy = conf.getSubjectDomainPolicy(expIssuerDomainPolicy);

            String isSubjectDomainPolicy = isMap.remove(expIssuerDomainPolicy);
            if (isSubjectDomainPolicy == null) {
                failureMsg.append("issuerDomainPolicy '").append(expIssuerDomainPolicy)
                    .append("' is absent but is required; ");
            } else if (!isSubjectDomainPolicy.equals(expSubjectDomainPolicy)) {
                addViolation(failureMsg, "subjectDomainPolicy for issuerDomainPolicy",
                        isSubjectDomainPolicy, expSubjectDomainPolicy);
            }
        }

        if (CollectionUtil.isNonEmpty(isMap)) {
            failureMsg.append("issuerDomainPolicies '").append(isMap.keySet());
            failureMsg.append("' are present but not expected; ");
        }
    } // method checkExtensionPolicyMappings

    private void checkExtensionInhibitAnyPolicy(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        QaInhibitAnyPolicy conf = inhibitAnyPolicy;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.inhibitAnyPolicy,
                    requestedExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", extensionValue,
                        (expected == null) ? "not present" : hex(expected));
            }
            return;
        }

        ASN1Integer asn1Int = ASN1Integer.getInstance(extensionValue);
        int isSkipCerts = asn1Int.getPositiveValue().intValue();
        if (isSkipCerts != conf.getSkipCerts()) {
            addViolation(failureMsg, "skipCerts", isSkipCerts, conf.getSkipCerts());
        }
    } // method checkExtensionInhibitAnyPolicy

    private void checkExtensionSubjectDirAttrs(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        SubjectDirectoryAttributesControl conf = certProfile.getSubjectDirAttrsControl();
        if (conf == null) {
            failureMsg.append("extension is present but not expected; ");
            return;
        }

        ASN1Encodable extInRequest = null;
        if (requestedExtensions != null) {
            extInRequest = requestedExtensions.getExtensionParsedValue(
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

            if (ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(attrType)) {
                expDateOfBirth = ASN1GeneralizedTime.getInstance(attrVal);
            } else if (ObjectIdentifiers.DN_PLACE_OF_BIRTH.equals(attrType)) {
                expPlaceOfBirth = DirectoryString.getInstance(attrVal).getString();
            } else if (ObjectIdentifiers.DN_GENDER.equals(attrType)) {
                expGender = DERPrintableString.getInstance(attrVal).getString();
            } else if (ObjectIdentifiers.DN_COUNTRY_OF_CITIZENSHIP.equals(attrType)) {
                String country = DERPrintableString.getInstance(attrVal).getString();
                expCountryOfCitizenshipList.add(country);
            } else if (ObjectIdentifiers.DN_COUNTRY_OF_RESIDENCE.equals(attrType)) {
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
            if ( !attrTypes.contains(attrType)) {
                failureMsg.append("attribute of type " + attrType.getId()
                    + " is present but not expected; ");
                continue;
            }

            ASN1Encodable[] attrs = attr.getAttributeValues();
            if (attrs.length != 1) {
                failureMsg.append("attribute of type " + attrType.getId()
                    + " does not single-value value: " + attrs.length + "; ");
                continue;
            }

            ASN1Encodable attrVal = attrs[0];

            if (ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(attrType)) {
                dateOfBirth = ASN1GeneralizedTime.getInstance(attrVal);
            } else if (ObjectIdentifiers.DN_PLACE_OF_BIRTH.equals(attrType)) {
                placeOfBirth = DirectoryString.getInstance(attrVal).getString();
            } else if (ObjectIdentifiers.DN_GENDER.equals(attrType)) {
                gender = DERPrintableString.getInstance(attrVal).getString();
            } else if (ObjectIdentifiers.DN_COUNTRY_OF_CITIZENSHIP.equals(attrType)) {
                String country = DERPrintableString.getInstance(attrVal).getString();
                countryOfCitizenshipList.add(country);
            } else if (ObjectIdentifiers.DN_COUNTRY_OF_RESIDENCE.equals(attrType)) {
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
            attrTypes.remove(ObjectIdentifiers.DN_DATE_OF_BIRTH);
        }

        if (placeOfBirth != null) {
            attrTypes.remove(ObjectIdentifiers.DN_PLACE_OF_BIRTH);
        }

        if (gender != null) {
            attrTypes.remove(ObjectIdentifiers.DN_GENDER);
        }

        if (!countryOfCitizenshipList.isEmpty()) {
            attrTypes.remove(ObjectIdentifiers.DN_COUNTRY_OF_CITIZENSHIP);
        }

        if (!countryOfResidenceList.isEmpty()) {
            attrTypes.remove(ObjectIdentifiers.DN_COUNTRY_OF_RESIDENCE);
        }

        attrTypes.removeAll(otherAttrs.keySet());

        if (!attrTypes.isEmpty()) {
            List<String> attrTypeTexts = new LinkedList<>();
            for (ASN1ObjectIdentifier oid : attrTypes) {
                attrTypeTexts.add(oid.getId());
            }
            failureMsg.append("required attributes of types " + attrTypeTexts
                    + " are not present; ");
        }

        if (dateOfBirth != null) {
            String timeStirng = dateOfBirth.getTimeString();
            if (!SubjectDnSpec.PATTERN_DATE_OF_BIRTH.matcher(timeStirng).matches()) {
                failureMsg.append("invalid dateOfBirth: " + timeStirng + "; ");
            }

            String exp = (expDateOfBirth == null) ? null : expDateOfBirth.getTimeString();
            if (!timeStirng.equalsIgnoreCase(exp)) {
                addViolation(failureMsg, "dateOfBirth", timeStirng, exp);
            }
        }

        if (gender != null) {
            if (!(gender.equalsIgnoreCase("F") || gender.equalsIgnoreCase("M"))) {
                failureMsg.append("invalid gender: " + gender + "; ");
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
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("countryOfCitizenship ").append(diffs.toString());
                failureMsg.append(" are present but not expected; ");
            }

            diffs = strInBnotInA(countryOfCitizenshipList, expCountryOfCitizenshipList);
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("countryOfCitizenship ").append(diffs.toString());
                failureMsg.append(" are absent but are required; ");
            }
        }

        if (!countryOfResidenceList.isEmpty()) {
            Set<String> diffs = strInBnotInA(expCountryOfResidenceList, countryOfResidenceList);
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("countryOfResidence ").append(diffs.toString());
                failureMsg.append(" are present but not expected; ");
            }

            diffs = strInBnotInA(countryOfResidenceList, expCountryOfResidenceList);
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("countryOfResidence ").append(diffs.toString());
                failureMsg.append(" are absent but are required; ");
            }
        }

        if (!otherAttrs.isEmpty()) {
            for (ASN1ObjectIdentifier attrType : otherAttrs.keySet()) {
                Set<ASN1Encodable> expAttrValues = expOtherAttrs.get(attrType);
                if (expAttrValues == null) {
                    failureMsg.append("attribute of type " + attrType.getId()
                            + " is present but not requested; ");
                    continue;
                }
                Set<ASN1Encodable> attrValues = otherAttrs.get(attrType);
                if (!attrValues.equals(expAttrValues)) {
                    failureMsg.append("attribute of type " + attrType.getId()
                        + " differs from the requested one; ");
                    continue;
                }
            }
        }
    } // method checkExtensionSubjectDirectoryAttributes

    private void checkExtensionSubjectAltName(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl, final X500Name requestedSubject) {
        Set<GeneralNameMode> conf = certProfile.getSubjectAltNameModes();

        GeneralName[] requested;
        try {
            requested = getRequestedSubjectAltNames(requestedSubject, requestedExtensions);
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
    } // method checkExtensionSubjectAltName

    private GeneralName[] getRequestedSubjectAltNames(final X500Name requestedSubject,
            final Extensions requestedExtensions)
    throws CertprofileException, BadCertTemplateException {
        ASN1Encodable extValue = (requestedExtensions == null) ? null :
            requestedExtensions.getExtensionParsedValue(Extension.subjectAlternativeName);

        Map<ASN1ObjectIdentifier, GeneralNameTag> subjectToSubjectAltNameModes =
                certProfile.getSubjectToSubjectAltNameModes();
        if (extValue == null && subjectToSubjectAltNameModes == null) {
            return null;
        }

        GeneralNames reqNames = (extValue == null) ? null : GeneralNames.getInstance(extValue);

        Set<GeneralNameMode> subjectAltNameModes = certProfile.getSubjectAltNameModes();
        if (subjectAltNameModes == null && subjectToSubjectAltNameModes == null) {
            return (reqNames == null) ? null : reqNames.getNames();
        }

        List<GeneralName> grantedNames = new LinkedList<>();
        // copy the required attributes of Subject
        if (subjectToSubjectAltNameModes != null) {
            X500Name grantedSubject;
            try {
                grantedSubject = certProfile.getSubject(requestedSubject).getGrantedSubject();
            } catch (CertprofileException | BadCertTemplateException ex) {
                if (certProfile.getSpecialCertprofileBehavior() == null) {
                    throw ex;
                }

                LogUtil.warn(LOG, ex, "could not derive granted subject from requested subject");
                grantedSubject = requestedSubject;
            }

            for (ASN1ObjectIdentifier attrType : subjectToSubjectAltNameModes.keySet()) {
                GeneralNameTag tag = subjectToSubjectAltNameModes.get(attrType);

                RDN[] rdns = grantedSubject.getRDNs(attrType);
                if (rdns == null) {
                    rdns = requestedSubject.getRDNs(attrType);
                }

                if (rdns == null) {
                    continue;
                }

                for (RDN rdn : rdns) {
                    String rdnValue = X509Util.rdnValueToString(rdn.getFirst().getValue());
                    switch (tag) {
                    case rfc822Name:
                    case dNSName:
                    case uniformResourceIdentifier:
                    case iPAddress:
                    case directoryName:
                    case registeredID:
                        grantedNames.add(new GeneralName(tag.getTag(), rdnValue));
                        break;
                    default:
                        throw new RuntimeException(
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
    }

    private void checkExtensionSubjectInfoAccess(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> conf =
                certProfile.getSubjectInfoAccessModes();
        if (conf == null) {
            failureMsg.append("extension is present but not expected; ");
            return;
        }

        ASN1Encodable requestExtValue = null;
        if (requestedExtensions != null) {
            requestExtValue = requestedExtensions.getExtensionParsedValue(
                    Extension.subjectInfoAccess);
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
                failureMsg.append("accessMethod in requestedExtension ");
                failureMsg.append(accessMethod.getId()).append(" is not allowed; ");
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
                failureMsg.append("invalid requestedExtension: ").append(ex.getMessage());
                failureMsg.append("; ");
                continue;
            }

            GeneralName certAccessLocation = certAccessDesc.getAccessLocation();
            if (!certAccessLocation.equals(accessLocation)) {
                failureMsg.append("accessLocation does not match the requested one; ");
            }
        }
    } // method checkExtensionSubjectInfoAccess

    private void checkExtensionIssuerAltNames(final StringBuilder failureMsg,
            final byte[] extensionValue, final X509IssuerInfo issuerInfo) {
        Extension caSubjectAltExtension = issuerInfo.getBcCert().getTBSCertificate().getExtensions()
                .getExtension(Extension.subjectAlternativeName);
        if (caSubjectAltExtension == null) {
            failureMsg.append("issuerAlternativeName is present but expected 'none'; ");
            return;
        }

        byte[] caSubjectAltExtensionValue = caSubjectAltExtension.getExtnValue().getOctets();
        if (!Arrays.equals(caSubjectAltExtensionValue, extensionValue)) {
            addViolation(failureMsg, "issuerAltNames", hex(extensionValue),
                    hex(caSubjectAltExtensionValue));
        }
    } // method checkExtensionIssuerAltNames

    private void checkExtensionCrlDistributionPoints(final StringBuilder failureMsg,
            final byte[] extensionValue, final X509IssuerInfo issuerInfo) {
        CRLDistPoint isCrlDistPoints = CRLDistPoint.getInstance(extensionValue);
        DistributionPoint[] isDistributionPoints = isCrlDistPoints.getDistributionPoints();
        int len = (isDistributionPoints == null) ? 0 : isDistributionPoints.length;
        if (len != 1) {
            addViolation(failureMsg, "size of CRLDistributionPoints", len, 1);
            return;
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
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("CRL URLs ").append(diffs.toString())
                    .append(" are present but not expected; ");
            }

            diffs = strInBnotInA(isCrlUrls, expCrlUrls);
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("CRL URLs ").append(diffs.toString())
                    .append(" are absent but are required; ");
            }
        }
    } // method checkExtensionCrlDistributionPoints

    private void checkExtensionDeltaCrlDistributionPoints(final StringBuilder failureMsg,
            final byte[] extensionValue, final X509IssuerInfo issuerInfo) {
        CRLDistPoint isCrlDistPoints = CRLDistPoint.getInstance(extensionValue);
        DistributionPoint[] isDistributionPoints = isCrlDistPoints.getDistributionPoints();
        int len = (isDistributionPoints == null) ? 0 : isDistributionPoints.length;
        if (len != 1) {
            addViolation(failureMsg, "size of CRLDistributionPoints (deltaCRL)", len, 1);
            return;
        }

        Set<String> isCrlUrls = new HashSet<>();
        for (DistributionPoint entry : isDistributionPoints) {
            int asn1Type = entry.getDistributionPoint().getType();
            if (asn1Type != DistributionPointName.FULL_NAME) {
                addViolation(failureMsg,
                        "tag of DistributionPointName of CRLDistibutionPoints (deltaCRL)",
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

            Set<String> expCrlUrls = issuerInfo.getCrlUrls();
            Set<String> diffs = strInBnotInA(expCrlUrls, isCrlUrls);
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("deltaCRL URLs ").append(diffs.toString())
                    .append(" are present but not expected; ");
            }

            diffs = strInBnotInA(isCrlUrls, expCrlUrls);
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("deltaCRL URLs ").append(diffs.toString())
                    .append(" are absent but are required; ");
            }
        }
    } // method checkExtensionDeltaCrlDistributionPoints

    private void checkExtensionAdmission(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        AdmissionSyntaxOption conf = certProfile.getAdmission();
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_admission;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(type, requestedExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension value", hex(extensionValue),
                        (expected == null) ? "not present" : hex(expected));
            }
            return;
        }

        List<List<String>> reqRegNumsList = null;
        if (requestedExtensions != null && conf.isInputFromRequestRequired()) {
            Extension extension = requestedExtensions.getExtension(type);
            if (extension == null) {
                failureMsg.append("no Admission extension is contained in the request;");
                return;
            }

            Admissions[] reqAdmissions =
                    org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax.getInstance(
                            extension.getParsedValue()).getContentsOfAdmissions();

            final int n = reqAdmissions.length;
            reqRegNumsList = new ArrayList<>(n);
            for (int i = 0; i < n; i++) {
                Admissions reqAdmission = reqAdmissions[i];
                ProfessionInfo[] reqPis = reqAdmission.getProfessionInfos();
                List<String> reqNums = new ArrayList<>(reqPis.length);
                reqRegNumsList.add(reqNums);
                for (ProfessionInfo reqPi : reqPis) {
                    String reqNum = reqPi.getRegistrationNumber();
                    reqNums.add(reqNum);
                }
            }
        }

        try {
            byte[] expected = conf.getExtensionValue(reqRegNumsList).getValue()
                    .toASN1Primitive().getEncoded();
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", hex(extensionValue), hex(expected));
            }
        } catch (IOException ex) {
            LogUtil.error(LOG, ex);
            failureMsg.append("IOException while computing the expected extension value;");
            return;
        } catch (BadCertTemplateException ex) {
            LogUtil.error(LOG, ex);
            failureMsg.append(
                    "BadCertTemplateException while computing the expected extension value;");
        }

    } // method checkExtensionAdmission

    private void checkExtensionAuthorityInfoAccess(final StringBuilder failureMsg,
            final byte[] extensionValue, final X509IssuerInfo issuerInfo) {
        AuthorityInfoAccessControl aiaControl = certProfile.getAiaControl();
        Set<String> expCaIssuerUris = (aiaControl == null || aiaControl.includesCaIssuers())
                ? issuerInfo.getCaIssuerUrls() : Collections.emptySet();

        Set<String> expOcspUris = (aiaControl == null || aiaControl.includesOcsp())
                ? issuerInfo.getOcspUrls() : Collections.emptySet();

        if (CollectionUtil.isEmpty(expCaIssuerUris) && CollectionUtil.isEmpty(expOcspUris)) {
            failureMsg.append("AIA is present but expected is 'none'; ");
            return;
        }

        AuthorityInformationAccess isAia = AuthorityInformationAccess.getInstance(extensionValue);
        checkAia(failureMsg, isAia, X509ObjectIdentifiers.id_ad_caIssuers, expCaIssuerUris);
        checkAia(failureMsg, isAia, X509ObjectIdentifiers.id_ad_ocsp, expOcspUris);
    } // method checkExtensionAuthorityInfoAccess

    private void checkExtensionOcspNocheck(final StringBuilder failureMsg,
            final byte[] extensionValue) {
        if (!Arrays.equals(DER_NULL, extensionValue)) {
            failureMsg.append("value is not DER NULL; ");
        }
    }

    private void checkExtensionRestriction(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        checkDirectoryString(ObjectIdentifiers.id_extension_restriction, restriction,
                failureMsg, extensionValue, requestedExtensions, extControl);
    }

    private void checkExtensionAdditionalInformation(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        checkDirectoryString(ObjectIdentifiers.id_extension_additionalInformation,
                additionalInformation, failureMsg, extensionValue, requestedExtensions, extControl);
    }

    private void checkDirectoryString(final ASN1ObjectIdentifier extType,
            final QaDirectoryString conf, final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        if (conf == null) {
            byte[] expected = getExpectedExtValue(extType,
                    requestedExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", hex(extensionValue),
                        (expected == null) ? "not present" : hex(expected));
            }
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
        switch (conf.getType()) {
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
            throw new RuntimeException("should not reach here, unknown DirectoryStringType "
                    + conf.getType());
        } // end switch

        if (!correctStringType) {
            failureMsg.append("extension value is not of type DirectoryString.")
                .append(conf.getText()).append("; ");
            return;
        }

        String extTextValue = ((ASN1String) asn1).getString();
        if (!conf.getText().equals(extTextValue)) {
            addViolation(failureMsg, "content", extTextValue, conf.getText());
        }
    } // method checkDirectoryString

    private void checkExtensionValidityModel(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        ASN1ObjectIdentifier conf = validityModelId;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(ObjectIdentifiers.id_extension_validityModel,
                    requestedExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", hex(extensionValue),
                        (expected == null) ? "not present" : hex(expected));
            }
            return;
        }

        ASN1ObjectIdentifier extValue = ASN1ObjectIdentifier.getInstance(extensionValue);
        if (!conf.equals(extValue)) {
            addViolation(failureMsg, "content", extValue, conf);
        }
    } // method checkExtensionValidityModel

    private void checkExtensionPrivateKeyUsagePeriod(final StringBuilder failureMsg,
            final byte[] extensionValue, final Date certNotBefore, final Date certNotAfter) {
        ASN1GeneralizedTime notBefore = new ASN1GeneralizedTime(certNotBefore);
        Date dateNotAfter;
        CertValidity privateKeyUsagePeriod = certProfile.getPrivateKeyUsagePeriod();
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
    } // method checkExtensionPrivateKeyUsagePeriod

    private void checkExtensionQcStatements(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        QcStatements conf = qcStatements;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.qCStatements,
                    requestedExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", extensionValue,
                        (expected == null) ? "not present" : hex(expected));
            }
            return;
        }

        final int expSize = conf.getQcStatement().size();
        ASN1Sequence extValue = ASN1Sequence.getInstance(extensionValue);
        final int isSize = extValue.size();
        if (isSize != expSize) {
            addViolation(failureMsg, "number of statements", isSize, expSize);
            return;
        }

        // extract the euLimit and pdsLocations data from request
        Map<String, int[]> reqQcEuLimits = new HashMap<>();
        Extension reqExtension = (requestedExtensions == null) ? null :
            requestedExtensions.getExtension(Extension.qCStatements);
        if (reqExtension != null) {
            ASN1Sequence seq = ASN1Sequence.getInstance(reqExtension.getParsedValue());

            final int n = seq.size();
            for (int j = 0; j < n; j++) {
                QCStatement stmt = QCStatement.getInstance(seq.getObjectAt(j));
                if (ObjectIdentifiers.id_etsi_qcs_QcLimitValue.equals(stmt.getStatementId())) {
                    MonetaryValue monetaryValue = MonetaryValue.getInstance(
                            stmt.getStatementInfo());
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
            QcStatementType exp = conf.getQcStatement().get(i);
            if (!is.getStatementId().getId().equals(exp.getStatementId().getValue())) {
                addViolation(failureMsg, "statmentId[" + i + "]",
                        is.getStatementId().getId(), exp.getStatementId().getValue());
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
                        addViolation(failureMsg, "statementInfo[" + i + "]",
                                hex(isValue), hex(expValue));
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
                        ASN1Sequence pdsLocSeq = ASN1Sequence.getInstance(
                                pdsLocsSeq.getObjectAt(k));
                        int size2 = pdsLocSeq.size();
                        if (size2 != 2) {
                            throw new IllegalArgumentException("sequence size is " + size2
                                    + " but expected 2");
                        }
                        String url = DERIA5String.getInstance(pdsLocSeq.getObjectAt(0)).getString();
                        String lang = DERPrintableString.getInstance(pdsLocSeq.getObjectAt(1))
                                .getString();
                        pdsLocations.add("url=" + url + ",lang=" + lang);
                    }

                    PdsLocationsType pdsLocationsConf = expStatementValue.getPdsLocations();
                    Set<String> expectedPdsLocations = new HashSet<>();
                    for (PdsLocationType m : pdsLocationsConf.getPdsLocation()) {
                        expectedPdsLocations.add("url=" + m.getUrl() + ",lang=" + m.getLanguage());
                    }

                    Set<String> diffs = strInBnotInA(expectedPdsLocations, pdsLocations);
                    if (CollectionUtil.isNonEmpty(diffs)) {
                        failureMsg.append("statementInfo[" + i + "]: ").append(diffs.toString());
                        failureMsg.append(" are present but not expected; ");
                    }

                    diffs = strInBnotInA(pdsLocations, expectedPdsLocations);
                    if (CollectionUtil.isNonEmpty(diffs)) {
                        failureMsg.append("statementInfo[" + i + "]: ").append(diffs.toString());
                        failureMsg.append(" are absent but are required; ");
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
                    throw new RuntimeException("statementInfo[" + i + "]should not reach here");
                }
            } catch (IOException ex) {
                failureMsg.append("statementInfo[").append(i).append("] has incorrect syntax; ");
            }
        }
    } // method checkExtensionQcStatements

    private void checkExtensionBiometricInfo(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        BiometricInfoOption conf = certProfile.getBiometricInfo();

        if (conf == null) {
            failureMsg.append("extension is present but not expected; ");
            return;
        }

        ASN1Encodable extInRequest = null;
        if (requestedExtensions != null) {
            extInRequest = requestedExtensions.getExtensionParsedValue(Extension.biometricInfo);
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

                addViolation(failureMsg, "biometricData[" + i + "].typeOfBiometricData",
                        isStr, expStr);
            }

            ASN1ObjectIdentifier is = isData.getHashAlgorithm().getAlgorithm();
            ASN1ObjectIdentifier exp = expData.getHashAlgorithm().getAlgorithm();
            if (!is.equals(exp)) {
                addViolation(failureMsg, "biometricData[" + i + "].hashAlgorithm",
                        is.getId(), exp.getId());
            }

            ASN1Encodable isHashAlgoParam = isData.getHashAlgorithm().getParameters();
            if (isHashAlgoParam == null) {
                failureMsg.append("biometricData[").append(i)
                    .append("].hashAlgorithm.parameters is 'present'");
                failureMsg.append(" but expected 'absent'; ");
            } else {
                try {
                    byte[] isBytes = isHashAlgoParam.toASN1Primitive().getEncoded();
                    if (!Arrays.equals(isBytes, DER_NULL)) {
                        addViolation(failureMsg,
                                "biometricData[" + i + "].biometricDataHash.parameters",
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
            if (conf.getSourceDataUriOccurrence() != TripleState.FORBIDDEN) {
                str = expData.getSourceDataUri();
                expSourceDataUri = (str == null) ? null : str.getString();
            }

            if (expSourceDataUri == null) {
                if (isSourceDataUri != null) {
                    addViolation(failureMsg, "biometricData[" + i + "].sourceDataUri",
                            "present", "absent");
                }
            } else {
                if (isSourceDataUri == null) {
                    failureMsg.append("biometricData[").append(i)
                        .append("].sourceDataUri is 'absent'");
                    failureMsg.append(" but expected 'present'; ");
                } else if (!isSourceDataUri.equals(expSourceDataUri)) {
                    addViolation(failureMsg, "biometricData[" + i + "].sourceDataUri",
                            isSourceDataUri, expSourceDataUri);
                }
            }
        }
    } // method checkExtensionBiometricInfo

    private void checkExtensionAuthorizationTemplate(final StringBuilder failureMsg,
            final byte[] extensionValue, final Extensions requestedExtensions,
            final ExtensionControl extControl) {
        QaAuthorizationTemplate conf = authorizationTemplate;

        if (conf == null) {
            byte[] expected = getExpectedExtValue(
                    ObjectIdentifiers.id_xipki_ext_authorizationTemplate,
                    requestedExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                addViolation(failureMsg, "extension valus", hex(extensionValue),
                        (expected == null) ? "not present" : hex(expected));
            }
            return;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(extensionValue);
        ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        ASN1OctetString accessRights = DEROctetString.getInstance(seq.getObjectAt(1));
        if (!conf.getType().equals(type.getId())) {
            addViolation(failureMsg, "type", type.getId(), conf.getType());
        }

        byte[] isRights = accessRights.getOctets();
        if (!Arrays.equals(conf.getAccessRights(), isRights)) {
            addViolation(failureMsg, "accessRights", hex(isRights), hex(conf.getAccessRights()));
        }
    } // method checkExtensionAuthorizationTemplate

    private Set<KeyUsageControl> getKeyusage(final boolean required) {
        Set<KeyUsageControl> ret = new HashSet<>();

        Set<KeyUsageControl> controls = certProfile.getKeyusages();
        if (controls != null) {
            for (KeyUsageControl control : controls) {
                if (control.isRequired() == required) {
                    ret.add(control);
                }
            }
        }
        return ret;
    }

    private Set<ExtKeyUsageControl> getExtKeyusage(final boolean required) {
        Set<ExtKeyUsageControl> ret = new HashSet<>();

        Set<ExtKeyUsageControl> controls = certProfile.getExtendedKeyusages();
        if (controls != null) {
            for (ExtKeyUsageControl control : controls) {
                if (control.isRequired() == required) {
                    ret.add(control);
                }
            }
        }
        return ret;
    }

    private byte[] getConstantExtensionValue(final ASN1ObjectIdentifier type) {
        return (constantExtensions == null) ? null : constantExtensions.get(type).getValue();
    }

    private Object getExtensionValue(final ASN1ObjectIdentifier type,
            final ExtensionsType extensionsType, final Class<?> expectedClass)
    throws CertprofileException {
        for (ExtensionType m : extensionsType.getExtension()) {
            if (!m.getType().getValue().equals(type.getId())) {
                continue;
            }

            if (m.getValue() == null || m.getValue().getAny() == null) {
                return null;
            }

            Object obj = m.getValue().getAny();
            if (expectedClass.isAssignableFrom(obj.getClass())) {
                return obj;
            } else if (ConstantExtValue.class.isAssignableFrom(obj.getClass())) {
                // will be processed later
                return null;
            } else {
                String displayName = ObjectIdentifiers.oidToDisplayName(type);
                throw new CertprofileException("the extension configuration for " + displayName
                        + " is not of the expected type " + expectedClass.getName());
            }
        }

        throw new RuntimeException("should not reach here: undefined extension "
                + ObjectIdentifiers.oidToDisplayName(type));
    } // method getExtensionValue

    public static Map<ASN1ObjectIdentifier, QaExtensionValue> buildConstantExtesions(
            final ExtensionsType extensionsType) throws CertprofileException {
        if (extensionsType == null) {
            return null;
        }

        Map<ASN1ObjectIdentifier, QaExtensionValue> map = new HashMap<>();

        for (ExtensionType m : extensionsType.getExtension()) {
            if (m.getValue() == null || !(m.getValue().getAny() instanceof ConstantExtValue)) {
                continue;
            }

            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(m.getType().getValue());
            if (Extension.subjectAlternativeName.equals(oid)
                    || Extension.subjectInfoAccess.equals(oid)
                    || Extension.biometricInfo.equals(oid)) {
                continue;
            }

            ConstantExtValue extConf = (ConstantExtValue) m.getValue().getAny();
            byte[] encodedValue = extConf.getValue();
            ASN1StreamParser parser = new ASN1StreamParser(encodedValue);
            try {
                parser.readObject();
            } catch (IOException ex) {
                throw new CertprofileException("could not parse the constant extension value", ex);
            }
            QaExtensionValue extension = new QaExtensionValue(m.isCritical(), encodedValue);
            map.put(oid, extension);
        }

        if (CollectionUtil.isEmpty(map)) {
            return null;
        }

        return Collections.unmodifiableMap(map);
    } // method buildConstantExtesions

    private static ASN1Encodable readAsn1Encodable(final byte[] encoded)
    throws CertprofileException {
        ASN1StreamParser parser = new ASN1StreamParser(encoded);
        try {
            return parser.readObject();
        } catch (IOException ex) {
            throw new CertprofileException("could not parse the constant extension value", ex);
        }
    }

    private static String hex(final byte[] bytes) {
        return Hex.toHexString(bytes);
    }

    private static Set<String> strInBnotInA(final Collection<String> collectionA,
            final Collection<String> collectionB) {
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
    }

    static Set<Range> buildParametersMap(final RangesType ranges) {
        if (ranges == null) {
            return null;
        }

        Set<Range> ret = new HashSet<>();
        for (RangeType range : ranges.getRange()) {
            if (range.getMin() != null || range.getMax() != null) {
                ret.add(new Range(range.getMin(), range.getMax()));
            }
        }
        return ret;
    }

    private static GeneralName createGeneralName(final GeneralName reqName,
            final Set<GeneralNameMode> modes) throws BadCertTemplateException {
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
                throw new BadCertTemplateException(
                        "otherName.type " + type.getId() + " is not allowed");
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
            DERSequence seq = new DERSequence(vector);

            return new GeneralName(GeneralName.otherName, seq);
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
            seq = new DERSequence(vector);
            return new GeneralName(GeneralName.ediPartyName, seq);
        default:
            throw new RuntimeException("should not reach here, unknwon GeneralName tag " + tag);
        } // end switch
    } // method createGeneralName

    private static Set<String> getKeyUsage(final byte[] extensionValue) {
        Set<String> usages = new HashSet<>();
        org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
                org.bouncycastle.asn1.x509.KeyUsage.getInstance(extensionValue);
        for (KeyUsage k : KeyUsage.values()) {
            if (reqKeyUsage.hasUsages(k.getBcUsage())) {
                usages.add(k.getName());
            }
        }

        return usages;
    }

    private static Set<String> getExtKeyUsage(final byte[] extensionValue) {
        Set<String> usages = new HashSet<>();
        org.bouncycastle.asn1.x509.ExtendedKeyUsage reqKeyUsage =
                org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extensionValue);
        for (KeyPurposeId usage : reqKeyUsage.getUsages()) {
            usages.add(usage.getId());
        }
        return usages;
    }

    private static void checkAia(final StringBuilder failureMsg,
            final AuthorityInformationAccess aia, final ASN1ObjectIdentifier accessMethod,
            final Set<String> expectedUris) {
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
            addViolation(failureMsg, "number of AIA " + typeDesc + " URIs",
                    size, expectedUris.size());
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
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append(typeDesc).append(" URIs ").append(diffs.toString());
            failureMsg.append(" are present but not expected; ");
        }

        diffs = strInBnotInA(isUris, expectedUris);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append(typeDesc).append(" URIs ").append(diffs.toString());
            failureMsg.append(" are absent but are required; ");
        }
    } // method checkAia

    private static void addViolation(final StringBuilder failureMsg, final String field,
            final Object is, final Object expected) {
        failureMsg.append(field).append(" is '").append(is);
        failureMsg.append("' but expected '").append(expected).append("';");
    }

}
