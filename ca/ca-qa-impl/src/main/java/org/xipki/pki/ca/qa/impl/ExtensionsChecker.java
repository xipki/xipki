/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.pki.ca.qa.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
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
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
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
import org.xipki.commons.security.api.ExtensionExistence;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.KeyUsage;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.util.AlgorithmUtil;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.api.BadCertTemplateException;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.api.profile.ExtensionControl;
import org.xipki.pki.ca.api.profile.GeneralNameMode;
import org.xipki.pki.ca.api.profile.Range;
import org.xipki.pki.ca.api.profile.x509.AuthorityInfoAccessControl;
import org.xipki.pki.ca.api.profile.x509.ExtKeyUsageControl;
import org.xipki.pki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.pki.ca.api.profile.x509.X509CertVersion;
import org.xipki.pki.ca.api.profile.x509.X509Certprofile;
import org.xipki.pki.ca.certprofile.BiometricInfoOption;
import org.xipki.pki.ca.certprofile.XmlX509CertprofileUtil;
import org.xipki.pki.ca.certprofile.x509.jaxb.AdditionalInformation;
import org.xipki.pki.ca.certprofile.x509.jaxb.Admission;
import org.xipki.pki.ca.certprofile.x509.jaxb.AuthorizationTemplate;
import org.xipki.pki.ca.certprofile.x509.jaxb.BiometricInfo;
import org.xipki.pki.ca.certprofile.x509.jaxb.ConstantExtValue;
import org.xipki.pki.ca.certprofile.x509.jaxb.ExtendedKeyUsage;
import org.xipki.pki.ca.certprofile.x509.jaxb.ExtensionType;
import org.xipki.pki.ca.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.pki.ca.certprofile.x509.jaxb.InhibitAnyPolicy;
import org.xipki.pki.ca.certprofile.x509.jaxb.PolicyConstraints;
import org.xipki.pki.ca.certprofile.x509.jaxb.PolicyMappings;
import org.xipki.pki.ca.certprofile.x509.jaxb.PrivateKeyUsagePeriod;
import org.xipki.pki.ca.certprofile.x509.jaxb.QCStatementType;
import org.xipki.pki.ca.certprofile.x509.jaxb.QCStatementValueType;
import org.xipki.pki.ca.certprofile.x509.jaxb.QCStatements;
import org.xipki.pki.ca.certprofile.x509.jaxb.QcEuLimitValueType;
import org.xipki.pki.ca.certprofile.x509.jaxb.Range2Type;
import org.xipki.pki.ca.certprofile.x509.jaxb.RangeType;
import org.xipki.pki.ca.certprofile.x509.jaxb.RangesType;
import org.xipki.pki.ca.certprofile.x509.jaxb.Restriction;
import org.xipki.pki.ca.certprofile.x509.jaxb.SMIMECapabilities;
import org.xipki.pki.ca.certprofile.x509.jaxb.SMIMECapability;
import org.xipki.pki.ca.certprofile.x509.jaxb.SubjectAltName;
import org.xipki.pki.ca.certprofile.x509.jaxb.SubjectInfoAccess;
import org.xipki.pki.ca.certprofile.x509.jaxb.SubjectInfoAccess.Access;
import org.xipki.pki.ca.certprofile.x509.jaxb.TlsFeature;
import org.xipki.pki.ca.certprofile.x509.jaxb.TripleState;
import org.xipki.pki.ca.certprofile.x509.jaxb.ValidityModel;
import org.xipki.pki.ca.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.pki.ca.qa.api.X509IssuerInfo;
import org.xipki.pki.ca.qa.impl.internal.QaAdmission;
import org.xipki.pki.ca.qa.impl.internal.QaAuthorizationTemplate;
import org.xipki.pki.ca.qa.impl.internal.QaCertificatePolicies;
import org.xipki.pki.ca.qa.impl.internal.QaCertificatePolicies.QaCertificatePolicyInformation;
import org.xipki.pki.ca.qa.impl.internal.QaDirectoryString;
import org.xipki.pki.ca.qa.impl.internal.QaExtensionValue;
import org.xipki.pki.ca.qa.impl.internal.QaGeneralSubtree;
import org.xipki.pki.ca.qa.impl.internal.QaInhibitAnyPolicy;
import org.xipki.pki.ca.qa.impl.internal.QaNameConstraints;
import org.xipki.pki.ca.qa.impl.internal.QaPolicyConstraints;
import org.xipki.pki.ca.qa.impl.internal.QaPolicyMappingsOption;
import org.xipki.pki.ca.qa.impl.internal.QaPolicyQualifierInfo;
import org.xipki.pki.ca.qa.impl.internal.QaPolicyQualifierInfo.QaCpsUriPolicyQualifier;
import org.xipki.pki.ca.qa.impl.internal.QaPolicyQualifierInfo.QaUserNoticePolicyQualifierInfo;
import org.xipki.pki.ca.qa.impl.internal.QaPolicyQualifiers;
import org.xipki.pki.ca.qa.impl.internal.QaTlsFeature;

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

    private String specialBehavior;

    private Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls;

    private X509CertVersion version;

    private Set<String> signatureAlgorithms;

    private boolean ca;

    private Integer pathLen;

    private AuthorityInfoAccessControl aiaControl;

    private Set<KeyUsageControl> keyusages;

    private Set<ExtKeyUsageControl> extendedKeyusages;

    private Set<GeneralNameMode> allowedSubjectAltNameModes;

    private Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> allowedSubjectInfoAccessModes;

    private boolean includeIssuerAndSerialInAki;

    private QaCertificatePolicies certificatePolicies;

    private QaPolicyMappingsOption policyMappings;

    private QaNameConstraints nameConstraints;

    private QaPolicyConstraints policyConstraints;

    private QaInhibitAnyPolicy inhibitAnyPolicy;

    private QaAdmission admission;

    private QaDirectoryString restriction;

    private QaDirectoryString additionalInformation;

    private ASN1ObjectIdentifier validityModelId;

    private CertValidity privateKeyUsagePeriod;

    private QCStatements qcStatements;

    private BiometricInfoOption biometricInfo;

    private QaAuthorizationTemplate authorizationTemplate;

    private QaTlsFeature tlsFeature;

    private QaExtensionValue smimeCapabilities;

    private Map<ASN1ObjectIdentifier, QaExtensionValue> constantExtensions;

    public ExtensionsChecker(
            final X509ProfileType conf)
    throws CertprofileException {
        ParamUtil.requireNonNull("conf", conf);
        try {
            this.version = X509CertVersion.getInstance(conf.getVersion());
            if (this.version == null) {
                throw new CertprofileException("invalid version " + conf.getVersion());
            }

            if (conf.getSignatureAlgorithms() != null) {
                this.signatureAlgorithms = new HashSet<>();
                for (String algo :conf.getSignatureAlgorithms().getAlgorithm()) {
                    String c14nAlgo;
                    try {
                        c14nAlgo = AlgorithmUtil.canonicalizeSignatureAlgo(algo);
                    } catch (NoSuchAlgorithmException ex) {
                        throw new CertprofileException(ex.getMessage(), ex);
                    }
                    this.signatureAlgorithms.add(c14nAlgo);
                }
            }

            this.ca = conf.isCa();
            this.specialBehavior = conf.getSpecialBehavior();
            if (this.specialBehavior != null
                    && !"gematik_gSMC_K".equalsIgnoreCase(this.specialBehavior)) {
                throw new CertprofileException("unknown special bahavior " + this.specialBehavior);
            }

            // Extensions
            ExtensionsType extensionsType = conf.getExtensions();

            // Extension controls
            this.extensionControls = XmlX509CertprofileUtil.buildExtensionControls(extensionsType);

            // BasicConstrains
            ASN1ObjectIdentifier type = Extension.basicConstraints;
            if (extensionControls.containsKey(type)) {
                org.xipki.pki.ca.certprofile.x509.jaxb.BasicConstraints extConf =
                        (org.xipki.pki.ca.certprofile.x509.jaxb.BasicConstraints)
                            getExtensionValue(type, extensionsType,
                                    org.xipki.pki.ca.certprofile.x509.jaxb.BasicConstraints.class);
                if (extConf != null) {
                    this.pathLen = extConf.getPathLen();
                }
            }

            // Extension KeyUsage
            type = Extension.keyUsage;
            if (extensionControls.containsKey(type)) {
                org.xipki.pki.ca.certprofile.x509.jaxb.KeyUsage extConf =
                        (org.xipki.pki.ca.certprofile.x509.jaxb.KeyUsage)
                            getExtensionValue(type, extensionsType,
                                    org.xipki.pki.ca.certprofile.x509.jaxb.KeyUsage.class);
                if (extConf != null) {
                    this.keyusages = XmlX509CertprofileUtil.buildKeyUsageOptions(extConf);
                }
            }

            // ExtendedKeyUsage
            type = Extension.extendedKeyUsage;
            if (extensionControls.containsKey(type)) {
                ExtendedKeyUsage extConf = (ExtendedKeyUsage) getExtensionValue(
                        type, extensionsType, ExtendedKeyUsage.class);
                if (extConf != null) {
                    this.extendedKeyusages =
                            XmlX509CertprofileUtil.buildExtKeyUsageOptions(extConf);
                }
            }

            // AuthorityKeyIdentifier
            type = Extension.authorityKeyIdentifier;
            if (extensionControls.containsKey(type)) {
                org.xipki.pki.ca.certprofile.x509.jaxb.AuthorityKeyIdentifier extConf =
                    (org.xipki.pki.ca.certprofile.x509.jaxb.AuthorityKeyIdentifier)
                        getExtensionValue(type, extensionsType,
                            org.xipki.pki.ca.certprofile.x509.jaxb.AuthorityKeyIdentifier.class);
                if (extConf != null) {
                    this.includeIssuerAndSerialInAki = extConf.isIncludeIssuerAndSerial();
                }
            }

            // Certificate Policies
            type = Extension.certificatePolicies;
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

            // admission
            type = ObjectIdentifiers.id_extension_admission;
            if (extensionControls.containsKey(type)) {
                Admission extConf = (Admission) getExtensionValue(
                        type, extensionsType, Admission.class);
                if (extConf != null) {
                    this.admission = new QaAdmission(extConf);
                }
            }

            // SubjectAltNameMode
            type = Extension.subjectAlternativeName;
            if (extensionControls.containsKey(type)) {
                SubjectAltName extConf = (SubjectAltName) getExtensionValue(
                        type, extensionsType, SubjectAltName.class);
                if (extConf != null) {
                    this.allowedSubjectAltNameModes =
                            XmlX509CertprofileUtil.buildGeneralNameMode(extConf);
                }
            }

            // SubjectInfoAccess
            type = Extension.subjectInfoAccess;
            if (extensionControls.containsKey(type)) {
                SubjectInfoAccess extConf = (SubjectInfoAccess) getExtensionValue(
                        type, extensionsType, SubjectInfoAccess.class);
                if (extConf != null) {
                    List<Access> list = extConf.getAccess();
                    this.allowedSubjectInfoAccessModes = new HashMap<>();
                    for (Access entry : list) {
                        this.allowedSubjectInfoAccessModes.put(
                                new ASN1ObjectIdentifier(entry.getAccessMethod().getValue()),
                                XmlX509CertprofileUtil.buildGeneralNameMode(
                                        entry.getAccessLocation()));
                    }
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

            // PrivateKeyUsagePeriod
            type = Extension.privateKeyUsagePeriod;
            if (extensionControls.containsKey(type)) {
                PrivateKeyUsagePeriod extConf = (PrivateKeyUsagePeriod) getExtensionValue(
                        type, extensionsType, PrivateKeyUsagePeriod.class);
                if (extConf != null) {
                    privateKeyUsagePeriod = CertValidity.getInstance(extConf.getValidity());
                }
            }

            // QCStatements
            type = Extension.qCStatements;
            if (extensionControls.containsKey(type)) {
                QCStatements extConf = (QCStatements) getExtensionValue(
                        type, extensionsType, QCStatements.class);
                if (extConf != null) {
                    qcStatements = extConf;
                }
            }

            // biometricInfo
            type = Extension.biometricInfo;
            if (extensionControls.containsKey(type)) {
                BiometricInfo extConf = (BiometricInfo) getExtensionValue(
                        type, extensionsType, BiometricInfo.class);
                if (extConf != null) {
                    try {
                        biometricInfo = new BiometricInfoOption(extConf);
                    } catch (NoSuchAlgorithmException ex) {
                        throw new CertprofileException(
                                "NoSuchAlgorithmException: " + ex.getMessage());
                    }
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
        } catch (RuntimeException ex) {
            final String message = "RuntimeException";
            LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
            LOG.debug(message, ex);
            throw new CertprofileException(
                    "RuntimeException thrown while initializing certprofile: " + ex.getMessage());
        }
    } // constructor

    public List<ValidationIssue> checkExtensions(
            final Certificate cert,
            final X509IssuerInfo issuerInfo,
            final Extensions requestExtensions) {
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
                getExensionTypes(cert, issuerInfo, requestExtensions);

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
                failureMsg.append("critical is '").append(ext.isCritical());
                failureMsg.append("' but expected '").append(extControl.isCritical()).append("'");
                failureMsg.append("; ");
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
                            requestExtensions, extControl);
                } else if (Extension.certificatePolicies.equals(oid)) {
                    // CertificatePolicies
                    checkExtensionCertificatePolicies(failureMsg, extensionValue,
                            requestExtensions, extControl);
                } else if (Extension.policyMappings.equals(oid)) {
                    // Policy Mappings
                    checkExtensionPolicyMappings(failureMsg, extensionValue, requestExtensions,
                            extControl);
                } else if (Extension.subjectAlternativeName.equals(oid)) {
                    // SubjectAltName
                    checkExtensionSubjectAltName(failureMsg, extensionValue, requestExtensions,
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
                    checkExtensionPolicyConstraints(failureMsg, extensionValue, requestExtensions,
                            extControl);
                } else if (Extension.extendedKeyUsage.equals(oid)) {
                    // ExtendedKeyUsage
                    checkExtensionExtendedKeyUsage(failureMsg, extensionValue, requestExtensions,
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
                    checkExtensionSubjectInfoAccess(failureMsg, extensionValue, requestExtensions,
                            extControl);
                } else if (ObjectIdentifiers.id_extension_admission.equals(oid)) {
                    // Admission
                    checkExtensionAdmission(failureMsg, extensionValue, requestExtensions,
                            extControl);
                } else if (ObjectIdentifiers.id_extension_pkix_ocsp_nocheck.equals(oid)) {
                    // ocsp-nocheck
                    checkExtensionOcspNocheck(failureMsg, extensionValue);
                } else if (ObjectIdentifiers.id_extension_restriction.equals(oid)) {
                    // restriction
                    checkExtensionRestriction(failureMsg, extensionValue, requestExtensions,
                            extControl);
                } else if (ObjectIdentifiers.id_extension_additionalInformation.equals(oid)) {
                    // additionalInformation
                    checkExtensionAdditionalInformation(failureMsg, extensionValue,
                            requestExtensions, extControl);
                } else if (ObjectIdentifiers.id_extension_validityModel.equals(oid)) {
                    // validityModel
                    checkExtensionValidityModel(failureMsg, extensionValue, requestExtensions,
                            extControl);
                } else if (Extension.privateKeyUsagePeriod.equals(oid)) {
                    // privateKeyUsagePeriod
                    checkExtensionPrivateKeyUsagePeriod(failureMsg, extensionValue,
                            jceCert.getNotBefore(), jceCert.getNotAfter());
                } else if (Extension.qCStatements.equals(oid)) {
                    // qCStatements
                    checkExtensionQcStatements(failureMsg, extensionValue, requestExtensions,
                            extControl);
                } else if (Extension.biometricInfo.equals(oid)) {
                    // biometricInfo
                    checkExtensionBiometricInfo(failureMsg, extensionValue, requestExtensions,
                            extControl);
                } else if (ObjectIdentifiers.id_pe_tlsfeature.equals(oid)) {
                    // tlsFeature
                    checkExtensionTlsFeature(failureMsg, extensionValue, requestExtensions,
                            extControl);
                } else if (ObjectIdentifiers.id_xipki_ext_authorizationTemplate.equals(oid)) {
                    // authorizationTemplate
                    checkExtensionAuthorizationTemplate(failureMsg, extensionValue,
                            requestExtensions, extControl);
                } else {
                    byte[] expected;
                    if (ObjectIdentifiers.id_smimeCapabilities.equals(oid)) {
                        // SMIMECapabilities
                        expected = smimeCapabilities.getValue();
                    } else {
                        expected = getExpectedExtValue(oid, requestExtensions, extControl);
                    }

                    if (!Arrays.equals(expected, extensionValue)) {
                        failureMsg.append("extension valus is '")
                            .append(hex(extensionValue));
                        failureMsg.append("' but expected '");
                        failureMsg.append((expected == null)
                                ? "not present"
                                : hex(expected));
                        failureMsg.append("'");
                        failureMsg.append("; ");
                    }
                }

                if (failureMsg.length() > 0) {
                    issue.setFailureMessage(failureMsg.toString());
                }

            } catch (IllegalArgumentException
                    | ClassCastException
                    | ArrayIndexOutOfBoundsException ex) {
                LOG.debug("extension value does not have correct syntax", ex);
                issue.setFailureMessage("extension value does not have correct syntax");
            }
        }

        return result;
    } // method checkExtensions

    private byte[] getExpectedExtValue(
            final ASN1ObjectIdentifier type,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        if (extControl.isRequest() && requestExtensions != null) {
            Extension reqExt = requestExtensions.getExtension(type);
            if (reqExt != null) {
                return reqExt.getExtnValue().getOctets();
            }
        } else if (constantExtensions != null && constantExtensions.containsKey(type)) {
            QaExtensionValue conf = constantExtensions.get(type);
            return conf.getValue();
        }

        return null;
    } // getExpectedExtValue

    private Set<ASN1ObjectIdentifier> getExensionTypes(
            final Certificate cert,
            final X509IssuerInfo issuerInfo,
            final Extensions requestedExtensions) {
        Set<ASN1ObjectIdentifier> types = new HashSet<>();
        // profile required extension types
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
            if (requestedExtensions.getExtension(type) != null) {
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
            if (requestedExtensions.getExtension(type) != null) {
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
            if (requestedExtensions.getExtension(type) != null) {
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
            if (requestedExtensions.getExtension(type) != null) {
                types.add(type);
            }
        }

        // Admission
        type = ObjectIdentifiers.id_extension_admission;
        if (wantedExtensionTypes.contains(type)) {
            if (admission != null) {
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
            if (requestedExtensions.getExtension(oid) != null) {
                if (constantExtensions.containsKey(oid)) {
                    types.add(oid);
                }
            }
        }

        return types;
    } // method getExensionTypes

    private ValidationIssue createExtensionIssue(
            final ASN1ObjectIdentifier extId) {
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

    private void checkExtensionBasicConstraints(
            final StringBuilder failureMsg,
            final byte[] extensionValue) {
        BasicConstraints bc = BasicConstraints.getInstance(extensionValue);
        if (ca != bc.isCA()) {
            failureMsg.append("ca is '").append(bc.isCA());
            failureMsg.append("' but expected '").append(ca).append("'");
            failureMsg.append("; ");
        }

        if (bc.isCA()) {
            BigInteger tmpPathLen = bc.getPathLenConstraint();
            if (pathLen == null) {
                if (tmpPathLen != null) {
                    failureMsg.append("pathLen is '").append(tmpPathLen);
                    failureMsg.append("' but expected 'absent'");
                    failureMsg.append("; ");
                }
            } else {
                if (tmpPathLen == null) {
                    failureMsg.append("pathLen is 'null' but expected '")
                        .append(pathLen)
                        .append("'");
                    failureMsg.append("; ");
                } else if (!BigInteger.valueOf(pathLen).equals(tmpPathLen)) {
                    failureMsg.append("pathLen is '").append(tmpPathLen);
                    failureMsg.append("' but expected '").append(pathLen).append("'");
                    failureMsg.append("; ");
                }
            }
        }
    } // method checkExtensionBasicConstraints

    private void checkExtensionSubjectKeyIdentifier(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final SubjectPublicKeyInfo subjectPublicKeyInfo) {
        // subjectKeyIdentifier
        SubjectKeyIdentifier asn1 = SubjectKeyIdentifier.getInstance(extensionValue);
        byte[] ski = asn1.getKeyIdentifier();
        byte[] pkData = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        byte[] expectedSki = HashCalculator.sha1(pkData);
        if (!Arrays.equals(expectedSki, ski)) {
            failureMsg.append("SKI is '")
                .append(hex(ski));
            failureMsg.append("' but expected is '")
                .append(hex(expectedSki))
                .append("'");
            failureMsg.append("; ");
        }
    } // method checkExtensionSubjectKeyIdentifier

    private void checkExtensionIssuerKeyIdentifier(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final X509IssuerInfo issuerInfo) {
        AuthorityKeyIdentifier asn1 = AuthorityKeyIdentifier.getInstance(extensionValue);
        byte[] keyIdentifier = asn1.getKeyIdentifier();
        if (keyIdentifier == null) {
            failureMsg.append("keyIdentifier is 'absent' but expected 'present'");
            failureMsg.append("; ");
        } else if (!Arrays.equals(issuerInfo.getSubjectKeyIdentifier(), keyIdentifier)) {
            failureMsg.append("keyIdentifier is '")
                .append(hex(keyIdentifier));
            failureMsg.append("' but expected '")
                .append(hex(issuerInfo.getSubjectKeyIdentifier()))
                .append("'");
            failureMsg.append("; ");
        }

        BigInteger serialNumber = asn1.getAuthorityCertSerialNumber();
        GeneralNames names = asn1.getAuthorityCertIssuer();

        if (includeIssuerAndSerialInAki) {
            if (serialNumber == null) {
                failureMsg.append("authorityCertSerialNumber is 'absent' but expected 'present'");
                failureMsg.append("; ");
            } else {
                if (!issuerInfo.getCert().getSerialNumber().equals(serialNumber)) {
                    failureMsg.append("authorityCertSerialNumber is '")
                        .append(serialNumber);
                    failureMsg.append("' but expected '")
                        .append(issuerInfo.getCert().getSerialNumber())
                        .append("'");
                    failureMsg.append("; ");
                }
            }

            if (names == null) {
                failureMsg.append("authorityCertIssuer is 'absent' but expected 'present'");
                failureMsg.append("; ");
            } else {
                GeneralName[] genNames = names.getNames();
                X500Name x500GenName = null;
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() != GeneralName.directoryName) {
                        continue;
                    }

                    if (x500GenName != null) {
                        failureMsg.append("authorityCertIssuer contains at least two ");
                        failureMsg.append("directoryName but expected one");
                        failureMsg.append("; ");
                        break;
                    } else {
                        x500GenName = (X500Name) genName.getName();
                    }
                }

                if (x500GenName == null) {
                    failureMsg.append(
                            "authorityCertIssuer does not contain directoryName but expected one");
                    failureMsg.append("; ");
                } else {
                    X500Name caSubject = issuerInfo.getBcCert().getTBSCertificate().getSubject();
                    if (!caSubject.equals(x500GenName)) {
                        failureMsg.append("authorityCertIssuer is '")
                            .append(x500GenName.toString());
                        failureMsg.append("' but expected '")
                            .append(caSubject.toString())
                            .append("'");
                        failureMsg.append("; ");
                    }
                }
            }
        } else {
            if (serialNumber != null) {
                failureMsg.append("authorityCertSerialNumber is 'absent' but expected 'present'");
                failureMsg.append("; ");
            }

            if (names != null) {
                failureMsg.append("authorityCertIssuer is 'absent' but expected 'present'");
                failureMsg.append("; ");
            }
        }
    } // method checkExtensionIssuerKeyIdentifier

    private void checkExtensionNameConstraints(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        QaNameConstraints conf = nameConstraints;

        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.nameConstraints, requestExtensions,
                    extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '")
                    .append(hex(extensionValue));
                failureMsg.append("' but expected '");
                failureMsg.append((expected == null)
                        ? "not present"
                        : hex(expected));
                failureMsg.append("'");
                failureMsg.append("; ");
            }
            return;
        }

        org.bouncycastle.asn1.x509.NameConstraints tmpNameConstraints =
                org.bouncycastle.asn1.x509.NameConstraints.getInstance(extensionValue);

        checkExtensionNameConstraintsSubtrees(failureMsg, "PermittedSubtrees",
                tmpNameConstraints.getPermittedSubtrees(),
                conf.getPermittedSubtrees());
        checkExtensionNameConstraintsSubtrees(failureMsg, "ExcludedSubtrees",
                tmpNameConstraints.getExcludedSubtrees(),
                conf.getExcludedSubtrees());
    } // method checkExtensionNameConstraints

    private void checkExtensionNameConstraintsSubtrees(
            final StringBuilder failureMsg,
            final String description,
            final GeneralSubtree[] subtrees,
            final List<QaGeneralSubtree> expectedSubtrees) {
        int isSize = (subtrees == null)
                ? 0
                : subtrees.length;
        int expSize = (expectedSubtrees == null)
                ? 0
                : expectedSubtrees.size();
        if (isSize != expSize) {
            failureMsg.append("size of ")
                .append(description)
                .append(" is '")
                .append(isSize);
            failureMsg.append("' but expected '")
                .append(expSize)
                .append("'");
            failureMsg.append("; ");
            return;
        }

        for (int i = 0; i < isSize; i++) {
            GeneralSubtree isSubtree = subtrees[i];
            QaGeneralSubtree expSubtree = expectedSubtrees.get(i);
            BigInteger bigInt = isSubtree.getMinimum();
            int isMinimum = (bigInt == null)
                    ? 0
                    : bigInt.intValue();
            Integer minimum = expSubtree.getMinimum();
            int expMinimum = (minimum == null)
                    ? 0
                    : minimum.intValue();
            String desc = description + " [" + i + "]";
            if (isMinimum != expMinimum) {
                failureMsg.append("minimum of ")
                    .append(desc)
                    .append(" is '").append(isMinimum);
                failureMsg.append("' but expected '")
                    .append(expMinimum)
                    .append("'");
                failureMsg.append("; ");
            }

            bigInt = isSubtree.getMaximum();
            Integer isMaximum = (bigInt == null)
                    ? null
                    : bigInt.intValue();
            Integer expMaximum = expSubtree.getMaximum();
            if (!CompareUtil.equalsObject(isMaximum, expMaximum)) {
                failureMsg.append("maxmum of ")
                    .append(desc)
                    .append(" is '")
                    .append(isMaximum);
                failureMsg.append("' but expected '")
                    .append(expMaximum)
                    .append("'");
                failureMsg.append("; ");
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
                failureMsg.append("base of ")
                    .append(desc)
                    .append(" is '")
                    .append(isBase);
                failureMsg.append("' but expected '")
                    .append(expBase)
                    .append("'");
                failureMsg.append("; ");
            }
        }
    } // method checkExtensionNameConstraintsSubtrees

    private void checkExtensionPolicyConstraints(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        QaPolicyConstraints conf = policyConstraints;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.policyConstraints,
                    requestExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '")
                    .append(hex(extensionValue));
                failureMsg.append("' but expected '");
                failureMsg.append((expected == null)
                        ? "not present"
                        : hex(expected));
                failureMsg.append("'");
                failureMsg.append("; ");
            }
            return;
        }

        org.bouncycastle.asn1.x509.PolicyConstraints isPolicyConstraints =
                org.bouncycastle.asn1.x509.PolicyConstraints.getInstance(extensionValue);
        Integer expRequireExplicitPolicy = conf.getRequireExplicitPolicy();
        BigInteger bigInt = isPolicyConstraints.getRequireExplicitPolicyMapping();
        Integer isRequreExplicitPolicy = (bigInt == null)
                ? null
                : bigInt.intValue();

        boolean match = true;
        if (expRequireExplicitPolicy == null) {
            if (isRequreExplicitPolicy != null) {
                match = false;
            }
        } else if (!expRequireExplicitPolicy.equals(isRequreExplicitPolicy)) {
            match = false;
        }

        if (!match) {
            failureMsg.append("requreExplicitPolicy is '")
                .append(isRequreExplicitPolicy);
            failureMsg.append("' but expected '")
                .append(expRequireExplicitPolicy)
                .append("'");
            failureMsg.append("; ");
        }

        Integer expInhibitPolicyMapping = conf.getInhibitPolicyMapping();
        bigInt = isPolicyConstraints.getInhibitPolicyMapping();
        Integer isInhibitPolicyMapping = (bigInt == null)
                ? null
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
            failureMsg.append("inhibitPolicyMapping is '")
                .append(isInhibitPolicyMapping)
                .append("' but expected '");
            failureMsg.append(expInhibitPolicyMapping)
                .append("'");
            failureMsg.append("; ");
        }
    } // method checkExtensionPolicyConstraints

    private void checkExtensionKeyUsage(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final boolean[] usages,
            final Extensions requestExtensions,
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
        if (extControl.isRequest() && requestExtensions != null
                && CollectionUtil.isNonEmpty(optionalKeyusage)) {
            Extension extension = requestExtensions.getExtension(Extension.keyUsage);
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
            failureMsg.append("usages ")
                .append(diffs.toString())
                .append(" are present but not expected");
            failureMsg.append("; ");
        }

        diffs = strInBnotInA(isUsages, expectedUsages);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("usages ")
                .append(diffs.toString())
                .append(" are absent but are required");
            failureMsg.append("; ");
        }
    } // method checkExtensionKeyUsage

    private void checkExtensionExtendedKeyUsage(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
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
        if (extControl.isRequest() && requestExtensions != null
                && CollectionUtil.isNonEmpty(optionalExtKeyusage)) {
            Extension extension = requestExtensions.getExtension(Extension.extendedKeyUsage);
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
            failureMsg.append("usages ")
                .append(diffs.toString())
                .append(" are present but not expected");
            failureMsg.append("; ");
        }

        diffs = strInBnotInA(isUsages, expectedUsages);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("usages ")
                .append(diffs.toString())
                .append(" are absent but are required");
            failureMsg.append("; ");
        }
    } // method checkExtensionExtendedKeyUsage

    private void checkExtensionTlsFeature(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        QaTlsFeature conf = tlsFeature;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(ObjectIdentifiers.id_pe_tlsfeature,
                    requestExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '")
                    .append(hex(extensionValue));
                failureMsg.append("' but expected '");
                failureMsg.append((expected == null)
                        ? "not present"
                        : hex(expected));
                failureMsg.append("'");
                failureMsg.append("; ");
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
            failureMsg.append("features ")
                .append(diffs.toString())
                .append(" are present but not expected");
            failureMsg.append("; ");
        }

        diffs = strInBnotInA(isFeatures, expFeatures);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("features ")
                .append(diffs.toString())
                .append(" are absent but are required");
            failureMsg.append("; ");
        }
    } // method checkExtensionTlsFeature

    private void checkExtensionCertificatePolicies(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        QaCertificatePolicies conf = certificatePolicies;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.certificatePolicies,
                    requestExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '")
                    .append(hex(extensionValue));
                failureMsg.append("' but expected '")
                    .append((expected == null)
                        ? "not present"
                        : hex(expected))
                    .append("'");
                failureMsg.append("; ");
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
                failureMsg.append("certificate policy '")
                    .append(isPolicyId)
                    .append("' is not expected");
                failureMsg.append("; ");
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
                        failureMsg.append("CPSUri '")
                            .append(value)
                            .append("' is absent but is required");
                        failureMsg.append("; ");
                    }
                } else if (qualifierInfo instanceof QaUserNoticePolicyQualifierInfo) {
                    String value =
                            ((QaUserNoticePolicyQualifierInfo) qualifierInfo).getUserNotice();
                    if (!isUserNotices.contains(value)) {
                        failureMsg.append("userNotice '")
                            .append(value)
                            .append("' is absent but is required");
                        failureMsg.append("; ");
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

            failureMsg.append("certificate policy '")
                .append(cp.getPolicyId())
                .append("' is absent but is required");
            failureMsg.append("; ");
        }
    } // method checkExtensionCertificatePolicies

    private void checkExtensionPolicyMappings(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        QaPolicyMappingsOption conf = policyMappings;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.policyMappings, requestExtensions,
                    extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '")
                    .append(hex(extensionValue));
                failureMsg.append("' but expected '")
                    .append((expected == null)
                            ? "not present"
                            : hex(expected))
                    .append("'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1Sequence isPolicyMappings = DERSequence.getInstance(extensionValue);
        Map<String, String> isMap = new HashMap<>();
        int size = isPolicyMappings.size();
        for (int i = 0; i < size; i++) {
            ASN1Sequence seq = (ASN1Sequence) isPolicyMappings.getObjectAt(i);

            CertPolicyId issuerDomainPolicy = CertPolicyId.getInstance(seq.getObjectAt(0));
            CertPolicyId subjectDomainPolicy = CertPolicyId.getInstance(seq.getObjectAt(1));
            isMap.put(issuerDomainPolicy.getId(), subjectDomainPolicy.getId());
        }

        Set<String> expIssuerDomainPolicies = conf.getIssuerDomainPolicies();
        for (String expIssuerDomainPolicy : expIssuerDomainPolicies) {
            String expSubjectDomainPolicy = conf.getSubjectDomainPolicy(expIssuerDomainPolicy);

            String isSubjectDomainPolicy = isMap.remove(expIssuerDomainPolicy);
            if (isSubjectDomainPolicy == null) {
                failureMsg.append("issuerDomainPolicy '")
                    .append(expIssuerDomainPolicy)
                    .append("' is absent but is required");
                failureMsg.append("; ");
            } else if (!isSubjectDomainPolicy.equals(expSubjectDomainPolicy)) {
                failureMsg.append("subjectDomainPolicy for issuerDomainPolicy is '")
                    .append(isSubjectDomainPolicy);
                failureMsg.append("' but expected '")
                    .append(expSubjectDomainPolicy)
                    .append("'");
                failureMsg.append("; ");
            }
        }

        if (CollectionUtil.isNonEmpty(isMap)) {
            failureMsg.append("issuerDomainPolicies '")
                .append(isMap.keySet())
                .append("' are present but not expected");
            failureMsg.append("; ");
        }
    } // method checkExtensionPolicyMappings

    private void checkExtensionInhibitAnyPolicy(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        QaInhibitAnyPolicy conf = inhibitAnyPolicy;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.inhibitAnyPolicy,
                    requestExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '").append(hex(extensionValue));
                failureMsg.append("' but expected '")
                    .append((expected == null)
                            ? "not present"
                            : hex(expected))
                    .append("'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1Integer asn1Int = ASN1Integer.getInstance(extensionValue);
        int isSkipCerts = asn1Int.getPositiveValue().intValue();
        if (isSkipCerts != conf.getSkipCerts()) {
            failureMsg.append("skipCerts is '")
                .append(isSkipCerts);
            failureMsg.append("' but expected '")
                .append(conf.getSkipCerts())
                .append("'");
            failureMsg.append("; ");
        }
    } // method checkExtensionInhibitAnyPolicy

    private void checkExtensionSubjectAltName(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        Set<GeneralNameMode> conf = allowedSubjectAltNameModes;
        if (conf == null) {
            failureMsg.append("extension is present but not expected");
            failureMsg.append("; ");
            return;
        }

        ASN1Encodable extInRequest = null;
        if (requestExtensions != null) {
            extInRequest = requestExtensions.getExtensionParsedValue(
                    Extension.subjectAlternativeName);
        }

        if (extInRequest == null) {
            failureMsg.append("extension is present but not expected");
            failureMsg.append("; ");
            return;
        }

        GeneralName[] requested = GeneralNames.getInstance(extInRequest).getNames();

        GeneralName[] is = GeneralNames.getInstance(extensionValue).getNames();

        GeneralName[] expected = new GeneralName[requested.length];
        for (int i = 0; i < is.length; i++) {
            try {
                expected[i] = createGeneralName(is[i], conf);
            } catch (BadCertTemplateException ex) {
                failureMsg.append("could not process ")
                    .append(i + 1)
                    .append("-th name: ")
                    .append(ex.getMessage());
                failureMsg.append("; ");
                return;
            }
        }

        if (is.length != expected.length) {
            failureMsg.append("size of GeneralNames is '")
                .append(is.length);
            failureMsg.append("' but expected '")
                .append(expected.length)
                .append("'");
            failureMsg.append("; ");
            return;
        }

        for (int i = 0; i < is.length; i++) {
            if (!is[i].equals(expected[i])) {
                failureMsg.append(i + 1)
                    .append("-th name does not match the requested one");
                failureMsg.append("; ");
            }
        }
    } // method checkExtensionSubjectAltName

    private void checkExtensionSubjectInfoAccess(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> conf = allowedSubjectInfoAccessModes;
        if (conf == null) {
            failureMsg.append("extension is present but not expected");
            failureMsg.append("; ");
            return;
        }

        ASN1Encodable requestExtValue = null;
        if (requestExtensions != null) {
            requestExtValue = requestExtensions.getExtensionParsedValue(
                    Extension.subjectInfoAccess);
        }
        if (requestExtValue == null) {
            failureMsg.append("extension is present but not expected");
            failureMsg.append("; ");
            return;
        }

        ASN1Sequence requestSeq = ASN1Sequence.getInstance(requestExtValue);
        ASN1Sequence certSeq = ASN1Sequence.getInstance(extensionValue);

        int size = requestSeq.size();

        if (certSeq.size() != size) {
            failureMsg.append("size of GeneralNames is '")
                .append(certSeq.size());
            failureMsg.append("' but expected '")
                .append(size)
                .append("'");
            failureMsg.append("; ");
            return;
        }

        for (int i = 0; i < size; i++) {
            AccessDescription ad = AccessDescription.getInstance(requestSeq.getObjectAt(i));
            ASN1ObjectIdentifier accessMethod = ad.getAccessMethod();

            Set<GeneralNameMode> generalNameModes;
            if (accessMethod == null) {
                generalNameModes = conf.get(X509Certprofile.OID_ZERO);
            } else {
                generalNameModes = conf.get(accessMethod);
            }

            if (generalNameModes == null) {
                failureMsg.append("accessMethod in requestExtension ");
                failureMsg.append((accessMethod == null)
                        ? "NULL"
                        : accessMethod.getId());
                failureMsg.append(" is not allowed");
                failureMsg.append("; ");
                continue;
            }

            AccessDescription certAccessDesc = AccessDescription.getInstance(
                    certSeq.getObjectAt(i));
            ASN1ObjectIdentifier certAccessMethod = certAccessDesc.getAccessMethod();

            boolean bo;
            if (accessMethod == null) {
                bo = certAccessDesc == null;
            } else {
                bo = accessMethod.equals(certAccessMethod);
            }

            if (!bo) {
                failureMsg.append("accessMethod is '")
                    .append((certAccessMethod == null)
                            ? "null"
                            : certAccessMethod.getId());
                failureMsg.append("' but expected '")
                    .append((accessMethod == null)
                            ? "null"
                            : accessMethod.getId());
                failureMsg.append("; ");
                continue;
            }

            GeneralName accessLocation;
            try {
                accessLocation = createGeneralName(ad.getAccessLocation(), generalNameModes);
            } catch (BadCertTemplateException ex) {
                failureMsg.append("invalid requestExtension: ")
                    .append(ex.getMessage());
                failureMsg.append("; ");
                continue;
            }

            GeneralName certAccessLocation = certAccessDesc.getAccessLocation();
            if (!certAccessLocation.equals(accessLocation)) {
                failureMsg.append("accessLocation does not match the requested one");
                failureMsg.append("; ");
            }
        }
    } // method checkExtensionSubjectInfoAccess

    private void checkExtensionIssuerAltNames(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final X509IssuerInfo issuerInfo) {
        Extension caSubjectAltExtension =
                issuerInfo.getBcCert().getTBSCertificate().getExtensions().getExtension(
                        Extension.subjectAlternativeName);
        if (caSubjectAltExtension == null) {
            failureMsg.append("issuerAlternativeName is present but expected 'none'");
            failureMsg.append("; ");
            return;
        }

        byte[] caSubjectAltExtensionValue = caSubjectAltExtension.getExtnValue().getOctets();
        if (!Arrays.equals(caSubjectAltExtensionValue, extensionValue)) {
            failureMsg.append("is '").append(hex(extensionValue));
            failureMsg.append("' but expected '")
                .append(hex(caSubjectAltExtensionValue))
                .append("'");
            failureMsg.append("; ");
        }
    } // method checkExtensionIssuerAltNames

    private void checkExtensionCrlDistributionPoints(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final X509IssuerInfo issuerInfo) {
        CRLDistPoint isCrlDistPoints = CRLDistPoint.getInstance(extensionValue);
        DistributionPoint[] isDistributionPoints = isCrlDistPoints.getDistributionPoints();
        int len = (isDistributionPoints == null)
                ? 0
                : isDistributionPoints.length;
        if (len != 1) {
            failureMsg.append("size of CRLDistributionPoints is '")
                .append(len)
                .append("' but expected is '1'");
            failureMsg.append("; ");
            return;
        }

        Set<String> isCrlUrls = new HashSet<>();
        for (DistributionPoint entry : isDistributionPoints) {
            int asn1Type = entry.getDistributionPoint().getType();
            if (asn1Type != DistributionPointName.FULL_NAME) {
                failureMsg.append("tag of DistributionPointName of CRLDistibutionPoints is '")
                    .append(asn1Type);
                failureMsg.append("' but expected is '")
                    .append(DistributionPointName.FULL_NAME)
                    .append("'");
                failureMsg.append("; ");
                continue;
            }

            GeneralNames isDistributionPointNames =
                    (GeneralNames) entry.getDistributionPoint().getName();
            GeneralName[] names = isDistributionPointNames.getNames();

            for (int i = 0; i < names.length; i++) {
                GeneralName name = names[i];
                if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                    failureMsg.append("tag of CRL URL is '").append(name.getTagNo());
                    failureMsg.append("' but expected is '")
                        .append(GeneralName.uniformResourceIdentifier)
                        .append("'");
                    failureMsg.append("; ");
                } else {
                    String uri = ((ASN1String) name.getName()).getString();
                    isCrlUrls.add(uri);
                }
            }

            Set<String> expCrlUrls = issuerInfo.getCrlUrls();
            Set<String> diffs = strInBnotInA(expCrlUrls, isCrlUrls);
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("CRL URLs ")
                    .append(diffs.toString())
                    .append(" are present but not expected");
                failureMsg.append("; ");
            }

            diffs = strInBnotInA(isCrlUrls, expCrlUrls);
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("CRL URLs ")
                    .append(diffs.toString())
                    .append(" are absent but are required");
                failureMsg.append("; ");
            }
        }
    } // method checkExtensionCrlDistributionPoints

    private void checkExtensionDeltaCrlDistributionPoints(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final X509IssuerInfo issuerInfo) {
        CRLDistPoint isCrlDistPoints = CRLDistPoint.getInstance(extensionValue);
        DistributionPoint[] isDistributionPoints = isCrlDistPoints.getDistributionPoints();
        int len = (isDistributionPoints == null)
                ? 0
                : isDistributionPoints.length;
        if (len != 1) {
            failureMsg.append("size of CRLDistributionPoints (deltaCRL) is '")
                .append(len)
                .append("' but expected is '1'");
            failureMsg.append("; ");
            return;
        }

        Set<String> isCrlUrls = new HashSet<>();
        for (DistributionPoint entry : isDistributionPoints) {
            int asn1Type = entry.getDistributionPoint().getType();
            if (asn1Type != DistributionPointName.FULL_NAME) {
                failureMsg
                    .append("tag of DistributionPointName of CRLDistibutionPoints (deltaCRL) is '")
                    .append(asn1Type);
                failureMsg.append("' but expected is '")
                    .append(DistributionPointName.FULL_NAME)
                    .append("'");
                failureMsg.append("; ");
                continue;
            }

            GeneralNames isDistributionPointNames =
                    (GeneralNames) entry.getDistributionPoint().getName();
            GeneralName[] names = isDistributionPointNames.getNames();

            for (int i = 0; i < names.length; i++) {
                GeneralName name = names[i];
                if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                    failureMsg.append("tag of deltaCRL URL is '")
                        .append(name.getTagNo());
                    failureMsg.append("' but expected is '")
                        .append(GeneralName.uniformResourceIdentifier)
                        .append("'");
                    failureMsg.append("; ");
                } else {
                    String uri = ((ASN1String) name.getName()).getString();
                    isCrlUrls.add(uri);
                }
            }

            Set<String> expCrlUrls = issuerInfo.getCrlUrls();
            Set<String> diffs = strInBnotInA(expCrlUrls, isCrlUrls);
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("deltaCRL URLs ")
                    .append(diffs.toString())
                    .append(" are present but not expected");
                failureMsg.append("; ");
            }

            diffs = strInBnotInA(isCrlUrls, expCrlUrls);
            if (CollectionUtil.isNonEmpty(diffs)) {
                failureMsg.append("deltaCRL URLs ")
                    .append(diffs.toString())
                    .append(" are absent but are required");
                failureMsg.append("; ");
            }
        }
    } // method checkExtensionDeltaCrlDistributionPoints

    private void checkExtensionAdmission(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        QaAdmission conf = admission;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(ObjectIdentifiers.id_extension_admission,
                    requestExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '").append(hex(extensionValue));
                failureMsg.append("' but expected '")
                    .append((expected == null)
                            ? "not present"
                            : hex(expected))
                    .append("'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(extensionValue);
        AdmissionSyntax isAdmissionSyntax = AdmissionSyntax.getInstance(seq);
        Admissions[] isAdmissions = isAdmissionSyntax.getContentsOfAdmissions();
        int len = (isAdmissions == null)
                ? 0
                : isAdmissions.length;
        if (len != 1) {
            failureMsg.append("size of Admissions is '")
                .append(len);
            failureMsg.append("' but expected is '1'");
            failureMsg.append("; ");
            return;
        }

        Admissions isAdmission = isAdmissions[0];
        ProfessionInfo[] isProfessionInfos = isAdmission.getProfessionInfos();
        len = (isProfessionInfos == null)
                ? 0
                : isProfessionInfos.length;
        if (len != 1) {
            failureMsg.append("size of ProfessionInfo is '")
                .append(len).append("' but expected is '1'");
            failureMsg.append("; ");
            return;
        }

        ProfessionInfo isProfessionInfo = isProfessionInfos[0];
        String isRegistrationNumber = isProfessionInfo.getRegistrationNumber();
        String expRegistrationNumber = conf.getRegistrationNumber();
        if (expRegistrationNumber == null) {
            if (isRegistrationNumber != null) {
                failureMsg.append("RegistrationNumber is '").append(isRegistrationNumber);
                failureMsg.append("' but expected is 'null'");
                failureMsg.append("; ");
            }
        } else if (!expRegistrationNumber.equals(isRegistrationNumber)) {
            failureMsg.append("RegistrationNumber is '").append(isRegistrationNumber);
            failureMsg.append("' but expected is '").append(expRegistrationNumber).append("'");
            failureMsg.append("; ");
        }

        byte[] isAddProfessionInfo = null;
        if (isProfessionInfo.getAddProfessionInfo() != null) {
            isAddProfessionInfo = isProfessionInfo.getAddProfessionInfo().getOctets();
        }
        byte[] expAddProfessionInfo = conf.getAddProfessionInfo();
        if (expAddProfessionInfo == null) {
            if (isAddProfessionInfo != null) {
                failureMsg.append("AddProfessionInfo is '").append(hex(isAddProfessionInfo));
                failureMsg.append("' but expected is 'null'");
                failureMsg.append("; ");
            }
        } else {
            if (isAddProfessionInfo == null) {
                failureMsg.append("AddProfessionInfo is 'null' but expected is '")
                    .append(hex(expAddProfessionInfo));
                failureMsg.append("'");
                failureMsg.append("; ");
            } else if (!Arrays.equals(expAddProfessionInfo, isAddProfessionInfo)) {
                failureMsg.append("AddProfessionInfo is '").append(hex(isAddProfessionInfo));
                failureMsg.append("' but expected is '")
                    .append(hex(expAddProfessionInfo)).append("'");
                failureMsg.append("; ");
            }
        }

        List<String> expProfessionOids = conf.getProfessionOids();
        ASN1ObjectIdentifier[] tmpIProfessionOids = isProfessionInfo.getProfessionOIDs();
        List<String> isProfessionOids = new LinkedList<>();
        if (tmpIProfessionOids != null) {
            for (ASN1ObjectIdentifier entry : tmpIProfessionOids) {
                isProfessionOids.add(entry.getId());
            }
        }

        Set<String> diffs = strInBnotInA(expProfessionOids, isProfessionOids);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("ProfessionOIDs ").append(diffs.toString())
                .append(" are present but not expected");
            failureMsg.append("; ");
        }

        diffs = strInBnotInA(isProfessionOids, expProfessionOids);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("ProfessionOIDs ").append(diffs.toString())
                .append(" are absent but are required");
            failureMsg.append("; ");
        }

        List<String> expProfessionItems = conf.getProfessionItems();
        DirectoryString[] items = isProfessionInfo.getProfessionItems();
        List<String> isProfessionItems = new LinkedList<>();
        if (items != null) {
            for (DirectoryString item : items) {
                isProfessionItems.add(item.getString());
            }
        }

        diffs = strInBnotInA(expProfessionItems, isProfessionItems);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("ProfessionItems ").append(diffs.toString())
                .append(" are present but not expected");
            failureMsg.append("; ");
        }

        diffs = strInBnotInA(isProfessionItems, expProfessionItems);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append("ProfessionItems ").append(diffs.toString())
                .append(" are absent but are required");
            failureMsg.append("; ");
        }
    } // method checkExtensionAdmission

    private void checkExtensionAuthorityInfoAccess(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final X509IssuerInfo issuerInfo) {
        Set<String> expCaIssuerUris;
        if (aiaControl == null || aiaControl.includesCaIssuers()) {
            expCaIssuerUris = issuerInfo.getCaIssuerUrls();
        } else {
            expCaIssuerUris = Collections.emptySet();
        }

        Set<String> expOcspUris;
        if (aiaControl == null || aiaControl.includesOcsp()) {
            expOcspUris = issuerInfo.getOcspUrls();
        } else {
            expOcspUris = Collections.emptySet();
        }

        if (CollectionUtil.isEmpty(expCaIssuerUris) && CollectionUtil.isEmpty(expOcspUris)) {
            failureMsg.append("AIA is present but expected is 'none'");
            failureMsg.append("; ");
            return;
        }

        AuthorityInformationAccess isAia = AuthorityInformationAccess.getInstance(extensionValue);
        checkAia(failureMsg, isAia, X509ObjectIdentifiers.id_ad_caIssuers, expCaIssuerUris);
        checkAia(failureMsg, isAia, X509ObjectIdentifiers.id_ad_ocsp, expOcspUris);
    } // method checkExtensionAuthorityInfoAccess

    private void checkExtensionOcspNocheck(
            final StringBuilder failureMsg,
            final byte[] extensionValue) {
        if (!Arrays.equals(DER_NULL, extensionValue)) {
            failureMsg.append("value is not DER NULL");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionRestriction(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        checkDirectoryString(ObjectIdentifiers.id_extension_restriction, restriction,
                failureMsg, extensionValue, requestExtensions, extControl);
    }

    private void checkExtensionAdditionalInformation(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        checkDirectoryString(ObjectIdentifiers.id_extension_additionalInformation,
                additionalInformation,
                failureMsg, extensionValue, requestExtensions, extControl);
    }

    private void checkDirectoryString(
            final ASN1ObjectIdentifier extType,
            final QaDirectoryString conf,
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        if (conf == null) {
            byte[] expected = getExpectedExtValue(extType,
                    requestExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '").append(hex(extensionValue));
                failureMsg.append("' but expected '")
                    .append((expected == null)
                            ? "not present"
                            : hex(expected))
                    .append("'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1Primitive asn1;
        try {
            asn1 = ASN1Primitive.fromByteArray(extensionValue);
        } catch (IOException ex) {
            failureMsg.append("invalid syntax of extension value");
            failureMsg.append("; ");
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
                .append(conf.getText());
            failureMsg.append("; ");
            return;
        }

        String extTextValue = ((ASN1String) asn1).getString();
        if (!conf.getText().equals(extTextValue)) {
            failureMsg.append("content '").append(extTextValue);
            failureMsg.append("' but expected '").append(conf.getText()).append("'");
            failureMsg.append("; ");
        }
    } // method checkDirectoryString

    private void checkExtensionValidityModel(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        ASN1ObjectIdentifier conf = validityModelId;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(ObjectIdentifiers.id_extension_validityModel,
                    requestExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '")
                    .append(hex(extensionValue));
                failureMsg.append("' but expected '")
                    .append((expected == null)
                            ? "not present"
                            : hex(expected))
                    .append("'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1ObjectIdentifier extValue = ASN1ObjectIdentifier.getInstance(extensionValue);
        if (!conf.equals(extValue)) {
            failureMsg.append("content is '").append(extValue);
            failureMsg.append("' but expected '").append(conf).append("'");
            failureMsg.append("; ");
        }
    } // method checkExtensionValidityModel

    private void checkExtensionPrivateKeyUsagePeriod(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Date certNotBefore,
            final Date certNotAfter) {
        ASN1GeneralizedTime notBefore = new ASN1GeneralizedTime(certNotBefore);
        Date dateNotAfter;
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
            failureMsg.append("notBefore is absent but expected present");
            failureMsg.append("; ");
        } else if (!time.equals(notBefore)) {
            failureMsg.append("notBefore is '").append(time.getTimeString());
            failureMsg.append("' but expected '").append(notBefore.getTimeString()).append("'");
            failureMsg.append("; ");
        }

        time = extValue.getNotAfter();
        if (time == null) {
            failureMsg.append("notAfter is absent but expected present");
            failureMsg.append("; ");
        } else if (!time.equals(notAfter)) {
            failureMsg.append("notAfter is '").append(time.getTimeString());
            failureMsg.append("' but expected '").append(notAfter.getTimeString()).append("'");
            failureMsg.append("; ");
        }
    } // method checkExtensionPrivateKeyUsagePeriod

    private void checkExtensionQcStatements(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        QCStatements conf = qcStatements;
        if (conf == null) {
            byte[] expected = getExpectedExtValue(Extension.qCStatements,
                    requestExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '").append(hex(extensionValue));
                failureMsg.append("' but expected '")
                    .append((expected == null)
                            ? "not present"
                            : hex(expected))
                    .append("'");
                failureMsg.append("; ");
            }
            return;
        }

        final int expSize = conf.getQCStatement().size();
        ASN1Sequence extValue = ASN1Sequence.getInstance(extensionValue);
        final int isSize = extValue.size();
        if (isSize != expSize) {
            failureMsg.append("number of statements is '").append(isSize);
            failureMsg.append("' but expected '").append(expSize).append("'");
            failureMsg.append("; ");
            return;
        }

        // extract the euLimit data from request
        Map<String, int[]> reqQcEuLimits = new HashMap<>();
        Extension extension = requestExtensions.getExtension(Extension.qCStatements);
        if (extension != null) {
            ASN1Sequence seq = ASN1Sequence.getInstance(extension.getParsedValue());

            final int n = seq.size();
            for (int j = 0; j < n; j++) {
                QCStatement stmt = QCStatement.getInstance(seq.getObjectAt(j));
                if (!ObjectIdentifiers.id_etsi_qcs_QcLimitValue.equals(stmt.getStatementId())) {
                    continue;
                }

                MonetaryValue monetaryValue = MonetaryValue.getInstance(stmt.getStatementInfo());
                int amount = monetaryValue.getAmount().intValue();
                int exponent = monetaryValue.getExponent().intValue();
                Iso4217CurrencyCode currency = monetaryValue.getCurrency();
                String currencyS = currency.isAlphabetic()
                        ? currency.getAlphabetic().toUpperCase()
                        : Integer.toString(currency.getNumeric());
                reqQcEuLimits.put(currencyS, new int[]{amount, exponent});
            }
        }

        for (int i = 0; i < expSize; i++) {
            QCStatement is = QCStatement.getInstance(extValue.getObjectAt(i));
            QCStatementType exp = conf.getQCStatement().get(i);
            if (!is.getStatementId().getId().equals(exp.getStatementId().getValue())) {
                failureMsg.append("statmentId[")
                    .append(i).append("] is '").append(is.getStatementId().getId());
                failureMsg.append("' but expected '").append(exp.getStatementId().getValue())
                    .append("'");
                failureMsg.append("; ");
                continue;
            }

            if (exp.getStatementValue() == null) {
                if (is.getStatementInfo() != null) {
                    failureMsg.append("statmentInfo[").append(i)
                        .append("] is 'present' but expected 'absent'");
                    failureMsg.append("; ");
                }
                continue;
            }

            if (is.getStatementInfo() == null) {
                failureMsg.append("statmentInfo[").append(i)
                    .append("] is 'absent' but expected 'present'");
                failureMsg.append("; ");
                continue;
            }

            QCStatementValueType expStatementValue = exp.getStatementValue();
            try {
                if (expStatementValue.getConstant() != null) {
                    byte[] expValue = expStatementValue.getConstant().getValue();
                    byte[] isValue = is.getStatementInfo().toASN1Primitive().getEncoded();
                    if (!Arrays.equals(isValue, expValue)) {
                        failureMsg.append("statementInfo[").append(i)
                            .append("] is '").append(hex(isValue));
                        failureMsg.append("' but expected '").append(hex(expValue)).append("'");
                        failureMsg.append("; ");
                    }
                } else if (expStatementValue.getQcRetentionPeriod() != null) {
                    String isValue = ASN1Integer.getInstance(is.getStatementInfo()).toString();
                    String expValue = expStatementValue.getQcRetentionPeriod().toString();
                    if (!isValue.equals(expValue)) {
                        failureMsg.append("statementInfo[")
                            .append(i)
                            .append("] is '")
                            .append(isValue);
                        failureMsg.append("' but expected '")
                            .append(expValue)
                            .append("'");
                        failureMsg.append("; ");
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
                        failureMsg.append("found no QcEuLimit for currency '")
                            .append(expCurrency)
                            .append("'");
                        failureMsg.append("; ");
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
                        failureMsg.append("found no QcEuLimit for currency '")
                            .append(expCurrency)
                            .append("'");
                        failureMsg.append("; ");
                        return;
                    }
                    String expExponent = Integer.toString(value);

                    MonetaryValue monterayValue = MonetaryValue.getInstance(is.getStatementInfo());
                    Iso4217CurrencyCode currency = monterayValue.getCurrency();
                    String isCurrency = currency.isAlphabetic()
                            ? currency.getAlphabetic()
                            : Integer.toString(currency.getNumeric());
                    String isAmount = monterayValue.getAmount().toString();
                    String isExponent = monterayValue.getExponent().toString();
                    if (!isCurrency.equals(expCurrency)) {
                        failureMsg.append("statementInfo[")
                            .append(i)
                            .append("].qcEuLimit.currency is '")
                            .append(isCurrency);
                        failureMsg.append("' but expected '")
                            .append(expCurrency)
                            .append("'");
                        failureMsg.append("; ");
                    }
                    if (!isAmount.equals(expAmount)) {
                        failureMsg.append("statementInfo[")
                            .append(i)
                            .append("].qcEuLimit.amount is '")
                            .append(isAmount);

                        failureMsg.append("' but expected '")
                            .append(expAmount)
                            .append("'");
                        failureMsg.append("; ");
                    }
                    if (!isExponent.equals(expExponent)) {
                        failureMsg.append("statementInfo[")
                            .append(i)
                            .append("].qcEuLimit.exponent is '")
                            .append(isExponent);
                        failureMsg.append("' but expected '")
                            .append(expExponent)
                            .append("'");
                        failureMsg.append("; ");
                    }
                } else {
                    throw new RuntimeException("statementInfo[" + i + "]should not reach here");
                }
            } catch (IOException ex) {
                failureMsg.append("statementInfo[")
                    .append(i)
                    .append("] has incorrect syntax");
                failureMsg.append("; ");
            }
        }
    } // method checkExtensionQcStatements

    private void checkExtensionBiometricInfo(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        BiometricInfoOption conf = biometricInfo;

        if (conf == null) {
            failureMsg.append("extension is present but not expected");
            failureMsg.append("; ");
            return;
        }

        ASN1Encodable extInRequest = null;
        if (requestExtensions != null) {
            extInRequest = requestExtensions.getExtensionParsedValue(Extension.biometricInfo);
        }

        if (extInRequest == null) {
            failureMsg.append("extension is present but not expected");
            failureMsg.append("; ");
            return;
        }

        ASN1Sequence extValueInReq = ASN1Sequence.getInstance(extInRequest);
        final int expSize = extValueInReq.size();

        ASN1Sequence extValue = ASN1Sequence.getInstance(extensionValue);
        final int isSize = extValue.size();
        if (isSize != expSize) {
            failureMsg.append("number of biometricData is '")
                .append(isSize);
            failureMsg.append("' but expected '")
                .append(expSize)
                .append("'");
            failureMsg.append("; ");
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

                failureMsg.append("biometricData[")
                    .append(i)
                    .append("].typeOfBiometricData is '")
                    .append(isStr);
                failureMsg.append("' but expected '")
                    .append(expStr)
                    .append("'");
                failureMsg.append("; ");
            }

            ASN1ObjectIdentifier is = isData.getHashAlgorithm().getAlgorithm();
            ASN1ObjectIdentifier exp = expData.getHashAlgorithm().getAlgorithm();
            if (!is.equals(exp)) {
                failureMsg.append("biometricData[")
                    .append(i)
                    .append("].hashAlgorithm is '")
                    .append(is.getId());
                failureMsg.append("' but expected '")
                    .append(exp.getId())
                    .append("'");
                failureMsg.append("; ");
            }

            ASN1Encodable isHashAlgoParam = isData.getHashAlgorithm().getParameters();
            if (isHashAlgoParam == null) {
                failureMsg.append("biometricData[")
                    .append(i)
                    .append("].hashAlgorithm.parameters is 'present'");
                failureMsg.append(" but expected 'absent'");
                failureMsg.append("; ");
            } else {
                try {
                    byte[] isBytes = isHashAlgoParam.toASN1Primitive().getEncoded();
                    if (!Arrays.equals(isBytes, DER_NULL)) {
                        failureMsg.append("biometricData[")
                            .append(i)
                            .append("].biometricDataHash.parameters is '")
                            .append(hex(isBytes));
                        failureMsg.append("' but expected '")
                            .append(hex(DER_NULL))
                            .append("'");
                        failureMsg.append("; ");
                    }
                } catch (IOException ex) {
                    failureMsg.append("biometricData[")
                        .append(i)
                        .append("].biometricDataHash.parameters has incorrect syntax");
                    failureMsg.append("; ");
                }
            }

            byte[] isBytes = isData.getBiometricDataHash().getOctets();
            byte[] expBytes = expData.getBiometricDataHash().getOctets();
            if (!Arrays.equals(isBytes, expBytes)) {
                failureMsg.append("biometricData[")
                    .append(i)
                    .append("].biometricDataHash is '")
                    .append(hex(isBytes));
                failureMsg.append("' but expected '")
                    .append(hex(expBytes))
                    .append("'");
                failureMsg.append("; ");
            }

            DERIA5String str = isData.getSourceDataUri();
            String isSourceDataUri = (str == null)
                    ? null
                    : str.getString();

            String expSourceDataUri = null;
            if (biometricInfo.getSourceDataUriOccurrence() != TripleState.FORBIDDEN) {
                str = expData.getSourceDataUri();
                expSourceDataUri = (str == null)
                        ? null
                        : str.getString();
            }

            if (expSourceDataUri == null) {
                if (isSourceDataUri != null) {
                    failureMsg.append("biometricData[")
                        .append(i)
                        .append("].sourceDataUri is 'present'");
                    failureMsg.append(" but expected 'absent'");
                    failureMsg.append("; ");
                }
            } else {
                if (isSourceDataUri == null) {
                    failureMsg.append("biometricData[")
                        .append(i)
                        .append("].sourceDataUri is 'absent'");
                    failureMsg.append(" but expected 'present'");
                    failureMsg.append("; ");
                } else if (!isSourceDataUri.equals(expSourceDataUri)) {
                    failureMsg.append("biometricData[")
                        .append(i)
                        .append("].sourceDataUri is '")
                        .append(isSourceDataUri);
                    failureMsg.append("' but expected '")
                        .append(expSourceDataUri).append("'");
                    failureMsg.append("; ");
                }
            }
        }
    } // method checkExtensionBiometricInfo

    private void checkExtensionAuthorizationTemplate(
            final StringBuilder failureMsg,
            final byte[] extensionValue,
            final Extensions requestExtensions,
            final ExtensionControl extControl) {
        QaAuthorizationTemplate conf = authorizationTemplate;

        if (conf == null) {
            byte[] expected = getExpectedExtValue(
                    ObjectIdentifiers.id_xipki_ext_authorizationTemplate,
                    requestExtensions, extControl);
            if (!Arrays.equals(expected, extensionValue)) {
                failureMsg.append("extension valus is '")
                    .append(hex(extensionValue));
                failureMsg.append("' but expected '")
                    .append((expected == null)
                            ? "not present"
                            : hex(expected))
                    .append("'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(extensionValue);
        ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        ASN1OctetString accessRights = DEROctetString.getInstance(seq.getObjectAt(1));
        if (!conf.getType().equals(type.getId())) {
            failureMsg.append("type is '").append(type.getId());
            failureMsg.append("' but expected '").append(conf.getType()).append("'");
            failureMsg.append("; ");
        }

        byte[] isRights = accessRights.getOctets();
        if (!Arrays.equals(conf.getAccessRights(), isRights)) {
            failureMsg.append("accessRights is '" + hex(isRights)
                    + "' but expected '" + hex(conf.getAccessRights()) + "'");
            failureMsg.append("; ");
        }
    } // method checkExtensionAuthorizationTemplate

    private Set<KeyUsageControl> getKeyusage(
            final boolean required) {
        Set<KeyUsageControl> ret = new HashSet<>();

        Set<KeyUsageControl> controls = keyusages;
        if (controls != null) {
            for (KeyUsageControl control : controls) {
                if (control.isRequired() == required) {
                    ret.add(control);
                }
            }
        }
        return ret;
    }

    private Set<ExtKeyUsageControl> getExtKeyusage(
            final boolean required) {
        Set<ExtKeyUsageControl> ret = new HashSet<>();

        Set<ExtKeyUsageControl> controls = extendedKeyusages;
        if (controls != null) {
            for (ExtKeyUsageControl control : controls) {
                if (control.isRequired() == required) {
                    ret.add(control);
                }
            }
        }
        return ret;
    }

    private byte[] getConstantExtensionValue(
            final ASN1ObjectIdentifier type) {
        return (constantExtensions == null)
                ? null
                : constantExtensions.get(type).getValue();
    }

    private Object getExtensionValue(
            final ASN1ObjectIdentifier type,
            final ExtensionsType extensionsType,
            final Class<?> expectedClass)
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
            final ExtensionsType extensionsType)
    throws CertprofileException {
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

    private static ASN1Encodable readAsn1Encodable(
            final byte[] encoded)
    throws CertprofileException {
        ASN1StreamParser parser = new ASN1StreamParser(encoded);
        try {
            return parser.readObject();
        } catch (IOException ex) {
            throw new CertprofileException("could not parse the constant extension value", ex);
        }
    }

    private static String hex(
            final byte[] bytes) {
        return Hex.toHexString(bytes);
    }

    private static Set<String> strInBnotInA(
            final Collection<String> collectionA,
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

    static Set<Range> buildParametersMap(
            final RangesType ranges) {
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

    private static GeneralName createGeneralName(
            final GeneralName reqName,
            final Set<GeneralNameMode> modes)
    throws BadCertTemplateException {
        int tag = reqName.getTagNo();
        GeneralNameMode mode = null;
        for (GeneralNameMode m : modes) {
            if (m.getTag().getTag() == tag) {
                mode = m;
                break;
            }
        }

        if (mode == null) {
            throw new BadCertTemplateException("generalName tag " + tag + " is not allowed");
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
            if (!mode.getAllowedTypes().contains(type)) {
                throw new BadCertTemplateException(
                        "otherName.type " + type.getId() + " is not allowed");
            }

            ASN1Encodable value = ((ASN1TaggedObject) reqSeq.getObjectAt(1)).getObject();
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
                        ((ASN1TaggedObject) reqSeq.getObjectAt(idx++)).getObject());
                nameAssigner = ds.getString();
            }

            DirectoryString ds = DirectoryString.getInstance(
                    ((ASN1TaggedObject) reqSeq.getObjectAt(idx++)).getObject());
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

    private static Set<String> getKeyUsage(
            final byte[] extensionValue) {
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

    private static Set<String> getExtKeyUsage(
            final byte[] extensionValue) {
        Set<String> usages = new HashSet<>();
        org.bouncycastle.asn1.x509.ExtendedKeyUsage reqKeyUsage =
                org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extensionValue);
        for (KeyPurposeId usage : reqKeyUsage.getUsages()) {
            usages.add(usage.getId());
        }
        return usages;
    }

    private static void checkAia(
            final StringBuilder failureMsg,
            final AuthorityInformationAccess aia,
            final ASN1ObjectIdentifier accessMethod,
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
            failureMsg.append("number of AIA ").append(typeDesc).append(" URIs is '").append(size);
            failureMsg.append("' but expected is '").append(expectedUris.size()).append("'");
            failureMsg.append("; ");
            return;
        }

        Set<String> isUris = new HashSet<>();
        for (int i = 0; i < size; i++) {
            GeneralName isAccessLocation = isAccessDescriptions.get(i).getAccessLocation();
            if (isAccessLocation.getTagNo() != GeneralName.uniformResourceIdentifier) {
                failureMsg.append("tag of accessLocation of AIA ")
                    .append(typeDesc)
                    .append(" is '").append(isAccessLocation.getTagNo());
                failureMsg.append("' but expected is '")
                    .append(GeneralName.uniformResourceIdentifier)
                    .append("'");
                failureMsg.append("; ");
            } else {
                String isOcspUri = ((ASN1String) isAccessLocation.getName()).getString();
                isUris.add(isOcspUri);
            }
        }

        Set<String> diffs = strInBnotInA(expectedUris, isUris);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append(typeDesc)
                .append(" URIs ")
                .append(diffs.toString())
                .append(" are present but not expected");
            failureMsg.append("; ");
        }

        diffs = strInBnotInA(isUris, expectedUris);
        if (CollectionUtil.isNonEmpty(diffs)) {
            failureMsg.append(typeDesc)
                .append(" URIs ")
                .append(diffs.toString())
                .append(" are absent but are required");
            failureMsg.append("; ");
        }
    } // method checkAia

}
