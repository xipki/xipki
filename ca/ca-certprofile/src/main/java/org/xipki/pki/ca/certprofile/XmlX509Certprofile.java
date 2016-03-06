/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.ca.certprofile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.util.AlgorithmUtil;
import org.xipki.pki.ca.api.BadCertTemplateException;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.api.profile.DirectoryStringType;
import org.xipki.pki.ca.api.profile.ExtensionControl;
import org.xipki.pki.ca.api.profile.ExtensionValue;
import org.xipki.pki.ca.api.profile.ExtensionValues;
import org.xipki.pki.ca.api.profile.GeneralNameMode;
import org.xipki.pki.ca.api.profile.KeyParametersOption;
import org.xipki.pki.ca.api.profile.Range;
import org.xipki.pki.ca.api.profile.RdnControl;
import org.xipki.pki.ca.api.profile.StringType;
import org.xipki.pki.ca.api.profile.x509.AuthorityInfoAccessControl;
import org.xipki.pki.ca.api.profile.x509.BaseX509Certprofile;
import org.xipki.pki.ca.api.profile.x509.CertificatePolicyInformation;
import org.xipki.pki.ca.api.profile.x509.ExtKeyUsageControl;
import org.xipki.pki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.pki.ca.api.profile.x509.SpecialX509CertprofileBehavior;
import org.xipki.pki.ca.api.profile.x509.SubjectControl;
import org.xipki.pki.ca.api.profile.x509.SubjectDnSpec;
import org.xipki.pki.ca.api.profile.x509.X509CertVersion;
import org.xipki.pki.ca.certprofile.internal.MonetaryValueOption;
import org.xipki.pki.ca.certprofile.internal.QcStatementOption;
import org.xipki.pki.ca.certprofile.x509.jaxb.AdditionalInformation;
import org.xipki.pki.ca.certprofile.x509.jaxb.Admission;
import org.xipki.pki.ca.certprofile.x509.jaxb.AuthorityInfoAccess;
import org.xipki.pki.ca.certprofile.x509.jaxb.AuthorityKeyIdentifier;
import org.xipki.pki.ca.certprofile.x509.jaxb.AuthorizationTemplate;
import org.xipki.pki.ca.certprofile.x509.jaxb.BasicConstraints;
import org.xipki.pki.ca.certprofile.x509.jaxb.BiometricInfo;
import org.xipki.pki.ca.certprofile.x509.jaxb.CertificatePolicies;
import org.xipki.pki.ca.certprofile.x509.jaxb.ConstantExtValue;
import org.xipki.pki.ca.certprofile.x509.jaxb.ExtendedKeyUsage;
import org.xipki.pki.ca.certprofile.x509.jaxb.ExtensionType;
import org.xipki.pki.ca.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.pki.ca.certprofile.x509.jaxb.InhibitAnyPolicy;
import org.xipki.pki.ca.certprofile.x509.jaxb.IntWithDescType;
import org.xipki.pki.ca.certprofile.x509.jaxb.KeyUsage;
import org.xipki.pki.ca.certprofile.x509.jaxb.NameConstraints;
import org.xipki.pki.ca.certprofile.x509.jaxb.NameValueType;
import org.xipki.pki.ca.certprofile.x509.jaxb.OidWithDescType;
import org.xipki.pki.ca.certprofile.x509.jaxb.PolicyConstraints;
import org.xipki.pki.ca.certprofile.x509.jaxb.PolicyMappings;
import org.xipki.pki.ca.certprofile.x509.jaxb.PrivateKeyUsagePeriod;
import org.xipki.pki.ca.certprofile.x509.jaxb.QCStatementType;
import org.xipki.pki.ca.certprofile.x509.jaxb.QCStatementValueType;
import org.xipki.pki.ca.certprofile.x509.jaxb.QCStatements;
import org.xipki.pki.ca.certprofile.x509.jaxb.QcEuLimitValueType;
import org.xipki.pki.ca.certprofile.x509.jaxb.Range2Type;
import org.xipki.pki.ca.certprofile.x509.jaxb.RdnType;
import org.xipki.pki.ca.certprofile.x509.jaxb.Restriction;
import org.xipki.pki.ca.certprofile.x509.jaxb.SMIMECapabilities;
import org.xipki.pki.ca.certprofile.x509.jaxb.SMIMECapability;
import org.xipki.pki.ca.certprofile.x509.jaxb.SubjectAltName;
import org.xipki.pki.ca.certprofile.x509.jaxb.SubjectInfoAccess;
import org.xipki.pki.ca.certprofile.x509.jaxb.SubjectInfoAccess.Access;
import org.xipki.pki.ca.certprofile.x509.jaxb.TlsFeature;
import org.xipki.pki.ca.certprofile.x509.jaxb.ValidityModel;
import org.xipki.pki.ca.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.pki.ca.certprofile.x509.jaxb.X509ProfileType.KeyAlgorithms;
import org.xipki.pki.ca.certprofile.x509.jaxb.X509ProfileType.Parameters;
import org.xipki.pki.ca.certprofile.x509.jaxb.X509ProfileType.Subject;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XmlX509Certprofile extends BaseX509Certprofile {

    private static final Logger LOG = LoggerFactory.getLogger(XmlX509Certprofile.class);

    private ExtensionValue additionalInformation;

    private ExtensionValue admission;

    private AuthorityInfoAccessControl aiaControl;

    private Set<GeneralNameMode> allowedSubjectAltNameModes;

    private Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> allowedSubjectInfoAccessModes;

    private ExtensionValue authorizationTemplate;

    private BiometricInfoOption biometricDataOption;

    private boolean ca;

    private ExtensionValue certificatePolicies;

    private Map<ASN1ObjectIdentifier, ExtensionValue> constantExtensions;

    private boolean duplicateKeyPermitted;

    private boolean duplicateSubjectPermitted;

    private Set<ExtKeyUsageControl> extendedKeyusages;

    private Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls;

    private boolean includeIssuerAndSerialInAki;

    private boolean incSerialNoIfSubjectExists;

    private ExtensionValue inhibitAnyPolicy;

    private Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms;

    private Set<KeyUsageControl> keyusages;

    private Integer maxSize;

    private ExtensionValue nameConstraints;

    private boolean notBeforeMidnight;

    private Map<String, String> parameters;

    private Integer pathLen;

    private ExtensionValue policyConstraints;

    private ExtensionValue policyMappings;

    private CertValidity privateKeyUsagePeriod;

    private ExtensionValue qcStatments;

    private List<QcStatementOption> qcStatementsOption;

    private boolean raOnly;

    private ExtensionValue restriction;

    private boolean serialNumberInReqPermitted;

    private List<String> signatureAlgorithms;

    private ExtensionValue smimeCapatibilities;

    private SpecialX509CertprofileBehavior specialBehavior;

    private SubjectControl subjectControl;

    private ExtensionValue tlsFeature;

    private CertValidity validity;

    private X509CertVersion version;

    private ExtensionValue validityModel;

    private void reset() {
        additionalInformation = null;
        admission = null;
        aiaControl = null;
        allowedSubjectAltNameModes = null;
        allowedSubjectInfoAccessModes = null;
        authorizationTemplate = null;
        biometricDataOption = null;
        ca = false;
        certificatePolicies = null;
        constantExtensions = null;
        duplicateKeyPermitted = true;
        duplicateSubjectPermitted = true;
        extendedKeyusages = null;
        extensionControls = null;
        includeIssuerAndSerialInAki = false;
        incSerialNoIfSubjectExists = false;
        inhibitAnyPolicy = null;
        keyAlgorithms = null;
        keyusages = null;
        maxSize = null;
        nameConstraints = null;
        notBeforeMidnight = false;
        parameters = null;
        pathLen = null;
        policyConstraints = null;
        policyMappings = null;
        privateKeyUsagePeriod = null;
        qcStatments = null;
        qcStatementsOption = null;
        raOnly = false;
        restriction = null;
        serialNumberInReqPermitted = true;
        signatureAlgorithms = null;
        smimeCapatibilities = null;
        specialBehavior = null;
        subjectControl = null;
        tlsFeature = null;
        validity = null;
        validityModel = null;
        version = null;
    } // method reset

    @Override
    public void initialize(
            final String data)
    throws CertprofileException {
        ParamUtil.requireNonBlank("data", data);

        reset();
        try {
            doInitialize(data);
        } catch (RuntimeException ex) {
            final String message = "RuntimeException";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            throw new CertprofileException(
                    "caught RuntimeException while initializing certprofile: " + ex.getMessage());
        }
    } // method initialize

    private void doInitialize(
            final String data)
    throws CertprofileException {
        byte[] bytes;
        try {
            bytes = data.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
            bytes = data.getBytes();
        }

        X509ProfileType conf = XmlX509CertprofileUtil.parse(new ByteArrayInputStream(bytes));

        if (conf.getVersion() != null) {
            String versionText = conf.getVersion();
            this.version = X509CertVersion.getInstance(versionText);
            if (this.version == null) {
                throw new CertprofileException(String.format(
                        "invalid version '%s'", versionText));
            }
        } else {
            this.version = X509CertVersion.v3;
        }

        if (conf.getSignatureAlgorithms() != null) {
            List<String> algoNames = conf.getSignatureAlgorithms().getAlgorithm();
            this.signatureAlgorithms = new ArrayList<>(algoNames.size());
            for (String algoName : algoNames) {
                try {
                    this.signatureAlgorithms.add(
                            AlgorithmUtil.canonicalizeSignatureAlgo(algoName));
                } catch (NoSuchAlgorithmException ex) {
                    throw new CertprofileException(ex.getMessage(), ex);
                }
            }
        }

        this.raOnly = conf.isRaOnly();

        this.maxSize = conf.getMaxSize();

        this.validity = CertValidity.getInstance(conf.getValidity());
        this.ca = conf.isCa();
        this.notBeforeMidnight = "midnight".equalsIgnoreCase(conf.getNotBeforeTime());

        String specBehavior = conf.getSpecialBehavior();
        if (specBehavior != null) {
            this.specialBehavior = SpecialX509CertprofileBehavior.getInstance(specBehavior);
        }

        if (conf.isDuplicateKey() != null) {
            duplicateKeyPermitted = conf.isDuplicateKey().booleanValue();
        }

        if (conf.isSerialNumberInReq() != null) {
            serialNumberInReqPermitted = conf.isSerialNumberInReq().booleanValue();
        }

        // KeyAlgorithms
        KeyAlgorithms keyAlgos = conf.getKeyAlgorithms();
        if (keyAlgos != null) {
            this.keyAlgorithms = XmlX509CertprofileUtil.buildKeyAlgorithms(keyAlgos);
        }

        // parameters
        Parameters confParams = conf.getParameters();
        if (confParams == null) {
            parameters = null;
        } else {
            Map<String, String> tmpMap = new HashMap<>();
            for (NameValueType nv : confParams.getParameter()) {
                tmpMap.put(nv.getName(), nv.getValue());
            }
            parameters = Collections.unmodifiableMap(tmpMap);
        }

        // Subject
        Subject subject = conf.getSubject();
        Boolean bo = subject.isDuplicateSubjectPermitted();
        if (bo != null) {
            duplicateSubjectPermitted = bo.booleanValue();
        }

        Map<ASN1ObjectIdentifier, RdnControl> subjectDnControls = new HashMap<>();

        for (RdnType rdn : subject.getRdn()) {
            ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(rdn.getType().getValue());

            List<Pattern> patterns = null;
            if (CollectionUtil.isNonEmpty(rdn.getRegex())) {
                patterns = new LinkedList<>();
                for (String regex : rdn.getRegex()) {
                    Pattern pattern = Pattern.compile(regex);
                    patterns.add(pattern);
                }
            }

            if (patterns == null) {
                Pattern pattern = SubjectDnSpec.getPattern(type);
                if (pattern != null) {
                    patterns = Arrays.asList(pattern);
                }
            }

            Range range;
            if (rdn.getMinLen() != null || rdn.getMaxLen() != null) {
                range = new Range(rdn.getMinLen(), rdn.getMaxLen());
            } else {
                range = null;
            }

            RdnControl rdnControl = new RdnControl(type, rdn.getMinOccurs(), rdn.getMaxOccurs());
            subjectDnControls.put(type, rdnControl);

            StringType stringType = XmlX509CertprofileUtil.convertStringType(
                    rdn.getStringType());
            rdnControl.setStringType(stringType);
            rdnControl.setStringLengthRange(range);
            rdnControl.setPatterns(patterns);
            rdnControl.setPrefix(rdn.getPrefix());
            rdnControl.setSuffix(rdn.getSuffix());
            rdnControl.setGroup(rdn.getGroup());
            SubjectDnSpec.fixRdnControl(rdnControl);
        }
        this.subjectControl = new SubjectControl(subject.isDnBackwards(), subjectDnControls);
        this.incSerialNoIfSubjectExists = subject.isIncSerialNumber();

        // Extensions
        ExtensionsType extensionsType = conf.getExtensions();

        // Extension controls
        this.extensionControls = XmlX509CertprofileUtil.buildExtensionControls(extensionsType);

        // additionalInformation
        initAdditionalInformation(extensionsType);

        // admission
        initAdmission(extensionsType);

        // AuthorityInfoAccess
        initAuthorityInfoAccess(extensionsType);

        // AuthorityKeyIdentifier
        initAuthorityKeyIdentifier(extensionsType);

        // authorizationTemplate
        initAuthorizationTemplate(extensionsType);

        // BasicConstrains
        initBasicConstraints(extensionsType);

        // biometricInfo
        initBiometricInfo(extensionsType);

        // Certificate Policies
        initCertificatePolicies(extensionsType);

        // ExtendedKeyUsage
        initExtendedKeyUsage(extensionsType);

        // Inhibit anyPolicy
        initInhibitAnyPolicy(extensionsType);

        // KeyUsage
        initKeyUsage(extensionsType);

        // Name Constrains
        initNameConstraints(extensionsType);

        // Policy Constraints
        initPolicyConstraints(extensionsType);

        // Policy Mappings
        initPolicyMappings(extensionsType);

        // PrivateKeyUsagePeriod
        initPrivateKeyUsagePeriod(extensionsType);

        // QCStatements
        initQcStatements(extensionsType);

        // restriction
        initRestriction(extensionsType);

        // SMIMECapatibilities
        initSmimeCapabilities(extensionsType);

        // SubjectAltNameMode
        initSubjectAlternativeName(extensionsType);

        // SubjectInfoAccess
        initSubjectInfoAccess(extensionsType);

        // tlsFeature
        initTlsFeature(extensionsType);

        // validityModel
        initValidityModel(extensionsType);

        // constant extensions
        this.constantExtensions = XmlX509CertprofileUtil.buildConstantExtesions(extensionsType);
    } // method doInitialize

    private void initAdditionalInformation(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_additionalInformation;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        AdditionalInformation extConf = (AdditionalInformation) getExtensionValue(
                type, extensionsType, AdditionalInformation.class);
        if (extConf == null) {
            return;
        }

        DirectoryStringType stringType =
                XmlX509CertprofileUtil.convertDirectoryStringType(extConf.getType());
        ASN1Encodable extValue = stringType.createDirectoryString(extConf.getText());
        additionalInformation =
                new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
    }

    private void initAdmission(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_admission;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        Admission extConf = (Admission) getExtensionValue(
                type, extensionsType, Admission.class);
        if (extConf == null) {
            return;
        }

        List<ASN1ObjectIdentifier> professionOids;
        List<String> professionItems;

        List<String> items = (type == null)
                ? null
                : extConf.getProfessionItem();
        professionItems = CollectionUtil.unmodifiableList(items);

        List<OidWithDescType> oidWithDescs = (type == null)
                ? null
                : extConf.getProfessionOid();
        professionOids = XmlX509CertprofileUtil.toOidList(oidWithDescs);

        this.admission = createAdmission(extensionControls.get(type).isCritical(),
                professionOids, professionItems,
                extConf.getRegistrationNumber(),
                extConf.getAddProfessionInfo());
    }

    private void initAuthorityInfoAccess(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.authorityInfoAccess;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        AuthorityInfoAccess extConf = (AuthorityInfoAccess) getExtensionValue(
                type, extensionsType, AuthorityInfoAccess.class);
        if (extConf == null) {
            return;
        }

        Boolean bo = extConf.isIncludeCaIssuers();
        boolean includesCaIssuers = (bo == null)
                ? true
                : bo.booleanValue();

        bo = extConf.isIncludeOcsp();
        boolean includesOcsp = (bo == null)
                ? true
                : bo.booleanValue();

        this.aiaControl = new AuthorityInfoAccessControl(includesCaIssuers, includesOcsp);
    }

    private void initAuthorityKeyIdentifier(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.authorityKeyIdentifier;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        AuthorityKeyIdentifier extConf = (AuthorityKeyIdentifier) getExtensionValue(
                type, extensionsType, AuthorityKeyIdentifier.class);
        if (extConf == null) {
            return;
        }

        this.includeIssuerAndSerialInAki = extConf.isIncludeIssuerAndSerial();
    }

    private void initAuthorizationTemplate(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_xipki_ext_authorizationTemplate;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        AuthorizationTemplate extConf = (AuthorizationTemplate) getExtensionValue(
                type, extensionsType, AuthorizationTemplate.class);
        if (extConf == null) {
            return;
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1ObjectIdentifier(extConf.getType().getValue()));
        vec.add(new DEROctetString(extConf.getAccessRights().getValue()));
        ASN1Encodable extValue = new DERSequence(vec);
        authorizationTemplate =
                new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
    }

    private void initBasicConstraints(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.basicConstraints;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        BasicConstraints extConf = (BasicConstraints) getExtensionValue(
                type, extensionsType, BasicConstraints.class);
        if (extConf == null) {
            return;
        }
        this.pathLen = extConf.getPathLen();
    }

    private void initBiometricInfo(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.biometricInfo;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        BiometricInfo extConf = (BiometricInfo) getExtensionValue(
                type, extensionsType, BiometricInfo.class);
        if (extConf == null) {
            return;
        }

        try {
            this.biometricDataOption = new BiometricInfoOption(extConf);
        } catch (NoSuchAlgorithmException ex) {
            throw new CertprofileException("NoSuchAlgorithmException: " + ex.getMessage());
        }
    }

    private void initCertificatePolicies(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.certificatePolicies;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        CertificatePolicies extConf = (CertificatePolicies) getExtensionValue(
                type, extensionsType, CertificatePolicies.class);
        if (extConf == null) {
            return;
        }

        List<CertificatePolicyInformation> policyInfos =
                XmlX509CertprofileUtil.buildCertificatePolicies(extConf);
        org.bouncycastle.asn1.x509.CertificatePolicies value = CollectionUtil.isEmpty(policyInfos)
                ? null
                : XmlX509CertprofileUtil.createCertificatePolicies(policyInfos);
        this.certificatePolicies =
                new ExtensionValue(extensionControls.get(type).isCritical(), value);
    }

    private void initExtendedKeyUsage(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.extendedKeyUsage;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        ExtendedKeyUsage extConf = (ExtendedKeyUsage) getExtensionValue(
                type, extensionsType, ExtendedKeyUsage.class);
        if (extConf == null) {
            return;
        }

        this.extendedKeyusages = XmlX509CertprofileUtil.buildExtKeyUsageOptions(extConf);
    }

    private void initInhibitAnyPolicy(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.inhibitAnyPolicy;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        InhibitAnyPolicy extConf = (InhibitAnyPolicy) getExtensionValue(
                type, extensionsType, InhibitAnyPolicy.class);
        if (extConf == null) {
            return;
        }

        int skipCerts = extConf.getSkipCerts();
        if (skipCerts < 0) {
            throw new CertprofileException(
                    "negative inhibitAnyPolicy.skipCerts is not allowed: " + skipCerts);
        }
        ASN1Integer value = new ASN1Integer(BigInteger.valueOf(skipCerts));
        this.inhibitAnyPolicy =
                new ExtensionValue(extensionControls.get(type).isCritical(), value);
    }

    private void initKeyUsage(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.keyUsage;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        KeyUsage extConf = (KeyUsage) getExtensionValue(
                type, extensionsType, KeyUsage.class);
        if (extConf == null) {
            return;
        }

        this.keyusages = XmlX509CertprofileUtil.buildKeyUsageOptions(extConf);
    }

    private void initNameConstraints(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.nameConstraints;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        NameConstraints extConf = (NameConstraints) getExtensionValue(
                type, extensionsType, NameConstraints.class);
        if (extConf == null) {
            return;
        }

        org.bouncycastle.asn1.x509.NameConstraints value =
                XmlX509CertprofileUtil.buildNameConstrains(extConf);
        this.nameConstraints = new ExtensionValue(extensionControls.get(type).isCritical(), value);
    }

    private void initPrivateKeyUsagePeriod(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.privateKeyUsagePeriod;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        PrivateKeyUsagePeriod extConf = (PrivateKeyUsagePeriod) getExtensionValue(
                type, extensionsType, PrivateKeyUsagePeriod.class);
        if (extConf == null) {
            return;
        }
        privateKeyUsagePeriod = CertValidity.getInstance(extConf.getValidity());
    }

    private void initPolicyConstraints(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.policyConstraints;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        PolicyConstraints extConf = (PolicyConstraints) getExtensionValue(
                type, extensionsType, PolicyConstraints.class);
        if (extConf == null) {
            return;
        }

        ASN1Sequence value = XmlX509CertprofileUtil.buildPolicyConstrains(extConf);
        this.policyConstraints =
                new ExtensionValue(extensionControls.get(type).isCritical(), value);
    }

    private void initPolicyMappings(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.policyMappings;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        PolicyMappings extConf = (PolicyMappings) getExtensionValue(
                type, extensionsType, PolicyMappings.class);
        if (extConf == null) {
            return;
        }

        org.bouncycastle.asn1.x509.PolicyMappings value =
                XmlX509CertprofileUtil.buildPolicyMappings(extConf);
        this.policyMappings = new ExtensionValue(extensionControls.get(type).isCritical(), value);
    }

    private void initQcStatements(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.qCStatements;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        QCStatements extConf = (QCStatements) getExtensionValue(
                type, extensionsType, QCStatements.class);

        if (extConf == null) {
            return;
        }

        List<QCStatementType> qcStatementTypes = extConf.getQCStatement();

        this.qcStatementsOption = new ArrayList<>(qcStatementTypes.size());
        Set<String> currencyCodes = new HashSet<>();
        boolean requireInfoFromReq = false;

        for (QCStatementType m : qcStatementTypes) {
            ASN1ObjectIdentifier qcStatementId =
                    new ASN1ObjectIdentifier(m.getStatementId().getValue());
            QcStatementOption qcStatementOption;

            QCStatementValueType statementValue = m.getStatementValue();
            if (statementValue == null) {
                QCStatement qcStatment = new QCStatement(qcStatementId);
                qcStatementOption = new QcStatementOption(qcStatment);
            } else if (statementValue.getQcRetentionPeriod() != null) {
                QCStatement qcStatment = new QCStatement(qcStatementId,
                        new ASN1Integer(statementValue.getQcRetentionPeriod()));
                qcStatementOption = new QcStatementOption(qcStatment);
            } else if (statementValue.getConstant() != null) {
                ASN1Encodable constantStatementValue;
                try {
                    constantStatementValue = new ASN1StreamParser(
                            statementValue.getConstant().getValue()).readObject();
                } catch (IOException ex) {
                    throw new CertprofileException(
                            "cannot parse the constant value of QcStatement");
                }
                QCStatement qcStatment = new QCStatement(qcStatementId,
                        constantStatementValue);
                qcStatementOption = new QcStatementOption(qcStatment);
            } else if (statementValue.getQcEuLimitValue() != null) {
                QcEuLimitValueType euLimitType = statementValue.getQcEuLimitValue();
                String tmpCurrency = euLimitType.getCurrency().toUpperCase();
                if (currencyCodes.contains(tmpCurrency)) {
                    throw new CertprofileException(
                            "Duplicated definition of qcStatments with QCEuLimitValue for "
                            + "the currency " + tmpCurrency);
                }

                Iso4217CurrencyCode currency;
                if (StringUtil.isNumber(tmpCurrency)) {
                    int countryCode = Integer.parseInt(tmpCurrency);
                    currency = new Iso4217CurrencyCode(countryCode);
                } else {
                    currency = new Iso4217CurrencyCode(tmpCurrency);
                }

                Range2Type r1 = euLimitType.getAmount();
                Range2Type r2 = euLimitType.getExponent();
                if (r1.getMin() == r1.getMax() && r2.getMin() == r2.getMax()) {
                    MonetaryValue monetaryValue =
                            new MonetaryValue(currency, r1.getMin(), r2.getMin());
                    QCStatement qcStatment =
                            new QCStatement(qcStatementId, monetaryValue);
                    qcStatementOption = new QcStatementOption(qcStatment);
                } else {
                    MonetaryValueOption monetaryValueOption =
                            new MonetaryValueOption(currency, r1, r2);
                    qcStatementOption =
                            new QcStatementOption(qcStatementId, monetaryValueOption);
                    requireInfoFromReq = true;
                }
                currencyCodes.add(tmpCurrency);
            } else {
                throw new RuntimeException("unknown value of qcStatment");
            }

            this.qcStatementsOption.add(qcStatementOption);
        } // end for

        if (requireInfoFromReq) {
            return;
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (QcStatementOption m : qcStatementsOption) {
            if (m.getStatement() == null) {
                throw new RuntimeException("should not reach here");
            }
            vec.add(m.getStatement());
        }
        ASN1Sequence seq = new DERSequence(vec);
        qcStatments = new ExtensionValue(extensionControls.get(type).isCritical(), seq);
        qcStatementsOption = null;
    }

    private void initRestriction(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_restriction;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        Restriction extConf = (Restriction) getExtensionValue(
                type, extensionsType, Restriction.class);
        if (extConf == null) {
            return;
        }

        DirectoryStringType stringType =
                XmlX509CertprofileUtil.convertDirectoryStringType(extConf.getType());
        ASN1Encodable extValue = stringType.createDirectoryString(extConf.getText());
        restriction = new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
    }

    private void initSmimeCapabilities(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_smimeCapabilities;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        SMIMECapabilities extConf = (SMIMECapabilities) getExtensionValue(
                type, extensionsType, SMIMECapabilities.class);
        if (extConf == null) {
            return;
        }

        List<SMIMECapability> list = extConf.getSMIMECapability();

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (SMIMECapability m : list) {
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(m.getCapabilityID().getValue());
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

        ASN1Encodable extValue = new DERSequence(vec);
        smimeCapatibilities =
                new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
    }

    private void initSubjectAlternativeName(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.subjectAlternativeName;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        SubjectAltName extConf = (SubjectAltName) getExtensionValue(
                type, extensionsType, SubjectAltName.class);
        if (extConf == null) {
            return;
        }

        this.allowedSubjectAltNameModes =
                XmlX509CertprofileUtil.buildGeneralNameMode(extConf);
    }

    private void initSubjectInfoAccess(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.subjectInfoAccess;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        SubjectInfoAccess extConf = (SubjectInfoAccess) getExtensionValue(
                type, extensionsType, SubjectInfoAccess.class);
        if (extConf == null) {
            return;
        }

        List<Access> list = extConf.getAccess();
        this.allowedSubjectInfoAccessModes = new HashMap<>();
        for (Access entry : list) {
            this.allowedSubjectInfoAccessModes.put(
                    new ASN1ObjectIdentifier(entry.getAccessMethod().getValue()),
                    XmlX509CertprofileUtil.buildGeneralNameMode(entry.getAccessLocation()));
        }
    }

    private void initTlsFeature(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_pe_tlsfeature;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        TlsFeature extConf = (TlsFeature) getExtensionValue(
                type, extensionsType, TlsFeature.class);

        if (extConf == null) {
            return;
        }

        List<Integer> features = new ArrayList<>(extConf.getFeature().size());
        for (IntWithDescType m : extConf.getFeature()) {
            int value = m.getValue();
            if (value < 0 || value > 65535) {
                throw new CertprofileException("invalid TLS feature (extensionType) " + value);
            }
            features.add(value);
        }
        Collections.sort(features);

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (Integer m : features) {
            vec.add(new ASN1Integer(m));
        }
        ASN1Encodable extValue = new DERSequence(vec);
        tlsFeature = new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
    }

    private void initValidityModel(ExtensionsType extensionsType)
    throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_validityModel;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        ValidityModel extConf = (ValidityModel) getExtensionValue(
                type, extensionsType, ValidityModel.class);
        if (extConf == null) {
            return;
        }

        ASN1ObjectIdentifier oid =
                new ASN1ObjectIdentifier(extConf.getModelId().getValue());
        ASN1Encodable extValue = new DERSequence(oid);
        validityModel = new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
    }

    @Override
    public CertValidity getValidity() {
        return validity;
    }

    @Override
    public String getParameter(
            final String paramName) {
        return (parameters == null)
                ? null
                : parameters.get(paramName);
    }

    @Override
    public ExtensionValues getExtensions(
            final Map<ASN1ObjectIdentifier, ExtensionControl> extensionOccurences,
            final X500Name requestedSubject,
            final Extensions requestedExtensions,
            final Date notBefore,
            final Date notAfter)
    throws CertprofileException, BadCertTemplateException {
        ExtensionValues values = new ExtensionValues();
        if (CollectionUtil.isEmpty(extensionOccurences)) {
            return values;
        }

        ParamUtil.requireNonNull("requestedSubject", requestedSubject);
        ParamUtil.requireNonNull("notBefore", notBefore);
        ParamUtil.requireNonNull("notAfter", notAfter);

        Map<ASN1ObjectIdentifier, ExtensionControl> occurences = new HashMap<>(extensionOccurences);

        // AuthorityKeyIdentifier
        // processed by the CA

        // SubjectKeyIdentifier
        // processed by the CA

        // KeyUsage
        // processed by the CA

        // CertificatePolicies
        ASN1ObjectIdentifier type = Extension.certificatePolicies;
        if (certificatePolicies != null && occurences.remove(type) != null) {
            values.addExtension(type, certificatePolicies);
        }

        // Policy Mappings
        type = Extension.policyMappings;
        if (policyMappings != null && occurences.remove(type) != null) {
            values.addExtension(type, policyMappings);
        }

        // SubjectAltName
        // processed by the CA

        // IssuerAltName
        // processed by the CA

        // Subject Directory Attributes
        // Will not supported

        // Basic Constraints
        // processed by the CA

        // Name Constraints
        type = Extension.nameConstraints;
        if (nameConstraints != null && occurences.remove(type) != null) {
            values.addExtension(type, nameConstraints);
        }

        // PolicyConstrains
        type = Extension.policyConstraints;
        if (policyConstraints != null && occurences.remove(type) != null) {
            values.addExtension(type, policyConstraints);
        }

        // ExtendedKeyUsage
        // processed by CA

        // CRL Distribution Points
        // processed by the CA

        // Inhibit anyPolicy
        type = Extension.inhibitAnyPolicy;
        if (inhibitAnyPolicy != null && occurences.remove(type) != null) {
            values.addExtension(type, inhibitAnyPolicy);
        }

        // Freshest CRL
        // processed by the CA

        // Authority Information Access
        // processed by the CA

        // Subject Information Access
        // processed by the CA

        // Admission
        type = ObjectIdentifiers.id_extension_admission;
        if (admission != null && occurences.remove(type) != null) {
            values.addExtension(type, admission);
        }

        // OCSP Nocheck
        // processed by the CA

        // restriction
        type = ObjectIdentifiers.id_extension_restriction;
        if (restriction != null && occurences.remove(type) != null) {
            values.addExtension(type, restriction);
        }

        // additionalInformation
        type = ObjectIdentifiers.id_extension_additionalInformation;
        if (additionalInformation != null && occurences.remove(type) != null) {
            values.addExtension(type, additionalInformation);
        }

        // validityModel
        type = ObjectIdentifiers.id_extension_validityModel;
        if (validityModel != null && occurences.remove(type) != null) {
            values.addExtension(type, validityModel);
        }

        // PrivateKeyUsagePeriod
        type = Extension.privateKeyUsagePeriod;
        if (occurences.remove(type) != null) {
            Date tmpNotAfter;
            if (privateKeyUsagePeriod == null) {
                tmpNotAfter = notAfter;
            } else {
                tmpNotAfter = privateKeyUsagePeriod.add(notBefore);
                if (tmpNotAfter.after(notAfter)) {
                    tmpNotAfter = notAfter;
                }
            }

            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(new DERTaggedObject(false, 0, new DERGeneralizedTime(notBefore)));
            vec.add(new DERTaggedObject(false, 1, new DERGeneralizedTime(tmpNotAfter)));
            ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(),
                    new DERSequence(vec));
            values.addExtension(type, extValue);
        }

        // QCStatements
        type = Extension.qCStatements;
        if ((qcStatments != null || qcStatementsOption != null)
                && occurences.remove(type) != null) {
            if (qcStatments != null) {
                values.addExtension(type, qcStatments);
            } else if (qcStatementsOption != null) {
                // extract the euLimit data from request
                Extension extension = requestedExtensions.getExtension(type);
                if (extension == null) {
                    throw new BadCertTemplateException(
                            "No QCStatement extension is contained in the request");
                }
                ASN1Sequence seq = ASN1Sequence.getInstance(extension.getParsedValue());

                Map<String, int[]> qcEuLimits = new HashMap<>();
                final int n = seq.size();
                for (int i = 0; i < n; i++) {
                    QCStatement stmt = QCStatement.getInstance(seq.getObjectAt(i));
                    if (!ObjectIdentifiers.id_etsi_qcs_QcLimitValue.equals(stmt.getStatementId())) {
                        continue;
                    }

                    MonetaryValue monetaryValue =
                            MonetaryValue.getInstance(stmt.getStatementInfo());
                    int amount = monetaryValue.getAmount().intValue();
                    int exponent = monetaryValue.getExponent().intValue();
                    Iso4217CurrencyCode currency = monetaryValue.getCurrency();
                    String currencyS = currency.isAlphabetic()
                            ? currency.getAlphabetic().toUpperCase()
                            : Integer.toString(currency.getNumeric());
                    qcEuLimits.put(currencyS, new int[]{amount, exponent});
                }

                ASN1EncodableVector vec = new ASN1EncodableVector();
                for (QcStatementOption m : qcStatementsOption) {
                    if (m.getStatement() != null) {
                        vec.add(m.getStatement());
                        continue;
                    }

                    MonetaryValueOption monetaryOption = m.getMonetaryValueOption();
                    String currencyS = monetaryOption.getCurrencyString();
                    int[] limit = qcEuLimits.get(currencyS);
                    if (limit == null) {
                        throw new BadCertTemplateException(
                                "no EuLimitValue is specified for currency '" + currencyS + "'");
                    }

                    int amount = limit[0];
                    Range2Type range = monetaryOption.getAmountRange();
                    if (amount < range.getMin() || amount > range.getMax()) {
                        throw new BadCertTemplateException("amount for currency '" + currencyS
                                + "' is not within [" + range.getMin() + ", "
                                + range.getMax() + "]");
                    }

                    int exponent = limit[1];
                    range = monetaryOption.getExponentRange();
                    if (exponent < range.getMin() || exponent > range.getMax()) {
                        throw new BadCertTemplateException("exponent for currency '" + currencyS
                                + "' is not within [" + range.getMin() + ", "
                                + range.getMax() + "]");
                    }

                    MonetaryValue monetaryVale = new MonetaryValue(
                            monetaryOption.getCurrency(), amount, exponent);
                    QCStatement qcStatment = new QCStatement(m.getStatementId(), monetaryVale);
                    vec.add(qcStatment);
                }

                ExtensionValue extValue = new ExtensionValue(
                        extensionControls.get(type).isCritical(),
                        new DERSequence(vec));
                values.addExtension(type, extValue);
            } else {
                throw new RuntimeException("should not reach here");
            }
        }

        // biometricData
        type = Extension.biometricInfo;
        if (biometricDataOption != null && occurences.remove(type) != null) {
            Extension extension = requestedExtensions.getExtension(type);
            if (extension == null) {
                throw new BadCertTemplateException(
                        "No biometricInfo extension is contained in the request");
            }
            ASN1Sequence seq = ASN1Sequence.getInstance(extension.getParsedValue());
            final int n = seq.size();
            if (n < 1) {
                throw new BadCertTemplateException(
                        "biometricInfo extension in request contains empty sequence");
            }

            ASN1EncodableVector vec = new ASN1EncodableVector();

            for (int i = 0; i < n; i++) {
                BiometricData bd = BiometricData.getInstance(seq.getObjectAt(i));
                TypeOfBiometricData bdType = bd.getTypeOfBiometricData();
                if (!biometricDataOption.isTypePermitted(bdType)) {
                    throw new BadCertTemplateException(
                            "biometricInfo[" + i + "].typeOfBiometricData is not permitted");
                }

                ASN1ObjectIdentifier hashAlgo = bd.getHashAlgorithm().getAlgorithm();
                if (!biometricDataOption.isHashAlgorithmPermitted(hashAlgo)) {
                    throw new BadCertTemplateException(
                            "biometricInfo[" + i + "].hashAlgorithm is not permitted");
                }

                int expHashValueSize;
                try {
                    expHashValueSize = AlgorithmUtil.getHashOutputSizeInOctets(hashAlgo);
                } catch (NoSuchAlgorithmException ex) {
                    throw new CertprofileException(
                            "should not happen, unknown hash algorithm " + hashAlgo);
                }

                byte[] hashValue = bd.getBiometricDataHash().getOctets();
                if (hashValue.length != expHashValueSize) {
                    throw new BadCertTemplateException(
                            "biometricInfo[" + i + "].biometricDataHash has incorrect length");
                }

                DERIA5String sourceDataUri = bd.getSourceDataUri();
                switch (biometricDataOption.getSourceDataUriOccurrence()) {
                case FORBIDDEN:
                    sourceDataUri = null;
                    break;
                case REQUIRED:
                    if (sourceDataUri == null) {
                        throw new BadCertTemplateException("biometricInfo[" + i
                            + "].sourceDataUri is not specified in request but is required");
                    }
                    break;
                case OPTIONAL:
                    break;
                default:
                    throw new BadCertTemplateException(
                            "could not reach here, unknown tripleState");
                }

                AlgorithmIdentifier newHashAlg =
                        new AlgorithmIdentifier(hashAlgo, DERNull.INSTANCE);
                BiometricData newBiometricData = new BiometricData(bdType, newHashAlg,
                        new DEROctetString(hashValue), sourceDataUri);
                vec.add(newBiometricData);
            }

            ExtensionValue extValue = new ExtensionValue(
                        extensionControls.get(type).isCritical(), new DERSequence(vec));
            values.addExtension(type, extValue);
        }

        // tlsFeature
        type = ObjectIdentifiers.id_pe_tlsfeature;
        if (tlsFeature != null && occurences.remove(type) != null) {
            values.addExtension(type, tlsFeature);
        }

        // authorizationTemplate
        type = ObjectIdentifiers.id_xipki_ext_authorizationTemplate;
        if (authorizationTemplate != null && occurences.remove(type) != null) {
            values.addExtension(type, authorizationTemplate);
        }

        // SMIME
        type = ObjectIdentifiers.id_smimeCapabilities;
        if (smimeCapatibilities != null && occurences.remove(type) != null) {
            values.addExtension(type, smimeCapatibilities);
        }

        // constant extensions
        if (constantExtensions != null) {
            for (ASN1ObjectIdentifier m : constantExtensions.keySet()) {
                ExtensionControl occurence = occurences.remove(m);
                if (occurence == null) {
                    continue;
                }

                ExtensionValue extensionValue = constantExtensions.get(m);
                if (extensionValue != null) {
                    values.addExtension(m, extensionValue);
                }
            }
        }

        return values;
    } // method getExtensions

    @Override
    public Set<KeyUsageControl> getKeyUsage() {
        return keyusages;
    }

    @Override
    public Set<ExtKeyUsageControl> getExtendedKeyUsages() {
        return extendedKeyusages;
    }

    @Override
    public boolean isCa() {
        return ca;
    }

    @Override
    public Integer getPathLenBasicConstraint() {
        return pathLen;
    }

    @Override
    public AuthorityInfoAccessControl getAiaControl() {
        return aiaControl;
    }

    @Override
    public boolean hasMidnightNotBefore() {
        return notBeforeMidnight;
    }

    @Override
    public Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls() {
        return extensionControls;
    }

    @Override
    public boolean isOnlyForRa() {
        return raOnly;
    }

    @Override
    public int getMaxCertSize() {
        return (maxSize == null)
                ? super.getMaxCertSize()
                : maxSize;
    }

    @Override
    public boolean includeIssuerAndSerialInAki() {
        return includeIssuerAndSerialInAki;
    }

    @Override
    public SubjectControl getSubjectControl() {
        return subjectControl;
    }

    @Override
    public SpecialX509CertprofileBehavior getSpecialCertprofileBehavior() {
        return specialBehavior;
    }

    private ExtensionValue createAdmission(
            final boolean critical,
            final List<ASN1ObjectIdentifier> professionOids,
            final List<String> professionItems,
            final String registrationNumber,
            final byte[] addProfessionInfo)
    throws CertprofileException {
        if (CollectionUtil.isEmpty(professionItems)
                && CollectionUtil.isEmpty(professionOids)
                && StringUtil.isBlank(registrationNumber)
                && (addProfessionInfo == null || addProfessionInfo.length == 0)) {
            return null;
        }

        DirectoryString[] tmpProfessionItems = null;
        if (CollectionUtil.isNonEmpty(professionItems)) {
            int size = professionItems.size();
            tmpProfessionItems = new DirectoryString[size];
            for (int i = 0; i < size; i++) {
                tmpProfessionItems[i] = new DirectoryString(professionItems.get(i));
            }
        }

        ASN1ObjectIdentifier[] tmpProfessionOids = null;
        if (CollectionUtil.isNonEmpty(professionOids)) {
            tmpProfessionOids = professionOids.toArray(new ASN1ObjectIdentifier[0]);
        }

        ASN1OctetString tmpAddProfessionInfo = null;
        if (addProfessionInfo != null && addProfessionInfo.length > 0) {
            tmpAddProfessionInfo = new DEROctetString(addProfessionInfo);
        }

        ProfessionInfo professionInfo = new ProfessionInfo(
                null, tmpProfessionItems, tmpProfessionOids, registrationNumber,
                tmpAddProfessionInfo);

        Admissions admissions = new Admissions(null, null,
                new ProfessionInfo[]{professionInfo});

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(admissions);

        AdmissionSyntax value = new AdmissionSyntax(null, new DERSequence(vector));
        return new ExtensionValue(critical, value);
    } // method createAdmission

    @Override
    public boolean isDuplicateKeyPermitted() {
        return duplicateKeyPermitted;
    }

    @Override
    public boolean isDuplicateSubjectPermitted() {
        return duplicateSubjectPermitted;
    }

    @Override
    public boolean isSerialNumberInReqPermitted() {
        return serialNumberInReqPermitted;
    }

    @Override
    public Set<GeneralNameMode> getSubjectAltNameModes() {
        return allowedSubjectAltNameModes;
    }

    @Override
    protected Map<ASN1ObjectIdentifier, KeyParametersOption> getKeyAlgorithms() {
        return keyAlgorithms;
    }

    @Override
    public Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> getSubjectInfoAccessModes() {
        return allowedSubjectInfoAccessModes;
    }

    @Override
    public X509CertVersion getVersion() {
        return version;
    }

    @Override
    public List<String> getSignatureAlgorithms() {
        return signatureAlgorithms;
    }

    @Override
    public boolean incSerialNumberIfSubjectExists() {
        return incSerialNoIfSubjectExists;
    }

    private static Object getExtensionValue(
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
                throw new CertprofileException("the extension configuration for "
                        + displayName
                        + " is not of the expected type " + expectedClass.getName());
            }
        }

        throw new RuntimeException("should not reach here: undefined extension "
                + ObjectIdentifiers.oidToDisplayName(type));
    } // method getExtensionValue

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

}
