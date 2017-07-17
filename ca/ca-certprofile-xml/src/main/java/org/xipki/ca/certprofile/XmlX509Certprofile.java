/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.certprofile;

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
import java.util.Vector;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.DirectoryStringType;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.GeneralNameMode;
import org.xipki.ca.api.profile.GeneralNameTag;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.api.profile.RdnControl;
import org.xipki.ca.api.profile.StringType;
import org.xipki.ca.api.profile.x509.AuthorityInfoAccessControl;
import org.xipki.ca.api.profile.x509.BaseX509Certprofile;
import org.xipki.ca.api.profile.x509.CertificatePolicyInformation;
import org.xipki.ca.api.profile.x509.ExtKeyUsageControl;
import org.xipki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.ca.api.profile.x509.SpecialX509CertprofileBehavior;
import org.xipki.ca.api.profile.x509.SubjectControl;
import org.xipki.ca.api.profile.x509.SubjectDirectoryAttributesControl;
import org.xipki.ca.api.profile.x509.SubjectDnSpec;
import org.xipki.ca.api.profile.x509.X509CertLevel;
import org.xipki.ca.api.profile.x509.X509CertVersion;
import org.xipki.ca.api.profile.x509.X509CertprofileUtil;
import org.xipki.ca.certprofile.commonpki.AdmissionSyntaxOption;
import org.xipki.ca.certprofile.x509.jaxb.AdditionalInformation;
import org.xipki.ca.certprofile.x509.jaxb.AdmissionSyntax;
import org.xipki.ca.certprofile.x509.jaxb.AuthorityInfoAccess;
import org.xipki.ca.certprofile.x509.jaxb.AuthorityKeyIdentifier;
import org.xipki.ca.certprofile.x509.jaxb.AuthorizationTemplate;
import org.xipki.ca.certprofile.x509.jaxb.BasicConstraints;
import org.xipki.ca.certprofile.x509.jaxb.BiometricInfo;
import org.xipki.ca.certprofile.x509.jaxb.CertificatePolicies;
import org.xipki.ca.certprofile.x509.jaxb.ConstantExtValue;
import org.xipki.ca.certprofile.x509.jaxb.ExtendedKeyUsage;
import org.xipki.ca.certprofile.x509.jaxb.ExtensionType;
import org.xipki.ca.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.ca.certprofile.x509.jaxb.InhibitAnyPolicy;
import org.xipki.ca.certprofile.x509.jaxb.IntWithDescType;
import org.xipki.ca.certprofile.x509.jaxb.KeyUsage;
import org.xipki.ca.certprofile.x509.jaxb.NameConstraints;
import org.xipki.ca.certprofile.x509.jaxb.NameValueType;
import org.xipki.ca.certprofile.x509.jaxb.PdsLocationType;
import org.xipki.ca.certprofile.x509.jaxb.PolicyConstraints;
import org.xipki.ca.certprofile.x509.jaxb.PolicyMappings;
import org.xipki.ca.certprofile.x509.jaxb.PrivateKeyUsagePeriod;
import org.xipki.ca.certprofile.x509.jaxb.QcEuLimitValueType;
import org.xipki.ca.certprofile.x509.jaxb.QcStatementType;
import org.xipki.ca.certprofile.x509.jaxb.QcStatementValueType;
import org.xipki.ca.certprofile.x509.jaxb.QcStatements;
import org.xipki.ca.certprofile.x509.jaxb.Range2Type;
import org.xipki.ca.certprofile.x509.jaxb.RdnType;
import org.xipki.ca.certprofile.x509.jaxb.Restriction;
import org.xipki.ca.certprofile.x509.jaxb.SMIMECapabilities;
import org.xipki.ca.certprofile.x509.jaxb.SMIMECapability;
import org.xipki.ca.certprofile.x509.jaxb.SubjectAltName;
import org.xipki.ca.certprofile.x509.jaxb.SubjectDirectoryAttributs;
import org.xipki.ca.certprofile.x509.jaxb.SubjectInfoAccess;
import org.xipki.ca.certprofile.x509.jaxb.SubjectInfoAccess.Access;
import org.xipki.ca.certprofile.x509.jaxb.SubjectToSubjectAltNameType;
import org.xipki.ca.certprofile.x509.jaxb.SubjectToSubjectAltNameType.Target;
import org.xipki.ca.certprofile.x509.jaxb.SubjectToSubjectAltNamesType;
import org.xipki.ca.certprofile.x509.jaxb.TlsFeature;
import org.xipki.ca.certprofile.x509.jaxb.ValidityModel;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType.KeyAlgorithms;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType.Parameters;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType.Subject;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XmlX509Certprofile extends BaseX509Certprofile {

    private static final Logger LOG = LoggerFactory.getLogger(XmlX509Certprofile.class);

    private ExtensionValue additionalInformation;

    private AdmissionSyntaxOption admission;

    private AuthorityInfoAccessControl aiaControl;

    private Map<ASN1ObjectIdentifier, GeneralNameTag> subjectToSubjectAltNameModes;

    private Set<GeneralNameMode> subjectAltNameModes;

    private Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> subjectInfoAccessModes;

    private ExtensionValue authorizationTemplate;

    private BiometricInfoOption biometricInfo;

    private X509CertLevel certLevel;

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

    private ExtensionValue smimeCapabilities;

    private SpecialX509CertprofileBehavior specialBehavior;

    private SubjectControl subjectControl;

    private ExtensionValue tlsFeature;

    private CertValidity validity;

    private X509CertVersion version;

    private ExtensionValue validityModel;

    private SubjectDirectoryAttributesControl subjectDirAttrsControl;

    private void reset() {
        additionalInformation = null;
        admission = null;
        aiaControl = null;
        subjectToSubjectAltNameModes = null;
        subjectAltNameModes = null;
        subjectInfoAccessModes = null;
        authorizationTemplate = null;
        biometricInfo = null;
        certLevel = null;
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
        smimeCapabilities = null;
        specialBehavior = null;
        subjectControl = null;
        tlsFeature = null;
        validity = null;
        validityModel = null;
        version = null;
        subjectDirAttrsControl = null;
    } // method reset

    @Override
    public void initialize(final String data) throws CertprofileException {
        ParamUtil.requireNonBlank("data", data);

        reset();
        try {
            byte[] bytes;
            try {
                bytes = data.getBytes("UTF-8");
            } catch (UnsupportedEncodingException ex) {
                bytes = data.getBytes();
            }

            X509ProfileType conf = XmlX509CertprofileUtil.parse(new ByteArrayInputStream(bytes));
            initialize0(conf);
        } catch (RuntimeException ex) {
            LogUtil.error(LOG, ex);
            throw new CertprofileException(
                    "caught RuntimeException while initializing certprofile: " + ex.getMessage());
        }
    } // method initialize

    public void initialize(X509ProfileType conf) throws CertprofileException {
        ParamUtil.requireNonNull("conf", conf);

        reset();
        try {
            initialize0(conf);
        } catch (RuntimeException ex) {
            LogUtil.error(LOG, ex);
            throw new CertprofileException(
                    "caught RuntimeException while initializing certprofile: " + ex.getMessage());
        }
    } // method initialize

    private void initialize0(X509ProfileType conf) throws CertprofileException {
        if (conf.getVersion() != null) {
            String versionText = conf.getVersion();
            this.version = X509CertVersion.forName(versionText);
            if (this.version == null) {
                throw new CertprofileException(String.format("invalid version '%s'", versionText));
            }
        } else {
            this.version = X509CertVersion.v3;
        }

        if (conf.getSignatureAlgorithms() != null) {
            List<String> algoNames = conf.getSignatureAlgorithms().getAlgorithm();
            List<String> list = new ArrayList<>(algoNames.size());
            for (String algoName : algoNames) {
                try {
                    list.add(AlgorithmUtil.canonicalizeSignatureAlgo(algoName));
                } catch (NoSuchAlgorithmException ex) {
                    throw new CertprofileException(ex.getMessage(), ex);
                }
            }

            this.signatureAlgorithms = Collections.unmodifiableList(list);
        }

        this.raOnly = conf.isRaOnly();
        this.maxSize = conf.getMaxSize();

        this.validity = CertValidity.getInstance(conf.getValidity());
        String str = conf.getCertLevel();
        if ("RootCA".equalsIgnoreCase(str)) {
            this.certLevel = X509CertLevel.RootCA;
        } else if ("SubCA".equalsIgnoreCase(str)) {
            this.certLevel = X509CertLevel.SubCA;
        } else if ("EndEntity".equalsIgnoreCase(str)) {
            this.certLevel = X509CertLevel.EndEntity;
        } else {
            throw new CertprofileException("invalid CertLevel '" + str + "'");
        }

        str = conf.getNotBeforeTime();
        if ("midnight".equalsIgnoreCase(str)) {
            this.notBeforeMidnight = true;
        } else if ("current".equalsIgnoreCase(str)) {
            this.notBeforeMidnight = false;
        } else {
            throw new CertprofileException("invalid notBefore '" + str + "'");
        }

        String specBehavior = conf.getSpecialBehavior();
        if (specBehavior != null) {
            this.specialBehavior = SpecialX509CertprofileBehavior.forName(specBehavior);
        }

        this.duplicateKeyPermitted = conf.isDuplicateKey();
        this.serialNumberInReqPermitted = conf.isSerialNumberInReq();

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
        duplicateSubjectPermitted = subject.isDuplicateSubjectPermitted();

        List<RdnControl> subjectDnControls = new LinkedList<>();

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

            Range range = (rdn.getMinLen() != null || rdn.getMaxLen() != null)
                    ? new Range(rdn.getMinLen(), rdn.getMaxLen()) :  null;

            RdnControl rdnControl = new RdnControl(type, rdn.getMinOccurs(), rdn.getMaxOccurs());
            subjectDnControls.add(rdnControl);

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
        this.subjectControl = new SubjectControl(subjectDnControls, subject.isKeepRdnOrder());
        this.incSerialNoIfSubjectExists = subject.isIncSerialNumber();

        // Extensions
        ExtensionsType extensionsType = conf.getExtensions();

        // SubjectToSubjectAltName
        initSubjectToSubjectAltNames(extensionsType);

        // Extension controls
        this.extensionControls = XmlX509CertprofileUtil.buildExtensionControls(extensionsType);

        // AdditionalInformation
        initAdditionalInformation(extensionsType);

        // Admission
        initAdmission(extensionsType);

        // AuthorityInfoAccess
        initAuthorityInfoAccess(extensionsType);

        // AuthorityKeyIdentifier
        initAuthorityKeyIdentifier(extensionsType);

        // AuthorizationTemplate
        initAuthorizationTemplate(extensionsType);

        // BasicConstrains
        initBasicConstraints(extensionsType);

        // BiometricInfo
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

        // Restriction
        initRestriction(extensionsType);

        // SMIMECapatibilities
        initSmimeCapabilities(extensionsType);

        // SubjectAltNameMode
        initSubjectAlternativeName(extensionsType);

        // SubjectInfoAccess
        initSubjectInfoAccess(extensionsType);

        // TlsFeature
        initTlsFeature(extensionsType);

        // validityModel
        initValidityModel(extensionsType);

        // SubjectDirectoryAttributes
        initSubjectDirAttrs(extensionsType);

        // constant extensions
        this.constantExtensions = XmlX509CertprofileUtil.buildConstantExtesions(extensionsType);

        // validate the configuration
        if (subjectToSubjectAltNameModes != null) {
            if (!extensionControls.containsKey(Extension.subjectAlternativeName)) {
                throw new CertprofileException(
                        "subjectToSubjectAltNames cannot be configured if extension subjectAltNames"
                        + " is not permitted");
            }

            if (subjectAltNameModes != null) {
                for (ASN1ObjectIdentifier attrType : subjectToSubjectAltNameModes.keySet()) {
                    GeneralNameTag nameTag = subjectToSubjectAltNameModes.get(attrType);
                    boolean allowed = false;
                    for (GeneralNameMode m : subjectAltNameModes) {
                        if (m.tag() == nameTag) {
                            allowed = true;
                            break;
                        }
                    }

                    if (!allowed) {
                        throw new CertprofileException("target SubjectAltName type " + nameTag
                                + " is not allowed");
                    }
                }
            }
        }
    } // method initialize0

    private void initSubjectToSubjectAltNames(ExtensionsType extensionsType)
            throws CertprofileException {
        SubjectToSubjectAltNamesType s2sType = extensionsType.getSubjectToSubjectAltNames();
        if (s2sType == null) {
            return;
        }

        subjectToSubjectAltNameModes = new HashMap<>();
        for (SubjectToSubjectAltNameType m : s2sType.getSubjectToSubjectAltName()) {
            Target target = m.getTarget();
            GeneralNameTag nameTag = null;

            if (target.getDirectoryName() != null) {
                nameTag = GeneralNameTag.directoryName;
            } else if (target.getDnsName() != null) {
                nameTag = GeneralNameTag.dNSName;
            } else if (target.getIpAddress() != null) {
                nameTag = GeneralNameTag.iPAddress;
            } else if (target.getRfc822Name() != null) {
                nameTag = GeneralNameTag.rfc822Name;
            } else if (target.getUniformResourceIdentifier() != null) {
                nameTag = GeneralNameTag.uniformResourceIdentifier;
            } else if (target.getRegisteredID() != null) {
                nameTag = GeneralNameTag.registeredID;
            } else {
                throw new RuntimeException(
                        "should not reach here, unknown SubjectToSubjectAltName target");
            }

            subjectToSubjectAltNameModes.put(new ASN1ObjectIdentifier(m.getSource().getValue()),
                    nameTag);
        }
    }

    private void initAdditionalInformation(ExtensionsType extensionsType)
            throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_additionalInformation;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        AdditionalInformation extConf = (AdditionalInformation) getExtensionValue(type,
                extensionsType, AdditionalInformation.class);
        if (extConf == null) {
            return;
        }

        DirectoryStringType stringType = XmlX509CertprofileUtil.convertDirectoryStringType(
                extConf.getType());
        ASN1Encodable extValue = stringType.createDirectoryString(extConf.getText());
        additionalInformation =
                new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
    }

    private void initAdmission(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_admission;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        AdmissionSyntax extConf = (AdmissionSyntax) getExtensionValue(type, extensionsType,
                AdmissionSyntax.class);
        if (extConf == null) {
            return;
        }

        this.admission = XmlX509CertprofileUtil.buildAdmissionSyntax(
                extensionControls.get(type).isCritical(), extConf);
    }

    private void initAuthorityInfoAccess(ExtensionsType extensionsType)
            throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.authorityInfoAccess;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        AuthorityInfoAccess extConf = (AuthorityInfoAccess) getExtensionValue(type, extensionsType,
                AuthorityInfoAccess.class);
        if (extConf == null) {
            return;
        }

        this.aiaControl = new AuthorityInfoAccessControl(extConf.isIncludeCaIssuers(),
                extConf.isIncludeOcsp());
    }

    private void initAuthorityKeyIdentifier(ExtensionsType extensionsType)
            throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.authorityKeyIdentifier;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        AuthorityKeyIdentifier extConf = (AuthorityKeyIdentifier) getExtensionValue(type,
                extensionsType, AuthorityKeyIdentifier.class);
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

        AuthorizationTemplate extConf = (AuthorizationTemplate) getExtensionValue(type,
                extensionsType, AuthorizationTemplate.class);
        if (extConf == null) {
            return;
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1ObjectIdentifier(extConf.getType().getValue()));
        vec.add(new DEROctetString(extConf.getAccessRights().getValue()));
        ASN1Encodable extValue = new DERSequence(vec);
        authorizationTemplate = new ExtensionValue(extensionControls.get(type).isCritical(),
                extValue);
    }

    private void initBasicConstraints(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.basicConstraints;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        BasicConstraints extConf = (BasicConstraints) getExtensionValue(type, extensionsType,
                BasicConstraints.class);
        if (extConf == null) {
            return;
        }
        this.pathLen = extConf.getPathLen();
    }

    private void initBiometricInfo(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.biometricInfo;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        BiometricInfo extConf = (BiometricInfo) getExtensionValue(type, extensionsType,
                BiometricInfo.class);
        if (extConf == null) {
            return;
        }

        try {
            this.biometricInfo = new BiometricInfoOption(extConf);
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

        CertificatePolicies extConf = (CertificatePolicies) getExtensionValue(type, extensionsType,
                CertificatePolicies.class);
        if (extConf == null) {
            return;
        }

        List<CertificatePolicyInformation> policyInfos =
                XmlX509CertprofileUtil.buildCertificatePolicies(extConf);
        org.bouncycastle.asn1.x509.CertificatePolicies value =
                XmlX509CertprofileUtil.createCertificatePolicies(policyInfos);
        this.certificatePolicies = new ExtensionValue(extensionControls.get(type).isCritical(),
                value);
    }

    private void initExtendedKeyUsage(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.extendedKeyUsage;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        ExtendedKeyUsage extConf = (ExtendedKeyUsage) getExtensionValue(type, extensionsType,
                ExtendedKeyUsage.class);
        if (extConf == null) {
            return;
        }

        this.extendedKeyusages = XmlX509CertprofileUtil.buildExtKeyUsageOptions(extConf);
    }

    private void initInhibitAnyPolicy(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.inhibitAnyPolicy;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        InhibitAnyPolicy extConf = (InhibitAnyPolicy) getExtensionValue(type, extensionsType,
                InhibitAnyPolicy.class);
        if (extConf == null) {
            return;
        }

        int skipCerts = extConf.getSkipCerts();
        if (skipCerts < 0) {
            throw new CertprofileException(
                    "negative inhibitAnyPolicy.skipCerts is not allowed: " + skipCerts);
        }
        ASN1Integer value = new ASN1Integer(BigInteger.valueOf(skipCerts));
        this.inhibitAnyPolicy = new ExtensionValue(extensionControls.get(type).isCritical(), value);
    }

    private void initKeyUsage(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.keyUsage;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        KeyUsage extConf = (KeyUsage) getExtensionValue(type, extensionsType, KeyUsage.class);
        if (extConf == null) {
            return;
        }

        this.keyusages = XmlX509CertprofileUtil.buildKeyUsageOptions(extConf);
    }

    private void initNameConstraints(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.nameConstraints;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        NameConstraints extConf = (NameConstraints) getExtensionValue(type, extensionsType,
                NameConstraints.class);
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

        PrivateKeyUsagePeriod extConf = (PrivateKeyUsagePeriod) getExtensionValue(type,
                extensionsType, PrivateKeyUsagePeriod.class);
        if (extConf == null) {
            return;
        }
        privateKeyUsagePeriod = CertValidity.getInstance(extConf.getValidity());
    }

    private void initPolicyConstraints(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.policyConstraints;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        PolicyConstraints extConf = (PolicyConstraints) getExtensionValue(type, extensionsType,
                PolicyConstraints.class);
        if (extConf == null) {
            return;
        }

        ASN1Sequence value = XmlX509CertprofileUtil.buildPolicyConstrains(extConf);
        this.policyConstraints = new ExtensionValue(extensionControls.get(type).isCritical(),
                value);
    }

    private void initPolicyMappings(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.policyMappings;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        PolicyMappings extConf = (PolicyMappings) getExtensionValue(type, extensionsType,
                PolicyMappings.class);
        if (extConf == null) {
            return;
        }

        org.bouncycastle.asn1.x509.PolicyMappings value =
                XmlX509CertprofileUtil.buildPolicyMappings(extConf);
        this.policyMappings = new ExtensionValue(extensionControls.get(type).isCritical(), value);
    }

    private void initQcStatements(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.qCStatements;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        QcStatements extConf = (QcStatements) getExtensionValue(type, extensionsType,
                QcStatements.class);

        if (extConf == null) {
            return;
        }

        List<QcStatementType> qcStatementTypes = extConf.getQcStatement();

        this.qcStatementsOption = new ArrayList<>(qcStatementTypes.size());
        Set<String> currencyCodes = new HashSet<>();
        boolean requireInfoFromReq = false;

        for (QcStatementType m : qcStatementTypes) {
            ASN1ObjectIdentifier qcStatementId = new ASN1ObjectIdentifier(
                    m.getStatementId().getValue());
            QcStatementOption qcStatementOption;

            QcStatementValueType statementValue = m.getStatementValue();
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
                            "can not parse the constant value of QcStatement");
                }
                QCStatement qcStatment = new QCStatement(qcStatementId, constantStatementValue);
                qcStatementOption = new QcStatementOption(qcStatment);
            } else if (statementValue.getQcEuLimitValue() != null) {
                QcEuLimitValueType euLimitType = statementValue.getQcEuLimitValue();
                String tmpCurrency = euLimitType.getCurrency().toUpperCase();
                if (currencyCodes.contains(tmpCurrency)) {
                    throw new CertprofileException(
                            "Duplicated definition of qcStatments with QCEuLimitValue for "
                            + "the currency " + tmpCurrency);
                }

                Iso4217CurrencyCode currency = StringUtil.isNumber(tmpCurrency)
                        ? new Iso4217CurrencyCode(Integer.parseInt(tmpCurrency))
                        : new Iso4217CurrencyCode(tmpCurrency);

                Range2Type r1 = euLimitType.getAmount();
                Range2Type r2 = euLimitType.getExponent();
                if (r1.getMin() == r1.getMax() && r2.getMin() == r2.getMax()) {
                    MonetaryValue monetaryValue = new MonetaryValue(currency, r1.getMin(),
                            r2.getMin());
                    QCStatement qcStatement = new QCStatement(qcStatementId, monetaryValue);
                    qcStatementOption = new QcStatementOption(qcStatement);
                } else {
                    MonetaryValueOption monetaryValueOption = new MonetaryValueOption(currency, r1,
                            r2);
                    qcStatementOption = new QcStatementOption(qcStatementId, monetaryValueOption);
                    requireInfoFromReq = true;
                }
                currencyCodes.add(tmpCurrency);
            } else if (statementValue.getPdsLocations() != null) {
                ASN1EncodableVector vec = new ASN1EncodableVector();
                for (PdsLocationType pl : statementValue.getPdsLocations().getPdsLocation()) {
                    ASN1EncodableVector vec2 = new ASN1EncodableVector();
                    vec2.add(new DERIA5String(pl.getUrl()));
                    String lang = pl.getLanguage();
                    if (lang.length() != 2) {
                        throw new RuntimeException("invalid language '" + lang + "'");
                    }
                    vec2.add(new DERPrintableString(lang));
                    DERSequence seq = new DERSequence(vec2);
                    vec.add(seq);
                }
                QCStatement qcStatement = new QCStatement(qcStatementId, new DERSequence(vec));
                qcStatementOption = new QcStatementOption(qcStatement);
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
            if (m.statement() == null) {
                throw new RuntimeException("should not reach here");
            }
            vec.add(m.statement());
        }
        ASN1Sequence seq = new DERSequence(vec);
        qcStatments = new ExtensionValue(extensionControls.get(type).isCritical(), seq);
        qcStatementsOption = null;
    }

    private void initRestriction(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_restriction;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        Restriction extConf = (Restriction) getExtensionValue(type, extensionsType,
                Restriction.class);
        if (extConf == null) {
            return;
        }

        DirectoryStringType stringType =
                XmlX509CertprofileUtil.convertDirectoryStringType(extConf.getType());
        ASN1Encodable extValue = stringType.createDirectoryString(extConf.getText());
        restriction = new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
    }

    private void initSmimeCapabilities(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_smimeCapabilities;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        SMIMECapabilities extConf = (SMIMECapabilities) getExtensionValue(type, extensionsType,
                SMIMECapabilities.class);
        if (extConf == null) {
            return;
        }

        List<SMIMECapability> list = extConf.getSMIMECapability();

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (SMIMECapability m : list) {
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(m.getCapabilityID().getValue());
            ASN1Encodable params = null;
            org.xipki.ca.certprofile.x509.jaxb.SMIMECapability.Parameters capParams =
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
        smimeCapabilities = new ExtensionValue(extensionControls.get(type).isCritical(),
                extValue);
    }

    private void initSubjectAlternativeName(ExtensionsType extensionsType)
            throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.subjectAlternativeName;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        SubjectAltName extConf = (SubjectAltName) getExtensionValue(type, extensionsType,
                SubjectAltName.class);
        if (extConf == null) {
            return;
        }

        this.subjectAltNameModes = XmlX509CertprofileUtil.buildGeneralNameMode(extConf);
    }

    private void initSubjectInfoAccess(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.subjectInfoAccess;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        SubjectInfoAccess extConf = (SubjectInfoAccess) getExtensionValue(type, extensionsType,
                SubjectInfoAccess.class);
        if (extConf == null) {
            return;
        }

        List<Access> list = extConf.getAccess();
        this.subjectInfoAccessModes = new HashMap<>();
        for (Access entry : list) {
            this.subjectInfoAccessModes.put(
                    new ASN1ObjectIdentifier(entry.getAccessMethod().getValue()),
                    XmlX509CertprofileUtil.buildGeneralNameMode(entry.getAccessLocation()));
        }
    }

    private void initTlsFeature(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_pe_tlsfeature;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        TlsFeature extConf = (TlsFeature) getExtensionValue(type, extensionsType, TlsFeature.class);

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

    private void initValidityModel(ExtensionsType extensionsType) throws CertprofileException {
        ASN1ObjectIdentifier type = ObjectIdentifiers.id_extension_validityModel;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        ValidityModel extConf = (ValidityModel) getExtensionValue(
                type, extensionsType, ValidityModel.class);
        if (extConf == null) {
            return;
        }

        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(extConf.getModelId().getValue());
        ASN1Encodable extValue = new DERSequence(oid);
        validityModel = new ExtensionValue(extensionControls.get(type).isCritical(), extValue);
    }

    private void initSubjectDirAttrs(ExtensionsType extensionsType)
            throws CertprofileException {
        ASN1ObjectIdentifier type = Extension.subjectDirectoryAttributes;
        if (!extensionControls.containsKey(type)) {
            return;
        }

        SubjectDirectoryAttributs extConf = (SubjectDirectoryAttributs) getExtensionValue(
                type, extensionsType, SubjectDirectoryAttributs.class);
        if (extConf == null) {
            return;
        }

        List<ASN1ObjectIdentifier> types = XmlX509CertprofileUtil.toOidList(extConf.getType());
        subjectDirAttrsControl = new SubjectDirectoryAttributesControl(types);
    }

    @Override
    public CertValidity validity() {
        return validity;
    }

    @Override
    public String parameter(final String paramName) {
        return (parameters == null) ? null : parameters.get(paramName);
    }

    @Override
    public ExtensionValues getExtensions(
            final Map<ASN1ObjectIdentifier, ExtensionControl> extensionOccurences,
            final X500Name requestedSubject, final X500Name grantedSubject,
            final Extensions requestedExtensions, final Date notBefore, final Date notAfter)
            throws CertprofileException, BadCertTemplateException {
        ExtensionValues values = new ExtensionValues();
        if (CollectionUtil.isEmpty(extensionOccurences)) {
            return values;
        }

        ParamUtil.requireNonNull("requestedSubject", requestedSubject);
        ParamUtil.requireNonNull("notBefore", notBefore);
        ParamUtil.requireNonNull("notAfter", notAfter);

        Set<ASN1ObjectIdentifier> occurences = new HashSet<>(extensionOccurences.keySet());

        // AuthorityKeyIdentifier
        // processed by the CA

        // SubjectKeyIdentifier
        // processed by the CA

        // KeyUsage
        // processed by the CA

        // CertificatePolicies
        ASN1ObjectIdentifier type = Extension.certificatePolicies;
        if (certificatePolicies != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, certificatePolicies);
            }
        }

        // Policy Mappings
        type = Extension.policyMappings;
        if (policyMappings != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, policyMappings);
            }
        }

        // SubjectAltName
        type = Extension.subjectAlternativeName;
        if (occurences.contains(type)) {
            GeneralNames genNames = createRequestedSubjectAltNames(requestedSubject, grantedSubject,
                    requestedExtensions);
            if (genNames != null) {
                ExtensionValue value = new ExtensionValue(extensionControls.get(type).isCritical(),
                        genNames);
                values.addExtension(type, value);
                occurences.remove(type);
            }
        }

        // IssuerAltName
        // processed by the CA

        // Subject Directory Attributes
        type = Extension.subjectDirectoryAttributes;
        if (occurences.contains(type) && subjectDirAttrsControl != null) {
            Extension extension = (requestedExtensions == null) ? null
                    : requestedExtensions.getExtension(type);
            if (extension == null) {
                throw new BadCertTemplateException(
                        "no SubjectDirecotryAttributes extension is contained in the request");
            }

            ASN1GeneralizedTime dateOfBirth = null;
            String placeOfBirth = null;
            String gender = null;
            List<String> countryOfCitizenshipList = new LinkedList<>();
            List<String> countryOfResidenceList = new LinkedList<>();
            Map<ASN1ObjectIdentifier, List<ASN1Encodable>> otherAttrs = new HashMap<>();

            Vector<?> reqSubDirAttrs = SubjectDirectoryAttributes.getInstance(
                    extension.getParsedValue()).getAttributes();
            final int n = reqSubDirAttrs.size();
            for (int i = 0; i < n; i++) {
                Attribute attr = (Attribute) reqSubDirAttrs.get(i);
                ASN1ObjectIdentifier attrType = attr.getAttrType();
                ASN1Encodable attrVal = attr.getAttributeValues()[0];

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
                    List<ASN1Encodable> otherAttrVals = otherAttrs.get(attrType);
                    if (otherAttrVals == null) {
                        otherAttrVals = new LinkedList<>();
                        otherAttrs.put(attrType, otherAttrVals);
                    }
                    otherAttrVals.add(attrVal);
                }
            }

            Vector<Attribute> attrs = new Vector<>();
            for (ASN1ObjectIdentifier attrType : subjectDirAttrsControl.types()) {
                if (ObjectIdentifiers.DN_DATE_OF_BIRTH.equals(attrType) ) {
                    if (dateOfBirth != null) {
                        String timeStirng = dateOfBirth.getTimeString();
                        if (!SubjectDnSpec.PATTERN_DATE_OF_BIRTH.matcher(timeStirng).matches()) {
                            throw new BadCertTemplateException("invalid dateOfBirth " + timeStirng);
                        }
                        attrs.add(new Attribute(attrType, new DERSet(dateOfBirth)));
                        continue;
                    }
                } else if (ObjectIdentifiers.DN_PLACE_OF_BIRTH.equals(attrType)) {
                    if (placeOfBirth != null) {
                        ASN1Encodable attrVal = new DERUTF8String(placeOfBirth);
                        attrs.add(new Attribute(attrType, new DERSet(attrVal)));
                        continue;
                    }
                } else if (ObjectIdentifiers.DN_GENDER.equals(attrType)) {
                    if (gender != null && !gender.isEmpty()) {
                        char ch = gender.charAt(0);
                        if (!(gender.length() == 1
                                && (ch == 'f' || ch == 'F' || ch == 'm' || ch == 'M'))) {
                            throw new BadCertTemplateException("invalid gender " + gender);
                        }
                        ASN1Encodable attrVal = new DERPrintableString(gender);
                        attrs.add(new Attribute(attrType, new DERSet(attrVal)));
                        continue;
                    }
                } else if (ObjectIdentifiers.DN_COUNTRY_OF_CITIZENSHIP.equals(attrType)) {
                    if (!countryOfCitizenshipList.isEmpty()) {
                        for (String country : countryOfCitizenshipList) {
                            if (!SubjectDnSpec.isValidCountryAreaCode(country)) {
                                throw new BadCertTemplateException(
                                        "invalid countryOfCitizenship code " + country);
                            }
                            ASN1Encodable attrVal = new DERPrintableString(country);
                            attrs.add(new Attribute(attrType, new DERSet(attrVal)));
                        }
                        continue;
                    }
                } else if (ObjectIdentifiers.DN_COUNTRY_OF_RESIDENCE.equals(attrType)) {
                    if (!countryOfResidenceList.isEmpty()) {
                        for (String country : countryOfResidenceList) {
                            if (!SubjectDnSpec.isValidCountryAreaCode(country)) {
                                throw new BadCertTemplateException(
                                        "invalid countryOfResidence code " + country);
                            }
                            ASN1Encodable attrVal = new DERPrintableString(country);
                            attrs.add(new Attribute(attrType, new DERSet(attrVal)));
                        }
                        continue;
                    }
                } else if (otherAttrs.containsKey(attrType)) {
                    for (ASN1Encodable attrVal : otherAttrs.get(attrType)) {
                        attrs.add(new Attribute(attrType, new DERSet(attrVal)));
                    }

                    continue;
                }

                throw new BadCertTemplateException("could not process type " + attrType.getId()
                        + " in extension SubjectDirectoryAttributes");
            }

            SubjectDirectoryAttributes subjDirAttrs = new SubjectDirectoryAttributes(attrs);
            ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(),
                    subjDirAttrs);
            values.addExtension(type, extValue);
            occurences.remove(type);
        }

        // Basic Constraints
        // processed by the CA

        // Name Constraints
        type = Extension.nameConstraints;
        if (nameConstraints != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, nameConstraints);
            }
        }

        // PolicyConstrains
        type = Extension.policyConstraints;
        if (policyConstraints != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, policyConstraints);
            }
        }

        // ExtendedKeyUsage
        // processed by CA

        // CRL Distribution Points
        // processed by the CA

        // Inhibit anyPolicy
        type = Extension.inhibitAnyPolicy;
        if (inhibitAnyPolicy != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, inhibitAnyPolicy);
            }
        }

        // Freshest CRL
        // processed by the CA

        // Authority Information Access
        // processed by the CA

        // Subject Information Access
        // processed by the CA

        // Admission
        type = ObjectIdentifiers.id_extension_admission;
        if (occurences.contains(type) && admission != null) {
            if (admission.isInputFromRequestRequired()) {
                Extension extension = (requestedExtensions == null) ? null
                        : requestedExtensions.getExtension(type);
                if (extension == null) {
                    throw new BadCertTemplateException(
                            "No Admission extension is contained in the request");
                }

                Admissions[] reqAdmissions =
                        org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax.getInstance(
                                extension.getParsedValue()).getContentsOfAdmissions();

                final int n = reqAdmissions.length;
                List<List<String>> reqRegNumsList = new ArrayList<>(n);
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
                values.addExtension(type, admission.extensionValue(reqRegNumsList));
                occurences.remove(type);
            } else {
                values.addExtension(type, admission.extensionValue(null));
                occurences.remove(type);
            }
        }

        // OCSP Nocheck
        // processed by the CA

        // restriction
        type = ObjectIdentifiers.id_extension_restriction;
        if (restriction != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, restriction);
            }
        }

        // AdditionalInformation
        type = ObjectIdentifiers.id_extension_additionalInformation;
        if (additionalInformation != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, additionalInformation);
            }
        }

        // ValidityModel
        type = ObjectIdentifiers.id_extension_validityModel;
        if (validityModel != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, validityModel);
            }
        }

        // PrivateKeyUsagePeriod
        type = Extension.privateKeyUsagePeriod;
        if (occurences.contains(type)) {
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
            occurences.remove(type);
        }

        // QCStatements
        type = Extension.qCStatements;
        if (occurences.contains(type) && (qcStatments != null || qcStatementsOption != null)) {
            if (qcStatments != null) {
                values.addExtension(type, qcStatments);
                occurences.remove(type);
            } else if (requestedExtensions != null && qcStatementsOption != null) {
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

                    MonetaryValue monetaryValue = MonetaryValue.getInstance(
                            stmt.getStatementInfo());
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
                    if (m.statement() != null) {
                        vec.add(m.statement());
                        continue;
                    }

                    MonetaryValueOption monetaryOption = m.monetaryValueOption();
                    String currencyS = monetaryOption.currencyString();
                    int[] limit = qcEuLimits.get(currencyS);
                    if (limit == null) {
                        throw new BadCertTemplateException(
                                "no EuLimitValue is specified for currency '" + currencyS + "'");
                    }

                    int amount = limit[0];
                    Range2Type range = monetaryOption.amountRange();
                    if (amount < range.getMin() || amount > range.getMax()) {
                        throw new BadCertTemplateException("amount for currency '" + currencyS
                                + "' is not within [" + range.getMin() + ", " + range.getMax()
                                + "]");
                    }

                    int exponent = limit[1];
                    range = monetaryOption.exponentRange();
                    if (exponent < range.getMin() || exponent > range.getMax()) {
                        throw new BadCertTemplateException("exponent for currency '" + currencyS
                                + "' is not within [" + range.getMin() + ", " + range.getMax()
                                + "]");
                    }

                    MonetaryValue monetaryVale = new MonetaryValue(
                            monetaryOption.currency(), amount, exponent);
                    QCStatement qcStatment = new QCStatement(m.statementId(), monetaryVale);
                    vec.add(qcStatment);
                }

                ExtensionValue extValue = new ExtensionValue(
                        extensionControls.get(type).isCritical(),
                        new DERSequence(vec));
                values.addExtension(type, extValue);
                occurences.remove(type);
            } else {
                throw new RuntimeException("should not reach here");
            }
        }

        // BiometricData
        type = Extension.biometricInfo;
        if (occurences.contains(type) && biometricInfo != null) {
            Extension extension = (requestedExtensions == null) ? null
                    : requestedExtensions.getExtension(type);
            if (extension == null) {
                throw new BadCertTemplateException(
                        "no biometricInfo extension is contained in the request");
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
                if (!biometricInfo.isTypePermitted(bdType)) {
                    throw new BadCertTemplateException(
                            "biometricInfo[" + i + "].typeOfBiometricData is not permitted");
                }

                ASN1ObjectIdentifier hashAlgo = bd.getHashAlgorithm().getAlgorithm();
                if (!biometricInfo.isHashAlgorithmPermitted(hashAlgo)) {
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
                switch (biometricInfo.sourceDataUriOccurrence()) {
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
                    throw new BadCertTemplateException("could not reach here, unknown tripleState");
                }

                AlgorithmIdentifier newHashAlg =
                        new AlgorithmIdentifier(hashAlgo, DERNull.INSTANCE);
                BiometricData newBiometricData = new BiometricData(bdType, newHashAlg,
                        new DEROctetString(hashValue), sourceDataUri);
                vec.add(newBiometricData);
            }

            ExtensionValue extValue = new ExtensionValue(extensionControls.get(type).isCritical(),
                    new DERSequence(vec));
            values.addExtension(type, extValue);
            occurences.remove(type);
        }

        // TlsFeature
        type = ObjectIdentifiers.id_pe_tlsfeature;
        if (tlsFeature != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, tlsFeature);
            }
        }

        // AuthorizationTemplate
        type = ObjectIdentifiers.id_xipki_ext_authorizationTemplate;
        if (authorizationTemplate != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, authorizationTemplate);
            }
        }

        // SMIME
        type = ObjectIdentifiers.id_smimeCapabilities;
        if (smimeCapabilities != null) {
            if (occurences.remove(type)) {
                values.addExtension(type, smimeCapabilities);
            }
        }

        // constant extensions
        if (constantExtensions != null) {
            for (ASN1ObjectIdentifier m : constantExtensions.keySet()) {
                if (!occurences.remove(m)) {
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

    private GeneralNames createRequestedSubjectAltNames(final X500Name requestedSubject,
            final X500Name grantedSubject, final Extensions requestedExtensions)
            throws BadCertTemplateException {
        ASN1Encodable extValue = (requestedExtensions == null) ? null :
            requestedExtensions.getExtensionParsedValue(Extension.subjectAlternativeName);

        if (extValue == null && subjectToSubjectAltNameModes == null) {
            return null;
        }

        GeneralNames reqNames = (extValue == null) ? null : GeneralNames.getInstance(extValue);
        if (subjectAltNameModes == null && subjectToSubjectAltNameModes == null) {
            return reqNames;
        }

        List<GeneralName> grantedNames = new LinkedList<>();
        // copy the required attributes of Subject
        if (subjectToSubjectAltNameModes != null) {
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
                        grantedNames.add(new GeneralName(tag.tag(), rdnValue));
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
                grantedNames.add(
                        X509CertprofileUtil.createGeneralName(reqL[i], subjectAltNameModes));
            }
        }

        return grantedNames.isEmpty() ? null :
            new GeneralNames(grantedNames.toArray(new GeneralName[0]));
    }

    @Override
    public Set<KeyUsageControl> keyUsage() {
        return keyusages;
    }

    @Override
    public Set<ExtKeyUsageControl> extendedKeyUsages() {
        return extendedKeyusages;
    }

    @Override
    public X509CertLevel certLevel() {
        return certLevel;
    }

    @Override
    public Integer pathLenBasicConstraint() {
        return pathLen;
    }

    @Override
    public AuthorityInfoAccessControl aiaControl() {
        return aiaControl;
    }

    @Override
    public boolean hasMidnightNotBefore() {
        return notBeforeMidnight;
    }

    @Override
    public Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls() {
        return extensionControls;
    }

    @Override
    public boolean isOnlyForRa() {
        return raOnly;
    }

    @Override
    public int maxCertSize() {
        return (maxSize == null) ? super.maxCertSize() : maxSize;
    }

    @Override
    public boolean includeIssuerAndSerialInAki() {
        return includeIssuerAndSerialInAki;
    }

    @Override
    public SubjectControl subjectControl() {
        return subjectControl;
    }

    @Override
    public SpecialX509CertprofileBehavior specialCertprofileBehavior() {
        return specialBehavior;
    }

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
    public Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms() {
        return keyAlgorithms;
    }

    @Override
    public Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> subjectInfoAccessModes() {
        return subjectInfoAccessModes;
    }

    @Override
    public X509CertVersion version() {
        return version;
    }

    @Override
    public List<String> signatureAlgorithms() {
        return signatureAlgorithms;
    }

    @Override
    public boolean incSerialNumberIfSubjectExists() {
        return incSerialNoIfSubjectExists;
    }

    public ExtensionValue additionalInformation() {
        return additionalInformation;
    }

    public AdmissionSyntaxOption admission() {
        return admission;
    }

    public Map<ASN1ObjectIdentifier, GeneralNameTag> subjectToSubjectAltNameModes() {
        return subjectToSubjectAltNameModes;
    }

    public Set<GeneralNameMode> subjectAltNameModes() {
        return subjectAltNameModes;
    }

    public ExtensionValue authorizationTemplate() {
        return authorizationTemplate;
    }

    public BiometricInfoOption biometricInfo() {
        return biometricInfo;
    }

    public ExtensionValue certificatePolicies() {
        return certificatePolicies;
    }

    public Map<ASN1ObjectIdentifier, ExtensionValue> constantExtensions() {
        return constantExtensions;
    }

    public Set<ExtKeyUsageControl> extendedKeyusages() {
        return extendedKeyusages;
    }

    public boolean isIncludeIssuerAndSerialInAki() {
        return includeIssuerAndSerialInAki;
    }

    public boolean isIncSerialNoIfSubjectExists() {
        return incSerialNoIfSubjectExists;
    }

    public ExtensionValue inhibitAnyPolicy() {
        return inhibitAnyPolicy;
    }

    public Set<KeyUsageControl> keyusages() {
        return keyusages;
    }

    public Integer maxSize() {
        return maxSize;
    }

    public ExtensionValue nameConstraints() {
        return nameConstraints;
    }

    public boolean isNotBeforeMidnight() {
        return notBeforeMidnight;
    }

    public Map<String, String> parameters() {
        return parameters;
    }

    public Integer pathLen() {
        return pathLen;
    }

    public ExtensionValue policyConstraints() {
        return policyConstraints;
    }

    public ExtensionValue policyMappings() {
        return policyMappings;
    }

    public CertValidity privateKeyUsagePeriod() {
        return privateKeyUsagePeriod;
    }

    public ExtensionValue qcStatments() {
        return qcStatments;
    }

    public List<QcStatementOption> qcStatementsOption() {
        return qcStatementsOption;
    }

    public boolean isRaOnly() {
        return raOnly;
    }

    public ExtensionValue restriction() {
        return restriction;
    }

    public ExtensionValue smimeCapabilities() {
        return smimeCapabilities;
    }

    public SpecialX509CertprofileBehavior specialBehavior() {
        return specialBehavior;
    }

    public ExtensionValue tlsFeature() {
        return tlsFeature;
    }

    public ExtensionValue validityModel() {
        return validityModel;
    }

    public SubjectDirectoryAttributesControl subjectDirAttrsControl() {
        return subjectDirAttrsControl;
    }

    private static Object getExtensionValue(final ASN1ObjectIdentifier type,
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

    private static ASN1Encodable readAsn1Encodable(final byte[] encoded)
            throws CertprofileException {
        ASN1StreamParser parser = new ASN1StreamParser(encoded);
        try {
            return parser.readObject();
        } catch (IOException ex) {
            throw new CertprofileException("could not parse the constant extension value", ex);
        }
    }

}
