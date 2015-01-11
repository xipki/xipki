/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.server.certprofile.x509;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertProfileException;
import org.xipki.ca.api.CertValidity;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.GeneralNameMode;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.AllowAllParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.DSAParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.ECParamatersOption;
import org.xipki.ca.api.profile.KeyParametersOption.RSAParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.Range;
import org.xipki.ca.api.profile.RDNOccurrence;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.ca.api.profile.x509.BaseX509CertProfile;
import org.xipki.ca.api.profile.x509.CertificatePolicyInformation;
import org.xipki.ca.api.profile.x509.ExtKeyUsageOccurrence;
import org.xipki.ca.api.profile.x509.KeyUsageOccurrence;
import org.xipki.ca.api.profile.x509.SpecialX509CertProfileBehavior;
import org.xipki.ca.api.profile.x509.X509Util;
import org.xipki.ca.server.certprofile.AddText;
import org.xipki.ca.server.certprofile.Condition;
import org.xipki.ca.server.certprofile.ExtensionValueOption;
import org.xipki.ca.server.certprofile.ExtensionValueOptions;
import org.xipki.ca.server.certprofile.SubjectDNOption;
import org.xipki.ca.server.certprofile.x509.jaxb.AlgorithmType;
import org.xipki.ca.server.certprofile.x509.jaxb.ConstantExtensionType;
import org.xipki.ca.server.certprofile.x509.jaxb.ECParametersType;
import org.xipki.ca.server.certprofile.x509.jaxb.ECParametersType.Curves;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionType;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.Admission;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.AuthorityKeyIdentifier;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.ConstantExtensions;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.ExtendedKeyUsage;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.ExtendedKeyUsage.Usage;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.InhibitAnyPolicy;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.PolicyConstraints;
import org.xipki.ca.server.certprofile.x509.jaxb.KeyUsageType;
import org.xipki.ca.server.certprofile.x509.jaxb.NameValueType;
import org.xipki.ca.server.certprofile.x509.jaxb.OidWithDescType;
import org.xipki.ca.server.certprofile.x509.jaxb.RdnType;
import org.xipki.ca.server.certprofile.x509.jaxb.SubjectInfoAccessType.Access;
import org.xipki.ca.server.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.ca.server.certprofile.x509.jaxb.X509ProfileType.KeyAlgorithms;
import org.xipki.ca.server.certprofile.x509.jaxb.X509ProfileType.Parameters;
import org.xipki.ca.server.certprofile.x509.jaxb.X509ProfileType.Subject;
import org.xipki.common.KeyUsage;
import org.xipki.common.LogUtil;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;

/**
 * @author Lijun Liao
 */

public class DefaultX509CertProfile extends BaseX509CertProfile
{
    private static final Logger LOG = LoggerFactory.getLogger(DefaultX509CertProfile.class);

    protected X509ProfileType profileConf;

    private SpecialX509CertProfileBehavior specialBehavior;

    private Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms;

    private Map<ASN1ObjectIdentifier, SubjectDNOption> subjectDNOptions;
    private Set<RDNOccurrence> subjectDNOccurrences;
    private Map<String, String> parameters;
    private Map<ASN1ObjectIdentifier, ExtensionControl> extensionOccurences;

    private CertValidity validity;
    private boolean incSerialNrIfSubjectExists;
    private boolean raOnly;
    private boolean qaOnly;
    private boolean backwardsSubject;
    private boolean ca;
    private boolean prefersECImplicitCA;
    private boolean duplicateKeyPermitted;
    private boolean duplicateSubjectPermitted;
    private boolean serialNumberInReqPermitted;
    private boolean notBeforeMidnight;
    private Integer pathLen;
    private KeyUsageOptions keyusages;
    private ExtKeyUsageOptions extendedKeyusages;
    private Set<GeneralNameMode> allowedSubjectAltNameModes;
    private Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> allowedSubjectInfoAccessModes;

    private AuthorityKeyIdentifierOption akiOption;
    private ExtensionValueOptions certificatePolicies;
    private ExtensionValueOptions policyMappings;
    private ExtensionValueOptions nameConstraints;
    private ExtensionValueOptions policyConstraints;
    private ExtensionValueOptions inhibitAnyPolicy;
    private ExtensionValueOptions admission;

    private Map<ASN1ObjectIdentifier, ExtensionValueOptions> constantExtensions;

    private void reset()
    {
        profileConf = null;
        keyAlgorithms = null;
        subjectDNOptions = null;
        subjectDNOccurrences = null;
        extensionOccurences = null;
        validity = null;
        notBeforeMidnight = false;
        akiOption = null;
        incSerialNrIfSubjectExists = false;
        raOnly = false;
        qaOnly = false;
        backwardsSubject = false;
        ca = false;
        prefersECImplicitCA = false;
        duplicateKeyPermitted = true;
        duplicateSubjectPermitted = true;
        serialNumberInReqPermitted = true;
        pathLen = null;
        keyusages = null;
        extendedKeyusages = null;
        allowedSubjectAltNameModes = null;
        allowedSubjectInfoAccessModes = null;
        certificatePolicies = null;
        nameConstraints = null;
        policyMappings = null;
        inhibitAnyPolicy = null;
        admission = null;
        constantExtensions = null;
    }

    @Override
    public void initialize(String data)
    throws CertProfileException
    {
        ParamChecker.assertNotEmpty("data", data);
        reset();

        try
        {
            X509ProfileType conf = XmlX509CertProfileUtil.parse(data);
            this.profileConf = conf;

            this.raOnly = conf.isRaOnly();
            this.qaOnly = conf.isQaOnly();
            this.validity = CertValidity.getInstance(conf.getValidity());
            this.ca = conf.isCa();
            this.prefersECImplicitCA = getBoolean(conf.isPrefersECImplicitCA(), false);
            this.notBeforeMidnight = "midnight".equalsIgnoreCase(conf.getNotBeforeTime());

            String specialBehavior = conf.getSpecialBehavior();
            if(specialBehavior != null)
            {
                this.specialBehavior = SpecialX509CertProfileBehavior.getInstance(specialBehavior);
            }

            if(conf.isDuplicateKey() != null)
            {
                duplicateKeyPermitted = conf.isDuplicateKey().booleanValue();
            }

            if(conf.isDuplicateSubject() != null)
            {
                duplicateSubjectPermitted = conf.isDuplicateSubject().booleanValue();
            }

            if(conf.isSerialNumberInReq() != null)
            {
                serialNumberInReqPermitted = conf.isSerialNumberInReq().booleanValue();
            }

            // KeyAlgorithms
            KeyAlgorithms keyAlgos = conf.getKeyAlgorithms();
            if(keyAlgos != null)
            {
                this.keyAlgorithms = new HashMap<>();
                for(AlgorithmType type : keyAlgos.getAlgorithm())
                {
                    KeyParametersOption keyParamsOption;

                    if(type.getECParameters() != null)
                    {
                        KeyParametersOption.ECParamatersOption option = new KeyParametersOption.ECParamatersOption();
                        keyParamsOption = option;

                        ECParametersType params = type.getECParameters();
                        if(params.getCurves() != null)
                        {
                            Curves curves = params.getCurves();
                            Set<ASN1ObjectIdentifier> curveOids = XmlX509CertProfileUtil.toOIDSet(curves.getCurve());
                            option.setCurveOids(curveOids);
                        }

                        if(params.getPointEncodings() != null)
                        {
                            List<Byte> bytes = params.getPointEncodings().getPointEncoding();
                            Set<Byte> pointEncodings = new HashSet<>(bytes);
                            option.setPointEncodings(pointEncodings);
                        }
                    } else if(type.getRSAParameters() != null)
                    {
                        KeyParametersOption.RSAParametersOption option = new KeyParametersOption.RSAParametersOption();
                        keyParamsOption = option;

                        Set<Range> modulusLengths = XmlX509CertProfileUtil.buildParametersMap(
                                type.getRSAParameters().getModulusLength());
                        option.setModulusLengths(modulusLengths);

                    } else if(type.getRSAPSSParameters() != null)
                    {
                        KeyParametersOption.RSAPSSParametersOption option = new KeyParametersOption.RSAPSSParametersOption();
                        keyParamsOption = option;

                        Set<Range> modulusLengths = XmlX509CertProfileUtil.buildParametersMap(
                                type.getRSAPSSParameters().getModulusLength());
                        option.setModulusLengths(modulusLengths);
                    } else if(type.getDSAParameters() != null)
                    {
                        KeyParametersOption.DSAParametersOption option = new KeyParametersOption.DSAParametersOption();
                        keyParamsOption = option;

                        Set<Range> pLengths = XmlX509CertProfileUtil.buildParametersMap(type.getDSAParameters().getPLength());
                        option.setPLengths(pLengths);

                        Set<Range> qLengths = XmlX509CertProfileUtil.buildParametersMap(type.getDSAParameters().getQLength());
                        option.setQLengths(qLengths);
                    } else if(type.getDHParameters() != null)
                    {
                        KeyParametersOption.DHParametersOption option = new KeyParametersOption.DHParametersOption();
                        keyParamsOption = option;

                        Set<Range> pLengths = XmlX509CertProfileUtil.buildParametersMap(type.getDHParameters().getPLength());
                        option.setPLengths(pLengths);

                        Set<Range> qLengths = XmlX509CertProfileUtil.buildParametersMap(type.getDHParameters().getQLength());
                        option.setQLengths(qLengths);
                    }
                    else if(type.getGostParameters() != null)
                    {
                        KeyParametersOption.GostParametersOption option = new KeyParametersOption.GostParametersOption();
                        keyParamsOption = option;

                        Set<ASN1ObjectIdentifier> set = XmlX509CertProfileUtil.toOIDSet(
                                type.getGostParameters().getPublicKeyParamSet());
                        option.setPublicKeyParamSets(set);

                        set = XmlX509CertProfileUtil.toOIDSet(type.getGostParameters().getDigestParamSet());
                        option.setDigestParamSets(set);

                        set = XmlX509CertProfileUtil.toOIDSet(type.getGostParameters().getEncryptionParamSet());
                        option.setEncryptionParamSets(set);
                    } else
                    {
                        keyParamsOption = KeyParametersOption.allowAll;
                    }

                    List<OidWithDescType> algIds = type.getAlgorithm();
                    for(OidWithDescType algId : algIds)
                    {
                        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(algId.getValue());
                        if(this.keyAlgorithms.containsKey(oid))
                        {
                            throw new CertProfileException("duplicate definition of keyAlgorithm " + oid.getId());
                        }
                        this.keyAlgorithms.put(oid, keyParamsOption);
                    }
                }
            }

            // parameters
            Parameters confParams = conf.getParameters();
            if(confParams == null)
            {
                parameters = null;
            }
            else
            {
                Map<String, String> tMap = new HashMap<>();
                for(NameValueType nv : confParams.getParameter())
                {
                    tMap.put(nv.getName(), nv.getValue());
                }
                parameters = Collections.unmodifiableMap(tMap);
            }

            // Subject
            Subject subject = conf.getSubject();
            if(subject != null)
            {
                this.backwardsSubject = subject.isDnBackwards();
                this.incSerialNrIfSubjectExists = subject.isIncSerialNrIfSubjectExists();

                this.subjectDNOccurrences = new HashSet<RDNOccurrence>();
                this.subjectDNOptions = new HashMap<>();

                for(RdnType t : subject.getRdn())
                {
                    ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(t.getType().getValue());
                    RDNOccurrence occ = new RDNOccurrence(type,
                            getInt(t.getMinOccurs(), 1), getInt(t.getMaxOccurs(), 1));
                    this.subjectDNOccurrences.add(occ);

                    List<Pattern> patterns = null;
                    if(t.getRegex().isEmpty() == false)
                    {
                        patterns = new LinkedList<>();
                        for(String regex : t.getRegex())
                        {
                            Pattern pattern = Pattern.compile(regex);
                            patterns.add(pattern);
                        }
                    }

                    List<AddText> addprefixes = XmlX509CertProfileUtil.buildAddText(t.getAddPrefix());
                    List<AddText> addsuffixes = XmlX509CertProfileUtil.buildAddText(t.getAddSuffix());
                    SubjectDNOption option = new SubjectDNOption(addprefixes, addsuffixes, patterns,
                            t.getMinLen(), t.getMaxLen());
                    this.subjectDNOptions.put(type, option);
                }
            }

            // Extensions
            ExtensionsType extensionsType = conf.getExtensions();

            this.pathLen = extensionsType.getPathLen();

            // Extension KeyUsage
            List<org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.KeyUsage> keyUsageTypeList =
                    extensionsType.getKeyUsage();
            if(keyUsageTypeList.isEmpty() == false)
            {
                List<KeyUsageOption> optionList = new ArrayList<>(keyUsageTypeList.size());

                for(org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.KeyUsage t : keyUsageTypeList)
                {
                    Set<KeyUsageOccurrence> set = new HashSet<>();
                    for(KeyUsageType type : t.getUsage())
                    {
                        boolean required = type.isRequired();
                        switch(type.getValue())
                        {
                        case C_RL_SIGN:
                            set.add(new KeyUsageOccurrence(KeyUsage.cRLSign, required));
                            break;
                        case DATA_ENCIPHERMENT:
                            set.add(new KeyUsageOccurrence(KeyUsage.dataEncipherment, required));
                            break;
                        case CONTENT_COMMITMENT:
                            set.add(new KeyUsageOccurrence(KeyUsage.contentCommitment, required));
                            break;
                        case DECIPHER_ONLY:
                            set.add(new KeyUsageOccurrence(KeyUsage.decipherOnly, required));
                            break;
                        case ENCIPHER_ONLY:
                            set.add(new KeyUsageOccurrence(KeyUsage.encipherOnly, required));
                            break;
                        case DIGITAL_SIGNATURE:
                            set.add(new KeyUsageOccurrence(KeyUsage.digitalSignature, required));
                            break;
                        case KEY_AGREEMENT:
                            set.add(new KeyUsageOccurrence(KeyUsage.keyAgreement, required));
                            break;
                        case KEY_CERT_SIGN:
                            set.add(new KeyUsageOccurrence(KeyUsage.keyCertSign, required));
                            break;
                        case KEY_ENCIPHERMENT:
                            set.add(new KeyUsageOccurrence(KeyUsage.keyEncipherment, required));
                            break;
                        default:
                            throw new RuntimeException("should not reach here");
                        }
                    }

                    Set<KeyUsageOccurrence> keyusageSet = Collections.unmodifiableSet(set);

                    Condition condition = XmlX509CertProfileUtil.createCondition(t.getCondition());
                    KeyUsageOption option = new KeyUsageOption(condition, keyusageSet);
                    optionList.add(option);
                }

                this.keyusages = new KeyUsageOptions(optionList);
            }

            // ExtendedKeyUsage
            List<ExtendedKeyUsage> extKeyUsageTypeList = extensionsType.getExtendedKeyUsage();
            if(extKeyUsageTypeList.isEmpty() == false)
            {
                List<ExtKeyUsageOption> optionList = new ArrayList<>(extKeyUsageTypeList.size());

                for(org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.ExtendedKeyUsage t : extKeyUsageTypeList)
                {
                    List<Usage> list = t.getUsage();
                    Set<ExtKeyUsageOccurrence> extendedKeyusageSet = new HashSet<>();
                    for(Usage entry : list)
                    {
                        ExtKeyUsageOccurrence usage = new ExtKeyUsageOccurrence(
                                new ASN1ObjectIdentifier(entry.getValue()), entry.isRequired());
                        extendedKeyusageSet.add(usage);
                    }
                    Condition condition = XmlX509CertProfileUtil.createCondition(t.getCondition());
                    ExtKeyUsageOption option = new ExtKeyUsageOption(condition, extendedKeyusageSet);
                    optionList.add(option);
                }

                this.extendedKeyusages = new ExtKeyUsageOptions(optionList);
            }

            // Extension Occurrences
            Map<ASN1ObjectIdentifier, ExtensionControl> occurrences = new HashMap<>();
            for(ExtensionType extensionType : extensionsType.getExtension())
            {
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(extensionType.getValue());
                boolean required = extensionType.isRequired();
                boolean critical = getBoolean(extensionType.isCritical(), false);
                occurrences.put(oid, new ExtensionControl(critical, required, extensionType.isPermittedInRequest()));
            }

            this.extensionOccurences = Collections.unmodifiableMap(occurrences);

            // AuthorityKeyIdentifier
            if(extensionOccurences.containsKey(Extension.authorityKeyIdentifier))
            {
                ExtensionControl extOccurrence = extensionOccurences.get(Extension.authorityKeyIdentifier);
                boolean includeIssuerAndSerial = true;

                AuthorityKeyIdentifier akiType = extensionsType.getAuthorityKeyIdentifier();
                if(akiType != null)
                {
                    Boolean B = akiType.isIncludeIssuerAndSerial();
                    if(B != null)
                    {
                        includeIssuerAndSerial = B.booleanValue();
                    }
                }

                this.akiOption = new AuthorityKeyIdentifierOption(includeIssuerAndSerial, extOccurrence);
            }
            else
            {
                this.akiOption = null;
            }

            // Certificate Policies
            ExtensionControl occurrence = occurrences.get(Extension.certificatePolicies);
            if(occurrence != null && extensionsType.getCertificatePolicies().isEmpty() == false)
            {
                List<ExtensionsType.CertificatePolicies> types = extensionsType.getCertificatePolicies();
                List<ExtensionValueOption> options = new ArrayList<>(types.size());
                for(ExtensionsType.CertificatePolicies type : types)
                {
                    List<CertificatePolicyInformation> policyInfos = XmlX509CertProfileUtil.buildCertificatePolicies(type);
                    CertificatePolicies value = X509Util.createCertificatePolicies(policyInfos);
                    ExtensionValue extension = new ExtensionValue(occurrence.isCritical(), value);
                    ExtensionValueOption option = new ExtensionValueOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.certificatePolicies = new ExtensionValueOptions(options);
            }

            // Policy Mappings
            occurrence = occurrences.get(Extension.policyMappings);
            if(occurrence != null && extensionsType.getPolicyMappings().isEmpty() == false)
            {
                List<ExtensionsType.PolicyMappings> types = extensionsType.getPolicyMappings();
                List<ExtensionValueOption> options = new ArrayList<>(types.size());
                for(ExtensionsType.PolicyMappings type : types)
                {
                    org.bouncycastle.asn1.x509.PolicyMappings value = XmlX509CertProfileUtil.buildPolicyMappings(type);
                    ExtensionValue extension = new ExtensionValue(occurrence.isCritical(), value);
                    ExtensionValueOption option = new ExtensionValueOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.policyMappings = new ExtensionValueOptions(options);
            }

            // Name Constrains
            occurrence = occurrences.get(Extension.nameConstraints);
            if(occurrence != null && extensionsType.getNameConstraints().isEmpty() == false)
            {
                List<ExtensionsType.NameConstraints> types = extensionsType.getNameConstraints();
                List<ExtensionValueOption> options = new ArrayList<>(types.size());
                for(ExtensionsType.NameConstraints type : types)
                {
                    NameConstraints value = XmlX509CertProfileUtil.buildNameConstrains(type);
                    ExtensionValue extension =new ExtensionValue(occurrence.isCritical(), value);
                    ExtensionValueOption option = new ExtensionValueOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.nameConstraints = new ExtensionValueOptions(options);
            }

            // Policy Constraints
            occurrence = occurrences.get(Extension.policyConstraints);
            if(occurrence != null && extensionsType.getPolicyConstraints().isEmpty() == false)
            {
                List<PolicyConstraints> types = extensionsType.getPolicyConstraints();
                List<ExtensionValueOption> options = new ArrayList<>(types.size());
                for(PolicyConstraints type : types)
                {
                    ASN1Sequence value = XmlX509CertProfileUtil.buildPolicyConstrains(type);
                    ExtensionValue extension =new ExtensionValue(occurrence.isCritical(), value);
                    ExtensionValueOption option = new ExtensionValueOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.policyConstraints = new ExtensionValueOptions(options);
            }

            // Inhibit anyPolicy
            occurrence = occurrences.get(Extension.inhibitAnyPolicy);
            if(occurrence != null && extensionsType.getInhibitAnyPolicy().isEmpty() == false)
            {
                List<InhibitAnyPolicy> types = extensionsType.getInhibitAnyPolicy();
                List<ExtensionValueOption> options = new ArrayList<>(types.size());
                for(InhibitAnyPolicy type : types)
                {
                    int skipCerts = type.getSkipCerts();
                    if(skipCerts < 0)
                    {
                        throw new CertProfileException("negative inhibitAnyPolicy.skipCerts is not allowed: " + skipCerts);
                    }
                    ASN1Integer value = new ASN1Integer(BigInteger.valueOf(skipCerts));
                    ExtensionValue extension =new ExtensionValue(occurrence.isCritical(), value);
                    ExtensionValueOption option = new ExtensionValueOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.inhibitAnyPolicy = new ExtensionValueOptions(options);
            }

            // admission
            occurrence = occurrences.get(ObjectIdentifiers.id_extension_admission);
            if(occurrence != null && extensionsType.getAdmission().isEmpty() == false)
            {
                List<Admission> types = extensionsType.getAdmission();
                List<ExtensionValueOption> options = new ArrayList<>(types.size());
                for(Admission type : types)
                {
                    List<ASN1ObjectIdentifier> professionOIDs;
                    List<String> professionItems;

                    List<String> items = type == null ? null : type.getProfessionItem();
                    if(items == null || items.isEmpty())
                    {
                        professionItems = null;
                    }
                    else
                    {
                        professionItems = Collections.unmodifiableList(new LinkedList<>(items));
                    }

                    List<OidWithDescType> oidWithDescs = (type == null) ? null : type.getProfessionOid();
                    professionOIDs = XmlX509CertProfileUtil.toOIDList(oidWithDescs);

                    ExtensionValue extension = createAdmission(occurrence.isCritical(),
                            professionOIDs, professionItems, type.getRegistrationNumber(), type.getAddProfessionInfo());
                    ExtensionValueOption option = new ExtensionValueOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.admission = new ExtensionValueOptions(options);
            }

            // SubjectAltNameMode
            if(extensionsType.getSubjectAltName() != null)
            {
                this.allowedSubjectAltNameModes = XmlX509CertProfileUtil.buildGeneralNameMode(
                        extensionsType.getSubjectAltName());
            }

            // SubjectInfoAccess
            if(extensionsType.getSubjectInfoAccess() != null)
            {
                List<Access> list = extensionsType.getSubjectInfoAccess().getAccess();
                this.allowedSubjectInfoAccessModes = new HashMap<>();
                for(Access entry : list)
                {
                    this.allowedSubjectInfoAccessModes.put(
                            new ASN1ObjectIdentifier(entry.getAccessMethod().getValue()),
                            XmlX509CertProfileUtil.buildGeneralNameMode(entry.getAccessLocation()));
                }
            }

            // constant extensions
            List<ConstantExtensions> cess = extensionsType.getConstantExtensions();
            if(cess != null && cess.isEmpty() == false)
            {
                Map<ASN1ObjectIdentifier, List<ExtensionValueOption>> map = new HashMap<>();
                for(ConstantExtensions ces : cess)
                {
                    for(ConstantExtensionType ce :ces.getConstantExtension())
                    {
                        ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(ce.getType().getValue());
                        occurrence = occurrences.get(type);
                        if(occurrence != null)
                        {
                            ASN1StreamParser parser = new ASN1StreamParser(ce.getValue());
                            ASN1Encodable value;
                            try
                            {
                                value = parser.readObject();
                            } catch (IOException e)
                            {
                                throw new CertProfileException("Could not parse the constant extension value", e);
                            }
                            ExtensionValue extension = new ExtensionValue(occurrence.isCritical(), value);
                            ExtensionValueOption option = new ExtensionValueOption(
                                    XmlX509CertProfileUtil.createCondition(ce.getCondition()), extension);

                            List<ExtensionValueOption> options = map.get(type);
                            if(options == null)
                            {
                                options = new LinkedList<>();
                                map.put(type, options);
                            }
                            options.add(option);
                        }
                    }
                }

                if(map.isEmpty() == false)
                {
                    this.constantExtensions = new HashMap<>(map.size());
                    for(ASN1ObjectIdentifier type : map.keySet())
                    {
                        List<ExtensionValueOption> options = map.get(type);
                        this.constantExtensions.put(type, new ExtensionValueOptions(options));
                    }
                }
            }
        }catch(RuntimeException e)
        {
            final String message = "RuntimeException";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            throw new CertProfileException("RuntimeException thrown while initializing certprofile: " + e.getMessage());
        }
    }

    @Override
    public CertValidity getValidity()
    {
        return validity;
    }

    @Override
    public String getParameter(String paramName)
    {
        return parameters == null ? null : parameters.get(paramName);
    }

    @Override
    public void checkPublicKey(SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException
    {
        if(keyAlgorithms == null || keyAlgorithms.isEmpty())
        {
            return;
        }

        ASN1ObjectIdentifier keyType = publicKey.getAlgorithm().getAlgorithm();
        if(keyAlgorithms.containsKey(keyType) == false)
        {
            throw new BadCertTemplateException("key type " + keyType.getId() + " is not permitted");
        }

        KeyParametersOption keyParamsOption = keyAlgorithms.get(keyType);
        if(keyParamsOption instanceof AllowAllParametersOption)
        {
            return;
        } else if(keyParamsOption instanceof ECParamatersOption)
        {
            ECParamatersOption ecOption = (ECParamatersOption) keyParamsOption;
            // parameters
            ASN1Encodable algParam = publicKey.getAlgorithm().getParameters();
            ASN1ObjectIdentifier curveOid;

            if(algParam instanceof ASN1ObjectIdentifier)
            {
                curveOid = (ASN1ObjectIdentifier) algParam;
                if(ecOption.allowsCurve(curveOid) == false)
                {
                    throw new BadCertTemplateException("EC curve " + SecurityUtil.getCurveName(curveOid) +
                            " (OID: " + curveOid.getId() + ") is not allowed");
                }
            } else
            {
                throw new BadCertTemplateException("Only namedCurve or implictCA EC public key is supported");
            }

            // point encoding
            if(ecOption.getPointEncodings() != null)
            {
                byte[] keyData = publicKey.getPublicKeyData().getBytes();
                if(keyData.length < 1)
                {
                    throw new BadCertTemplateException("invalid publicKeyData");
                }
                byte pointEncoding = keyData[0];
                if(ecOption.getPointEncodings().contains(pointEncoding) == false)
                {
                    throw new BadCertTemplateException("Unaccepted EC point encoding " + pointEncoding);
                }
            }

            try
            {
                XmlX509CertProfileUtil.checkECSubjectPublicKeyInfo(curveOid, publicKey.getPublicKeyData().getBytes());
            }catch(BadCertTemplateException e)
            {
                throw e;
            }catch(Exception e)
            {
                LOG.debug("populateFromPubKeyInfo", e);
                throw new BadCertTemplateException("Invalid public key: " + e.getMessage());
            }

            return;
        } else if(keyParamsOption instanceof RSAParametersOption)
        {
            RSAParametersOption rsaOption = (RSAParametersOption) keyParamsOption;

            ASN1Integer modulus;
            try
            {
                ASN1Sequence seq = ASN1Sequence.getInstance(publicKey.getPublicKeyData().getBytes());
                modulus = ASN1Integer.getInstance(seq.getObjectAt(0));
            }catch(IllegalArgumentException e)
            {
                throw new BadCertTemplateException("invalid publicKeyData");
            }

            int modulusLength = modulus.getPositiveValue().bitLength();
            if((rsaOption.allowsModulusLength(modulusLength)))
            {
                return;
            }
        } else if(keyParamsOption instanceof DSAParametersOption)
        {
            DSAParametersOption dsaOption = (DSAParametersOption) keyParamsOption;
            ASN1Encodable params = publicKey.getAlgorithm().getParameters();
            if(params == null)
            {
                throw new BadCertTemplateException("null Dss-Parms is not permitted");
            }

            int pLength;
            int qLength;

            try
            {
                ASN1Sequence seq = ASN1Sequence.getInstance(params);
                ASN1Integer p = ASN1Integer.getInstance(seq.getObjectAt(0));
                ASN1Integer q = ASN1Integer.getInstance(seq.getObjectAt(1));
                pLength = p.getPositiveValue().bitLength();
                qLength = q.getPositiveValue().bitLength();
            } catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e)
            {
                throw new BadCertTemplateException("illegal Dss-Parms");
            }

            boolean match = dsaOption.allowsPLength(pLength);
            if(match)
            {
                match = dsaOption.allowsQLength(qLength);
            }

            if(match)
            {
                return;
            }
        } else
        {
            throw new RuntimeException("should not reach here");
        }

        throw new BadCertTemplateException("the given publicKey is not permitted");
    }

    @Override
    public SubjectInfo getSubject(X500Name requestedSubject)
    throws CertProfileException, BadCertTemplateException
    {
        verifySubjectDNOccurence(requestedSubject);
        checkSubjectContent(requestedSubject);

        RDN[] requstedRDNs = requestedSubject.getRDNs();
        Set<RDNOccurrence> occurences = getSubjectDNSubset();
        List<RDN> rdns = new LinkedList<>();
        List<ASN1ObjectIdentifier> types = backwardsSubject() ?
                ObjectIdentifiers.getBackwardDNs() : ObjectIdentifiers.getForwardDNs();

        for(ASN1ObjectIdentifier type : types)
        {
            if(Extension.subjectAlternativeName.equals(type) || Extension.subjectInfoAccess.equals(type))
            {
                continue;
            }

            RDNOccurrence occurrence = null;
            if(occurences != null)
            {
                occurrence = getRDNOccurrence(occurences, type);
                if(occurrence == null || occurrence.getMaxOccurs() < 1)
                {
                    continue;
                }
            }

            RDN[] thisRDNs = getRDNs(requstedRDNs, type);
            int n = thisRDNs == null ? 0 : thisRDNs.length;
            if(n == 0)
            {
                continue;
            }

            if(n == 1)
            {
                String value = SecurityUtil.rdnValueToString(thisRDNs[0].getFirst().getValue());
                rdns.add(createSubjectRDN(value, type, 0));
            }
            else
            {
                String[] values = new String[n];
                for(int i = 0; i < n; i++)
                {
                    values[i] = SecurityUtil.rdnValueToString(thisRDNs[i].getFirst().getValue());
                }
                values = sortRDNs(type, values);

                int i = 0;
                for(String value : values)
                {
                    rdns.add(createSubjectRDN(value, type, i++));
                }
            }
        }

        X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
        return new SubjectInfo(grantedSubject, null);
    }

    @Override
    protected RDN createSubjectRDN(String text, ASN1ObjectIdentifier type, int index)
    throws BadCertTemplateException
    {
        text = text.trim();

        SubjectDNOption option = subjectDNOptions.get(type);
        if(option != null)
        {
            AddText addPrefix = option.getAddprefix(parameterResolver);
            String prefix = addPrefix == null ? null : addPrefix.getText();

            AddText addSuffix = option.getAddsufix(parameterResolver);
            String suffix = addSuffix == null ? null : addSuffix.getText();

            if(prefix != null || suffix != null)
            {
                String _text = text.toLowerCase();
                if(prefix != null)
                {
                    if(_text.startsWith(prefix.toLowerCase()))
                    {
                        text = text.substring(prefix.length());
                        _text = text.toLowerCase();
                    }
                }

                if(suffix != null)
                {
                    if(_text.endsWith(suffix.toLowerCase()))
                    {
                        text = text.substring(0, text.length() - suffix.length());
                    }
                }
            }

            List<Pattern> patterns = option.getPatterns();
            if(patterns != null)
            {
                Pattern p = patterns.get(index);
                if(p.matcher(text).matches() == false)
                {
                    throw new BadCertTemplateException("invalid subject " + ObjectIdentifiers.oidToDisplayName(type) +
                            " '" + text + "' against regex '" + p.pattern() + "'");
                }
            }

            StringBuilder sb = new StringBuilder();
            if(prefix != null)
            {
                sb.append(prefix);
            }
            sb.append(text);
            if(suffix != null)
            {
                sb.append(suffix);
            }
            text = sb.toString();

            int len = text.length();
            Integer minLen = option.getMinLen();
            if(minLen != null)
            {
                if(len < minLen)
                {
                    throw new BadCertTemplateException("subject " + ObjectIdentifiers.oidToDisplayName(type) +
                            " '" + text + "' is too short (length (" + len + ") < minLen (" + minLen + ")");
                }
            }

            Integer maxLen = option.getMaxLen();
            if(maxLen != null)
            {
                if(len > maxLen)
                {
                    throw new BadCertTemplateException("subject " + ObjectIdentifiers.oidToDisplayName(type) +
                            " '" + text + "' is too long (length (" + len + ") > maxLen (" + maxLen + ")");
                }
            }
        }

        ASN1Encodable dnValue;
        if(ObjectIdentifiers.DN_SERIALNUMBER.equals(type) || ObjectIdentifiers.DN_C.equals(type))
        {
            dnValue = new DERPrintableString(text);
        }
        else
        {
            dnValue = new DERUTF8String(text);
        }

        return new RDN(type, dnValue);
    }

    @Override
    protected String[] sortRDNs(ASN1ObjectIdentifier type, String[] values)
    {
        SubjectDNOption option = subjectDNOptions.get(type);
        if(option == null)
        {
            return values;
        }

        List<Pattern> patterns = option.getPatterns();
        if(patterns == null || patterns.isEmpty())
        {
            return values;
        }

        List<String> result = new ArrayList<>(values.length);
        for(Pattern p : patterns)
        {
            for(String value : values)
            {
                if(result.contains(value) == false && p.matcher(value).matches())
                {
                    result.add(value);
                }
            }
        }
        for(String value : values)
        {
            if(result.contains(value) == false)
            {
                result.add(value);
            }
        }

        return result.toArray(new String[0]);
    }

    @Override
    public ExtensionTuples getExtensions(
            Map<ASN1ObjectIdentifier, ExtensionControl> extensionOccurences,
            X500Name requestedSubject, Extensions requestedExtensions)
    throws CertProfileException, BadCertTemplateException
    {
        ExtensionTuples tuples = new ExtensionTuples();
        if(extensionOccurences == null || extensionOccurences.isEmpty())
        {
            return tuples;
        }

        Map<ASN1ObjectIdentifier, ExtensionControl> occurences = new HashMap<>(extensionOccurences);

        // AuthorityKeyIdentifier
        // processed by the CA

        // SubjectKeyIdentifier
        // processed by the CA

        // KeyUsage
        // processed by the CA

        // CertificatePolicies
        ASN1ObjectIdentifier type = Extension.certificatePolicies;
        if(certificatePolicies != null && occurences.remove(type) != null)
        {
            tuples.addExtension(type, certificatePolicies.getExtensionValue(parameterResolver));
        }

        // Policy Mappings
        type = Extension.policyMappings;
        if(policyMappings != null && occurences.remove(type) != null)
        {
            tuples.addExtension(type, policyMappings.getExtensionValue(parameterResolver));
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
        if(nameConstraints != null && occurences.remove(type) != null)
        {
            tuples.addExtension(type, nameConstraints.getExtensionValue(parameterResolver));
        }

        // PolicyConstrains
        type = Extension.policyConstraints;
        if(policyConstraints != null && occurences.remove(type) != null)
        {
            tuples.addExtension(type, policyConstraints.getExtensionValue(parameterResolver));
        }

        // ExtendedKeyUsage
        // processed by CA

        // CRL Distribution Points
        // processed by the CA

        // Inhibit anyPolicy
        type = Extension.inhibitAnyPolicy;
        if(inhibitAnyPolicy != null && occurences.remove(type) != null)
        {
            tuples.addExtension(type, inhibitAnyPolicy.getExtensionValue(parameterResolver));
        }

        // Freshest CRL
        // processed by the CA

        // Authority Information Access
        // processed by the CA

        // Subject Information Access
        // processed by the CA

        // Admission
        type = ObjectIdentifiers.id_extension_admission;
        if(admission != null && occurences.remove(type) != null)
        {
            tuples.addExtension(type, admission.getExtensionValue(parameterResolver));
        }

        // OCSP Nocheck
        // processed by the CA

        // constant extensions
        if(constantExtensions != null)
        {
            for(ASN1ObjectIdentifier m : constantExtensions.keySet())
            {
                ExtensionControl occurence = occurences.remove(m);
                if(occurence != null)
                {
                    ExtensionValue extensionValue = constantExtensions.get(m).getExtensionValue(parameterResolver);
                    if(extensionValue != null)
                    {
                        tuples.addExtension(m, extensionValue);
                    }
                }
            }
        }

        return tuples;
    }

    @Override
    public boolean incSerialNumberIfSubjectExists()
    {
        return incSerialNrIfSubjectExists;
    }

    @Override
    public Set<KeyUsageOccurrence> getKeyUsage()
    {
        return keyusages == null ? null : keyusages.getKeyusage(parameterResolver);
    }

    @Override
    public Set<ExtKeyUsageOccurrence> getExtendedKeyUsages()
    {
        return extendedKeyusages == null ? null : extendedKeyusages.getExtKeyusage(parameterResolver);
    }

    @Override
    public boolean isCA()
    {
        return ca;
    }

    @Override
    public boolean prefersECImplicitCA()
    {
        return prefersECImplicitCA;
    }

    @Override
    public Integer getPathLenBasicConstraint()
    {
        return pathLen;
    }

    @Override
    public boolean hasMidnightNotBefore()
    {
        return notBeforeMidnight;
    }

    @Override
    public Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls()
    {
        return extensionOccurences;
    }

    @Override
    public boolean backwardsSubject()
    {
        return backwardsSubject;
    }

    @Override
    public boolean isOnlyForRA()
    {
        return raOnly;
    }

    @Override
    public boolean isOnlyForQA()
    {
        return qaOnly;
    }

    @Override
    public boolean includeIssuerAndSerialInAKI()
    {
        return akiOption == null ? false : akiOption.isIncludeIssuerAndSerial();
    }

    @Override
    public Set<RDNOccurrence> getSubjectDNSubset()
    {
        return subjectDNOccurrences;
    }

    @Override
    public SpecialX509CertProfileBehavior getSpecialCertProfileBehavior()
    {
        return specialBehavior;
    }

    private ExtensionValue createAdmission(boolean critical,
            List<ASN1ObjectIdentifier> professionOIDs,
            List<String> professionItems,
            String registrationNumber,
            byte[] addProfessionInfo)
    throws CertProfileException
    {
        if(professionItems == null || professionItems.isEmpty())
        {
            if(professionOIDs == null || professionOIDs.isEmpty())
            {
                if(registrationNumber == null || registrationNumber.isEmpty())
                {
                    if(addProfessionInfo == null || addProfessionInfo.length == 0)
                    {
                        return null;
                    }
                }
            }
        }

        DirectoryString[] _professionItems = null;
        if(professionItems != null && professionItems.size() > 0)
        {
            int n = professionItems.size();
            _professionItems = new DirectoryString[n];
            for(int i = 0; i < n; i++)
            {
                _professionItems[i] = new DirectoryString(professionItems.get(i));
            }
        }

        ASN1ObjectIdentifier[] _professionOIDs = null;
        if(professionOIDs != null && professionOIDs.size() > 0)
        {
            _professionOIDs = professionOIDs.toArray(new ASN1ObjectIdentifier[0]);
        }

        ASN1OctetString _addProfessionInfo = null;
        if(addProfessionInfo != null && addProfessionInfo.length > 0)
        {
            _addProfessionInfo = new DEROctetString(addProfessionInfo);
        }

        ProfessionInfo professionInfo = new ProfessionInfo(
                    null, _professionItems, _professionOIDs, registrationNumber, _addProfessionInfo);

        Admissions admissions = new Admissions(null, null,
                new ProfessionInfo[]{professionInfo});

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(admissions);

        AdmissionSyntax value = new AdmissionSyntax(null, new DERSequence(vector));
        return new ExtensionValue(critical, value);
    }

    @Override
    public boolean isDuplicateKeyPermitted()
    {
        return duplicateKeyPermitted;
    }

    @Override
    public boolean isDuplicateSubjectPermitted()
    {
        return duplicateSubjectPermitted;
    }

    @Override
    public boolean isSerialNumberInReqPermitted()
    {
        return serialNumberInReqPermitted;
    }

    @Override
    public Set<GeneralNameMode> getSubjectAltNameModes()
    {
        return allowedSubjectAltNameModes;
    }

    @Override
    public Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> getSubjectInfoAccessModes()
    {
        return allowedSubjectInfoAccessModes;
    }

    private static boolean getBoolean(Boolean b, boolean dfltValue)
    {
        return b == null ? dfltValue : b.booleanValue();
    }

    private static int getInt(Integer i, int dfltValue)
    {
        return i == null ? dfltValue : i.intValue();
    }

}
