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
import org.bouncycastle.asn1.DERNull;
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
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertProfileException;
import org.xipki.ca.api.CertValidity;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.ExtensionTuple;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.RDNOccurrence;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.ca.api.profile.x509.BaseX509CertProfile;
import org.xipki.ca.api.profile.x509.CertificatePolicyInformation;
import org.xipki.ca.api.profile.x509.KeyUsage;
import org.xipki.ca.api.profile.x509.SpecialX509CertProfileBehavior;
import org.xipki.ca.api.profile.x509.X509Util;
import org.xipki.ca.server.certprofile.AddText;
import org.xipki.ca.server.certprofile.Condition;
import org.xipki.ca.server.certprofile.ExtensionTupleOption;
import org.xipki.ca.server.certprofile.ExtensionTupleOptions;
import org.xipki.ca.server.certprofile.GeneralNameMode;
import org.xipki.ca.server.certprofile.KeyParametersOption;
import org.xipki.ca.server.certprofile.KeyParametersOption.AllowAllParametersOption;
import org.xipki.ca.server.certprofile.KeyParametersOption.DSAParametersOption;
import org.xipki.ca.server.certprofile.KeyParametersOption.ECParamatersOption;
import org.xipki.ca.server.certprofile.KeyParametersOption.RSAParametersOption;
import org.xipki.ca.server.certprofile.Range;
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
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.InhibitAnyPolicy;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.PolicyConstraints;
import org.xipki.ca.server.certprofile.x509.jaxb.KeyUsageType;
import org.xipki.ca.server.certprofile.x509.jaxb.NameValueType;
import org.xipki.ca.server.certprofile.x509.jaxb.OidWithDescType;
import org.xipki.ca.server.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.ca.server.certprofile.x509.jaxb.X509ProfileType.AllowedClientExtensions;
import org.xipki.ca.server.certprofile.x509.jaxb.X509ProfileType.KeyAlgorithms;
import org.xipki.ca.server.certprofile.x509.jaxb.X509ProfileType.Parameters;
import org.xipki.ca.server.certprofile.x509.jaxb.X509ProfileType.Subject;
import org.xipki.ca.server.certprofile.x509.jaxb.RdnType;
import org.xipki.ca.server.certprofile.x509.jaxb.SubjectInfoAccessType.Access;
import org.xipki.common.CmpUtf8Pairs;
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
    private static final Set<String> criticalOnlyExtensionTypes;
    private static final Set<String> noncriticalOnlyExtensionTypes;
    private static final Set<String> caOnlyExtensionTypes;
    private static final Set<ASN1ObjectIdentifier> ignoreRDNs;

    protected X509ProfileType profileConf;

    private SpecialX509CertProfileBehavior specialBehavior;

    private Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms;

    private Map<ASN1ObjectIdentifier, SubjectDNOption> subjectDNOptions;
    private Set<RDNOccurrence> subjectDNOccurrences;
    private Map<String, String> parameters;
    private Map<ASN1ObjectIdentifier, ExtensionOccurrence> extensionOccurences;
    private Map<ASN1ObjectIdentifier, ExtensionOccurrence> additionalExtensionOccurences;

    private CertValidity validity;
    private boolean incSerialNrIfSubjectExists;
    private boolean raOnly;
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
    private Set<ASN1ObjectIdentifier> allowedClientExtensions;
    private Set<GeneralNameMode> allowedSubjectAltNameModes;
    private Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> allowedSubjectInfoAccessModes;

    private AuthorityKeyIdentifierOption akiOption;
    private ExtensionTupleOptions certificatePolicies;
    private ExtensionTupleOptions policyMappings;
    private ExtensionTupleOptions nameConstraints;
    private ExtensionTupleOptions policyConstraints;
    private ExtensionTupleOptions inhibitAnyPolicy;
    private ExtensionTuple ocspNoCheck;
    private ExtensionTupleOptions admission;

    private Map<ASN1ObjectIdentifier, ExtensionTupleOptions> constantExtensions;

    static
    {
        criticalOnlyExtensionTypes = new HashSet<>(5);
        criticalOnlyExtensionTypes.add(Extension.basicConstraints.getId());
        criticalOnlyExtensionTypes.add(Extension.keyUsage.getId());
        criticalOnlyExtensionTypes.add(Extension.policyMappings.getId());
        criticalOnlyExtensionTypes.add(Extension.nameConstraints.getId());
        criticalOnlyExtensionTypes.add(Extension.policyConstraints.getId());
        criticalOnlyExtensionTypes.add(Extension.inhibitAnyPolicy.getId());

        noncriticalOnlyExtensionTypes = new HashSet<>(7);
        noncriticalOnlyExtensionTypes.add(Extension.authorityKeyIdentifier.getId());
        noncriticalOnlyExtensionTypes.add(Extension.subjectKeyIdentifier.getId());
        noncriticalOnlyExtensionTypes.add(Extension.issuerAlternativeName.getId());
        noncriticalOnlyExtensionTypes.add(Extension.subjectDirectoryAttributes.getId());
        noncriticalOnlyExtensionTypes.add(Extension.freshestCRL.getId());
        noncriticalOnlyExtensionTypes.add(Extension.authorityInfoAccess.getId());
        noncriticalOnlyExtensionTypes.add(Extension.subjectInfoAccess.getId());

        caOnlyExtensionTypes = new HashSet<String>(4);
        caOnlyExtensionTypes.add(Extension.policyMappings.getId());
        caOnlyExtensionTypes.add(Extension.nameConstraints.getId());
        caOnlyExtensionTypes.add(Extension.policyConstraints.getId());
        caOnlyExtensionTypes.add(Extension.inhibitAnyPolicy.getId());

        ignoreRDNs = new HashSet<>(2);
        ignoreRDNs.add(Extension.subjectAlternativeName);
        ignoreRDNs.add(Extension.subjectInfoAccess);
    }

    private void reset()
    {
        profileConf = null;
        keyAlgorithms = null;
        subjectDNOptions = null;
        subjectDNOccurrences = null;
        extensionOccurences = null;
        additionalExtensionOccurences = null;
        validity = null;
        notBeforeMidnight = false;
        akiOption = null;
        incSerialNrIfSubjectExists = false;
        raOnly = false;
        backwardsSubject = false;
        ca = false;
        prefersECImplicitCA = false;
        duplicateKeyPermitted = true;
        duplicateSubjectPermitted = true;
        serialNumberInReqPermitted = true;
        pathLen = null;
        keyusages = null;
        extendedKeyusages = null;
        allowedClientExtensions = null;
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

            this.raOnly = getBoolean(conf.isOnlyForRA(), false);
            this.validity = CertValidity.getInstance(conf.getValidity());
            this.ca = conf.isCa();
            this.prefersECImplicitCA = getBoolean(conf.isPrefersECImplicitCA(), false);
            this.notBeforeMidnight = "midnight".equalsIgnoreCase(conf.getNotBeforeTime());

            String specialBehavior = conf.getSpecialBehavior();
            if(specialBehavior != null)
            {
                this.specialBehavior = SpecialX509CertProfileBehavior.getInstance(specialBehavior);
            }

            if(conf.isDuplicateKeyPermitted() != null)
            {
                duplicateKeyPermitted = conf.isDuplicateKeyPermitted().booleanValue();
            }

            if(conf.isDuplicateSubjectPermitted() != null)
            {
                duplicateSubjectPermitted = conf.isDuplicateSubjectPermitted().booleanValue();
            }

            if(conf.isSerialNumberInReqPermitted() != null)
            {
                serialNumberInReqPermitted = conf.isSerialNumberInReqPermitted().booleanValue();
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

            // Allowed extensions to be fulfilled by the client
            AllowedClientExtensions clientExtensions = conf.getAllowedClientExtensions();
            if(clientExtensions != null)
            {
                this.allowedClientExtensions = XmlX509CertProfileUtil.toOIDSet(clientExtensions.getType());
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
                    Set<KeyUsage> set = new HashSet<>();
                    for(KeyUsageType type : t.getUsage())
                    {
                        switch(type)
                        {
                        case C_RL_SIGN:
                            set.add(KeyUsage.cRLSign);
                            break;
                        case DATA_ENCIPHERMENT:
                            set.add(KeyUsage.dataEncipherment);
                            break;
                        case CONTENT_COMMITMENT:
                            set.add(KeyUsage.contentCommitment);
                            break;
                        case DECIPHER_ONLY:
                            set.add(KeyUsage.decipherOnly);
                            break;
                        case ENCIPHER_ONLY:
                            set.add(KeyUsage.encipherOnly);
                            break;
                        case DIGITAL_SIGNATURE:
                            set.add(KeyUsage.digitalSignature);
                            break;
                        case KEY_AGREEMENT:
                            set.add(KeyUsage.keyAgreement);
                            break;
                        case KEY_CERT_SIGN:
                            set.add(KeyUsage.keyCertSign);
                            break;
                        case KEY_ENCIPHERMENT:
                            set.add(KeyUsage.keyEncipherment);
                            break;
                        default:
                            throw new RuntimeException("should not reach here");
                        }
                    }
                    Set<KeyUsage> keyusageSet = Collections.unmodifiableSet(set);

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
                    Set<ASN1ObjectIdentifier> extendedKeyusageSet = XmlX509CertProfileUtil.toOIDSet(t.getUsage());
                    Condition condition = XmlX509CertProfileUtil.createCondition(t.getCondition());
                    ExtKeyUsageOption option = new ExtKeyUsageOption(condition, extendedKeyusageSet);
                    optionList.add(option);
                }

                this.extendedKeyusages = new ExtKeyUsageOptions(optionList);
            }

            // Extension Occurrences
            Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurrences = new HashMap<>();
            for(ExtensionType extensionType : extensionsType.getExtension())
            {
                String oid = extensionType.getValue();
                if(ca == false && caOnlyExtensionTypes.contains(oid))
                {
                    LOG.warn("ignore CA-only extension {}", oid);
                    continue;
                }

                boolean required = extensionType.isRequired();
                Boolean b = extensionType.isCritical();

                boolean critical;
                if(criticalOnlyExtensionTypes.contains(oid))
                {
                    critical = true;
                }
                else if(noncriticalOnlyExtensionTypes.contains(oid))
                {
                    critical = false;
                }
                else if(ca && Extension.basicConstraints.getId().equals(oid))
                {
                    critical = true;
                }
                else
                {
                    critical = b == null ? false : b.booleanValue();
                }

                if(b != null && b.booleanValue() != critical)
                {
                    LOG.warn("corrected the critical of extenion {} from {} to {}", new Object[]{oid, b, critical});
                }

                occurrences.put(new ASN1ObjectIdentifier(oid),
                        ExtensionOccurrence.getInstance(critical, required));
            }

            this.extensionOccurences = Collections.unmodifiableMap(occurrences);

            occurrences = new HashMap<>(occurrences);
            occurrences.remove(Extension.authorityKeyIdentifier);
            occurrences.remove(Extension.subjectKeyIdentifier);
            occurrences.remove(Extension.authorityInfoAccess);
            occurrences.remove(Extension.cRLDistributionPoints);
            occurrences.remove(Extension.freshestCRL);
            occurrences.remove(Extension.issuerAlternativeName);
            this.additionalExtensionOccurences = Collections.unmodifiableMap(occurrences);

            // AuthorityKeyIdentifier
            if(extensionOccurences.containsKey(Extension.authorityKeyIdentifier))
            {
                ExtensionOccurrence extOccurrence = extensionOccurences.get(Extension.authorityKeyIdentifier);
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
            ASN1ObjectIdentifier extensionOid = Extension.certificatePolicies;
            ExtensionOccurrence occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getCertificatePolicies().isEmpty() == false)
            {
                List<ExtensionsType.CertificatePolicies> types = extensionsType.getCertificatePolicies();
                List<ExtensionTupleOption> options = new ArrayList<>(types.size());
                for(ExtensionsType.CertificatePolicies type : types)
                {
                    List<CertificatePolicyInformation> policyInfos = XmlX509CertProfileUtil.buildCertificatePolicies(type);
                    CertificatePolicies value = X509Util.createCertificatePolicies(policyInfos);
                    ExtensionTuple extension = createExtension(extensionOid, occurrence.isCritical(), value);
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.certificatePolicies = new ExtensionTupleOptions(options);
            }

            // Policy Mappings
            extensionOid = Extension.policyMappings;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getPolicyMappings().isEmpty() == false)
            {
                List<ExtensionsType.PolicyMappings> types = extensionsType.getPolicyMappings();
                List<ExtensionTupleOption> options = new ArrayList<>(types.size());
                for(ExtensionsType.PolicyMappings type : types)
                {
                    org.bouncycastle.asn1.x509.PolicyMappings value = XmlX509CertProfileUtil.buildPolicyMappings(type);
                    ExtensionTuple extension = createExtension(extensionOid, occurrence.isCritical(), value);
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.policyMappings = new ExtensionTupleOptions(options);
            }

            // Name Constrains
            extensionOid = Extension.nameConstraints;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getNameConstraints().isEmpty() == false)
            {
                List<ExtensionsType.NameConstraints> types = extensionsType.getNameConstraints();
                List<ExtensionTupleOption> options = new ArrayList<>(types.size());
                for(ExtensionsType.NameConstraints type : types)
                {
                    NameConstraints value = XmlX509CertProfileUtil.buildNameConstrains(type);
                    ExtensionTuple extension = createExtension(extensionOid, occurrence.isCritical(), value);
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.nameConstraints = new ExtensionTupleOptions(options);
            }

            // Policy Constraints
            extensionOid = Extension.policyConstraints;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getPolicyConstraints().isEmpty() == false)
            {
                List<PolicyConstraints> types = extensionsType.getPolicyConstraints();
                List<ExtensionTupleOption> options = new ArrayList<>(types.size());
                for(PolicyConstraints type : types)
                {
                    ASN1Sequence value = XmlX509CertProfileUtil.buildPolicyConstrains(type);
                    ExtensionTuple extension = createExtension(extensionOid, occurrence.isCritical(), value);
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.policyConstraints = new ExtensionTupleOptions(options);
            }

            // Inhibit anyPolicy
            extensionOid = Extension.inhibitAnyPolicy;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getInhibitAnyPolicy().isEmpty() == false)
            {
                List<InhibitAnyPolicy> types = extensionsType.getInhibitAnyPolicy();
                List<ExtensionTupleOption> options = new ArrayList<>(types.size());
                for(InhibitAnyPolicy type : types)
                {
                    int skipCerts = type.getSkipCerts();
                    if(skipCerts < 0)
                    {
                        throw new CertProfileException("negative inhibitAnyPolicy.skipCerts is not allowed: " + skipCerts);
                    }
                    ASN1Integer value = new ASN1Integer(BigInteger.valueOf(skipCerts));
                    ExtensionTuple extension = createExtension(extensionOid, occurrence.isCritical(), value);
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.inhibitAnyPolicy = new ExtensionTupleOptions(options);
            }

            // OCSP NoCheck
            extensionOid = ObjectIdentifiers.id_extension_pkix_ocsp_nocheck;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null)
            {
                DERNull value = DERNull.INSTANCE;
                this.ocspNoCheck = createExtension(extensionOid, occurrence.isCritical(), value);
            }

            // admission
            extensionOid = ObjectIdentifiers.id_extension_admission;
            occurrence = occurrences.get(extensionOid);
            if(occurrence != null && extensionsType.getAdmission().isEmpty() == false)
            {
                List<Admission> types = extensionsType.getAdmission();
                List<ExtensionTupleOption> options = new ArrayList<>(types.size());
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

                    List<OidWithDescType> oidWithDescs =  type == null ? null : type.getProfessionOid();
                    professionOIDs = XmlX509CertProfileUtil.toOIDList(oidWithDescs);

                    ExtensionTuple extension = createAdmission(occurrence.isCritical(),
                            professionOIDs, professionItems, type.getRegistrationNumber(), type.getAddProfessionInfo());
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            XmlX509CertProfileUtil.createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.admission = new ExtensionTupleOptions(options);
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
                Map<ASN1ObjectIdentifier, List<ExtensionTupleOption>> map = new HashMap<>();
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
                            ExtensionTuple extension = createExtension(type, occurrence.isCritical(), value);
                            ExtensionTupleOption option = new ExtensionTupleOption(
                                    XmlX509CertProfileUtil.createCondition(ce.getCondition()), extension);

                            List<ExtensionTupleOption> options = map.get(type);
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
                        List<ExtensionTupleOption> options = map.get(type);
                        this.constantExtensions.put(type, new ExtensionTupleOptions(options));
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
    public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier()
    {
        return akiOption == null ? null : akiOption.getOccurence();
    }

    @Override
    public ExtensionOccurrence getOccurenceOfSubjectKeyIdentifier()
    {
        return extensionOccurences.get(Extension.subjectKeyIdentifier);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfCRLDistributinPoints()
    {
        return extensionOccurences.get(Extension.cRLDistributionPoints);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfFreshestCRL()
    {
        return extensionOccurences.get(Extension.freshestCRL);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfAuthorityInfoAccess()
    {
        return extensionOccurences.get(Extension.authorityInfoAccess);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfIssuerAltName()
    {
        return extensionOccurences.get(Extension.issuerAlternativeName);
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
        verifySubjectDNOccurence(requestedSubject, ignoreRDNs);
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
    public ExtensionTuples getExtensions(X500Name requestedSubject, Extensions requestedExtensions)
    throws CertProfileException, BadCertTemplateException
    {
        ExtensionTuples tuples = super.getExtensions(requestedSubject, requestedExtensions);

        Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurences = new HashMap<>(getAdditionalExtensionOccurences());
        if(occurences == null || occurences.isEmpty())
        {
            return tuples;
        }

        // AuthorityKeyIdentifier
        // processed by the CA

        // SubjectKeyIdentifier
        // processed by the CA

        // KeyUsage
        // processed by the parent class
        occurences.remove(Extension.keyUsage);

        // CertificatePolicies
        processExtension(tuples, occurences, Extension.certificatePolicies, certificatePolicies, requestedExtensions);

        // Policy Mappings
        processExtension(tuples, occurences, Extension.policyMappings, policyMappings, requestedExtensions);

        // SubjectAltName
        ASN1ObjectIdentifier extensionType = Extension.subjectAlternativeName;
        ExtensionOccurrence occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            ExtensionTuple extension = null;
            if(allowedSubjectAltNameModes != null)
            {
                RDN[] rdns = requestedSubject.getRDNs(extensionType);
                if(rdns != null && rdns.length > 0)
                {
                    final int n = rdns.length;
                    GeneralName[] names = new GeneralName[n];
                    for(int i = 0; i < n; i++)
                    {
                        String value = SecurityUtil.rdnValueToString(rdns[i].getFirst().getValue());
                        names[i] = XmlX509CertProfileUtil.createGeneralName(value, allowedSubjectAltNameModes);
                    }
                    extension = createExtension(extensionType, occurence.isCritical(), new GeneralNames(names));
                }
            }

            if(extension == null)
            {
                extension = retrieveExtensionTupleFromRequest(
                        occurence.isCritical(), extensionType, requestedExtensions);
            }
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }

        // IssuerAltName
        // processed by the CA

        // Subject Directory Attributes
        // Will not supported

        // Basic Constraints
        // processed by the parent class
        occurences.remove(Extension.basicConstraints);

        // Name Constraints
        processExtension(tuples, occurences, Extension.nameConstraints, nameConstraints, requestedExtensions);

        // PolicyConstrains
        processExtension(tuples, occurences, Extension.policyConstraints, policyConstraints, requestedExtensions);

        // ExtendedKeyUsage
        // processed by the parent class
        occurences.remove(Extension.extendedKeyUsage);

        // CRL Distribution Points
        // processed by the CA

        // Inhibit anyPolicy
        processExtension(tuples, occurences, Extension.inhibitAnyPolicy, inhibitAnyPolicy, requestedExtensions);

        // Freshest CRL
        // processed by the CA

        // Authority Information Access
        // processed by the CA

        // Subject Information Access
        extensionType = Extension.subjectInfoAccess;
        occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            ExtensionTuple extension = null;
            if(allowedSubjectInfoAccessModes != null)
            {
                RDN[] rdns = requestedSubject.getRDNs(extensionType);
                if(rdns != null && rdns.length > 0)
                {
                    ASN1EncodableVector vector = new ASN1EncodableVector();

                    for(RDN rdn : rdns)
                    {
                        String value = SecurityUtil.rdnValueToString(rdn.getFirst().getValue());
                        try
                        {
                            CmpUtf8Pairs pairs = new CmpUtf8Pairs(value);
                            String identifier = pairs.getNames().iterator().next();
                            ASN1ObjectIdentifier accessMethod = new ASN1ObjectIdentifier(identifier);
                            Set<GeneralNameMode> generalNameModes = allowedSubjectInfoAccessModes.get(accessMethod);
                            if(generalNameModes == null)
                            {
                                throw new BadCertTemplateException("subjectInfoAccess.accessMethod " + identifier+
                                        " is not allowed");
                            }

                            String accessLocation = pairs.getValue(identifier);

                            GeneralName location = XmlX509CertProfileUtil.createGeneralName(accessLocation, generalNameModes);
                            AccessDescription accessDescription = new AccessDescription(accessMethod, location);
                            vector.add(accessDescription);
                        } catch(BadCertTemplateException e)
                        {
                            throw e;
                        }
                        catch(Exception e)
                        {
                            LOG.debug("Exception while processing subjectInfoAccess '{}': {}", value, e.getMessage());
                            throw new BadCertTemplateException("invalid subjectInfoAccess '" + value + "'");
                        }
                    }

                    ASN1Sequence seq = new DERSequence(vector);
                    extension = createExtension(extensionType, occurence.isCritical(), seq);
                }
            }

            if(extension == null)
            {
                extension = retrieveExtensionTupleFromRequest(
                        occurence.isCritical(), extensionType, requestedExtensions);
            }
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }

        // Admission
        processExtension(tuples, occurences, ObjectIdentifiers.id_extension_admission, admission, requestedExtensions);

        // OCSP Nocheck
        processExtension(tuples, occurences, ObjectIdentifiers.id_extension_pkix_ocsp_nocheck,
                ocspNoCheck, requestedExtensions);

        // constant extensions
        if(constantExtensions != null)
        {
            for(ASN1ObjectIdentifier type : constantExtensions.keySet())
            {
                occurence = occurences.remove(type);
                if(occurence != null)
                {
                    ExtensionTuple extensionTuple = constantExtensions.get(type).getExtensionTuple(parameterResolver);
                    if(extensionTuple != null)
                    {
                        tuples.addExtension(extensionTuple);
                    }
                }
            }
        }

        // check whether there is unknown extensions
        if(occurences.isEmpty() == false)
        {
            StringBuilder sb = new StringBuilder("Extensions with the following types are not processed: ");
            for(ASN1ObjectIdentifier extnType : occurences.keySet())
            {
                sb.append(extnType.getId()).append(", ");
            }
            throw new CertProfileException(sb.substring(0, sb.length() - 2));
        }

        return tuples;
    }

    private ExtensionTuple retrieveExtensionTupleFromRequest(boolean critical, ASN1ObjectIdentifier extensionType,
            Extensions requestedExtensions)
    {
        // consider the Extensions contained in the request
        if(allowedClientExtensions == null || allowedClientExtensions.isEmpty())
        {
            return null;
        }

        Extension ext = requestedExtensions.getExtension(extensionType);
        return (ext == null) ? null :new ExtensionTuple(critical, ext);
    }

    @Override
    public boolean incSerialNumberIfSubjectExists()
    {
        return incSerialNrIfSubjectExists;
    }

    @Override
    protected Set<KeyUsage> getKeyUsage()
    {
        return keyusages == null ? null : keyusages.getKeyusage(parameterResolver);
    }

    @Override
    protected Set<ASN1ObjectIdentifier> getExtendedKeyUsages()
    {
        return extendedKeyusages == null ? null : extendedKeyusages.getExtKeyusage(parameterResolver);
    }

    @Override
    protected boolean isCa()
    {
        return ca;
    }

    @Override
    public boolean prefersECImplicitCA()
    {
        return prefersECImplicitCA;
    }

    @Override
    protected Integer getPathLenBasicConstraint()
    {
        return pathLen;
    }

    @Override
    public boolean hasMidnightNotBefore()
    {
        return notBeforeMidnight;
    }

    @Override
    protected Map<ASN1ObjectIdentifier, ExtensionOccurrence> getAdditionalExtensionOccurences()
    {
        if(additionalExtensionOccurences.containsKey(Extension.extendedKeyUsage))
        {
            ExtensionOccurrence occ = additionalExtensionOccurences.get(Extension.extendedKeyUsage);
            if(occ.isCritical())
            {
                Set<ASN1ObjectIdentifier> extKeyusage = extendedKeyusages.getExtKeyusage(parameterResolver);
                if(extKeyusage != null && extKeyusage.contains(ObjectIdentifiers.anyExtendedKeyUsage))
                {
                    Map<ASN1ObjectIdentifier, ExtensionOccurrence> newMap = new HashMap<>(additionalExtensionOccurences);
                    newMap.put(Extension.extendedKeyUsage, ExtensionOccurrence.getInstance(false, occ.isRequired()));
                    return newMap;
                }
            }
        }

        return additionalExtensionOccurences;
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

    private ExtensionTuple createAdmission(boolean critical,
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
        return createExtension(ObjectIdentifiers.id_extension_admission, critical, value);
    }

    private void processExtension(ExtensionTuples tuples,
            Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurences,
            ASN1ObjectIdentifier extensionType,
            ExtensionTupleOptions preferredExtensions,
            Extensions requestedExtensions)
    throws CertProfileException
    {
        ExtensionOccurrence occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            ExtensionTuple extension = preferredExtensions.getExtensionTuple(parameterResolver);
            if(extension == null)
            {
                extension = retrieveExtensionTupleFromRequest(
                        occurence.isCritical(), extensionType, requestedExtensions);
            }
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }
    }

    private void processExtension(ExtensionTuples tuples,
            Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurences,
            ASN1ObjectIdentifier extensionType,
            ExtensionTuple preferredExtension,
            Extensions requestedExtensions)
    throws CertProfileException
    {
        ExtensionOccurrence occurence = occurences.remove(extensionType);
        if(occurence != null)
        {
            ExtensionTuple extension = preferredExtension;
            if(extension == null)
            {
                extension = retrieveExtensionTupleFromRequest(
                        occurence.isCritical(), extensionType, requestedExtensions);
            }
            checkAndAddExtension(extensionType, occurence, extension, tuples);
        }
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

    private static boolean getBoolean(Boolean b, boolean dfltValue)
    {
        return b == null ? dfltValue : b.booleanValue();
    }

    private static int getInt(Integer i, int dfltValue)
    {
        return i == null ? dfltValue : i.intValue();
    }

}
