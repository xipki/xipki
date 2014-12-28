/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.qa.certprofile.x509;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.regex.Pattern;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
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
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertProfileException;
import org.xipki.ca.api.CertValidity;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.RDNOccurrence;
import org.xipki.ca.api.profile.x509.KeyUsage;
import org.xipki.ca.qa.ValidationIssue;
import org.xipki.ca.qa.ValidationResult;
import org.xipki.ca.qa.certprofile.GeneralNameMode;
import org.xipki.ca.qa.certprofile.GeneralNameTag;
import org.xipki.ca.qa.certprofile.KeyParamRange;
import org.xipki.ca.qa.certprofile.KeyParamRanges;
import org.xipki.ca.qa.certprofile.SubjectDNOption;
import org.xipki.ca.qa.certprofile.x509.conf.AdmissionConf;
import org.xipki.ca.qa.certprofile.x509.conf.AuthorityKeyIdentifierOption;
import org.xipki.ca.qa.certprofile.x509.conf.CPSUriPolicyQualifierInfo;
import org.xipki.ca.qa.certprofile.x509.conf.CertificatePoliciesConf;
import org.xipki.ca.qa.certprofile.x509.conf.CertificatePolicyInformationConf;
import org.xipki.ca.qa.certprofile.x509.conf.GeneralSubtreeConf;
import org.xipki.ca.qa.certprofile.x509.conf.InhibitAnyPolicyConf;
import org.xipki.ca.qa.certprofile.x509.conf.NameConstraintsConf;
import org.xipki.ca.qa.certprofile.x509.conf.PolicyConstraintsConf;
import org.xipki.ca.qa.certprofile.x509.conf.PolicyMappingsConf;
import org.xipki.ca.qa.certprofile.x509.conf.PolicyQualifierInfoConf;
import org.xipki.ca.qa.certprofile.x509.conf.PolicyQualifiersConf;
import org.xipki.ca.qa.certprofile.x509.conf.UserNoticePolicyQualifierInfo;
import org.xipki.ca.qa.certprofile.x509.jaxb.AlgorithmType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ConstantExtensionType;
import org.xipki.ca.qa.certprofile.x509.jaxb.CurveType;
import org.xipki.ca.qa.certprofile.x509.jaxb.CurveType.Encodings;
import org.xipki.ca.qa.certprofile.x509.jaxb.DirectoryStringType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ECParameterType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.ConstantExtensions;
import org.xipki.ca.qa.certprofile.x509.jaxb.GeneralNameType;
import org.xipki.ca.qa.certprofile.x509.jaxb.KeyUsageType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ObjectFactory;
import org.xipki.ca.qa.certprofile.x509.jaxb.OidWithDescType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ParameterType;
import org.xipki.ca.qa.certprofile.x509.jaxb.RdnType;
import org.xipki.ca.qa.certprofile.x509.jaxb.SubjectInfoAccessType.Access;
import org.xipki.ca.qa.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.common.HashAlgoType;
import org.xipki.common.HashCalculator;
import org.xipki.common.LogUtil;
import org.xipki.common.LruCache;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class X509CertProfileQA
{
    private static final Logger LOG = LoggerFactory.getLogger(X509CertProfileQA.class);
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");
    private static final long SECOND = 1000L;
    private static final char GENERALNAME_SEP = '|';
    public static final String MODULUS_LENGTH = "moduluslength";
    public static final String P_LENGTH = "plength";
    public static final String Q_LENGTH = "qlength";

    private static final Map<ASN1ObjectIdentifier, String> extOidNameMap;
    private static final List<String> allUsages = Arrays.asList(
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

    static
    {
        extOidNameMap = new HashMap<>();
        extOidNameMap.put(ObjectIdentifiers.id_extension_admission, "admission");
        extOidNameMap.put(Extension.auditIdentity, "auditIdentity");
        extOidNameMap.put(Extension.authorityInfoAccess, "authorityInfoAccess");
        extOidNameMap.put(Extension.authorityKeyIdentifier, "authorityKeyIdentifier");
        extOidNameMap.put(Extension.basicConstraints, "basicConstraints");
        extOidNameMap.put(Extension.biometricInfo, "biometricInfo");
        extOidNameMap.put(Extension.certificateIssuer, "certificateIssuer");
        extOidNameMap.put(Extension.certificatePolicies, "certificatePolicies");
        extOidNameMap.put(Extension.cRLDistributionPoints, "cRLDistributionPoints");
        extOidNameMap.put(Extension.deltaCRLIndicator, "deltaCRLIndicator");
        extOidNameMap.put(Extension.extendedKeyUsage, "extendedKeyUsage");
        extOidNameMap.put(Extension.freshestCRL, "freshestCRL");
        extOidNameMap.put(Extension.inhibitAnyPolicy, "inhibitAnyPolicy");
        extOidNameMap.put(Extension.instructionCode, "instructionCode");
        extOidNameMap.put(Extension.issuerAlternativeName, "issuerAlternativeName");
        extOidNameMap.put(Extension.issuingDistributionPoint, "issuingDistributionPoint");
        extOidNameMap.put(Extension.keyUsage, "keyUsage");
        extOidNameMap.put(Extension.logoType, "logoType");
        extOidNameMap.put(Extension.nameConstraints, "nameConstraints");
        extOidNameMap.put(ObjectIdentifiers.id_extension_pkix_ocsp_nocheck, "pkixOcspNocheck");
        extOidNameMap.put(Extension.policyConstraints, "policyConstraints");
        extOidNameMap.put(Extension.policyMappings, "policyMappings");
        extOidNameMap.put(Extension.privateKeyUsagePeriod, "privateKeyUsagePeriod");
        extOidNameMap.put(Extension.qCStatements, "qCStatements");
        extOidNameMap.put(Extension.subjectAlternativeName, "subjectAlternativeName");
        extOidNameMap.put(Extension.subjectDirectoryAttributes, "subjectDirectoryAttributes");
        extOidNameMap.put(Extension.subjectInfoAccess, "subjectInfoAccess");
        extOidNameMap.put(Extension.subjectKeyIdentifier, "subjectKeyIdentifier");
        extOidNameMap.put(Extension.targetInformation, "targetInformation");
    }

    private static final Set<ASN1ObjectIdentifier> ignoreRDNs;

    private final static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

    protected final X509ProfileType profileConf;

    private Map<ASN1ObjectIdentifier, Set<Byte>> allowedEcCurves;
    private Map<ASN1ObjectIdentifier, List<KeyParamRanges>> nonEcKeyAlgorithms;

    private Map<ASN1ObjectIdentifier, SubjectDNOption> subjectDNOptions;
    private Map<ASN1ObjectIdentifier, RDNOccurrence> subjectDNOccurrences;
    private Map<ASN1ObjectIdentifier, ExtensionOccurrence> extensionOccurences;

    private CertValidity validity;
    private int syntaxVersion;
    private String specialBehavior;
    private boolean ca;
    private boolean notBeforeMidnight;
    private Integer pathLen;
    private Set<String> keyusage;
    private Set<String> extendedKeyusages;
    private Set<GeneralNameMode> allowedSubjectAltNameModes;
    private Map<String, Set<GeneralNameMode>> allowedSubjectInfoAccessModes;

    private AuthorityKeyIdentifierOption akiOption;
    private Set<String> sigantureAlgorithms;
    private CertificatePoliciesConf certificatePolicies;
    private PolicyMappingsConf policyMappings;
    private NameConstraintsConf nameConstraints;
    private PolicyConstraintsConf policyConstraints;
    private InhibitAnyPolicyConf inhibitAnyPolicy;
    private AdmissionConf admission;

    private Map<ASN1ObjectIdentifier, byte[]> constantExtensions;
    private static LruCache<ASN1ObjectIdentifier, Integer> ecCurveFieldSizes = new LruCache<>(100);

    static
    {
        ignoreRDNs = new HashSet<>(2);
        ignoreRDNs.add(Extension.subjectAlternativeName);
        ignoreRDNs.add(Extension.subjectInfoAccess);
    }

    public X509CertProfileQA(X509ProfileType conf)
    throws CertProfileException
    {
        try
        {
            this.profileConf = conf;

            this.syntaxVersion = conf.getVersion();
            if(conf.getSignatureAlgorithms() != null)
            {
                List<OidWithDescType> _algorithms = conf.getSignatureAlgorithms().getAlgorithm();
                Set<String> oids = new HashSet<>(_algorithms.size());
                for(OidWithDescType _algorithm : _algorithms)
                {
                    oids.add(_algorithm.getValue());
                }
                this.sigantureAlgorithms = Collections.unmodifiableSet(oids);
            }

            this.validity = CertValidity.getInstance(conf.getValidity());
            this.ca = conf.isCa();
            this.notBeforeMidnight = "midnight".equalsIgnoreCase(conf.getNotBeforeTime());
            this.specialBehavior = conf.getSpecialBehavior();
            if(this.specialBehavior != null && "gematik_gSMC_K".equalsIgnoreCase(this.specialBehavior) == false)
            {
                throw new CertProfileException("unknown special bahavior " + this.specialBehavior);
            }

            // KeyAlgorithms
            if(conf.getKeyAlgorithms() != null)
            {
                List<AlgorithmType> types = conf.getKeyAlgorithms().getAlgorithm();
                this.nonEcKeyAlgorithms = new HashMap<>();
                this.allowedEcCurves = new HashMap<>();

                for(AlgorithmType type : types)
                {
                    ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(type.getAlgorithm().getValue());
                    if(X9ObjectIdentifiers.id_ecPublicKey.equals(oid))
                    {
                        ECParameterType params = type.getEcParameter();
                        if(params != null)
                        {
                            for(CurveType curveType :params.getCurve())
                            {
                                ASN1ObjectIdentifier curveOid = new ASN1ObjectIdentifier(curveType.getOid().getValue());
                                Encodings encodingsType = curveType.getEncodings();
                                Set<Byte> encodings = new HashSet<>();
                                if(encodingsType != null)
                                {
                                    encodings.addAll(encodingsType.getEncoding());
                                }
                                this.allowedEcCurves.put(curveOid, encodings);
                            }
                        }
                    }
                    else
                    {
                        KeyParamRanges ranges = null;

                        List<ParameterType> paramTypes = type.getParameter();
                        if(paramTypes.isEmpty() == false)
                        {
                            Map<String, List<KeyParamRange>> map = new HashMap<>(paramTypes.size());
                            for(ParameterType paramType : paramTypes)
                            {
                                if(paramType.getMin() != null || paramType.getMax() != null)
                                {
                                    List<KeyParamRange> list = map.get(paramType.getName());
                                    if(list == null)
                                    {
                                        list = new LinkedList<>();
                                        map.put(paramType.getName(), list);
                                    }

                                    list.add(new KeyParamRange(paramType.getMin(), paramType.getMax()));
                                }
                            }

                            if(map.isEmpty() == false)
                            {
                                ranges = new KeyParamRanges(map);
                            }
                        }

                        List<KeyParamRanges> list = this.nonEcKeyAlgorithms.get(oid);
                        if(list == null)
                        {
                            list = new LinkedList<>();
                            this.nonEcKeyAlgorithms.put(oid, list);
                        }

                        if(ranges != null)
                        {
                            list.add(ranges);
                        }
                    }
                }

                if(allowedEcCurves.isEmpty())
                {
                    allowedEcCurves = null;
                }

                if(nonEcKeyAlgorithms.isEmpty())
                {
                    nonEcKeyAlgorithms = null;
                }
            }

            // Subject
            if(conf.getSubject() != null)
            {
                this.subjectDNOccurrences = new HashMap<>();
                this.subjectDNOptions = new HashMap<>();

                for(RdnType t : conf.getSubject().getRdn())
                {
                    ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(t.getType().getValue());
                    RDNOccurrence occ = new RDNOccurrence(type,
                            getInt(t.getMinOccurs(), 1), getInt(t.getMaxOccurs(), 1));
                    this.subjectDNOccurrences.put(type, occ);

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

                    boolean ignoreReq = t.isIgnoreReq() == null ? false : t.isIgnoreReq().booleanValue();
                    SubjectDNOption option = new SubjectDNOption(t.getPrefix(), t.getSuffix(), patterns,
                            t.getMinLen(), t.getMaxLen(), t.getDirectoryStringType(), ignoreReq);
                    this.subjectDNOptions.put(type, option);
                }
            }

            // Extensions
            ExtensionsType extensionsType = conf.getExtensions();
            this.pathLen = extensionsType.getPathLen();

            // Extension Occurrences
            Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurrences = new HashMap<>();
            for(ExtensionType extensionType : extensionsType.getExtension())
            {
                String oid = extensionType.getValue();
                boolean required = extensionType.isRequired();
                Boolean b = extensionType.isCritical();

                boolean critical = b == null ? false : b.booleanValue();

                occurrences.put(new ASN1ObjectIdentifier(oid),
                        ExtensionOccurrence.getInstance(critical, required));
            }

            this.extensionOccurences = Collections.unmodifiableMap(occurrences);

            // Extension KeyUsage
            ExtensionOccurrence occurrence = extensionOccurences.get(Extension.keyUsage);
            if(occurrence != null && extensionsType.getKeyUsage() != null)
            {
                List<KeyUsageType> keyUsageTypeList = extensionsType.getKeyUsage().getUsage();

                Set<String> usages = new HashSet<>();
                for(KeyUsageType type : keyUsageTypeList)
                {
                    switch(type)
                    {
                    case C_RL_SIGN:
                        usages.add(KeyUsage.cRLSign.getName());
                        break;
                    case DATA_ENCIPHERMENT:
                        usages.add(KeyUsage.dataEncipherment.getName());
                        break;
                    case CONTENT_COMMITMENT:
                        usages.add(KeyUsage.contentCommitment.getName());
                        break;
                    case DECIPHER_ONLY:
                        usages.add(KeyUsage.decipherOnly.getName());
                        break;
                    case ENCIPHER_ONLY:
                        usages.add(KeyUsage.encipherOnly.getName());
                        break;
                    case DIGITAL_SIGNATURE:
                        usages.add(KeyUsage.digitalSignature.getName());
                        break;
                    case KEY_AGREEMENT:
                        usages.add(KeyUsage.keyAgreement.getName());
                        break;
                    case KEY_CERT_SIGN:
                        usages.add(KeyUsage.keyCertSign.getName());
                        break;
                    case KEY_ENCIPHERMENT:
                        usages.add(KeyUsage.keyEncipherment.getName());
                        break;
                    }
                }

                this.keyusage = Collections.unmodifiableSet(usages);
            }

            // ExtendedKeyUsage
            occurrence = extensionOccurences.get(Extension.extendedKeyUsage);
            if(occurrence != null && extensionsType.getExtendedKeyUsage() != null)
            {
                List<OidWithDescType> extKeyUsageTypeList = extensionsType.getExtendedKeyUsage().getUsage();
                Set<String> extendedKeyusageSet = new HashSet<String>();
                for(OidWithDescType t : extKeyUsageTypeList)
                {
                    extendedKeyusageSet.add(t.getValue());
                }

                this.extendedKeyusages = Collections.unmodifiableSet(extendedKeyusageSet);
            }

            // AuthorityKeyIdentifier
            occurrence = extensionOccurences.get(Extension.authorityKeyIdentifier);
            if(occurrence != null)
            {
                boolean includeIssuerAndSerial = true;

                org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.AuthorityKeyIdentifier akiType =
                        extensionsType.getAuthorityKeyIdentifier();
                if(akiType != null)
                {
                    Boolean B = akiType.isIncludeIssuerAndSerial();
                    if(B != null)
                    {
                        includeIssuerAndSerial = B.booleanValue();
                    }
                }

                this.akiOption = new AuthorityKeyIdentifierOption(includeIssuerAndSerial, occurrence);
            }
            else
            {
                this.akiOption = null;
            }

            // Certificate Policies
            occurrence = occurrences.get(Extension.certificatePolicies);
            if(occurrence != null && extensionsType.getCertificatePolicies() != null)
            {
                this.certificatePolicies = new CertificatePoliciesConf(extensionsType.getCertificatePolicies());
            }

            // Policy Mappings
            occurrence = occurrences.get(Extension.policyMappings);
            if(occurrence != null && extensionsType.getPolicyMappings() != null)
            {
                this.policyMappings = new PolicyMappingsConf(extensionsType.getPolicyMappings());
            }

            // Name Constrains
            occurrence = occurrences.get(Extension.nameConstraints);
            if(occurrence != null && extensionsType.getNameConstraints() != null)
            {
                this.nameConstraints = new NameConstraintsConf(extensionsType.getNameConstraints());
            }

            // Policy Constraints
            occurrence = occurrences.get(Extension.policyConstraints);
            if(occurrence != null && extensionsType.getPolicyConstraints() == null)
            {
                this.policyConstraints = new PolicyConstraintsConf(extensionsType.getPolicyConstraints());
            }

            // Inhibit anyPolicy
            occurrence = occurrences.get(Extension.inhibitAnyPolicy);
            if(occurrence != null && extensionsType.getInhibitAnyPolicy() == null)
            {
                this.inhibitAnyPolicy = new InhibitAnyPolicyConf(extensionsType.getInhibitAnyPolicy());
            }

            // admission
            occurrence = occurrences.get(ObjectIdentifiers.id_extension_admission);
            if(occurrence != null && extensionsType.getAdmission() != null)
            {
                this.admission = new AdmissionConf(extensionsType.getAdmission());
            }

            // SubjectAltNameMode
            occurrence = occurrences.get(Extension.subjectAlternativeName);
            if(occurrence != null && extensionsType.getSubjectAltName() != null)
            {
                this.allowedSubjectAltNameModes = buildGeneralNameMode(extensionsType.getSubjectAltName());
            }

            // SubjectInfoAccess
            occurrence = occurrences.get(Extension.subjectInfoAccess);
            if(occurrence != null && extensionsType.getSubjectInfoAccess() != null)
            {
                List<Access> list = extensionsType.getSubjectInfoAccess().getAccess();
                this.allowedSubjectInfoAccessModes = new HashMap<>();
                for(Access entry : list)
                {
                    this.allowedSubjectInfoAccessModes.put(entry.getAccessMethod().getValue(),
                            buildGeneralNameMode(entry.getAccessLocation()));
                }
            }

            // constant extensions
            ConstantExtensions cess = extensionsType.getConstantExtensions();
            if(cess != null && cess.getConstantExtension().isEmpty() == false)
            {
                Map<ASN1ObjectIdentifier, byte[]> map = new HashMap<>();
                for(ConstantExtensionType ce : cess.getConstantExtension())
                {
                        ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(ce.getType().getValue());
                        occurrence = occurrences.get(type);
                        if(occurrence != null)
                        {
                            try
                            {
                                ASN1StreamParser parser = new ASN1StreamParser(ce.getValue());
                                parser.readObject();
                            } catch (IOException e)
                            {
                                throw new CertProfileException("Could not parse the constant extension value", e);
                            }
                            map.put(type, ce.getValue());
                        }
                }

                if(map.isEmpty() == false)
                {
                    this.constantExtensions = new HashMap<>(map.size());
                    this.constantExtensions = Collections.unmodifiableMap(map);
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

    public ValidationResult checkCert(byte[] certBytes, X509IssuerInfo issuerInfo,
            X500Name requestedSubject, SubjectPublicKeyInfo requestedPublicKey)
    {
        ParamChecker.assertNotNull("certBytes", certBytes);
        ParamChecker.assertNotNull("issuerInfo", issuerInfo);
        ParamChecker.assertNotNull("requestedSubject", requestedSubject);
        ParamChecker.assertNotNull("requestedPublicKey", requestedPublicKey);

        List<ValidationIssue> resultIssues = new LinkedList<ValidationIssue>();

        Certificate bcCert;
        X509Certificate cert;

        // certificate encoding
        {
            ValidationIssue issue = new ValidationIssue("X509.ENCODING", "certificate encoding");
            resultIssues.add(issue);
            try
            {
                bcCert = Certificate.getInstance(certBytes);
                cert = SecurityUtil.parseCert(certBytes);
            } catch (CertificateException | IOException e)
            {
                issue.setFailureMessage("certificate is not corrected encoded");
                return new ValidationResult(resultIssues);
            }
        }

        // syntax version
        {
            ValidationIssue issue = new ValidationIssue("X509.VERSION", "certificate version");
            resultIssues.add(issue);
            int versionNumber = cert.getVersion();
            if(versionNumber != syntaxVersion)
            {
                issue.setFailureMessage("is '" + versionNumber + "' but expected '" + syntaxVersion + "'");
            }
        }

        // signatureAlgorithm
        if(sigantureAlgorithms != null)
        {
            ValidationIssue issue = new ValidationIssue("X509.SIGALG", "signature algorithm");
            resultIssues.add(issue);

            AlgorithmIdentifier sigAlgId = bcCert.getSignatureAlgorithm();
            AlgorithmIdentifier tbsSigAlgId = bcCert.getTBSCertificate().getSignature();
            if(tbsSigAlgId.equals(sigAlgId) == false)
            {
                issue.setFailureMessage("Certificate.tbsCertificate.signature != Certificate.signatureAlgorithm");
            } else
            {
                String sigAlgo = sigAlgId.getAlgorithm().getId();
                if(sigantureAlgorithms.contains(sigAlgo) == false)
                {
                    issue.setFailureMessage("signatureAlgorithm '" + sigAlgo + "' is not allowed");
                }
            }
        }

        // notBefore
        if(notBeforeMidnight)
        {
            ValidationIssue issue = new ValidationIssue("X509.NOTBEFORE", "not before midnight");
            resultIssues.add(issue);
            Calendar c = Calendar.getInstance(UTC);
            c.setTime(cert.getNotBefore());
            int hourOfDay = c.get(Calendar.HOUR_OF_DAY);
            int minute = c.get(Calendar.MINUTE);
            int second = c.get(Calendar.SECOND);

            if(hourOfDay != 0 || minute != 0 || second != 0)
            {
                issue.setFailureMessage(" '" + cert.getNotBefore() + "' is not midnight time (UTC)");
            }
        }

        // validity
        {
            ValidationIssue issue = new ValidationIssue("X509.VALIDITY", "cert validity");
            resultIssues.add(issue);

            Date expectedNotAfter = validity.add(cert.getNotBefore());
            if(Math.abs(expectedNotAfter.getTime() - cert.getNotAfter().getTime()) > 60 * SECOND)
            {
                issue.setFailureMessage("cert validity is not within " + validity.toString());
            }
        }

        // public key
        {
            SubjectPublicKeyInfo publicKey = bcCert.getSubjectPublicKeyInfo();
            if(((nonEcKeyAlgorithms == null || nonEcKeyAlgorithms.isEmpty())
                    && (allowedEcCurves == null || allowedEcCurves.isEmpty())) == false)
            {
                ValidationIssue issue = new ValidationIssue("X509.PUBKEY.SYN", "whether public key is permitted");
                resultIssues.add(issue);
                try
                {
                    checkPublicKey(publicKey);
                }catch(BadCertTemplateException e)
                {
                    issue.setFailureMessage(e.getMessage());
                }
            }

            ValidationIssue issue = new ValidationIssue("X509.PUBKEY.REQ", "whether public key matches the request one");
            resultIssues.add(issue);
            SubjectPublicKeyInfo c14nRequestedPublicKey = SecurityUtil.toRfc3279Style(requestedPublicKey);
            if(c14nRequestedPublicKey.equals(publicKey) == false)
            {
                issue.setFailureMessage("public in the certificate does not equal the requested one");
            }
        }

        // Signature
        {
            ValidationIssue issue = new ValidationIssue("X509.SIG", "whether certificate is signed by CA");
            resultIssues.add(issue);
            try
            {
                cert.verify(issuerInfo.getCert().getPublicKey(), "BC");
            }catch(Exception e)
            {
                issue.setFailureMessage("invalid signature");
            }
        }

        // issuer
        {
            ValidationIssue issue = new ValidationIssue("X509.ISSUER", "certificate issuer");
            resultIssues.add(issue);
            if(cert.getIssuerX500Principal().equals(issuerInfo.getCert().getSubjectX500Principal()) == false)
            {
                issue.setFailureMessage("issue in certificate does not equal the subject of CA certificate");
            }
        }

        // subject
        X500Name subject = bcCert.getTBSCertificate().getSubject();
        resultIssues.addAll(checkSubject(subject, requestedSubject));

        // extensions
        resultIssues.addAll(checkExtensions(bcCert, cert, issuerInfo, requestedSubject));

        return new ValidationResult(resultIssues);
    }

    private List<ValidationIssue> checkExtensions(Certificate bcCert, X509Certificate cert,
            X509IssuerInfo issuerInfo, X500Name requestedSubject)
    {
        List<ValidationIssue> result = new LinkedList<>();

        Extensions extensions = bcCert.getTBSCertificate().getExtensions();
        ASN1ObjectIdentifier[] oids = extensions.getExtensionOIDs();
        if(oids == null)
        {
            ValidationIssue issue = new ValidationIssue("X509.EXT.GEN", "extension general");
            result.add(issue);
            issue.setFailureMessage("no extension is present");
            return result;
        }

        for(ASN1ObjectIdentifier extType : extensionOccurences.keySet())
        {
            ExtensionOccurrence extOccurrence = extensionOccurences.get(extType);
            if(extOccurrence.isRequired() == false)
            {
                continue;
            }

            boolean present = false;
            for(ASN1ObjectIdentifier oid : oids)
            {
                if(oid.equals(extType))
                {
                    present = true;
                    break;
                }
            }

            if(present == false)
            {
                ValidationIssue issue = createExtensionIssue(extType);
                result.add(issue);
                issue.setFailureMessage("extension is absent but is required");
            }
        }

        for(ASN1ObjectIdentifier oid : oids)
        {
            ValidationIssue issue = createExtensionIssue(oid);
            result.add(issue);

            Extension ext = extensions.getExtension(oid);
            StringBuilder failureMsg = new StringBuilder();
            ExtensionOccurrence extOccurrence = extensionOccurences.get(oid);
            if(extOccurrence == null)
            {
                failureMsg.append("extension is present but is not permitted");
                failureMsg.append("; ");
            } else if(extOccurrence.isCritical() != ext.isCritical())
            {
                failureMsg.append("critical is '" + ext.isCritical() +
                        "' but expected '" + extOccurrence.isCritical() + "'");
                failureMsg.append("; ");
            }

            byte[] extensionValue = ext.getExtnValue().getOctets();

            try
            {
                if(constantExtensions != null && constantExtensions.containsKey(oid))
                {
                    byte[] expectedextensionValue = constantExtensions.get(oid);
                    if(Arrays.equals(expectedextensionValue, extensionValue) == false)
                    {
                        failureMsg.append("extension valus is '" + hex(extensionValue) +
                                "' but expected '" + hex(expectedextensionValue) + "'");
                        failureMsg.append("; ");
                    }
                }
                else if(Extension.basicConstraints.equals(oid))
                {
                    checkExtensionBasicConstraints(extensionValue, failureMsg);
                } else if(Extension.subjectKeyIdentifier.equals(oid))
                {
                    checkExtensionSubjectKeyIdentifier(extensionValue, bcCert.getSubjectPublicKeyInfo(), failureMsg);
                } else if(Extension.authorityKeyIdentifier.equals(oid))
                {
                    checkExtensionIssuerKeyIdentifier(extensionValue, issuerInfo, failureMsg);
                } else if(Extension.keyUsage.equals(oid))
                {
                    if(keyusage != null)
                    {
                        checkExtensionKeyUsage(cert.getKeyUsage(), failureMsg);
                    }
                } else if(Extension.extendedKeyUsage.equals(oid))
                {
                    if(extendedKeyusages != null)
                    {
                        checkExtensionExtendedKeyUsage(extensionValue, failureMsg);
                    }
                } else if(Extension.certificatePolicies.equals(oid))
                {
                    if(certificatePolicies != null)
                    {
                        checkExtensionCertificatePolicies(extensionValue, failureMsg);
                    }
                } else if(Extension.policyMappings.equals(oid))
                {
                    if(policyMappings != null)
                    {
                        checkExtensionPolicyMappings(extensionValue, failureMsg);
                    }
                } else if(Extension.nameConstraints.equals(oid))
                {
                    if(nameConstraints != null)
                    {
                        checkExtensionNameConstraints(extensionValue, failureMsg);
                    }
                } else if(Extension.policyConstraints.equals(oid))
                {
                    if(policyConstraints != null)
                    {
                        checkExtensionPolicyConstraints(extensionValue, failureMsg);
                    }
                } else if(Extension.inhibitAnyPolicy.equals(oid))
                {
                    if(inhibitAnyPolicy != null)
                    {
                        checkExtensionInhibitAnyPolicy(extensionValue, failureMsg);
                    }
                } else if(Extension.subjectAlternativeName.equals(oid))
                {
                    checkExtensionSubjectAltName(extensionValue, requestedSubject, failureMsg);
                } else if(Extension.issuerAlternativeName.equals(oid))
                {
                    checkExtensionIssuerAltNames(extensionValue, issuerInfo, failureMsg);
                } else if(Extension.authorityInfoAccess.equals(oid))
                {
                    checkExtensionAuthorityInfoAccess(extensionValue, issuerInfo, failureMsg);
                } else if(Extension.cRLDistributionPoints.equals(oid))
                {
                    checkExtensionCrlDistributionPoints(extensionValue, issuerInfo, failureMsg);
                } else if(Extension.deltaCRLIndicator.equals(oid))
                {
                    checkExtensionDeltaCrlDistributionPoints(extensionValue, issuerInfo, failureMsg);
                } else if(ObjectIdentifiers.id_extension_admission.equals(oid))
                {
                    checkExtensionAdmission(extensionValue, issuerInfo, failureMsg);
                } else
                {
                    // do nothing
                }
            }catch(IllegalArgumentException | ClassCastException | ArrayIndexOutOfBoundsException e)
            {
                LOG.debug("extension value does not have correct syntax", e);
                issue.setFailureMessage("extension value does not have correct syntax");
            }

            if(failureMsg.length() > 0)
            {
                issue.setFailureMessage(failureMsg.toString());
            }
        }

        return result;
    }

    public static X509ProfileType parse(InputStream confStream)
    throws CertProfileException, IOException
    {
        synchronized (jaxbUnmarshallerLock)
        {
            JAXBElement<?> rootElement;
            try
            {
                if(jaxbUnmarshaller == null)
                {
                    JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
                    jaxbUnmarshaller = context.createUnmarshaller();

                    final SchemaFactory schemaFact = SchemaFactory.newInstance(
                            javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    URL url = X509CertProfileQA.class.getResource("/xsd/qa-x509certprofile.xsd");
                    jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
                }

                rootElement = (JAXBElement<?>) jaxbUnmarshaller.unmarshal(confStream);
            }
            catch(JAXBException | SAXException e)
            {
                throw new CertProfileException("parse profile failed, message: " + e.getMessage(), e);
            } finally
            {
                confStream.close();
            }

            Object rootType = rootElement.getValue();
            if(rootType instanceof X509ProfileType)
            {
                return (X509ProfileType) rootElement.getValue();
            }
            else
            {
                throw new CertProfileException("invalid root element type");
            }
        }
    }

    private void checkPublicKey(SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException
    {
        if((nonEcKeyAlgorithms == null || nonEcKeyAlgorithms.isEmpty())
                && (allowedEcCurves == null || allowedEcCurves.isEmpty()))
        {
            return;
        }

        ASN1ObjectIdentifier keyType = publicKey.getAlgorithm().getAlgorithm();
        if(X9ObjectIdentifiers.id_ecPublicKey.equals(keyType))
        {
            ASN1ObjectIdentifier curveOid;
            try
            {
                ASN1Encodable algParam = publicKey.getAlgorithm().getParameters();
                curveOid = ASN1ObjectIdentifier.getInstance(algParam);
            } catch(IllegalArgumentException e)
            {
                throw new BadCertTemplateException("Only named EC public key is supported");
            }

            if(allowedEcCurves != null && allowedEcCurves.isEmpty() == false)
            {
                if(allowedEcCurves.containsKey(curveOid) == false)
                {
                    throw new BadCertTemplateException("EC curve " + SecurityUtil.getCurveName(curveOid) +
                            " (OID: " + curveOid.getId() + ") is not allowed");
                }
            }

            byte[] keyData = publicKey.getPublicKeyData().getBytes();

            Set<Byte> allowedEncodings = allowedEcCurves.get(curveOid);
            if(allowedEncodings != null && allowedEncodings.isEmpty() == false)
            {
                if(allowedEncodings.contains(keyData[0]) == false)
                {
                    throw new BadCertTemplateException("Unaccepted EC point encoding " + keyData[0]);
                }
            }

            try
            {
                checkECSubjectPublicKeyInfo(curveOid, publicKey.getPublicKeyData().getBytes());
            }catch(BadCertTemplateException e)
            {
                throw e;
            }catch(Exception e)
            {
                LOG.debug("populateFromPubKeyInfo", e);
                throw new BadCertTemplateException("Invalid public key: " + e.getMessage());
            }

            return;
        }
        else
        {
            if(nonEcKeyAlgorithms == null || allowedEcCurves.isEmpty())
            {
                return;
            }

            if(nonEcKeyAlgorithms.containsKey(keyType))
            {
                List<KeyParamRanges> list = nonEcKeyAlgorithms.get(keyType);
                if(list.isEmpty())
                {
                    return;
                }

                if(PKCSObjectIdentifiers.rsaEncryption.equals(keyType))
                {
                    ASN1Sequence seq = ASN1Sequence.getInstance(publicKey.getPublicKeyData().getBytes());
                    ASN1Integer modulus = ASN1Integer.getInstance(seq.getObjectAt(0));
                    int modulusLength = modulus.getPositiveValue().bitLength();
                    for(KeyParamRanges ranges : list)
                    {
                        if(satisfy(modulusLength, MODULUS_LENGTH, ranges))
                        {
                            return;
                        }
                    }
                }
                else if(X9ObjectIdentifiers.id_dsa.equals(keyType))
                {
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

                    for(KeyParamRanges ranges : list)
                    {
                        boolean match = satisfy(pLength, P_LENGTH, ranges);
                        if(match)
                        {
                            match = satisfy(qLength, Q_LENGTH, ranges);
                        }

                        if(match)
                        {
                            return;
                        }
                    }
                }
                else
                {
                    throw new BadCertTemplateException("Unknown key type " + keyType.getId());
                }
            }
        }

        throw new BadCertTemplateException("the given publicKey is not permitted");
    }

    private static void checkECSubjectPublicKeyInfo(ASN1ObjectIdentifier curveOid, byte[] encoded)
    throws BadCertTemplateException
    {
        Integer expectedLength = ecCurveFieldSizes.get(curveOid);
        if(expectedLength == null)
        {
            X9ECParameters ecP = ECUtil.getNamedCurveByOid(curveOid);
            ECCurve curve = ecP.getCurve();
            expectedLength = (curve.getFieldSize() + 7) / 8;
            ecCurveFieldSizes.put(curveOid, expectedLength);
        }

        switch (encoded[0])
        {
            case 0x02: // compressed
            case 0x03: // compressed
            {
                if (encoded.length != (expectedLength + 1))
                {
                    throw new BadCertTemplateException("Incorrect length for compressed encoding");
                }
                break;
            }
            case 0x04: // uncompressed
            case 0x06: // hybrid
            case 0x07: // hybrid
            {
                if (encoded.length != (2 * expectedLength + 1))
                {
                    throw new BadCertTemplateException("Incorrect length for uncompressed/hybrid encoding");
                }
                break;
            }
            default:
                throw new BadCertTemplateException("Invalid point encoding 0x" + Integer.toString(encoded[0], 16));
        }
    }

    private static boolean satisfy(int len, String paramName, KeyParamRanges ranges)
    {
        List<KeyParamRange> rangeList = ranges.getRanges(paramName);
        if(rangeList == null || rangeList.isEmpty())
        {
            return true;
        }

        for(KeyParamRange range : rangeList)
        {
            if(range.match(len))
            {
                return true;
            }
        }

        return false;
    }

    private List<ValidationIssue> checkSubject(X500Name subject, X500Name requestedSubject)
    {
        // collect subject attribute types to check
        Set<ASN1ObjectIdentifier> oids = new HashSet<>();

        for(ASN1ObjectIdentifier oid : subjectDNOccurrences.keySet())
        {
            oids.add(oid);
        }

        for(ASN1ObjectIdentifier oid : subject.getAttributeTypes())
        {
            oids.add(oid);
        }

        List<ValidationIssue> result = new LinkedList<>();
        for(ASN1ObjectIdentifier type : oids)
        {
            ValidationIssue issue = checkSubjectAttribute(type, subject, requestedSubject);
            result.add(issue);
        }

        return result;
    }

    private ValidationIssue checkSubjectAttribute(ASN1ObjectIdentifier type,
            X500Name subject, X500Name requestedSubject)
    {
        ValidationIssue issue = createSubjectIssue(type);

        // occurrence
        int minOccurs;
        int maxOccurs;
        RDNOccurrence rdnOccurrence = subjectDNOccurrences.get(type);
        if(rdnOccurrence == null)
        {
            minOccurs = 0;
            maxOccurs = 0;
        } else
        {
            minOccurs = rdnOccurrence.getMinOccurs();
            maxOccurs = rdnOccurrence.getMaxOccurs();
        }
        RDN[] rdns = subject.getRDNs(type);
        int rdnsSize = rdns == null ? 0 : rdns.length;

        if(rdnsSize < minOccurs || rdnsSize > maxOccurs)
        {
            issue.setFailureMessage("number of RDNs '" + rdnsSize +
                    "' is not within [" + minOccurs + ", " + maxOccurs + "]");
            return issue;
        }

        RDN[] requestedRdns = null;
        if(ignoreRDNs.contains(type) == false)
        {
            requestedRdns = requestedSubject.getRDNs(type);
        }

        if(rdnsSize == 0)
        {
            // check optional attribute but is present in requestedSubject
            if(maxOccurs > 0 && requestedRdns != null && requestedRdns.length > 0)
            {
                issue.setFailureMessage("is absent but expected present");
            }
            return issue;
        }

        SubjectDNOption rdnOption = subjectDNOptions.get(type);

        // check the encoding
        DirectoryStringType stringType;
        if(rdnOption != null && rdnOption.getDirectoryStringType() != null)
        {
            stringType = rdnOption.getDirectoryStringType();
        } else if(ObjectIdentifiers.DN_C.equals(type) || ObjectIdentifiers.DN_SERIALNUMBER.equals(type))
        {
            stringType = DirectoryStringType.PRINTABLE_STRING;
        } else
        {
            stringType = DirectoryStringType.UTF_8_STRING;
        }

        StringBuilder failureMsg = new StringBuilder();
        List<String> requestedCoreAtvTextValues = new LinkedList<>();
        if(requestedRdns != null)
        {
            for(RDN requestedRdn : requestedRdns)
            {
                String textValue = SecurityUtil.rdnValueToString(requestedRdn.getFirst().getValue());
                requestedCoreAtvTextValues.add(textValue);
            }

            // sort the requestedRDNs
            if(rdnOption != null && rdnOption.getPatterns() != null)
            {
                List<String> sorted = new ArrayList<>(requestedCoreAtvTextValues.size());
                for(Pattern p : rdnOption.getPatterns())
                {
                    for(String value : requestedCoreAtvTextValues)
                    {
                        if(sorted.contains(value) == false && p.matcher(value).matches())
                        {
                            sorted.add(value);
                        }
                    }
                }
                for(String value : requestedCoreAtvTextValues)
                {
                    if(sorted.contains(value) == false)
                    {
                        sorted.add(value);
                    }
                }
                requestedCoreAtvTextValues = sorted;
            }
        }

        for(int i = 0; i < rdns.length; i++)
        {
            RDN rdn = rdns[i];
            AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
            if(atvs.length > 1)
            {
                failureMsg.append("Size of RDN + [" + i + "]is '" + atvs.length + "' but expected '1'");
                failureMsg.append("; ");
                continue;
            }

            ASN1Encodable atvValue = atvs[0].getValue();
            boolean correctStringType = true;
            switch(stringType)
            {
                case BMP_STRING:
                    correctStringType = (atvValue instanceof DERBMPString);
                    break;
                case PRINTABLE_STRING:
                    correctStringType = (atvValue instanceof DERPrintableString);
                    break;
                case TELETEX_STRING:
                    correctStringType = (atvValue instanceof DERT61String);
                    break;
                case UNIVERSAL_STRING:
                    correctStringType = (atvValue instanceof DERUniversalString);
                    break;
                case UTF_8_STRING:
                    correctStringType = (atvValue instanceof DERUTF8String);
                    break;
                default:
                    throw new RuntimeException("should not reach here");
            }

            if(correctStringType == false)
            {
                failureMsg.append("RDN + [" + i + "] is not of type DirectoryString." + stringType.value());
                failureMsg.append("; ");
                continue;
            }

            String atvTextValue = SecurityUtil.rdnValueToString(atvValue);
            String coreAtvTextValue = atvTextValue;

            if(rdnOption != null)
            {
                String prefix = rdnOption.getPrefix();

                if(prefix != null)
                {
                    if(coreAtvTextValue.startsWith(prefix) == false)
                    {
                        failureMsg.append("RDN + [" + i + "] '" + atvTextValue+
                                "' does not start with prefix '" + prefix + "'");
                        failureMsg.append("; ");
                        continue;
                    } else
                    {
                        coreAtvTextValue = coreAtvTextValue.substring(prefix.length());
                    }
                }

                String suffix = rdnOption.getSuffix();
                if(suffix != null)
                {
                    if(coreAtvTextValue.endsWith(suffix) == false)
                    {
                        failureMsg.append("RDN + [" + i + "] '" + atvTextValue+
                                "' does not end with suffx '" + suffix + "'");
                        failureMsg.append("; ");
                        continue;
                    } else
                    {
                        coreAtvTextValue = coreAtvTextValue.substring(0, coreAtvTextValue.length() - suffix.length());
                    }
                }

                List<Pattern> patterns = rdnOption.getPatterns();
                if(patterns != null)
                {
                    Pattern pattern = patterns.get(i);
                    boolean matches = pattern.matcher(coreAtvTextValue).matches();
                    if(matches == false)
                    {
                        failureMsg.append("RDN + [" + i + "] '" + coreAtvTextValue+
                                "' is not valid against regex '" + pattern.pattern() + "'");
                        failureMsg.append("; ");
                        continue;
                    }
                }
            }

            if(rdnOption == null || rdnOption.isIgnoreReq() == false)
            {
                if(requestedCoreAtvTextValues.isEmpty())
                {
                    if(type.equals(ObjectIdentifiers.DN_SERIALNUMBER) == false)
                    {
                        failureMsg.append("is present but not contained in the request");
                        failureMsg.append("; ");
                    }
                } else
                {
                    String requestedCoreAtvTextValue = requestedCoreAtvTextValues.get(i);
                    if(ObjectIdentifiers.DN_CN.equals(type) &&
                            specialBehavior != null && "gematik_gSMC_K".equals(specialBehavior))
                    {
                        if(coreAtvTextValue.startsWith(requestedCoreAtvTextValue + "-") == false)
                        {
                            failureMsg.append("content '" + coreAtvTextValue + "' does not start with '" +
                                    requestedCoreAtvTextValue + "-'");
                            failureMsg.append("; ");
                        }
                    } else
                    {
                        if(coreAtvTextValue.equals(requestedCoreAtvTextValue) == false)
                        {
                            failureMsg.append("content '" + coreAtvTextValue + "' but expected '" +
                                    requestedCoreAtvTextValue + "'");
                            failureMsg.append("; ");
                        }
                    }
                }
            }
        }

        int n = failureMsg.length();
        if(n > 2)
        {
            failureMsg.delete(n - 2, n);
            issue.setFailureMessage(failureMsg.toString());
        }

        return issue;
    }

    public boolean includeIssuerAndSerialInAKI()
    {
        return akiOption == null ? false : akiOption.isIncludeIssuerAndSerial();
    }

    private static int getInt(Integer i, int dfltValue)
    {
        return i == null ? dfltValue : i.intValue();
    }

    private static Set<GeneralNameMode> buildGeneralNameMode(GeneralNameType name)
    {
        Set<GeneralNameMode> ret = new HashSet<>();
        if(name.getOtherName() != null)
        {
            List<OidWithDescType> list = name.getOtherName().getType();
            Set<ASN1ObjectIdentifier> set = new HashSet<>();
            for(OidWithDescType entry : list)
            {
                set.add(new ASN1ObjectIdentifier(entry.getValue()));
            }
            ret.add(new GeneralNameMode(GeneralNameTag.otherName, set));
        }

        if(name.getRfc822Name() != null)
        {
            ret.add(new GeneralNameMode(GeneralNameTag.rfc822Name));
        }

        if(name.getDNSName() != null)
        {
            ret.add(new GeneralNameMode(GeneralNameTag.dNSName));
        }

        if(name.getDirectoryName() != null)
        {
            ret.add(new GeneralNameMode(GeneralNameTag.directoryName));
        }

        if(name.getEdiPartyName() != null)
        {
            ret.add(new GeneralNameMode(GeneralNameTag.ediPartyName));
        }

        if(name.getUniformResourceIdentifier() != null)
        {
            ret.add(new GeneralNameMode(GeneralNameTag.uniformResourceIdentifier));
        }

        if(name.getIPAddress() != null)
        {
            ret.add(new GeneralNameMode(GeneralNameTag.iPAddress));
        }

        if(name.getRegisteredID() != null)
        {
            ret.add(new GeneralNameMode(GeneralNameTag.registeredID));
        }

        return ret;
    }

    private ValidationIssue createSubjectIssue(ASN1ObjectIdentifier subjectAttrType)
    {
        ValidationIssue issue;
        String attrName = ObjectIdentifiers.getName(subjectAttrType);
        if(attrName == null)
        {
            attrName = subjectAttrType.getId().replace('.', '_');
            issue = new ValidationIssue("X509.SUBJECT." + attrName, "attribute " + subjectAttrType.getId());
        }
        else
        {
            issue = new ValidationIssue("X509.SUBJECT." + attrName, "extension " + attrName +
                    " (" + subjectAttrType.getId() + ")");
        }
        return issue;
    }

    private ValidationIssue createExtensionIssue(ASN1ObjectIdentifier extId)
    {
        ValidationIssue issue;
        String extName = extOidNameMap.get(extId);
        if(extName == null)
        {
            extName = extId.getId().replace('.', '_');
            issue = new ValidationIssue("X509.EXT." + extName, "extension " + extId.getId());
        }
        else
        {
            issue = new ValidationIssue("X509.EXT." + extName, "extension " + extName + " (" + extId.getId() + ")");
        }
        return issue;
    }

    private void checkExtensionBasicConstraints(byte[] extensionValue, StringBuilder failureMsg)
    {
        BasicConstraints bc =  BasicConstraints.getInstance(extensionValue);
        if(ca != bc.isCA())
        {
            failureMsg.append("ca is '" + bc.isCA() + "' but expected '" + ca + "'");
            failureMsg.append("; ");
        }

        if(bc.isCA())
        {
            BigInteger _pathLen = bc.getPathLenConstraint();
            if(pathLen == null)
            {
                if(_pathLen != null)
                {
                    failureMsg.append("pathLen is '" + _pathLen + "' but expected 'absent'");
                    failureMsg.append("; ");
                }
            }
            else
            {
                if(_pathLen == null)
                {
                    failureMsg.append("pathLen is 'null' but expected '" +  pathLen + "'");
                    failureMsg.append("; ");
                }
                else if(BigInteger.valueOf(pathLen).equals(_pathLen)== false)
                {
                    failureMsg.append("pathLen is '" + _pathLen + "' but expected '" +  pathLen + "'");
                    failureMsg.append("; ");
                }
            }
        }
    }

    private void checkExtensionSubjectKeyIdentifier(byte[] extensionValue, SubjectPublicKeyInfo subjectPublicKeyInfo,
            StringBuilder failureMsg)
    {
        // subjectKeyIdentifier
        SubjectKeyIdentifier asn1 = SubjectKeyIdentifier.getInstance(extensionValue);
        byte[] ski = asn1.getKeyIdentifier();
        byte[] pkData = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        byte[] expectedSki = HashCalculator.hash(HashAlgoType.SHA1, pkData);
        if(Arrays.equals(expectedSki, ski) == false)
        {
            failureMsg.append("SKI is '" + hex(ski) + "' but expected is '" + hex(expectedSki) + "'");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionIssuerKeyIdentifier(byte[] extensionValue, X509IssuerInfo issuerInfo,
            StringBuilder failureMsg)
    {
        AuthorityKeyIdentifier asn1 = AuthorityKeyIdentifier.getInstance(extensionValue);
        byte[] keyIdentifier = asn1.getKeyIdentifier();
        if(keyIdentifier == null)
        {
            failureMsg.append("keyIdentifier is 'absent' but expected 'present'");
            failureMsg.append("; ");
        }
        else if(Arrays.equals(issuerInfo.getSubjectKeyIdentifier(), keyIdentifier) == false)
        {
            failureMsg.append("keyIdentifier is '" + hex(keyIdentifier) + "' but expected '" +
                    hex(issuerInfo.getSubjectKeyIdentifier()) + "'");
            failureMsg.append("; ");
        }

        BigInteger serialNumber = asn1.getAuthorityCertSerialNumber();
        GeneralNames names = asn1.getAuthorityCertIssuer();
        if(serialNumber != null)
        {
            if(names == null)
            {
                failureMsg.append("authorityCertIssuer is 'absent' but expected 'present'");
                failureMsg.append("; ");
            }
            if(issuerInfo.getCert().getSerialNumber().equals(serialNumber) == false)
            {
                failureMsg.append("authorityCertSerialNumber is '" + serialNumber + "' but expected '" +
                        issuerInfo.getCert().getSerialNumber() + "'");
                failureMsg.append("; ");
            }
        }

        if(names != null)
        {
            if(serialNumber == null)
            {
                failureMsg.append("authorityCertSerialNumber is 'absent' but expected 'present'");
                failureMsg.append("; ");
            }
            GeneralName[] genNames = names.getNames();
            X500Name x500GenName = null;
            for(GeneralName genName : genNames)
            {
                if(genName.getTagNo() == GeneralName.directoryName)
                {
                    if(x500GenName != null)
                    {
                        failureMsg.append("authorityCertIssuer contains at least two directoryName "
                                + "but expected one");
                        failureMsg.append("; ");
                        break;
                    }
                    else
                    {
                        x500GenName = (X500Name) genName.getName();
                    }
                }
            }

            if(x500GenName == null)
            {
                failureMsg.append("authorityCertIssuer does not contain directoryName but expected one");
                failureMsg.append("; ");
            }
            else
            {
                X500Name caSubject = issuerInfo.getBcCert().getTBSCertificate().getSubject();
                if(caSubject.equals(x500GenName) == false)
                {
                    failureMsg.append("authorityCertIssuer is '" + x500GenName.toString()
                            + "' but expected '" + caSubject.toString() + "'");
                    failureMsg.append("; ");
                }
            }
        }
    }

    private void checkExtensionNameConstraints(byte[] extensionValue, StringBuilder failureMsg)
    {
        org.bouncycastle.asn1.x509.NameConstraints iNameConstraints =
                org.bouncycastle.asn1.x509.NameConstraints.getInstance(extensionValue);
        checkExtensionNameConstraintsSubtrees("PermittedSubtrees", iNameConstraints.getPermittedSubtrees(),
                nameConstraints.getPermittedSubtrees(), failureMsg);
        checkExtensionNameConstraintsSubtrees("ExcludedSubtrees", iNameConstraints.getExcludedSubtrees(),
                nameConstraints.getExcludedSubtrees(), failureMsg);
    }

    private void checkExtensionNameConstraintsSubtrees(String description, GeneralSubtree[] subtrees,
            List<GeneralSubtreeConf> expectedSubtrees, StringBuilder failureMsg)
    {
        int iSize = subtrees == null ? 0 : subtrees.length;
        int eSize = expectedSubtrees == null ? 0 : expectedSubtrees.size();
        if(iSize != eSize)
        {
            failureMsg.append("Size of " + description + " is '" + iSize + "' but expected '" + eSize + "'");
            failureMsg.append("; ");
        } else
        {
            for(int i = 0; i < iSize; i++)
            {
                GeneralSubtree iSubtree = subtrees[i];
                GeneralSubtreeConf eSubtree = expectedSubtrees.get(i);
                BigInteger bigInt = iSubtree.getMinimum();
                int iMinimum = bigInt == null ? 0 : bigInt.intValue();
                Integer _int = eSubtree.getMinimum();
                int eMinimum = _int == null ? 0 : _int.intValue();
                String desc = description + " [" + i + "]";
                if(iMinimum != eMinimum)
                {
                    failureMsg.append("minimum of " + desc + " is '" + iMinimum + "' but expected '" + eMinimum + "'");
                    failureMsg.append("; ");
                }

                bigInt = iSubtree.getMaximum();
                Integer iMaximum = bigInt == null ? null : bigInt.intValue();
                Integer eMaximum = eSubtree.getMaximum();
                if(iMaximum != eMaximum)
                {
                    failureMsg.append("maxmum of " + desc + " is '" + iMaximum + "' but expected '" + eMaximum + "'");
                    failureMsg.append("; ");
                }

                GeneralName iBase = iSubtree.getBase();

                GeneralName eBase;
                if(eSubtree.getDirectoryName() != null)
                {
                    eBase = new GeneralName(SecurityUtil.reverse(
                            new X500Name(eSubtree.getDirectoryName())));
                }
                else if(eSubtree.getDNSName() != null)
                {
                    eBase = new GeneralName(GeneralName.dNSName, eSubtree.getDNSName());
                }
                else if(eSubtree.getIpAddress() != null)
                {
                    eBase = new GeneralName(GeneralName.iPAddress, eSubtree.getIpAddress());
                }
                else if(eSubtree.getRfc822Name() != null)
                {
                    eBase = new GeneralName(GeneralName.rfc822Name, eSubtree.getRfc822Name());
                }
                else if(eSubtree.getUri() != null)
                {
                    eBase = new GeneralName(GeneralName.uniformResourceIdentifier, eSubtree.getUri());
                }
                else
                {
                    throw new RuntimeException("should not reach here");
                }

                if(iBase.equals(eBase) == false)
                {
                    failureMsg.append("base of " + desc + " is '" + iBase + "' but expected '" + eBase + "'");
                    failureMsg.append("; ");
                }
            }
        }
    }

    private void checkExtensionPolicyConstraints(byte[] extensionValue, StringBuilder failureMsg)
    {
        org.bouncycastle.asn1.x509.PolicyConstraints iPolicyConstraints =
                org.bouncycastle.asn1.x509.PolicyConstraints.getInstance(extensionValue);
        Integer eRequireExplicitPolicy = policyConstraints.getRequireExplicitPolicy();
        BigInteger bigInt = iPolicyConstraints.getRequireExplicitPolicyMapping();
        Integer iRequreExplicitPolicy = bigInt == null ? null : bigInt.intValue();

        boolean match = true;
        if(eRequireExplicitPolicy == null)
        {
            if(iRequreExplicitPolicy != null)
            {
                match = false;
            }
        } else if(eRequireExplicitPolicy.equals(iRequreExplicitPolicy) == false)
        {
            match = false;
        }

        if(match == false)
        {
            failureMsg.append("requreExplicitPolicy is '" + iRequreExplicitPolicy + "' but expected '" +
                    eRequireExplicitPolicy + "'");
            failureMsg.append("; ");
        }

        Integer eInhibitPolicyMapping = policyConstraints.getInhibitPolicyMapping();
        bigInt = iPolicyConstraints.getInhibitPolicyMapping();
        Integer iInhibitPolicyMapping = bigInt == null ? null : bigInt.intValue();

        match = true;
        if(eInhibitPolicyMapping == null)
        {
            if(iInhibitPolicyMapping != null)
            {
                match = false;
            }
        } else if(eInhibitPolicyMapping.equals(iInhibitPolicyMapping) == false)
        {
            match = false;
        }

        if(match == false)
        {
            failureMsg.append("inhibitPolicyMapping is '" + iInhibitPolicyMapping + "' but expected '" +
                    eInhibitPolicyMapping + "'");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionKeyUsage(boolean[] usages, StringBuilder failureMsg)
    {
        Set<String> iUsages = new HashSet<>();
        int n = usages.length;

        if(n > allUsages.size())
        {
            failureMsg.append("invalid syntax: size of valid bits is larger than 8");
            failureMsg.append("; ");
        }
        else
        {
            for(int i = 0; i < n; i++)
            {
                if(usages[i])
                {
                    iUsages.add(allUsages.get(i));
                }
            }

            Set<String> diffs = str_in_b_not_in_a(keyusage, iUsages);
            if(diffs.isEmpty() == false)
            {
                failureMsg.append("Usages " + diffs.toString() + " are present but not expected");
                failureMsg.append("; ");
            }

            diffs = str_in_b_not_in_a(iUsages, keyusage);
            if(diffs.isEmpty() == false)
            {
                failureMsg.append("Usages " + diffs.toString() + " are absent but are required");
                failureMsg.append("; ");
            }
        }
    }

    private void checkExtensionExtendedKeyUsage(byte[] extensionValue, StringBuilder failureMsg)
    {
        ExtendedKeyUsage asn1 = ExtendedKeyUsage.getInstance(extensionValue);
        KeyPurposeId[] _usages = asn1.getUsages();
        Set<String> iUsages = new HashSet<>();
        for(KeyPurposeId _usage : _usages)
        {
            iUsages.add(_usage.getId());
        }

        Set<String> diffs = str_in_b_not_in_a(extendedKeyusages, iUsages);
        if(diffs.isEmpty() == false)
        {
            failureMsg.append("Usages " + diffs.toString() + " are present but not expected");
            failureMsg.append("; ");
        }

        diffs = str_in_b_not_in_a(iUsages, extendedKeyusages);
        if(diffs.isEmpty() == false)
        {
            failureMsg.append("Usages " + diffs.toString() + " are absent but are required");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionCertificatePolicies(byte[] extensionValue, StringBuilder failureMsg)
    {
        org.bouncycastle.asn1.x509.CertificatePolicies asn1 =
                org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(extensionValue);
        PolicyInformation[] iPolicyInformations = asn1.getPolicyInformation();

        for(PolicyInformation iPolicyInformation : iPolicyInformations)
        {
            ASN1ObjectIdentifier iPolicyId = iPolicyInformation.getPolicyIdentifier();
            CertificatePolicyInformationConf eCp = certificatePolicies.getPolicyInformation(iPolicyId.getId());
            if(eCp == null)
            {
                failureMsg.append("certificate policy '" + iPolicyId + "' is not expected");
            } else
            {
                PolicyQualifiersConf eCpPq = eCp.getPolicyQualifiers();
                if(eCpPq != null)
                {
                    ASN1Sequence iPolicyQualifiers = iPolicyInformation.getPolicyQualifiers();
                    List<String> iCpsUris = new LinkedList<>();
                    List<String> iUserNotices = new LinkedList<>();

                    int n = iPolicyQualifiers.size();
                    for(int i = 0; i < n; i++)
                    {
                        PolicyQualifierInfo iPolicyQualifierInfo =
                                (PolicyQualifierInfo) iPolicyQualifiers.getObjectAt(i);
                        ASN1ObjectIdentifier iPolicyQualifierId = iPolicyQualifierInfo.getPolicyQualifierId();
                        ASN1Encodable iQualifier = iPolicyQualifierInfo.getQualifier();
                        if(PolicyQualifierId.id_qt_cps.equals(iPolicyQualifierId))
                        {
                            String iCpsUri = ((DERIA5String) iQualifier).getString();
                            iCpsUris.add(iCpsUri);
                        } else if (PolicyQualifierId.id_qt_unotice.equals(iPolicyQualifierId))
                        {
                            UserNotice iUserNotice = UserNotice.getInstance(iQualifier);
                            if(iUserNotice.getExplicitText() != null)
                            {
                                iUserNotices.add(iUserNotice.getExplicitText().getString());
                            }
                        }
                    }

                    List<PolicyQualifierInfoConf> qualifierInfos = eCpPq.getPolicyQualifiers();
                    for(PolicyQualifierInfoConf qualifierInfo : qualifierInfos)
                    {
                        if(qualifierInfo instanceof CPSUriPolicyQualifierInfo)
                        {
                            String value = ((CPSUriPolicyQualifierInfo) qualifierInfo).getCPSUri();
                            if(iCpsUris.contains(value) == false)
                            {
                                failureMsg.append("CPSUri '" + value + "' is absent but is required");
                            }
                        }else if(qualifierInfo instanceof UserNoticePolicyQualifierInfo)
                        {
                            String value = ((UserNoticePolicyQualifierInfo) qualifierInfo).getUserNotice();
                            if(iUserNotices.contains(value) == false)
                            {
                                failureMsg.append("userNotice '" + value + "' is absent but is required");
                            }
                        }else
                        {
                            throw new RuntimeException("should not reach here");
                        }
                    }
                }
            }
        }

        for(CertificatePolicyInformationConf cp : certificatePolicies.getPolicyInformations())
        {
            boolean present = false;
            for(PolicyInformation iPolicyInformation : iPolicyInformations)
            {
                if(iPolicyInformation.getPolicyIdentifier().getId().equals(cp.getPolicyId()))
                {
                    present = true;
                    break;
                }
            }

            if(present == false)
            {
                failureMsg.append("certificate policy '" + cp.getPolicyId() + "' is "
                        + "absent but is required");
                failureMsg.append("; ");
            }
        }
    }

    private void checkExtensionPolicyMappings(byte[] extensionValue, StringBuilder failureMsg)
    {
        ASN1Sequence iPolicyMappings = DERSequence.getInstance(extensionValue);
        Map<String, String> iMap = new HashMap<>();
        int size = iPolicyMappings.size();
        for(int i = 0; i < size; i++)
        {
            ASN1Sequence seq = (ASN1Sequence) iPolicyMappings.getObjectAt(i);

            CertPolicyId issuerDomainPolicy = CertPolicyId.getInstance(seq.getObjectAt(0));
            CertPolicyId subjectDomainPolicy = CertPolicyId.getInstance(seq.getObjectAt(1));
            iMap.put(issuerDomainPolicy.getId(), subjectDomainPolicy.getId());
        }

        Set<String> eIssuerDomainPolicies = policyMappings.getIssuerDomainPolicies();
        for(String eIssuerDomainPolicy : eIssuerDomainPolicies)
        {
            String eSubjectDomainPolicy = policyMappings.getSubjectDomainPolicy(eIssuerDomainPolicy);

            String iSubjectDomainPolicy = iMap.remove(eIssuerDomainPolicy);
            if(iSubjectDomainPolicy == null)
            {
                failureMsg.append("issuerDomainPolicy '" + eIssuerDomainPolicy + "' is absent but is required");
                failureMsg.append("; ");
            } else if(iSubjectDomainPolicy.equals(eSubjectDomainPolicy) == false)
            {
                failureMsg.append("subjectDomainPolicy for issuerDomainPolicy is '" + iSubjectDomainPolicy +
                        "' but expected '" + eSubjectDomainPolicy + "'");
                failureMsg.append("; ");
            }
        }

        if(iMap.isEmpty() == false)
        {
            failureMsg.append("issuerDomainPolicies '" + iMap.keySet() + "' are present but not expected");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionInhibitAnyPolicy(byte[] extensionValue, StringBuilder failureMsg)
    {
        ASN1Integer asn1Int = ASN1Integer.getInstance(extensionValue);
        int iSkipCerts = asn1Int.getPositiveValue().intValue();
        if(iSkipCerts != inhibitAnyPolicy.getSkipCerts())
        {
            failureMsg.append("skipCerts is '" + iSkipCerts + "' but expected '" +
                    inhibitAnyPolicy.getSkipCerts() + "'");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionSubjectAltName(byte[] extensionValue,
            X500Name requestedSubject, StringBuilder failureMsg)
    {
        RDN[] rdns = requestedSubject.getRDNs(Extension.subjectAlternativeName);
        if(rdns == null || rdns.length < 1)
        {
            failureMsg.append("subjectAltName is present but is not expected");
            failureMsg.append("; ");
            return;
        }

        final int eSize = rdns.length;

        GeneralName[] _iNames = GeneralNames.getInstance(extensionValue).getNames();
        if(_iNames.length != eSize)
        {
            failureMsg.append("size of GeneralNames is '" + _iNames.length + "' but expected '" +
                    eSize + "'");
            failureMsg.append("; ");
            return;
        }
        List<GeneralName> iNames = new LinkedList<>();
        for(GeneralName iName : _iNames)
        {
            iNames.add(iName);
        }

        List<GeneralName> eNames = new LinkedList<>();
        for(int i = 0; i < eSize; i++)
        {
            String value = SecurityUtil.rdnValueToString(rdns[i].getFirst().getValue());
            eNames.add(createGeneralName(value, allowedSubjectAltNameModes));
        }

        Set<Object> diffs = obj_in_b_not_in_a(eNames, iNames);
        if(diffs.isEmpty() == false)
        {
            failureMsg.append("subjectAltName entries " + diffs.toString() + " are present but not expected");
            failureMsg.append("; ");
        }

        diffs = obj_in_b_not_in_a(iNames, eNames);
        if(diffs.isEmpty() == false)
        {
            failureMsg.append("subjectAltName entries " + diffs.toString() + " are absent but are required");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionIssuerAltNames(byte[] extensionValue,
            X509IssuerInfo issuerInfo, StringBuilder failureMsg)
    {
        Extension caSubjectAltExtension = issuerInfo.getBcCert().getTBSCertificate().getExtensions().getExtension(
                Extension.subjectAlternativeName);
        if(caSubjectAltExtension == null)
        {
            failureMsg.append("issuerAlternativeName is present but expected 'none'");
            failureMsg.append("; ");
        }
        else
        {
            byte[] caSubjectAltExtensionValue = caSubjectAltExtension.getExtnValue().getOctets();
            if(Arrays.equals(caSubjectAltExtensionValue, extensionValue) == false)
            {
                failureMsg.append("is '" + hex(extensionValue) + "' but expected '" +
                        hex(caSubjectAltExtensionValue) + "'");
                failureMsg.append("; ");
            }
        }
    }

    private void checkExtensionAuthorityInfoAccess(byte[] extensionValue,
            X509IssuerInfo issuerInfo, StringBuilder failureMsg)
    {
        Set<String> eOCSPUris = issuerInfo.getOcspURLs();
        if(eOCSPUris == null)
        {
            failureMsg.append("AIA is present but expected is 'none'");
            failureMsg.append("; ");
        }
        else
        {
            AuthorityInformationAccess iAIA = AuthorityInformationAccess.getInstance(extensionValue);
            AccessDescription[] iAccessDescriptions = iAIA.getAccessDescriptions();
            List<AccessDescription> iOCSPAccessDescriptions = new LinkedList<>();
            for(AccessDescription iAccessDescription : iAccessDescriptions)
            {
                if(iAccessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_ocsp))
                {
                    iOCSPAccessDescriptions.add(iAccessDescription);
                }
            }

            int n = iOCSPAccessDescriptions.size();
            if(n != eOCSPUris.size())
            {
                failureMsg.append("Number of AIA OCSP URIs is '" + n +
                        "' but expected is '" + eOCSPUris.size() + "'");
                failureMsg.append("; ");
            }
            else
            {
                Set<String> iOCSPUris = new HashSet<>();
                for(int i = 0; i < n; i++)
                {
                    GeneralName iAccessLocation = iOCSPAccessDescriptions.get(i).getAccessLocation();
                    if(iAccessLocation.getTagNo() != GeneralName.uniformResourceIdentifier)
                    {
                        failureMsg.append("Tag of accessLocation of AIA OCSP is '" + iAccessLocation.getTagNo() +
                                "' but expected is '" + GeneralName.uniformResourceIdentifier + "'");
                        failureMsg.append("; ");
                    }
                    else
                    {
                        String iOCSPUri = ((ASN1String) iAccessLocation.getName()).getString();
                        iOCSPUris.add(iOCSPUri);
                    }
                }

                Set<String> diffs = str_in_b_not_in_a(eOCSPUris, iOCSPUris);
                if(diffs.isEmpty() == false)
                {
                    failureMsg.append("OCSP URLs " + diffs.toString() + " are present but not expected");
                    failureMsg.append("; ");
                }

                diffs = str_in_b_not_in_a(iOCSPUris, eOCSPUris);
                if(diffs.isEmpty() == false)
                {
                    failureMsg.append("OCSP URLs " + diffs.toString() + " are absent but are required");
                    failureMsg.append("; ");
                }
            }
        }
    }

    private void checkExtensionCrlDistributionPoints(byte[] extensionValue,
            X509IssuerInfo issuerInfo, StringBuilder failureMsg)
    {
        CRLDistPoint iCRLDistPoints = CRLDistPoint.getInstance(extensionValue);
        DistributionPoint[] iDistributionPoints = iCRLDistPoints.getDistributionPoints();
        int n = iDistributionPoints == null ? 0 : iDistributionPoints.length;
        if(n != 1)
        {
            failureMsg.append("Size of CRLDistributionPoints is '" + n + "' but expected is '1'");
        }
        else
        {
            Set<String> iCrlURLs = new HashSet<>();
            for(DistributionPoint entry : iDistributionPoints)
            {
                int asn1Type = entry.getDistributionPoint().getType();
                if(asn1Type != DistributionPointName.FULL_NAME)
                {
                    failureMsg.append("Tag of DistributionPointName of CRLDistibutionPoints is '" + asn1Type +
                            "' but expected is '" + DistributionPointName.FULL_NAME + "'");
                    failureMsg.append("; ");
                } else
                {
                    GeneralNames iDistributionPointNames = (GeneralNames) entry.getDistributionPoint().getName();
                    GeneralName[] names = iDistributionPointNames.getNames();

                    for(int i = 0; i < names.length; i++)
                    {
                        GeneralName name = names[i];
                        if(name.getTagNo() != GeneralName.uniformResourceIdentifier)
                        {
                            failureMsg.append("Tag of CRL URL is '" + name.getTagNo() +
                                    "' but expected is '" + GeneralName.uniformResourceIdentifier + "'");
                            failureMsg.append("; ");
                        }
                        else
                        {
                            String uri = ((ASN1String) name.getName()).getString();
                            iCrlURLs.add(uri);
                        }
                    }

                    Set<String> eCRLUrls = issuerInfo.getCrlURLs();
                    Set<String> diffs = str_in_b_not_in_a(eCRLUrls, iCrlURLs);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("CRL URLs " + diffs.toString() + " are present but not expected");
                        failureMsg.append("; ");
                    }

                    diffs = str_in_b_not_in_a(iCrlURLs, eCRLUrls);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("CRL URLs " + diffs.toString() + " are absent but are required");
                        failureMsg.append("; ");
                    }
                }
            }
        }
    }

    private void checkExtensionDeltaCrlDistributionPoints(byte[] extensionValue,
            X509IssuerInfo issuerInfo, StringBuilder failureMsg)
    {
        CRLDistPoint iCRLDistPoints = CRLDistPoint.getInstance(extensionValue);
        DistributionPoint[] iDistributionPoints = iCRLDistPoints.getDistributionPoints();
        int n = iDistributionPoints == null ? 0 : iDistributionPoints.length;
        if(n != 1)
        {
            failureMsg.append("Size of CRLDistributionPoints (deltaCRL) is '" + n + "' but expected is '1'");
        }
        else
        {
            Set<String> iCrlURLs = new HashSet<>();
            for(DistributionPoint entry : iDistributionPoints)
            {
                int asn1Type = entry.getDistributionPoint().getType();
                if(asn1Type != DistributionPointName.FULL_NAME)
                {
                    failureMsg.append("Tag of DistributionPointName of CRLDistibutionPoints (deltaCRL) is '" +
                            asn1Type + "' but expected is '" + DistributionPointName.FULL_NAME + "'");
                    failureMsg.append("; ");
                } else
                {
                    GeneralNames iDistributionPointNames = (GeneralNames) entry.getDistributionPoint().getName();
                    GeneralName[] names = iDistributionPointNames.getNames();

                    for(int i = 0; i < names.length; i++)
                    {
                        GeneralName name = names[i];
                        if(name.getTagNo() != GeneralName.uniformResourceIdentifier)
                        {
                            failureMsg.append("Tag of deltaCRL URL is '" + name.getTagNo() +
                                    "' but expected is '" + GeneralName.uniformResourceIdentifier + "'");
                            failureMsg.append("; ");
                        }
                        else
                        {
                            String uri = ((ASN1String) name.getName()).getString();
                            iCrlURLs.add(uri);
                        }
                    }

                    Set<String> eCRLUrls = issuerInfo.getCrlURLs();
                    Set<String> diffs = str_in_b_not_in_a(eCRLUrls, iCrlURLs);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("deltaCRL URLs " + diffs.toString() + " are present but not expected");
                        failureMsg.append("; ");
                    }

                    diffs = str_in_b_not_in_a(iCrlURLs, eCRLUrls);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("deltaCRL URLs " + diffs.toString() + " are absent but are required");
                        failureMsg.append("; ");
                    }
                }
            }
        }
    }

    private void checkExtensionAdmission(byte[] extensionValue,
            X509IssuerInfo issuerInfo, StringBuilder failureMsg)
    {
        if(admission == null)
        {
            failureMsg.append("Admissions is present but expected is 'none'");
            failureMsg.append("; ");
        } else
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(extensionValue);
            AdmissionSyntax iAdmissionSyntax = AdmissionSyntax.getInstance(seq);
            Admissions[] iAdmissions = iAdmissionSyntax.getContentsOfAdmissions();
            int n = iAdmissions == null ? 0 : iAdmissions.length;
            if(n != 1)
            {
                failureMsg.append("Size of Admissions is '" + n + "' but expected is '1'");
                failureMsg.append("; ");
            }
            else
            {
                Admissions iAdmission = iAdmissions[0];
                ProfessionInfo[] iProfessionInfos = iAdmission.getProfessionInfos();
                n = iProfessionInfos == null ? 0 : iProfessionInfos.length;
                if(n != 1)
                {
                    failureMsg.append("Size of ProfessionInfo is '" + n + "' but expected is '1'");
                    failureMsg.append("; ");
                } else
                {
                    ProfessionInfo iProfessionInfo = iProfessionInfos[0];
                    String iRegistrationNumber = iProfessionInfo.getRegistrationNumber();
                    String eRegistrationNumber = admission.getRegistrationNumber();
                    if(eRegistrationNumber == null)
                    {
                        if(iRegistrationNumber != null)
                        {
                            failureMsg.append("RegistrationNumber is '" + iRegistrationNumber +
                                    "' but expected is 'null'");
                            failureMsg.append("; ");
                        }
                    } else if(eRegistrationNumber.equals(iRegistrationNumber) == false)
                    {
                        failureMsg.append("RegistrationNumber is '" + iRegistrationNumber +
                                "' but expected is '" + eRegistrationNumber + "'");
                        failureMsg.append("; ");
                    }

                    byte[] iAddProfessionInfo = null;
                    if(iProfessionInfo.getAddProfessionInfo() != null)
                    {
                        iAddProfessionInfo = iProfessionInfo.getAddProfessionInfo().getOctets();
                    }
                    byte[] eAddProfessionInfo = admission.getAddProfessionInfo();
                    if(eAddProfessionInfo == null)
                    {
                        if(iAddProfessionInfo != null)
                        {
                            failureMsg.append("AddProfessionInfo is '" + hex(iAddProfessionInfo) +
                                    "' but expected is 'null'");
                            failureMsg.append("; ");
                        }
                    } else
                    {
                        if(iAddProfessionInfo == null)
                        {
                            failureMsg.append("AddProfessionInfo is 'null' but expected is '" +
                                    hex(eAddProfessionInfo) + "'");
                            failureMsg.append("; ");
                        } else if(Arrays.equals(eAddProfessionInfo, iAddProfessionInfo) == false)
                        {
                            failureMsg.append("AddProfessionInfo is '" + hex(iAddProfessionInfo) +
                                    "' but expected is '" + hex(eAddProfessionInfo) + "'");
                            failureMsg.append("; ");
                        }
                    }

                    List<String> eProfessionOids = admission.getProfessionOIDs();
                    ASN1ObjectIdentifier[] _iProfessionOids = iProfessionInfo.getProfessionOIDs();
                    List<String> iProfessionOids = new LinkedList<>();
                    if(_iProfessionOids != null)
                    {
                        for(ASN1ObjectIdentifier entry : _iProfessionOids)
                        {
                            iProfessionOids.add(entry.getId());
                        }
                    }

                    Set<String> diffs = str_in_b_not_in_a(eProfessionOids, iProfessionOids);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("ProfessionOIDs " + diffs.toString() + " are present but not expected");
                        failureMsg.append("; ");
                    }

                    diffs = str_in_b_not_in_a(iProfessionOids, eProfessionOids);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("ProfessionOIDs " + diffs.toString() + " are absent but are required");
                        failureMsg.append("; ");
                    }

                    List<String> eProfessionItems = admission.getProfessionItems();
                    DirectoryString[] items = iProfessionInfo.getProfessionItems();
                    List<String> iProfessionItems = new LinkedList<>();
                    if(items != null)
                    {
                        for(DirectoryString item : items)
                        {
                            iProfessionItems.add(item.getString());
                        }
                    }

                    diffs = str_in_b_not_in_a(eProfessionItems, iProfessionItems);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("ProfessionItems " + diffs.toString() + " are present but not expected");
                        failureMsg.append("; ");
                    }

                    diffs = str_in_b_not_in_a(iProfessionItems, eProfessionItems);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("ProfessionItems " + diffs.toString() + " are absent but are required");
                        failureMsg.append("; ");
                    }
                }
            }
        }
    }

    private static String hex(byte[] bytes)
    {
        return Hex.toHexString(bytes);
    }

    private static Set<String> str_in_b_not_in_a(Collection<String> a, Collection<String> b)
    {
        if(b == null)
        {
            return Collections.emptySet();
        }

        Set<String> result = new HashSet<>();
        for(String entry : b)
        {
            if(a == null || a.contains(entry) == false)
            {
                result.add(entry);
            }
        }
        return result;
    }

    private static Set<Object> obj_in_b_not_in_a(Collection<? extends Object> a, Collection<? extends Object> b)
    {
        Set<Object> result = new HashSet<>();
        for(Object entry : b)
        {
            if(a.contains(entry) == false)
            {
                result.add(entry);
            }
        }
        return result;
    }

    private static GeneralName createGeneralName(String value, Set<GeneralNameMode> modes)
    {
        int idxTagSep = value.indexOf(GENERALNAME_SEP);
        if(idxTagSep == -1 || idxTagSep == 0 || idxTagSep == value.length() - 1)
        {
            throw new IllegalArgumentException("invalid generalName " + value);
        }
        String s = value.substring(0, idxTagSep);

        int tag;
        try
        {
            tag = Integer.parseInt(s);
        }catch(NumberFormatException e)
        {
            throw new IllegalArgumentException("invalid generalName tag " + s);
        }

        GeneralNameMode mode = null;

        for(GeneralNameMode m : modes)
        {
            if(m.getTag().getTag() == tag)
            {
                mode = m;
                break;
            }
        }

        if(mode == null)
        {
            throw new IllegalArgumentException("generalName tag " + tag + " is not allowed");
        }

        String name = value.substring(idxTagSep + 1);

        switch(mode.getTag())
        {
            case otherName:
            {
                int idxSep = name.indexOf(GENERALNAME_SEP);
                if(idxSep == -1 || idxSep == 0 || idxSep == name.length() - 1)
                {
                    throw new IllegalArgumentException("invalid otherName " + name);
                }
                String otherTypeOid = name.substring(0, idxSep);
                ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(otherTypeOid);
                if(mode.getAllowedTypes().contains(type) == false)
                {
                    throw new IllegalArgumentException("otherName.type " + otherTypeOid + " is not allowed");
                }
                String otherValue = name.substring(idxSep + 1);

                ASN1EncodableVector vector = new ASN1EncodableVector();
                vector.add(type);
                vector.add(new DERTaggedObject(true, 0, new DERUTF8String(otherValue)));
                DERSequence seq = new DERSequence(vector);

                return new GeneralName(GeneralName.otherName, seq);
            }
            case rfc822Name:
                return new GeneralName(tag, name);
            case dNSName:
                return new GeneralName(tag, name);
            case directoryName:
            {
                X500Name x500Name = SecurityUtil.reverse(new X500Name(name));
                return new GeneralName(GeneralName.directoryName, x500Name);
            }
            case ediPartyName:
            {
                int idxSep = name.indexOf(GENERALNAME_SEP);
                if(idxSep == -1 || idxSep == name.length() - 1)
                {
                    throw new IllegalArgumentException("invalid ediPartyName " + name);
                }
                String nameAssigner = idxSep == 0 ? null : name.substring(0, idxSep);
                String partyName = name.substring(idxSep + 1);
                ASN1EncodableVector vector = new ASN1EncodableVector();
                if(nameAssigner != null)
                {
                    vector.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
                }
                vector.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
                ASN1Sequence seq = new DERSequence(vector);
                return new GeneralName(GeneralName.ediPartyName, seq);
            }
            case uniformResourceIdentifier:
                return new GeneralName(tag, name);
            case iPAddress:
                return new GeneralName(tag, name);
            case registeredID:
                return new GeneralName(tag, name);
            default:
                throw new RuntimeException("should not reach here");
        }
    }

}
