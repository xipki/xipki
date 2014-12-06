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

package org.xipki.ca.server.certprofile.x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECCurve;
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
import org.xipki.ca.api.profile.x509.AbstractX509CertProfile;
import org.xipki.ca.api.profile.x509.CertificatePolicyInformation;
import org.xipki.ca.api.profile.x509.CertificatePolicyQualifier;
import org.xipki.ca.api.profile.x509.KeyUsage;
import org.xipki.ca.api.profile.x509.SpecialX509CertProfileBehavior;
import org.xipki.ca.api.profile.x509.X509Util;
import org.xipki.ca.server.certprofile.AddText;
import org.xipki.ca.server.certprofile.Condition;
import org.xipki.ca.server.certprofile.ExtensionTupleOption;
import org.xipki.ca.server.certprofile.ExtensionTupleOptions;
import org.xipki.ca.server.certprofile.GeneralNameMode;
import org.xipki.ca.server.certprofile.GeneralNameTag;
import org.xipki.ca.server.certprofile.KeyParamRange;
import org.xipki.ca.server.certprofile.KeyParamRanges;
import org.xipki.ca.server.certprofile.SubjectDNOption;
import org.xipki.ca.server.certprofile.jaxb.AddTextType;
import org.xipki.ca.server.certprofile.jaxb.AlgorithmType;
import org.xipki.ca.server.certprofile.jaxb.CertificatePolicyInformationType;
import org.xipki.ca.server.certprofile.jaxb.CertificatePolicyInformationType.PolicyQualifiers;
import org.xipki.ca.server.certprofile.jaxb.ConditionType;
import org.xipki.ca.server.certprofile.jaxb.ConstantExtensionType;
import org.xipki.ca.server.certprofile.jaxb.CurveType;
import org.xipki.ca.server.certprofile.jaxb.CurveType.Encodings;
import org.xipki.ca.server.certprofile.jaxb.ECParameterType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.Admission;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.AuthorityKeyIdentifier;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.ConstantExtensions;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.ExtendedKeyUsage;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.InhibitAnyPolicy;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.PolicyConstraints;
import org.xipki.ca.server.certprofile.jaxb.GeneralNameType;
import org.xipki.ca.server.certprofile.jaxb.GeneralSubtreeBaseType;
import org.xipki.ca.server.certprofile.jaxb.GeneralSubtreesType;
import org.xipki.ca.server.certprofile.jaxb.KeyUsageType;
import org.xipki.ca.server.certprofile.jaxb.NameValueType;
import org.xipki.ca.server.certprofile.jaxb.ObjectFactory;
import org.xipki.ca.server.certprofile.jaxb.OidWithDescType;
import org.xipki.ca.server.certprofile.jaxb.ParameterType;
import org.xipki.ca.server.certprofile.jaxb.PolicyIdMappingType;
import org.xipki.ca.server.certprofile.jaxb.ProfileType;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.AllowedClientExtensions;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.KeyAlgorithms;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.Parameters;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.Subject;
import org.xipki.ca.server.certprofile.jaxb.RdnType;
import org.xipki.ca.server.certprofile.jaxb.SubjectInfoAccessType.Access;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.SecurityUtil;
import org.xipki.common.LogUtil;
import org.xipki.common.LruCache;
import org.xipki.common.ObjectIdentifiers;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class DefaultX509CertProfile extends AbstractX509CertProfile
{
    private static final Logger LOG = LoggerFactory.getLogger(DefaultX509CertProfile.class);
    private static final char GENERALNAME_SEP = '|';
    public static final String MODULUS_LENGTH = "moduluslength";
    public static final String P_LENGTH = "plength";
    public static final String Q_LENGTH = "qlength";

    private static final Set<String> criticalOnlyExtensionTypes;
    private static final Set<String> noncriticalOnlyExtensionTypes;
    private static final Set<String> caOnlyExtensionTypes;
    private static final Set<ASN1ObjectIdentifier> ignoreRDNs;

    private final static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

    protected ProfileType profileConf;

    private SpecialX509CertProfileBehavior specialBehavior;
    private Map<ASN1ObjectIdentifier, Set<Byte>> allowedEcCurves;
    private Map<ASN1ObjectIdentifier, List<KeyParamRanges>> nonEcKeyAlgorithms;

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
    private static LruCache<ASN1ObjectIdentifier, Integer> ecCurveFieldSizes = new LruCache<>(100);

    static
    {
        criticalOnlyExtensionTypes = new HashSet<>(5);
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
        allowedEcCurves = null;
        nonEcKeyAlgorithms = null;
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
        reset();

        try
        {
            ProfileType conf = parse(data);
            this.profileConf = conf;

            this.raOnly = getBoolean(conf.isOnlyForRA(), false);
            this.validity = CertValidity.getInstance(conf.getValidity());
            this.ca = conf.isCa();
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
                List<AlgorithmType> types = keyAlgos.getAlgorithm();
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

                    Pattern pattern = null;
                    if(t.getConstraint() != null)
                    {
                        String regex = t.getConstraint().getRegex();
                        if(regex != null)
                        {
                            pattern = Pattern.compile(regex);
                        }
                    }

                    List<AddText> addprefixes = buildAddText(t.getAddPrefix());
                    List<AddText> addsuffixes = buildAddText(t.getAddSuffix());
                    SubjectDNOption option = new SubjectDNOption(addprefixes, addsuffixes, pattern);
                    this.subjectDNOptions.put(type, option);
                }
            }

            // Allowed extensions to be fulfilled by the client
            AllowedClientExtensions clientExtensions = conf.getAllowedClientExtensions();
            if(clientExtensions != null)
            {
                this.allowedClientExtensions = new HashSet<>();
                for(OidWithDescType t : clientExtensions.getType())
                {
                    this.allowedClientExtensions.add(new ASN1ObjectIdentifier(t.getValue()));
                }
            }

            // Extensions
            ExtensionsType extensionsType = conf.getExtensions();

            this.pathLen = extensionsType.getPathLen();

            // Extension KeyUsage
            List<org.xipki.ca.server.certprofile.jaxb.ExtensionsType.KeyUsage> keyUsageTypeList = extensionsType.getKeyUsage();
            if(keyUsageTypeList.isEmpty() == false)
            {
                List<KeyUsageOption> optionList = new ArrayList<>(keyUsageTypeList.size());

                for(org.xipki.ca.server.certprofile.jaxb.ExtensionsType.KeyUsage t : keyUsageTypeList)
                {
                    Set<KeyUsage> set = new HashSet<>();
                    for(KeyUsageType type : t.getUsage())
                    {
                        switch(type)
                        {
                        case CRL_SIGN:
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
                        case KEYCERT_SIGN:
                            set.add(KeyUsage.keyCertSign);
                            break;
                        case KEY_ENCIPHERMENT:
                            set.add(KeyUsage.keyEncipherment);
                            break;
                        }
                    }
                    Set<KeyUsage> keyusageSet = Collections.unmodifiableSet(set);

                    Condition condition = createCondition(t.getCondition());
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

                for(org.xipki.ca.server.certprofile.jaxb.ExtensionsType.ExtendedKeyUsage t : extKeyUsageTypeList)
                {
                    Set<ASN1ObjectIdentifier> set = new HashSet<>();
                    for(OidWithDescType type : t.getUsage())
                    {
                        set.add(new ASN1ObjectIdentifier(type.getValue()));
                    }
                    Set<ASN1ObjectIdentifier> extendedKeyusageSet = Collections.unmodifiableSet(set);

                    Condition condition = createCondition(t.getCondition());
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
                    List<CertificatePolicyInformation> policyInfos = buildCertificatePolicies(type);
                    CertificatePolicies value = X509Util.createCertificatePolicies(policyInfos);
                    ExtensionTuple extension = createExtension(extensionOid, occurrence.isCritical(), value);
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            createCondition(type.getCondition()), extension);
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
                    org.bouncycastle.asn1.x509.PolicyMappings value = buildPolicyMappings(type);
                    ExtensionTuple extension = createExtension(extensionOid, occurrence.isCritical(), value);
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            createCondition(type.getCondition()), extension);
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
                    NameConstraints value = buildNameConstrains(type);
                    ExtensionTuple extension = createExtension(extensionOid, occurrence.isCritical(), value);
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            createCondition(type.getCondition()), extension);
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
                    ASN1Sequence value = buildPolicyConstrains(type);
                    ExtensionTuple extension = createExtension(extensionOid, occurrence.isCritical(), value);
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            createCondition(type.getCondition()), extension);
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
                            createCondition(type.getCondition()), extension);
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
                    if(oidWithDescs == null || oidWithDescs.isEmpty())
                    {
                        professionOIDs = null;
                    }
                    else
                    {
                        List<ASN1ObjectIdentifier> oids = new LinkedList<>();
                        for(OidWithDescType entry : oidWithDescs)
                        {
                            oids.add(new ASN1ObjectIdentifier(entry.getValue()));
                        }
                        professionOIDs = Collections.unmodifiableList(oids);
                    }

                    ExtensionTuple extension = createAdmission(occurrence.isCritical(),
                            professionOIDs, professionItems, type.getRegistrationNumber(), type.getAddProfessionInfo());
                    ExtensionTupleOption option = new ExtensionTupleOption(
                            createCondition(type.getCondition()), extension);
                    options.add(option);
                }
                this.admission = new ExtensionTupleOptions(options);
            }

            // SubjectAltNameMode
            if(extensionsType.getSubjectAltName() != null)
            {
                this.allowedSubjectAltNameModes = buildGeneralNameMode(extensionsType.getSubjectAltName());
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
                            buildGeneralNameMode(entry.getAccessLocation()));
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
                                    createCondition(ce.getCondition()), extension);

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

    private static ProfileType parse(String xmlConf)
    throws CertProfileException
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
                    URL url = DefaultX509CertProfile.class.getResource("/xsd/certprofile.xsd");
                    jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
                }

                rootElement = (JAXBElement<?>) jaxbUnmarshaller.unmarshal(
                        new ByteArrayInputStream(xmlConf.getBytes()));
            }
            catch(JAXBException | SAXException e)
            {
                throw new CertProfileException("parse profile failed, message: " + e.getMessage(), e);
            }

            Object rootType = rootElement.getValue();
            if(rootType instanceof ProfileType)
            {
                return (ProfileType) rootElement.getValue();
            }
            else
            {
                throw new CertProfileException("invalid root element type");
            }
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
                rdns.add(createSubjectRDN(value, type));
            }
            else
            {
                String[] values = new String[n];
                for(int i = 0; i < n; i++)
                {
                    values[i] = SecurityUtil.rdnValueToString(thisRDNs[i].getFirst().getValue());
                }
                values = sortRDNs(type, values);

                for(String value : values)
                {
                    rdns.add(createSubjectRDN(value, type));
                }
            }
        }

        X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
        return new SubjectInfo(grantedSubject, null);
    }

    @Override
    protected RDN createSubjectRDN(String text, ASN1ObjectIdentifier type)
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

            Pattern p = option.getPattern();
            if(p != null && p.matcher(text).matches() == false)
            {
                throw new BadCertTemplateException("invalid subject " + ObjectIdentifiers.oidToDisplayName(type) +
                        " '" + text + "' against regex '" + p.pattern() + "'");
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
                        names[i] = createGeneralName(value, allowedSubjectAltNameModes);
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

                            GeneralName location = createGeneralName(accessLocation, generalNameModes);
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

    private static List<CertificatePolicyInformation> buildCertificatePolicies(ExtensionsType.CertificatePolicies type)
    {
        List<CertificatePolicyInformationType> policyPairs = type.getCertificatePolicyInformation();
        if(policyPairs == null || policyPairs.isEmpty())
        {
            return null;
        }

        List<CertificatePolicyInformation> policies = new ArrayList<CertificatePolicyInformation>(policyPairs.size());
        for(CertificatePolicyInformationType policyPair : policyPairs)
        {
            List<CertificatePolicyQualifier> qualifiers = null;

            PolicyQualifiers policyQualifiers = policyPair.getPolicyQualifiers();
            if(policyQualifiers != null)
            {
                List<JAXBElement<String>> cpsUriOrUserNotice = policyQualifiers.getCpsUriOrUserNotice();

                qualifiers = new ArrayList<CertificatePolicyQualifier>(cpsUriOrUserNotice.size());
                for(JAXBElement<String> element : cpsUriOrUserNotice)
                {
                    String elementValue = element.getValue();
                    CertificatePolicyQualifier qualifier = null;
                    String elementName = element.getName().getLocalPart();
                    if("cpsUri".equals(elementName))
                    {
                        qualifier = CertificatePolicyQualifier.getInstanceForCpsUri(elementValue);
                    }
                    else
                    {
                        qualifier = CertificatePolicyQualifier.getInstanceForUserNotice(elementValue);
                    }
                    qualifiers.add(qualifier);
                }
            }

            CertificatePolicyInformation cpi = new CertificatePolicyInformation(
                    policyPair.getPolicyIdentifier().getValue(), qualifiers);

            policies.add(cpi);
        }

        return policies;
    }

    private static PolicyMappings buildPolicyMappings(
            org.xipki.ca.server.certprofile.jaxb.ExtensionsType.PolicyMappings type)
    {
        List<PolicyIdMappingType> mappings = type.getMapping();
        final int n = mappings.size();

        CertPolicyId[] issuerDomainPolicy = new CertPolicyId[n];
        CertPolicyId[] subjectDomainPolicy = new CertPolicyId[n];

        for(int i = 0; i < n; i++)
        {
            PolicyIdMappingType mapping = mappings.get(i);
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(mapping.getIssuerDomainPolicy().getValue());
            issuerDomainPolicy[i] = CertPolicyId.getInstance(oid);

            oid = new ASN1ObjectIdentifier(mapping.getSubjectDomainPolicy().getValue());
            subjectDomainPolicy[i] = CertPolicyId.getInstance(oid);
        }

        return new PolicyMappings(issuerDomainPolicy, subjectDomainPolicy);
    }

    private static NameConstraints buildNameConstrains(
            org.xipki.ca.server.certprofile.jaxb.ExtensionsType.NameConstraints type)
    throws CertProfileException
    {
        GeneralSubtree[] permitted = buildGeneralSubtrees(type.getPermittedSubtrees());
        GeneralSubtree[] excluded = buildGeneralSubtrees(type.getExcludedSubtrees());
        if(permitted == null && excluded == null)
        {
            return null;
        }
        return new NameConstraints(permitted, excluded);
    }

    private static GeneralSubtree[] buildGeneralSubtrees(GeneralSubtreesType subtrees)
    throws CertProfileException
    {
        if(subtrees == null || subtrees.getBase().isEmpty())
        {
            return null;
        }

        List<GeneralSubtreeBaseType> list = subtrees.getBase();
        final int n = list.size();
        GeneralSubtree[] ret = new GeneralSubtree[n];
        for(int i = 0; i < n; i++)
        {
            ret[i] = buildGeneralSubtree(list.get(i));
        }

        return ret;
    }

    private static GeneralSubtree buildGeneralSubtree(GeneralSubtreeBaseType type)
    throws CertProfileException
    {
        GeneralName base = null;
        if(type.getDirectoryName() != null)
        {
            base = new GeneralName(SecurityUtil.reverse(
                    new X500Name(type.getDirectoryName())));
        }
        else if(type.getDNSName() != null)
        {
            base = new GeneralName(GeneralName.dNSName, type.getDNSName());
        }
        else if(type.getIpAddress() != null)
        {
            base = new GeneralName(GeneralName.iPAddress, type.getIpAddress());
        }
        else if(type.getRfc822Name() != null)
        {
            base = new GeneralName(GeneralName.rfc822Name, type.getRfc822Name());
        }
        else if(type.getUri() != null)
        {
            base = new GeneralName(GeneralName.uniformResourceIdentifier, type.getUri());
        }
        else
        {
            throw new RuntimeException("should not reach here");
        }

        Integer i = type.getMinimum();
        if(i != null && i < 0)
        {
            throw new CertProfileException("negative minimum is not allowed: " + i);
        }

        BigInteger minimum = (i == null) ? null : BigInteger.valueOf(i.intValue());

        i = type.getMaximum();
        if(i != null && i < 0)
        {
            throw new CertProfileException("negative maximum is not allowed: " + i);
        }

        BigInteger maximum = (i == null) ? null : BigInteger.valueOf(i.intValue());

        return new GeneralSubtree(base, minimum, maximum);
    }

    private static ASN1Sequence buildPolicyConstrains(PolicyConstraints type)
    throws CertProfileException
    {
        Integer requireExplicitPolicy = type.getRequireExplicitPolicy();
        if(requireExplicitPolicy != null && requireExplicitPolicy < 0)
        {
            throw new CertProfileException("negative requireExplicitPolicy is not allowed: " + requireExplicitPolicy);
        }

        Integer inhibitPolicyMapping = type.getInhibitPolicyMapping();
        if(inhibitPolicyMapping != null && inhibitPolicyMapping < 0)
        {
            throw new CertProfileException("negative inhibitPolicyMapping is not allowed: " + inhibitPolicyMapping);
        }

        if(requireExplicitPolicy == null && inhibitPolicyMapping == null)
        {
            return null;
        }

        final boolean explicit = false;
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (requireExplicitPolicy != null)
        {
            vec.add(new DERTaggedObject(explicit, 0, new ASN1Integer(BigInteger.valueOf(requireExplicitPolicy))));
        }

        if (inhibitPolicyMapping != null)
        {
            vec.add(new DERTaggedObject(explicit, 1, new ASN1Integer(BigInteger.valueOf(inhibitPolicyMapping))));
        }

        return new DERSequence(vec);
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

    private static boolean getBoolean(Boolean b, boolean dfltValue)
    {
        return b == null ? dfltValue : b.booleanValue();
    }

    private static int getInt(Integer i, int dfltValue)
    {
        return i == null ? dfltValue : i.intValue();
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

    private static GeneralName createGeneralName(String value, Set<GeneralNameMode> modes)
    throws BadCertTemplateException
    {
        int idxTagSep = value.indexOf(GENERALNAME_SEP);
        if(idxTagSep == -1 || idxTagSep == 0 || idxTagSep == value.length() - 1)
        {
            throw new BadCertTemplateException("invalid generalName " + value);
        }
        String s = value.substring(0, idxTagSep);

        int tag;
        try
        {
            tag = Integer.parseInt(s);
        }catch(NumberFormatException e)
        {
            throw new BadCertTemplateException("invalid generalName tag " + s);
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
            throw new BadCertTemplateException("generalName tag " + tag + " is not allowed");
        }

        String name = value.substring(idxTagSep + 1);

        switch(mode.getTag())
        {
            case otherName:
            {
                int idxSep = name.indexOf(GENERALNAME_SEP);
                if(idxSep == -1 || idxSep == 0 || idxSep == name.length() - 1)
                {
                    throw new BadCertTemplateException("invalid otherName " + name);
                }
                String otherTypeOid = name.substring(0, idxSep);
                ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(otherTypeOid);
                if(mode.getAllowedTypes().contains(type) == false)
                {
                    throw new BadCertTemplateException("otherName.type " + otherTypeOid + " is not allowed");
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
                    throw new BadCertTemplateException("invalid ediPartyName " + name);
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

    private static List<AddText> buildAddText(List<AddTextType> types)
    {
        if(types == null || types.isEmpty())
        {
            return null;
        }

        List<AddText> ret = new ArrayList<>(types.size());
        for(AddTextType type : types)
        {
            Condition c = createCondition(type.getCondition());
            ret.add(new AddText(c, type.getText()));
        }

        return ret;
    }

    private static Condition createCondition(ConditionType type)
    {
        return type == null ? null : new Condition(type);
    }

}
