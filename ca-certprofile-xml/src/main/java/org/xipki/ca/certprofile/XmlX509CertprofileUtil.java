/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.certprofile;

import java.io.IOException;
import java.io.InputStream;
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

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.DirectoryStringType;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.GeneralNameMode;
import org.xipki.ca.api.profile.GeneralNameTag;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.api.profile.StringType;
import org.xipki.ca.api.profile.x509.CertificatePolicyInformation;
import org.xipki.ca.api.profile.x509.CertificatePolicyQualifier;
import org.xipki.ca.api.profile.x509.ExtKeyUsageControl;
import org.xipki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.ca.certprofile.commonpki.AdmissionSyntaxOption;
import org.xipki.ca.certprofile.commonpki.AdmissionsOption;
import org.xipki.ca.certprofile.commonpki.ProfessionInfoOption;
import org.xipki.ca.certprofile.commonpki.RegistrationNumberOption;
import org.xipki.ca.certprofile.x509.jaxb.AdmissionSyntax;
import org.xipki.ca.certprofile.x509.jaxb.AdmissionsType;
import org.xipki.ca.certprofile.x509.jaxb.AlgorithmType;
import org.xipki.ca.certprofile.x509.jaxb.CertificatePolicies;
import org.xipki.ca.certprofile.x509.jaxb.CertificatePolicyInformationType;
import org.xipki.ca.certprofile.x509.jaxb.CertificatePolicyInformationType.PolicyQualifiers;
import org.xipki.ca.certprofile.x509.jaxb.ConstantExtValue;
import org.xipki.ca.certprofile.x509.jaxb.DHParameters;
import org.xipki.ca.certprofile.x509.jaxb.DSAParameters;
import org.xipki.ca.certprofile.x509.jaxb.ECParameters;
import org.xipki.ca.certprofile.x509.jaxb.ECParameters.Curves;
import org.xipki.ca.certprofile.x509.jaxb.ExtendedKeyUsage;
import org.xipki.ca.certprofile.x509.jaxb.ExtendedKeyUsage.Usage;
import org.xipki.ca.certprofile.x509.jaxb.ExtensionType;
import org.xipki.ca.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.ca.certprofile.x509.jaxb.GeneralNameType;
import org.xipki.ca.certprofile.x509.jaxb.GeneralSubtreeBaseType;
import org.xipki.ca.certprofile.x509.jaxb.GeneralSubtreesType;
import org.xipki.ca.certprofile.x509.jaxb.GostParameters;
import org.xipki.ca.certprofile.x509.jaxb.NamingAuthorityType;
import org.xipki.ca.certprofile.x509.jaxb.ObjectFactory;
import org.xipki.ca.certprofile.x509.jaxb.OidWithDescType;
import org.xipki.ca.certprofile.x509.jaxb.PolicyConstraints;
import org.xipki.ca.certprofile.x509.jaxb.PolicyIdMappingType;
import org.xipki.ca.certprofile.x509.jaxb.ProfessionInfoType;
import org.xipki.ca.certprofile.x509.jaxb.ProfessionInfoType.RegistrationNumber;
import org.xipki.ca.certprofile.x509.jaxb.RSAPSSParameters;
import org.xipki.ca.certprofile.x509.jaxb.RSAParameters;
import org.xipki.ca.certprofile.x509.jaxb.RangeType;
import org.xipki.ca.certprofile.x509.jaxb.RangesType;
import org.xipki.ca.certprofile.x509.jaxb.UsageType;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType.KeyAlgorithms;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.common.util.XmlUtil;
import org.xipki.security.KeyUsage;
import org.xipki.security.util.X509Util;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XmlX509CertprofileUtil {

    private static final Logger LOG = LoggerFactory.getLogger(XmlX509CertprofileUtil.class);

    private static final Object JAXB_LOCK = new Object();

    private static Unmarshaller jaxbUnmarshaller;

    private XmlX509CertprofileUtil() {
    }

    public static X509ProfileType parse(final InputStream xmlConfStream)
            throws CertprofileException {
        ParamUtil.requireNonNull("xmlConfStream", xmlConfStream);
        synchronized (JAXB_LOCK) {
            JAXBElement<?> rootElement;
            try {
                if (jaxbUnmarshaller == null) {
                    JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
                    jaxbUnmarshaller = context.createUnmarshaller();

                    final SchemaFactory schemaFact = SchemaFactory.newInstance(
                            javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    URL url = XmlX509CertprofileUtil.class.getResource("/xsd/certprofile.xsd");
                    jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
                }

                rootElement = (JAXBElement<?>) jaxbUnmarshaller.unmarshal(xmlConfStream);
            } catch (SAXException ex) {
                throw new CertprofileException("parse profile failed, message: " + ex.getMessage(),
                        ex);
            } catch (JAXBException ex) {
                throw new CertprofileException(
                        "parse profile failed, message: " + XmlUtil.getMessage(ex), ex);
            }

            try {
                xmlConfStream.close();
            } catch (IOException ex) {
                LOG.warn("could not close xmlConfStream: {}", ex.getMessage());
            }

            Object rootType = rootElement.getValue();
            if (rootType instanceof X509ProfileType) {
                return (X509ProfileType) rootElement.getValue();
            } else {
                throw new CertprofileException("invalid root element type");
            }
        }
    } // method parse

    public static List<CertificatePolicyInformation> buildCertificatePolicies(
            final CertificatePolicies type) {
        List<CertificatePolicyInformationType> policyPairs = type.getCertificatePolicyInformation();

        List<CertificatePolicyInformation> policies =
                new ArrayList<CertificatePolicyInformation>(policyPairs.size());
        for (CertificatePolicyInformationType policyPair : policyPairs) {
            List<CertificatePolicyQualifier> qualifiers = null;

            PolicyQualifiers policyQualifiers = policyPair.getPolicyQualifiers();
            if (policyQualifiers != null) {
                List<JAXBElement<String>> cpsUriOrUserNotice =
                        policyQualifiers.getCpsUriOrUserNotice();

                qualifiers = new ArrayList<CertificatePolicyQualifier>(cpsUriOrUserNotice.size());
                for (JAXBElement<String> element : cpsUriOrUserNotice) {
                    String elementValue = element.getValue();
                    CertificatePolicyQualifier qualifier = null;
                    String elementName = element.getName().getLocalPart();
                    qualifier = "cpsUri".equals(elementName)
                        ? CertificatePolicyQualifier.getInstanceForCpsUri(elementValue)
                        : CertificatePolicyQualifier.getInstanceForUserNotice(elementValue);
                    qualifiers.add(qualifier);
                }
            }

            CertificatePolicyInformation cpi = new CertificatePolicyInformation(
                    policyPair.getPolicyIdentifier().getValue(), qualifiers);
            policies.add(cpi);
        }

        return policies;
    } // method buildCertificatePolicies

    public static PolicyMappings buildPolicyMappings(
            final org.xipki.ca.certprofile.x509.jaxb.PolicyMappings type) {
        ParamUtil.requireNonNull("type", type);
        List<PolicyIdMappingType> mappings = type.getMapping();
        final int n = mappings.size();

        CertPolicyId[] issuerDomainPolicy = new CertPolicyId[n];
        CertPolicyId[] subjectDomainPolicy = new CertPolicyId[n];

        for (int i = 0; i < n; i++) {
            PolicyIdMappingType mapping = mappings.get(i);
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(
                    mapping.getIssuerDomainPolicy().getValue());
            issuerDomainPolicy[i] = CertPolicyId.getInstance(oid);

            oid = new ASN1ObjectIdentifier(mapping.getSubjectDomainPolicy().getValue());
            subjectDomainPolicy[i] = CertPolicyId.getInstance(oid);
        }

        return new PolicyMappings(issuerDomainPolicy, subjectDomainPolicy);
    } // method buildPolicyMappings

    public static NameConstraints buildNameConstrains(
            final org.xipki.ca.certprofile.x509.jaxb.NameConstraints type)
            throws CertprofileException {
        ParamUtil.requireNonNull("type", type);
        GeneralSubtree[] permitted = buildGeneralSubtrees(type.getPermittedSubtrees());
        GeneralSubtree[] excluded = buildGeneralSubtrees(type.getExcludedSubtrees());
        return (permitted == null && excluded == null) ? null
                : new NameConstraints(permitted, excluded);
    } // method buildNameConstrains

    private static GeneralSubtree[] buildGeneralSubtrees(final GeneralSubtreesType subtrees)
            throws CertprofileException {
        if (subtrees == null || CollectionUtil.isEmpty(subtrees.getBase())) {
            return null;
        }

        List<GeneralSubtreeBaseType> list = subtrees.getBase();
        final int n = list.size();
        GeneralSubtree[] ret = new GeneralSubtree[n];
        for (int i = 0; i < n; i++) {
            ret[i] = buildGeneralSubtree(list.get(i));
        }

        return ret;
    } // method buildGeneralSubtrees

    private static GeneralSubtree buildGeneralSubtree(final GeneralSubtreeBaseType type)
            throws CertprofileException {
        ParamUtil.requireNonNull("type", type);
        GeneralName base = null;
        if (type.getDirectoryName() != null) {
            base = new GeneralName(X509Util.reverse(
                    new X500Name(type.getDirectoryName())));
        } else if (type.getDnsName() != null) {
            base = new GeneralName(GeneralName.dNSName, type.getDnsName());
        } else if (type.getIpAddress() != null) {
            base = new GeneralName(GeneralName.iPAddress, type.getIpAddress());
        } else if (type.getRfc822Name() != null) {
            base = new GeneralName(GeneralName.rfc822Name, type.getRfc822Name());
        } else if (type.getUri() != null) {
            base = new GeneralName(GeneralName.uniformResourceIdentifier, type.getUri());
        } else {
            throw new RuntimeException(
                    "should not reach here, unknown child of GeneralSubtreeBaseType");
        }

        Integer min = type.getMinimum();
        if (min != null && min < 0) {
            throw new CertprofileException("negative minimum is not allowed: " + min);
        }
        BigInteger minimum = (min == null) ? null : BigInteger.valueOf(min.intValue());

        Integer max = type.getMaximum();
        if (max != null && max < 0) {
            throw new CertprofileException("negative maximum is not allowed: " + max);
        }
        BigInteger maximum = (max == null) ? null : BigInteger.valueOf(max.intValue());

        return new GeneralSubtree(base, minimum, maximum);
    } // method buildGeneralSubtree

    public static ASN1Sequence buildPolicyConstrains(final PolicyConstraints type)
            throws CertprofileException {
        ParamUtil.requireNonNull("type", type);
        Integer requireExplicitPolicy = type.getRequireExplicitPolicy();
        if (requireExplicitPolicy != null && requireExplicitPolicy < 0) {
            throw new CertprofileException(
                    "negative requireExplicitPolicy is not allowed: " + requireExplicitPolicy);
        }

        Integer inhibitPolicyMapping = type.getInhibitPolicyMapping();
        if (inhibitPolicyMapping != null && inhibitPolicyMapping < 0) {
            throw new CertprofileException(
                    "negative inhibitPolicyMapping is not allowed: " + inhibitPolicyMapping);
        }

        if (requireExplicitPolicy == null && inhibitPolicyMapping == null) {
            return null;
        }

        final boolean explicit = false;
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (requireExplicitPolicy != null) {
            vec.add(new DERTaggedObject(explicit, 0,
                    new ASN1Integer(BigInteger.valueOf(requireExplicitPolicy))));
        }

        if (inhibitPolicyMapping != null) {
            vec.add(new DERTaggedObject(explicit, 1,
                    new ASN1Integer(BigInteger.valueOf(inhibitPolicyMapping))));
        }

        return new DERSequence(vec);
    } //method buildPolicyConstrains

    public static Set<GeneralNameMode> buildGeneralNameMode(final GeneralNameType name)
            throws CertprofileException {
        ParamUtil.requireNonNull("name", name);

        Set<GeneralNameMode> ret = new HashSet<>();
        if (name.getOtherName() != null) {
            List<OidWithDescType> list = name.getOtherName().getType();
            Set<ASN1ObjectIdentifier> set = new HashSet<>();
            for (OidWithDescType entry : list) {
                set.add(new ASN1ObjectIdentifier(entry.getValue()));
            }
            ret.add(new GeneralNameMode(GeneralNameTag.otherName, set));
        }

        if (name.getRfc822Name() != null) {
            ret.add(new GeneralNameMode(GeneralNameTag.rfc822Name));
        }

        if (name.getDnsName() != null) {
            ret.add(new GeneralNameMode(GeneralNameTag.dNSName));
        }

        if (name.getDirectoryName() != null) {
            ret.add(new GeneralNameMode(GeneralNameTag.directoryName));
        }

        if (name.getEdiPartyName() != null) {
            ret.add(new GeneralNameMode(GeneralNameTag.ediPartyName));
        }

        if (name.getUniformResourceIdentifier() != null) {
            ret.add(new GeneralNameMode(GeneralNameTag.uniformResourceIdentifier));
        }

        if (name.getIpAddress() != null) {
            ret.add(new GeneralNameMode(GeneralNameTag.iPAddress));
        }

        if (name.getRegisteredID() != null) {
            ret.add(new GeneralNameMode(GeneralNameTag.registeredID));
        }

        if (ret.isEmpty()) {
            throw new CertprofileException("GeneralNameType must not be empty");
        }

        return ret;
    } // method buildGeneralNameMode

    private static Set<Range> buildParametersMap(final RangesType ranges) {
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

    public static Map<ASN1ObjectIdentifier, KeyParametersOption> buildKeyAlgorithms(
            final KeyAlgorithms keyAlgos) throws CertprofileException {
        ParamUtil.requireNonNull("keyAlgos", keyAlgos);
        Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms = new HashMap<>();
        for (AlgorithmType type : keyAlgos.getAlgorithm()) {
            List<OidWithDescType> algIds = type.getAlgorithm();
            List<ASN1ObjectIdentifier> oids = new ArrayList<>(algIds.size());
            for (OidWithDescType algId : algIds) {
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(algId.getValue());
                if (keyAlgorithms.containsKey(oid)) {
                    throw new CertprofileException(
                            "duplicate definition of keyAlgorithm " + oid.getId());
                }
                oids.add(oid);
            }

            KeyParametersOption keyParamsOption = convertKeyParametersOption(type);
            for (ASN1ObjectIdentifier oid : oids) {
                keyAlgorithms.put(oid, keyParamsOption);
            }
        }
        return CollectionUtil.unmodifiableMap(keyAlgorithms);
    } // method buildKeyAlgorithms

    public static Map<ASN1ObjectIdentifier, ExtensionControl> buildExtensionControls(
            final ExtensionsType extensionsType) throws CertprofileException {
        ParamUtil.requireNonNull("extensionsType", extensionsType);
        // Extension controls
        Map<ASN1ObjectIdentifier, ExtensionControl> controls = new HashMap<>();
        for (ExtensionType m : extensionsType.getExtension()) {
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(m.getType().getValue());
            if (controls.containsKey(oid)) {
                throw new CertprofileException(
                        "duplicated definition of extension " + oid.getId());
            }
            ExtensionControl ctrl = new ExtensionControl(m.isCritical(), m.isRequired(),
                    m.isPermittedInRequest());
            controls.put(oid, ctrl);
        }

        return Collections.unmodifiableMap(controls);
    } // method buildExtensionControls

    public static List<ASN1ObjectIdentifier> toOidList(
            final List<OidWithDescType> oidWithDescTypes) {
        if (CollectionUtil.isEmpty(oidWithDescTypes)) {
            return null;
        }

        List<ASN1ObjectIdentifier> oids = new LinkedList<>();
        for (OidWithDescType type : oidWithDescTypes) {
            oids.add(new ASN1ObjectIdentifier(type.getValue()));
        }
        return Collections.unmodifiableList(oids);
    } // method toOidList

    public static Set<KeyUsageControl> buildKeyUsageOptions(
            final org.xipki.ca.certprofile.x509.jaxb.KeyUsage extConf) {
        ParamUtil.requireNonNull("extConf", extConf);
        List<UsageType> usages = extConf.getUsage();
        Set<KeyUsageControl> controls = new HashSet<>();

        for (UsageType m : usages) {
            boolean required = m.isRequired();
            switch (m.getValue()) {
            case CRL_SIGN:
                controls.add(new KeyUsageControl(KeyUsage.cRLSign, required));
                break;
            case DATA_ENCIPHERMENT:
                controls.add(new KeyUsageControl(KeyUsage.dataEncipherment, required));
                break;
            case CONTENT_COMMITMENT:
                controls.add(new KeyUsageControl(KeyUsage.contentCommitment, required));
                break;
            case DECIPHER_ONLY:
                controls.add(new KeyUsageControl(KeyUsage.decipherOnly, required));
                break;
            case ENCIPHER_ONLY:
                controls.add(new KeyUsageControl(KeyUsage.encipherOnly, required));
                break;
            case DIGITAL_SIGNATURE:
                controls.add(new KeyUsageControl(KeyUsage.digitalSignature, required));
                break;
            case KEY_AGREEMENT:
                controls.add(new KeyUsageControl(KeyUsage.keyAgreement, required));
                break;
            case KEY_CERT_SIGN:
                controls.add(new KeyUsageControl(KeyUsage.keyCertSign, required));
                break;
            case KEY_ENCIPHERMENT:
                controls.add(new KeyUsageControl(KeyUsage.keyEncipherment, required));
                break;
            default:
                throw new RuntimeException(
                    "should not reach here, unknown GeneralSubtreeBaseType " + m.getValue());
            }
        }

        return Collections.unmodifiableSet(controls);
    } // method buildKeyUsageOptions

    public static Set<ExtKeyUsageControl> buildExtKeyUsageOptions(final ExtendedKeyUsage extConf) {
        ParamUtil.requireNonNull("extConf", extConf);
        List<Usage> usages = extConf.getUsage();
        Set<ExtKeyUsageControl> controls = new HashSet<>();

        for (Usage m : usages) {
            ExtKeyUsageControl usage = new ExtKeyUsageControl(
                    new ASN1ObjectIdentifier(m.getValue()), m.isRequired());
            controls.add(usage);
        }

        return Collections.unmodifiableSet(controls);
    } // method buildExtKeyUsageOptions

    public static Map<ASN1ObjectIdentifier, ExtensionValue> buildConstantExtesions(
            final ExtensionsType extensionsType) throws CertprofileException {
        if (extensionsType == null) {
            return null;
        }

        Map<ASN1ObjectIdentifier, ExtensionValue> map = new HashMap<>();

        for (ExtensionType m : extensionsType.getExtension()) {
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(m.getType().getValue());
            if (Extension.subjectAlternativeName.equals(oid)
                    || Extension.subjectInfoAccess.equals(oid)
                    || Extension.biometricInfo.equals(oid)) {
                continue;
            }

            if (m.getValue() == null || !(m.getValue().getAny() instanceof ConstantExtValue)) {
                continue;
            }

            ConstantExtValue extConf = (ConstantExtValue) m.getValue().getAny();
            byte[] encodedValue = extConf.getValue();
            ASN1StreamParser parser = new ASN1StreamParser(encodedValue);
            ASN1Encodable value;
            try {
                value = parser.readObject();
            } catch (IOException ex) {
                throw new CertprofileException("could not parse the constant extension value", ex);
            }
            ExtensionValue extension = new ExtensionValue(m.isCritical(), value);
            map.put(oid, extension);
        }

        if (CollectionUtil.isEmpty(map)) {
            return null;
        }

        return Collections.unmodifiableMap(map);
    } // buildConstantExtesions

    public static Set<ASN1ObjectIdentifier> toOidSet(final List<OidWithDescType> oidWithDescTypes) {
        if (CollectionUtil.isEmpty(oidWithDescTypes)) {
            return null;
        }

        Set<ASN1ObjectIdentifier> oids = new HashSet<>();
        for (OidWithDescType type : oidWithDescTypes) {
            oids.add(new ASN1ObjectIdentifier(type.getValue()));
        }
        return Collections.unmodifiableSet(oids);
    }

    public static AdmissionSyntaxOption buildAdmissionSyntax(final boolean critical,
            final AdmissionSyntax type)
            throws CertprofileException {
        List<AdmissionsOption> admissionsList = new LinkedList<>();
        for (AdmissionsType at : type.getContentsOfAdmissions()) {
            List<ProfessionInfoOption> professionInfos = new LinkedList<>();
            for (ProfessionInfoType pi : at.getProfessionInfo()) {
                NamingAuthority namingAuthorityL3 = null;
                if (pi.getNamingAuthority() != null) {
                    namingAuthorityL3 = buildNamingAuthority(pi.getNamingAuthority());
                }

                List<OidWithDescType> oidTypes = pi.getProfessionOid();
                List<ASN1ObjectIdentifier> oids = null;
                if (CollectionUtil.isNonEmpty(oidTypes) ) {
                    oids = new LinkedList<>();
                    for (OidWithDescType k : oidTypes) {
                        oids.add(new ASN1ObjectIdentifier(k.getValue()));
                    }
                }

                RegistrationNumber rnType = pi.getRegistrationNumber();
                RegistrationNumberOption rno = (rnType == null) ? null
                        : new RegistrationNumberOption(rnType.getRegex(), rnType.getConstant());

                ProfessionInfoOption pio = new ProfessionInfoOption(namingAuthorityL3,
                        pi.getProfessionItem(), oids, rno, pi.getAddProfessionInfo());

                professionInfos.add(pio);
            }

            GeneralName admissionAuthority = null;
            if (at.getNamingAuthority() != null) {
                admissionAuthority = GeneralName.getInstance(
                        asn1PrimitivefromByteArray(at.getAdmissionAuthority()));
            }

            NamingAuthority namingAuthority = null;
            if (at.getNamingAuthority() != null) {
                namingAuthority = buildNamingAuthority(at.getNamingAuthority());
            }

            AdmissionsOption admissionsOption = new AdmissionsOption(admissionAuthority,
                    namingAuthority, professionInfos);
            admissionsList.add(admissionsOption);
        }

        GeneralName admissionAuthority = null;
        if (type.getAdmissionAuthority() != null) {
            admissionAuthority = GeneralName.getInstance(type.getAdmissionAuthority());
        }

        return new AdmissionSyntaxOption(critical, admissionAuthority, admissionsList);
    }

    private static ASN1Primitive asn1PrimitivefromByteArray(final byte[] encoded)
            throws CertprofileException {
        try {
            return ASN1Primitive.fromByteArray(encoded);
        } catch (IOException ex) {
            throw new CertprofileException(ex.getMessage(), ex);
        }
    }

    private static KeyParametersOption convertKeyParametersOption(final AlgorithmType type)
            throws CertprofileException {
        ParamUtil.requireNonNull("type", type);
        if (type.getParameters() == null || type.getParameters().getAny() == null) {
            return KeyParametersOption.ALLOW_ALL;
        }

        Object paramsObj = type.getParameters().getAny();
        if (paramsObj instanceof ECParameters) {
            ECParameters params = (ECParameters) paramsObj;
            KeyParametersOption.ECParamatersOption option =
                    new KeyParametersOption.ECParamatersOption();

            if (params.getCurves() != null) {
                Curves curves = params.getCurves();
                Set<ASN1ObjectIdentifier> curveOids = toOidSet(curves.getCurve());
                option.setCurveOids(curveOids);
            }

            if (params.getPointEncodings() != null) {
                List<Byte> bytes = params.getPointEncodings().getPointEncoding();
                Set<Byte> pointEncodings = new HashSet<>(bytes);
                option.setPointEncodings(pointEncodings);
            }

            return option;
        } else if (paramsObj instanceof RSAParameters) {
            RSAParameters params = (RSAParameters) paramsObj;
            KeyParametersOption.RSAParametersOption option =
                    new KeyParametersOption.RSAParametersOption();

            Set<Range> modulusLengths = buildParametersMap(params.getModulusLength());
            option.setModulusLengths(modulusLengths);

            return option;
        } else if (paramsObj instanceof RSAPSSParameters) {
            RSAPSSParameters params = (RSAPSSParameters) paramsObj;
            KeyParametersOption.RSAPSSParametersOption option =
                    new KeyParametersOption.RSAPSSParametersOption();

            Set<Range> modulusLengths = buildParametersMap(params.getModulusLength());
            option.setModulusLengths(modulusLengths);

            return option;
        } else if (paramsObj instanceof DSAParameters) {
            DSAParameters params = (DSAParameters) paramsObj;
            KeyParametersOption.DSAParametersOption option =
                    new KeyParametersOption.DSAParametersOption();

            Set<Range> plengths = buildParametersMap(params.getPLength());
            option.setPlengths(plengths);

            Set<Range> qlengths = buildParametersMap(params.getQLength());
            option.setQlengths(qlengths);

            return option;
        } else if (paramsObj instanceof DHParameters) {
            DHParameters params = (DHParameters) paramsObj;
            KeyParametersOption.DHParametersOption option =
                    new KeyParametersOption.DHParametersOption();

            Set<Range> plengths = buildParametersMap(params.getPLength());
            option.setPlengths(plengths);

            Set<Range> qlengths = buildParametersMap(params.getQLength());
            option.setQlengths(qlengths);

            return option;
        } else if (paramsObj instanceof GostParameters) {
            GostParameters params = (GostParameters) paramsObj;
            KeyParametersOption.GostParametersOption option =
                    new KeyParametersOption.GostParametersOption();

            Set<ASN1ObjectIdentifier> set = toOidSet(params.getPublicKeyParamSet());
            option.setPublicKeyParamSets(set);

            set = toOidSet(params.getDigestParamSet());
            option.setDigestParamSets(set);

            set = toOidSet(params.getEncryptionParamSet());
            option.setEncryptionParamSets(set);

            return option;
        } else {
            throw new CertprofileException(
                    "unknown public key parameters type " + paramsObj.getClass().getName());
        }
    } // method convertKeyParametersOption

    public static final DirectoryStringType convertDirectoryStringType(
            final org.xipki.ca.certprofile.x509.jaxb.DirectoryStringType jaxbType) {
        if (jaxbType == null) {
            return null;
        }

        switch (jaxbType) {
        case BMP_STRING:
            return DirectoryStringType.bmpString;
        case PRINTABLE_STRING:
            return DirectoryStringType.printableString;
        case TELETEX_STRING:
            return DirectoryStringType.teletexString;
        case UTF_8_STRING:
            return DirectoryStringType.utf8String;
        default:
            throw new RuntimeException(
                "should not reach here, undefined DirectoryStringType " + jaxbType);
        }
    }

    public static final StringType convertStringType(
            final org.xipki.ca.certprofile.x509.jaxb.StringType jaxbType) {
        if (jaxbType == null) {
            return null;
        }

        switch (jaxbType) {
        case BMP_STRING:
            return StringType.bmpString;
        case PRINTABLE_STRING:
            return StringType.printableString;
        case TELETEX_STRING:
            return StringType.teletexString;
        case UTF_8_STRING:
            return StringType.utf8String;
        case IA_5_STRING:
            return StringType.ia5String;
        default:
            throw new RuntimeException("should not reach here, undefined StringType " + jaxbType);
        }
    }

    public static org.bouncycastle.asn1.x509.CertificatePolicies createCertificatePolicies(
            final List<CertificatePolicyInformation> policyInfos) throws CertprofileException {
        ParamUtil.requireNonEmpty("policyInfos", policyInfos);

        int size = policyInfos.size();
        PolicyInformation[] infos = new PolicyInformation[size];

        int idx = 0;
        for (CertificatePolicyInformation policyInfo : policyInfos) {
            String policyId = policyInfo.certPolicyId();
            List<CertificatePolicyQualifier> qualifiers = policyInfo.qualifiers();

            ASN1Sequence policyQualifiers = null;
            if (CollectionUtil.isNonEmpty(qualifiers)) {
                policyQualifiers = createPolicyQualifiers(qualifiers);
            }

            ASN1ObjectIdentifier policyOid = new ASN1ObjectIdentifier(policyId);
            infos[idx++] = (policyQualifiers == null) ? new PolicyInformation(policyOid)
                    : new PolicyInformation(policyOid, policyQualifiers);
        }

        return new org.bouncycastle.asn1.x509.CertificatePolicies(infos);
    }

    private static ASN1Sequence createPolicyQualifiers(
            final List<CertificatePolicyQualifier> qualifiers) {
        ParamUtil.requireNonNull("qualifiers", qualifiers);
        List<PolicyQualifierInfo> qualifierInfos = new ArrayList<>(qualifiers.size());
        for (CertificatePolicyQualifier qualifier : qualifiers) {
            PolicyQualifierInfo qualifierInfo;
            if (qualifier.cpsUri() != null) {
                qualifierInfo = new PolicyQualifierInfo(qualifier.cpsUri());
            } else if (qualifier.userNotice() != null) {
                UserNotice userNotice = new UserNotice(null, qualifier.userNotice());
                qualifierInfo = new PolicyQualifierInfo(PKCSObjectIdentifiers.id_spq_ets_unotice,
                        userNotice);
            } else {
                qualifierInfo = null;
            }

            if (qualifierInfo != null) {
                qualifierInfos.add(qualifierInfo);
            }
            //PolicyQualifierId qualifierId
        }

        return new DERSequence(qualifierInfos.toArray(new PolicyQualifierInfo[0]));
    }

    private static NamingAuthority buildNamingAuthority(final NamingAuthorityType jaxb) {
        ASN1ObjectIdentifier oid = (jaxb.getOid() == null) ? null
                : new ASN1ObjectIdentifier(jaxb.getOid().getValue());
        String url = StringUtil.isBlank(jaxb.getUrl()) ? null
                : jaxb.getUrl();
        DirectoryString text = StringUtil.isBlank(jaxb.getText()) ? null
                : new DirectoryString(jaxb.getText());
        return new NamingAuthority(oid, url, text);
    }

}
