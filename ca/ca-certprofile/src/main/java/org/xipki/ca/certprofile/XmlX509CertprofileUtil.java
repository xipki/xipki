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
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.xipki.ca.api.CertprofileException;
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
import org.xipki.ca.certprofile.x509.jaxb.ObjectFactory;
import org.xipki.ca.certprofile.x509.jaxb.OidWithDescType;
import org.xipki.ca.certprofile.x509.jaxb.PolicyConstraints;
import org.xipki.ca.certprofile.x509.jaxb.PolicyIdMappingType;
import org.xipki.ca.certprofile.x509.jaxb.RSAPSSParameters;
import org.xipki.ca.certprofile.x509.jaxb.RSAParameters;
import org.xipki.ca.certprofile.x509.jaxb.RangeType;
import org.xipki.ca.certprofile.x509.jaxb.RangesType;
import org.xipki.ca.certprofile.x509.jaxb.UsageType;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType.KeyAlgorithms;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.security.api.KeyUsage;
import org.xipki.security.api.util.X509Util;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class XmlX509CertprofileUtil
{
    private final static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

    public static X509ProfileType parse(
            final InputStream xmlConfStream)
    throws CertprofileException
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
                    URL url = XmlX509CertprofileUtil.class.getResource("/xsd/certprofile.xsd");
                    jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
                }

                rootElement = (JAXBElement<?>) jaxbUnmarshaller.unmarshal(xmlConfStream);
                try
                {
                    xmlConfStream.close();
                } catch (IOException e)
                {
                }
            }
            catch(SAXException e)
            {
                throw new CertprofileException("parse profile failed, message: " + e.getMessage(), e);
            } catch(JAXBException e)
            {
                throw new CertprofileException("parse profile failed, message: " + XMLUtil.getMessage((JAXBException) e), e);
            }

            Object rootType = rootElement.getValue();
            if(rootType instanceof X509ProfileType)
            {
                return (X509ProfileType) rootElement.getValue();
            }
            else
            {
                throw new CertprofileException("invalid root element type");
            }
        }
    }

    public static List<CertificatePolicyInformation> buildCertificatePolicies(
            final CertificatePolicies type)
    {
        List<CertificatePolicyInformationType> policyPairs = type.getCertificatePolicyInformation();
        if(CollectionUtil.isEmpty(policyPairs))
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

    public static PolicyMappings buildPolicyMappings(
            final org.xipki.ca.certprofile.x509.jaxb.PolicyMappings type)
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

    public static NameConstraints buildNameConstrains(
            final org.xipki.ca.certprofile.x509.jaxb.NameConstraints type)
    throws CertprofileException
    {
        GeneralSubtree[] permitted = buildGeneralSubtrees(type.getPermittedSubtrees());
        GeneralSubtree[] excluded = buildGeneralSubtrees(type.getExcludedSubtrees());
        if(permitted == null && excluded == null)
        {
            return null;
        }
        return new NameConstraints(permitted, excluded);
    }

    private static GeneralSubtree[] buildGeneralSubtrees(
            final GeneralSubtreesType subtrees)
    throws CertprofileException
    {
        if(subtrees == null || CollectionUtil.isEmpty(subtrees.getBase()))
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

    private static GeneralSubtree buildGeneralSubtree(
            final GeneralSubtreeBaseType type)
    throws CertprofileException
    {
        GeneralName base = null;
        if(type.getDirectoryName() != null)
        {
            base = new GeneralName(X509Util.reverse(
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
            throw new RuntimeException("should not reach here, unknown child of GeneralSubtreeBaseType");
        }

        Integer i = type.getMinimum();
        if(i != null && i < 0)
        {
            throw new CertprofileException("negative minimum is not allowed: " + i);
        }

        BigInteger minimum = (i == null) ? null : BigInteger.valueOf(i.intValue());

        i = type.getMaximum();
        if(i != null && i < 0)
        {
            throw new CertprofileException("negative maximum is not allowed: " + i);
        }

        BigInteger maximum = (i == null) ? null : BigInteger.valueOf(i.intValue());

        return new GeneralSubtree(base, minimum, maximum);
    }

    public static ASN1Sequence buildPolicyConstrains(
            final PolicyConstraints type)
    throws CertprofileException
    {
        Integer requireExplicitPolicy = type.getRequireExplicitPolicy();
        if(requireExplicitPolicy != null && requireExplicitPolicy < 0)
        {
            throw new CertprofileException("negative requireExplicitPolicy is not allowed: " + requireExplicitPolicy);
        }

        Integer inhibitPolicyMapping = type.getInhibitPolicyMapping();
        if(inhibitPolicyMapping != null && inhibitPolicyMapping < 0)
        {
            throw new CertprofileException("negative inhibitPolicyMapping is not allowed: " + inhibitPolicyMapping);
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

    public static Set<GeneralNameMode> buildGeneralNameMode(
            final GeneralNameType name)
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

    private static Set<Range> buildParametersMap(
            final RangesType ranges)
    {
        if(ranges == null)
        {
            return null;
        }

        Set<Range> ret = new HashSet<>();
        for(RangeType range : ranges.getRange())
        {
            if(range.getMin() != null || range.getMax() != null)
            {
                ret.add(new Range(range.getMin(), range.getMax()));
            }
        }
        return ret;
    }

    public static Map<ASN1ObjectIdentifier, KeyParametersOption> buildKeyAlgorithms(
            final KeyAlgorithms keyAlgos)
    throws CertprofileException
    {
        Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms = new HashMap<>();
        for(AlgorithmType type : keyAlgos.getAlgorithm())
        {
            List<OidWithDescType> algIds = type.getAlgorithm();
            List<ASN1ObjectIdentifier> oids = new ArrayList<>(algIds.size());
            for(OidWithDescType algId : algIds)
            {
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(algId.getValue());
                if(keyAlgorithms.containsKey(oid))
                {
                    throw new CertprofileException("duplicate definition of keyAlgorithm " + oid.getId());
                }
                oids.add(oid);
            }

            KeyParametersOption keyParamsOption = convertKeyParametersOption(type);
            for(ASN1ObjectIdentifier oid : oids)
            {
                keyAlgorithms.put(oid, keyParamsOption);
            }
        }
        return CollectionUtil.unmodifiableMap(keyAlgorithms, false, true);
    }

    public static Map<ASN1ObjectIdentifier, ExtensionControl> buildExtensionControls(
            final ExtensionsType extensionsType)
    throws CertprofileException
    {
        // Extension controls
        Map<ASN1ObjectIdentifier, ExtensionControl> controls = new HashMap<>();
        for(ExtensionType m : extensionsType.getExtension())
        {
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(m.getType().getValue());
            if(controls.containsKey(oid))
            {
                throw new CertprofileException("duplicated definition of extension " + oid.getId());
            }
            controls.put(oid, new ExtensionControl(m.isCritical(), m.isRequired(), m.isPermittedInRequest()));
        }

        return Collections.unmodifiableMap(controls);
    }

    public static List<ASN1ObjectIdentifier> toOIDList(
            final List<OidWithDescType> oidWithDescTypes)
    {
        if(CollectionUtil.isEmpty(oidWithDescTypes))
        {
            return null;
        }

        List<ASN1ObjectIdentifier> oids = new LinkedList<>();
        for(OidWithDescType type : oidWithDescTypes)
        {
            oids.add(new ASN1ObjectIdentifier(type.getValue()));
        }
        return Collections.unmodifiableList(oids);
    }

    public static Set<KeyUsageControl> buildKeyUsageOptions(
            final org.xipki.ca.certprofile.x509.jaxb.KeyUsage extConf)
    {
        List<UsageType> usages = extConf.getUsage();
        Set<KeyUsageControl> controls = new HashSet<>();

        for(UsageType m : usages)
        {
            boolean required = m.isRequired();
            switch(m.getValue())
            {
            case C_RL_SIGN:
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
                throw new RuntimeException("should not reach here, unknown GeneralSubtreeBaseType " + m.getValue());
            }
        }

        return Collections.unmodifiableSet(controls);
    }

    public static Set<ExtKeyUsageControl> buildExtKeyUsageOptions(
            final ExtendedKeyUsage extConf)
    {
        List<Usage> usages = extConf.getUsage();
        Set<ExtKeyUsageControl> controls = new HashSet<>();

        for(Usage m : usages)
        {
            ExtKeyUsageControl usage = new ExtKeyUsageControl(
                    new ASN1ObjectIdentifier(m.getValue()), m.isRequired());
            controls.add(usage);
        }

        return Collections.unmodifiableSet(controls);
    }

    public static Map<ASN1ObjectIdentifier, ExtensionValue> buildConstantExtesions(
            final ExtensionsType extensionsType)
    throws CertprofileException
    {
        if(extensionsType == null)
        {
            return null;
        }

        Map<ASN1ObjectIdentifier, ExtensionValue> map = new HashMap<>();

        for(ExtensionType m : extensionsType.getExtension())
        {
            if(m.getValue() == null || m.getValue().getAny() instanceof ConstantExtValue == false)
            {
                continue;
            }

            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(m.getType().getValue());
            if(Extension.subjectAlternativeName.equals(oid) ||
                    Extension.subjectInfoAccess.equals(oid) ||
                    Extension.biometricInfo.equals(oid))
            {
                continue;
            }

            ConstantExtValue extConf = (ConstantExtValue) m.getValue().getAny();
            byte[] encodedValue = extConf.getValue();
            ASN1StreamParser parser = new ASN1StreamParser(encodedValue);
            ASN1Encodable value;
            try
            {
                value = parser.readObject();
            } catch (IOException e)
            {
                throw new CertprofileException("could not parse the constant extension value", e);
            }
            ExtensionValue extension = new ExtensionValue(m.isCritical(), value);
            map.put(oid, extension);
        }

        if(CollectionUtil.isEmpty(map))
        {
            return null;
        }

        return Collections.unmodifiableMap(map);
    }

    public static Set<ASN1ObjectIdentifier> toOIDSet(
            final List<OidWithDescType> oidWithDescTypes)
    {
        if(CollectionUtil.isEmpty(oidWithDescTypes))
        {
            return null;
        }

        Set<ASN1ObjectIdentifier> oids = new HashSet<>();
        for(OidWithDescType type : oidWithDescTypes)
        {
            oids.add(new ASN1ObjectIdentifier(type.getValue()));
        }
        return Collections.unmodifiableSet(oids);
    }

    private static final KeyParametersOption convertKeyParametersOption(
            final AlgorithmType type)
    throws CertprofileException
    {
        if(type.getParameters() == null || type.getParameters().getAny() == null)
        {
            return KeyParametersOption.allowAll;
        }

        Object paramsObj = type.getParameters().getAny();
        if(paramsObj instanceof ECParameters)
        {
            ECParameters params = (ECParameters) paramsObj;
            KeyParametersOption.ECParamatersOption option = new KeyParametersOption.ECParamatersOption();

            if(params.getCurves() != null)
            {
                Curves curves = params.getCurves();
                Set<ASN1ObjectIdentifier> curveOids = toOIDSet(curves.getCurve());
                option.setCurveOids(curveOids);
            }

            if(params.getPointEncodings() != null)
            {
                List<Byte> bytes = params.getPointEncodings().getPointEncoding();
                Set<Byte> pointEncodings = new HashSet<>(bytes);
                option.setPointEncodings(pointEncodings);
            }

            return option;
        }
        else if(paramsObj instanceof RSAParameters)
        {
            RSAParameters params = (RSAParameters) paramsObj;
            KeyParametersOption.RSAParametersOption option = new KeyParametersOption.RSAParametersOption();

            Set<Range> modulusLengths = buildParametersMap(params.getModulusLength());
            option.setModulusLengths(modulusLengths);

            return option;
        }
        else if(paramsObj instanceof RSAPSSParameters)
        {
            RSAPSSParameters params = (RSAPSSParameters) paramsObj;
            KeyParametersOption.RSAPSSParametersOption option = new KeyParametersOption.RSAPSSParametersOption();

            Set<Range> modulusLengths = buildParametersMap(params.getModulusLength());
            option.setModulusLengths(modulusLengths);

            return option;
        }
        else if(paramsObj instanceof DSAParameters)
        {
            DSAParameters params = (DSAParameters) paramsObj;
            KeyParametersOption.DSAParametersOption option = new KeyParametersOption.DSAParametersOption();

            Set<Range> pLengths = buildParametersMap(params.getPLength());
            option.setPLengths(pLengths);

            Set<Range> qLengths = buildParametersMap(params.getQLength());
            option.setQLengths(qLengths);

            return option;
        }
        else if(paramsObj instanceof DHParameters)
        {
            DHParameters params = (DHParameters) paramsObj;
            KeyParametersOption.DHParametersOption option = new KeyParametersOption.DHParametersOption();

            Set<Range> pLengths = buildParametersMap(params.getPLength());
            option.setPLengths(pLengths);

            Set<Range> qLengths = buildParametersMap(params.getQLength());
            option.setQLengths(qLengths);

            return option;
        }
        else if(paramsObj instanceof GostParameters)
        {
            GostParameters params = (GostParameters) paramsObj;
            KeyParametersOption.GostParametersOption option = new KeyParametersOption.GostParametersOption();

            Set<ASN1ObjectIdentifier> set = toOIDSet(params.getPublicKeyParamSet());
            option.setPublicKeyParamSets(set);

            set = toOIDSet(params.getDigestParamSet());
            option.setDigestParamSets(set);

            set = toOIDSet(params.getEncryptionParamSet());
            option.setEncryptionParamSets(set);

            return option;
        }
        else
        {
            throw new CertprofileException("unknown public key parameters type " + paramsObj.getClass().getName());
        }
    }

    public static final DirectoryStringType convertDirectoryStringType(
            final org.xipki.ca.certprofile.x509.jaxb.DirectoryStringType jaxbType)
    {
        if(jaxbType == null)
        {
            return null;
        }
        switch(jaxbType)
        {
        case BMP_STRING:
            return DirectoryStringType.bmpString;
        case PRINTABLE_STRING:
            return DirectoryStringType.printableString;
        case TELETEX_STRING:
            return DirectoryStringType.teletexString;
        case UTF_8_STRING:
            return DirectoryStringType.utf8String;
        default:
            throw new RuntimeException("should not reach here, undefined DirectoryStringType " + jaxbType);
        }
    }

    public static final StringType convertStringType(
            final org.xipki.ca.certprofile.x509.jaxb.StringType jaxbType)
    {
        if(jaxbType == null)
        {
            return null;
        }
        switch(jaxbType)
        {
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

}
