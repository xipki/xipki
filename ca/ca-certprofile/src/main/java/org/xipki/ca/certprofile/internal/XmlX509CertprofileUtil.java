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

package org.xipki.ca.certprofile.internal;

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
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.GeneralNameMode;
import org.xipki.ca.api.profile.GeneralNameTag;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.Range;
import org.xipki.ca.api.profile.x509.CertificatePolicyInformation;
import org.xipki.ca.api.profile.x509.CertificatePolicyQualifier;
import org.xipki.ca.api.profile.x509.ExtKeyUsageControl;
import org.xipki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.ca.certprofile.internal.x509.jaxb.AddTextType;
import org.xipki.ca.certprofile.internal.x509.jaxb.AlgorithmType;
import org.xipki.ca.certprofile.internal.x509.jaxb.CertificatePolicyInformationType;
import org.xipki.ca.certprofile.internal.x509.jaxb.CertificatePolicyInformationType.PolicyQualifiers;
import org.xipki.ca.certprofile.internal.x509.jaxb.ConditionType;
import org.xipki.ca.certprofile.internal.x509.jaxb.ConstantExtensionType;
import org.xipki.ca.certprofile.internal.x509.jaxb.ECParametersType;
import org.xipki.ca.certprofile.internal.x509.jaxb.ECParametersType.Curves;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionType;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.AuthorityKeyIdentifier;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.ConstantExtensions;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.ExtendedKeyUsage;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.ExtendedKeyUsage.Usage;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.PolicyConstraints;
import org.xipki.ca.certprofile.internal.x509.jaxb.GeneralNameType;
import org.xipki.ca.certprofile.internal.x509.jaxb.GeneralSubtreeBaseType;
import org.xipki.ca.certprofile.internal.x509.jaxb.GeneralSubtreesType;
import org.xipki.ca.certprofile.internal.x509.jaxb.KeyUsageType;
import org.xipki.ca.certprofile.internal.x509.jaxb.ObjectFactory;
import org.xipki.ca.certprofile.internal.x509.jaxb.OidWithDescType;
import org.xipki.ca.certprofile.internal.x509.jaxb.PolicyIdMappingType;
import org.xipki.ca.certprofile.internal.x509.jaxb.RangeType;
import org.xipki.ca.certprofile.internal.x509.jaxb.RangesType;
import org.xipki.ca.certprofile.internal.x509.jaxb.X509ProfileType;
import org.xipki.ca.certprofile.internal.x509.jaxb.X509ProfileType.KeyAlgorithms;
import org.xipki.common.KeyUsage;
import org.xipki.common.SecurityUtil;
import org.xipki.common.XMLUtil;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class XmlX509CertprofileUtil
{
    private final static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

    public static X509ProfileType parse(InputStream xmlConfStream)
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

    public static List<CertificatePolicyInformation> buildCertificatePolicies(ExtensionsType.CertificatePolicies type)
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

    public static PolicyMappings buildPolicyMappings(
            org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.PolicyMappings type)
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
            org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.NameConstraints type)
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

    public static GeneralSubtree[] buildGeneralSubtrees(GeneralSubtreesType subtrees)
    throws CertprofileException
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

    public static GeneralSubtree buildGeneralSubtree(GeneralSubtreeBaseType type)
    throws CertprofileException
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

    public static ASN1Sequence buildPolicyConstrains(PolicyConstraints type)
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

    public static Set<GeneralNameMode> buildGeneralNameMode(GeneralNameType name)
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

    public static List<AddText> buildAddText(List<AddTextType> types)
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

    public static Condition createCondition(ConditionType type)
    {
        return type == null ? null : new Condition(type);
    }

    public static Set<Range> buildParametersMap(RangesType ranges)
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

    public static Map<ASN1ObjectIdentifier, KeyParametersOption> buildKeyAlgorithms(KeyAlgorithms keyAlgos)
    throws CertprofileException
    {
        Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms = new HashMap<>();
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
                    Set<ASN1ObjectIdentifier> curveOids = XmlX509CertprofileUtil.toOIDSet(curves.getCurve());
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

                Set<Range> modulusLengths = XmlX509CertprofileUtil.buildParametersMap(
                        type.getRSAParameters().getModulusLength());
                option.setModulusLengths(modulusLengths);

            } else if(type.getRSAPSSParameters() != null)
            {
                KeyParametersOption.RSAPSSParametersOption option = new KeyParametersOption.RSAPSSParametersOption();
                keyParamsOption = option;

                Set<Range> modulusLengths = XmlX509CertprofileUtil.buildParametersMap(
                        type.getRSAPSSParameters().getModulusLength());
                option.setModulusLengths(modulusLengths);
            } else if(type.getDSAParameters() != null)
            {
                KeyParametersOption.DSAParametersOption option = new KeyParametersOption.DSAParametersOption();
                keyParamsOption = option;

                Set<Range> pLengths = XmlX509CertprofileUtil.buildParametersMap(type.getDSAParameters().getPLength());
                option.setPLengths(pLengths);

                Set<Range> qLengths = XmlX509CertprofileUtil.buildParametersMap(type.getDSAParameters().getQLength());
                option.setQLengths(qLengths);
            } else if(type.getDHParameters() != null)
            {
                KeyParametersOption.DHParametersOption option = new KeyParametersOption.DHParametersOption();
                keyParamsOption = option;

                Set<Range> pLengths = XmlX509CertprofileUtil.buildParametersMap(type.getDHParameters().getPLength());
                option.setPLengths(pLengths);

                Set<Range> qLengths = XmlX509CertprofileUtil.buildParametersMap(type.getDHParameters().getQLength());
                option.setQLengths(qLengths);
            }
            else if(type.getGostParameters() != null)
            {
                KeyParametersOption.GostParametersOption option = new KeyParametersOption.GostParametersOption();
                keyParamsOption = option;

                Set<ASN1ObjectIdentifier> set = XmlX509CertprofileUtil.toOIDSet(
                        type.getGostParameters().getPublicKeyParamSet());
                option.setPublicKeyParamSets(set);

                set = XmlX509CertprofileUtil.toOIDSet(type.getGostParameters().getDigestParamSet());
                option.setDigestParamSets(set);

                set = XmlX509CertprofileUtil.toOIDSet(type.getGostParameters().getEncryptionParamSet());
                option.setEncryptionParamSets(set);
            } else
            {
                keyParamsOption = KeyParametersOption.allowAll;
            }

            List<OidWithDescType> algIds = type.getAlgorithm();
            for(OidWithDescType algId : algIds)
            {
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(algId.getValue());
                if(keyAlgorithms.containsKey(oid))
                {
                    throw new CertprofileException("duplicate definition of keyAlgorithm " + oid.getId());
                }
                keyAlgorithms.put(oid, keyParamsOption);
            }
        }
        return keyAlgorithms.isEmpty() ? null : Collections.unmodifiableMap(keyAlgorithms);
    }

    public static Map<ASN1ObjectIdentifier, ExtensionControl> buildExtensionControls(
            ExtensionsType extensionsType)
    {
        // Extension controls
        Map<ASN1ObjectIdentifier, ExtensionControl> controls = new HashMap<>();
        for(ExtensionType extensionType : extensionsType.getExtension())
        {
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(extensionType.getValue());
            boolean required = extensionType.isRequired();
            boolean critical = getBoolean(extensionType.isCritical(), false);
            controls.put(oid, new ExtensionControl(critical, required, extensionType.isPermittedInRequest()));
        }

        return Collections.unmodifiableMap(controls);
    }

    public static List<ASN1ObjectIdentifier> toOIDList(List<OidWithDescType> oidWithDescTypes)
    {
        if(oidWithDescTypes == null || oidWithDescTypes.isEmpty())
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

    public static KeyUsageOptions buildKeyUsageOptions(
            List<org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.KeyUsage> usages)
    {
        List<KeyUsageOption> optionList = new ArrayList<>(usages.size());

        for(org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.KeyUsage t : usages)
        {
            Set<KeyUsageControl> set = new HashSet<>();
            for(KeyUsageType type : t.getUsage())
            {
                boolean required = type.isRequired();
                switch(type.getValue())
                {
                case C_RL_SIGN:
                    set.add(new KeyUsageControl(KeyUsage.cRLSign, required));
                    break;
                case DATA_ENCIPHERMENT:
                    set.add(new KeyUsageControl(KeyUsage.dataEncipherment, required));
                    break;
                case CONTENT_COMMITMENT:
                    set.add(new KeyUsageControl(KeyUsage.contentCommitment, required));
                    break;
                case DECIPHER_ONLY:
                    set.add(new KeyUsageControl(KeyUsage.decipherOnly, required));
                    break;
                case ENCIPHER_ONLY:
                    set.add(new KeyUsageControl(KeyUsage.encipherOnly, required));
                    break;
                case DIGITAL_SIGNATURE:
                    set.add(new KeyUsageControl(KeyUsage.digitalSignature, required));
                    break;
                case KEY_AGREEMENT:
                    set.add(new KeyUsageControl(KeyUsage.keyAgreement, required));
                    break;
                case KEY_CERT_SIGN:
                    set.add(new KeyUsageControl(KeyUsage.keyCertSign, required));
                    break;
                case KEY_ENCIPHERMENT:
                    set.add(new KeyUsageControl(KeyUsage.keyEncipherment, required));
                    break;
                default:
                    throw new RuntimeException("should not reach here");
                }
            }

            Set<KeyUsageControl> keyusageSet = Collections.unmodifiableSet(set);

            Condition condition = XmlX509CertprofileUtil.createCondition(t.getCondition());
            KeyUsageOption option = new KeyUsageOption(condition, keyusageSet);
            optionList.add(option);
        }

        return new KeyUsageOptions(optionList);
    }

    public static ExtKeyUsageOptions buildExtKeyUsageOptions(List<ExtendedKeyUsage> usages)
    {
        List<ExtKeyUsageOption> optionList = new ArrayList<>(usages.size());

        for(org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.ExtendedKeyUsage t : usages)
        {
            List<Usage> list = t.getUsage();
            Set<ExtKeyUsageControl> extendedKeyusageSet = new HashSet<>();
            for(Usage entry : list)
            {
                ExtKeyUsageControl usage = new ExtKeyUsageControl(
                        new ASN1ObjectIdentifier(entry.getValue()), entry.isRequired());
                extendedKeyusageSet.add(usage);
            }
            Condition condition = XmlX509CertprofileUtil.createCondition(t.getCondition());
            ExtKeyUsageOption option = new ExtKeyUsageOption(condition, extendedKeyusageSet);
            optionList.add(option);
        }

        return new ExtKeyUsageOptions(optionList);
    }

    public static AuthorityKeyIdentifierOption buildAuthorityKeyIdentifier(
            AuthorityKeyIdentifier akiType, ExtensionControl control)
    {
        boolean includeIssuerAndSerial = true;
        if(akiType != null)
        {
            Boolean B = akiType.isIncludeIssuerAndSerial();
            if(B != null)
            {
                includeIssuerAndSerial = B.booleanValue();
            }
        }

        return new AuthorityKeyIdentifierOption(includeIssuerAndSerial, control);
    }

    public static Map<ASN1ObjectIdentifier, ExtensionValueOptions> buildConstantExtesions(
            List<ConstantExtensions> cess,
            Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls)
    throws CertprofileException
    {
        Map<ASN1ObjectIdentifier, List<ExtensionValueOption>> map = new HashMap<>();
        for(ConstantExtensions ces : cess)
        {
            for(ConstantExtensionType ce :ces.getConstantExtension())
            {
                ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(ce.getType().getValue());
                ExtensionControl extensionControl = extensionControls.get(type);
                if(extensionControl != null)
                {
                    byte[] encodedValue = ce.getValue();
                    ASN1StreamParser parser = new ASN1StreamParser(encodedValue);
                    ASN1Encodable value;
                    try
                    {
                        value = parser.readObject();
                    } catch (IOException e)
                    {
                        throw new CertprofileException("Could not parse the constant extension value", e);
                    }
                    ExtensionValue extension = new ExtensionValue(extensionControl.isCritical(), value);
                    ExtensionValueOption option = new ExtensionValueOption(
                            XmlX509CertprofileUtil.createCondition(ce.getCondition()), extension);

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

        if(map.isEmpty())
        {
            return null;
        }

        Map<ASN1ObjectIdentifier, ExtensionValueOptions> constantExtensions = new HashMap<>(map.size());
        for(ASN1ObjectIdentifier type : map.keySet())
        {
            List<ExtensionValueOption> options = map.get(type);
            constantExtensions.put(type, new ExtensionValueOptions(options));
        }

        return Collections.unmodifiableMap(constantExtensions);
    }

    public static Set<ASN1ObjectIdentifier> toOIDSet(List<OidWithDescType> oidWithDescTypes)
    {
        if(oidWithDescTypes == null || oidWithDescTypes.isEmpty())
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

    public static boolean getBoolean(Boolean b, boolean dfltValue)
    {
        return b == null ? dfltValue : b.booleanValue();
    }

    public static int getInt(Integer i, int dfltValue)
    {
        return i == null ? dfltValue : i.intValue();
    }

}
