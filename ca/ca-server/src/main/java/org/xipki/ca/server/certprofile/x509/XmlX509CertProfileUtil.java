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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertProfileException;
import org.xipki.ca.api.profile.GeneralNameMode;
import org.xipki.ca.api.profile.GeneralNameTag;
import org.xipki.ca.api.profile.KeyParametersOption.Range;
import org.xipki.ca.api.profile.x509.CertificatePolicyInformation;
import org.xipki.ca.api.profile.x509.CertificatePolicyQualifier;
import org.xipki.ca.server.certprofile.AddText;
import org.xipki.ca.server.certprofile.Condition;
import org.xipki.ca.server.certprofile.x509.jaxb.AddTextType;
import org.xipki.ca.server.certprofile.x509.jaxb.CertificatePolicyInformationType;
import org.xipki.ca.server.certprofile.x509.jaxb.CertificatePolicyInformationType.PolicyQualifiers;
import org.xipki.ca.server.certprofile.x509.jaxb.ConditionType;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.PolicyConstraints;
import org.xipki.ca.server.certprofile.x509.jaxb.GeneralNameType;
import org.xipki.ca.server.certprofile.x509.jaxb.GeneralSubtreeBaseType;
import org.xipki.ca.server.certprofile.x509.jaxb.GeneralSubtreesType;
import org.xipki.ca.server.certprofile.x509.jaxb.ObjectFactory;
import org.xipki.ca.server.certprofile.x509.jaxb.OidWithDescType;
import org.xipki.ca.server.certprofile.x509.jaxb.PolicyIdMappingType;
import org.xipki.ca.server.certprofile.x509.jaxb.RangeType;
import org.xipki.ca.server.certprofile.x509.jaxb.RangesType;
import org.xipki.ca.server.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.common.LruCache;
import org.xipki.common.SecurityUtil;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class XmlX509CertProfileUtil
{
    private final static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

    private static LruCache<ASN1ObjectIdentifier, Integer> ecCurveFieldSizes = new LruCache<>(100);

    static X509ProfileType parse(String xmlConf)
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
                    URL url = XmlX509CertProfileUtil.class.getResource("/xsd/certprofile.xsd");
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

    static void checkECSubjectPublicKeyInfo(ASN1ObjectIdentifier curveOid, byte[] encoded)
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

    static List<CertificatePolicyInformation> buildCertificatePolicies(ExtensionsType.CertificatePolicies type)
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

    static PolicyMappings buildPolicyMappings(
            org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.PolicyMappings type)
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

    static NameConstraints buildNameConstrains(
            org.xipki.ca.server.certprofile.x509.jaxb.ExtensionsType.NameConstraints type)
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

    static GeneralSubtree[] buildGeneralSubtrees(GeneralSubtreesType subtrees)
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

    static GeneralSubtree buildGeneralSubtree(GeneralSubtreeBaseType type)
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

    static ASN1Sequence buildPolicyConstrains(PolicyConstraints type)
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

    static Set<GeneralNameMode> buildGeneralNameMode(GeneralNameType name)
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

    static List<AddText> buildAddText(List<AddTextType> types)
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

    static Condition createCondition(ConditionType type)
    {
        return type == null ? null : new Condition(type);
    }

    static Set<Range> buildParametersMap(RangesType ranges)
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

    static List<ASN1ObjectIdentifier> toOIDList(List<OidWithDescType> oidWithDescTypes)
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

    static Set<ASN1ObjectIdentifier> toOIDSet(List<OidWithDescType> oidWithDescTypes)
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

}
