/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This work is part of XiPKI, owned by Lijun Liao (lijun.liao@gmail.com)
 *
 */

package org.xipki.ca.profile.xml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.xipki.ca.profile.xml.jaxb.CertificatePolicyInformationType;
import org.xipki.ca.profile.xml.jaxb.CertificatePolicyInformationType.PolicyQualifiers;
import org.xipki.ca.profile.xml.jaxb.ConstantExtensionType;
import org.xipki.ca.profile.xml.jaxb.ExtensionsType.CertificateProfiles;
import org.xipki.ca.profile.xml.jaxb.ExtensionsType.ConstantExtensions;
import org.xipki.ca.profile.xml.jaxb.ObjectFactory;
import org.xipki.ca.profile.xml.jaxb.ProfileType;
import org.xipki.ca.profile.xml.jaxb.SubjectRdnOccurrenceType;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import xipki.ca.api.EnvironmentParameterResolver;
import xipki.ca.api.profile.BadCertTemplateException;
import xipki.ca.api.profile.CertProfile;
import xipki.ca.api.profile.CertProfileException;
import xipki.ca.api.profile.CertificatePolicyInformation;
import xipki.ca.api.profile.CertificatePolicyQualifier;
import xipki.ca.api.profile.ExtensionOccurrence;
import xipki.ca.api.profile.ExtensionTuple;
import xipki.ca.api.profile.ExtensionTuples;
import xipki.ca.api.profile.KeyUsage;
import xipki.ca.api.profile.PublicCAInfo;
import xipki.ca.api.profile.SubjectInfo;

public class XmlCertProfile implements CertProfile {
	private ProfileType conf;
	
	private boolean ca;
	private Integer pathLen;
	private Set<KeyUsage> keyusages;
	private Set<String> extendedKeyusages;
	private Map<String, ExtensionOccurrence> extensionOccurences;
	
	private final static Object jaxbUnmarshallerLock = new Object();
	private static Unmarshaller jaxbUnmarshaller;
	

	@SuppressWarnings("unused")
	private EnvironmentParameterResolver paramterResolver;
	
	@Override
	public void setEnvironmentParamterResolver(
			EnvironmentParameterResolver paramterResolver)
	{
		this.paramterResolver = paramterResolver;
	}
	
	public XmlCertProfile()
	{
	}
	
	public void initialize(String configuration) throws CertProfileException
	{
		this.conf = parse(configuration);
		// FIXME: initialize the parameters
	}
	
	private static synchronized ProfileType parse(String xmlConf) throws CertProfileException
	{
		synchronized (jaxbUnmarshallerLock) {
			JAXBElement<?> rootElement;
			try{
				if(jaxbUnmarshaller == null)
				{
					JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
					jaxbUnmarshaller = context.createUnmarshaller();
				}
				
				rootElement = (JAXBElement<?>) jaxbUnmarshaller.unmarshal(
						new ByteArrayInputStream(xmlConf.getBytes()));
			}
			catch(JAXBException e)
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
	public Integer getValidity() {
		return conf.getValidity();
	}

	@Override
	public Set<KeyUsage> getKeyUsage() {
		return keyusages;
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
	public Set<String> getExtendedKeyUsages() {
		return extendedKeyusages;
	}

	@Override
	public Map<String, ExtensionOccurrence> getExtensionOccurences() {
		return extensionOccurences;
	}

	@Override
	public ExtensionTuples getExtensions(X500Principal requestedSubject,
			Set<java.security.cert.Extension> requestedExtensions,
			PublicCAInfo publicCaInfo, Set<String> processedExtensions)
			throws CertProfileException, BadCertTemplateException
	{		
		Map<String, ExtensionOccurrence> remainingOccurences = new HashMap<String, ExtensionOccurrence>();
		for(String extnType : extensionOccurences.keySet())
		{
			if(processedExtensions == null || !processedExtensions.contains(extnType))
			{
				remainingOccurences.put(extnType, extensionOccurences.get(extnType));
			}
		}
		
		ExtensionTuples tuples = new ExtensionTuples();
			
		ConstantExtensions constExtensions = conf.getExtensions().getConstantExtensions();
		if(constExtensions != null)
		{
			 List<ConstantExtensionType> constantExtensionList = constExtensions.getConstantExtension();
			 for(ConstantExtensionType constantExtension : constantExtensionList)
			 {
				 String extensionType = constantExtension.getType();
				 ExtensionOccurrence occurence = remainingOccurences.remove(extensionType);
					
				if(occurence != null)
				{
					ExtensionTuple extensionTuple = new ExtensionTuple(
							extensionType,
							occurence.isCritical(), 
							constantExtension.getValue());
					tuples.addExtension(extensionTuple);
				}
			 }
		}
		
		return tuples;
	}
	
	@Override
	public List<CertificatePolicyInformation> getCertificatePolicies() {
		CertificateProfiles xmlCertPolicies = conf.getExtensions().getCertificateProfiles();		
		if(xmlCertPolicies == null)
		{
			return null;
		}
		
		List<CertificatePolicyInformationType> policyPairs = xmlCertPolicies.getCertificatePolicyInformation();		
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
					policyPair.getPolicyIdentifier(), qualifiers);

			policies.add(cpi);
		}
		
		return policies;
	}

	@Override
	public SubjectInfo getSubject(X500Principal requestedSubject)
			throws CertProfileException, BadCertTemplateException
	{
		X500Name bcRequestedSubject = X500Name.getInstance(requestedSubject.getEncoded());
		verifySubjectDNOccurence(bcRequestedSubject);
				
		List<SubjectRdnOccurrenceType> occurences = conf.getSubjectRdnOccurrences().getSubjectRdnOccurrence();

		List<RDN> rdns = new ArrayList<RDN>(occurences.size());
		
		for(SubjectRdnOccurrenceType occurence : occurences)
		{
			int maxOccurs = occurence.getMaxOccurs();
			String type = occurence.getType();
			for(int i = 0; i < maxOccurs; i++)
			{
				String fieldValue = getSubjectFieldFirstValue(bcRequestedSubject, type, i-1);
				if(fieldValue == null)
				{
					break;
				}
				
				String directStringType = occurence.getDirectoryStringType();
				ASN1Encodable asn1FieldValue ;
				if("PrintableString".equals(directStringType))
				{
					asn1FieldValue = new DERPrintableString(fieldValue);
				}
				else
				{
					asn1FieldValue = new DERUTF8String(fieldValue);
				}

				RDN rdn = new RDN(new ASN1ObjectIdentifier(type), asn1FieldValue);
				rdns.add(rdn);
			}
		}
		
		X500Name bcGrantedSubject = new X500Name(rdns.toArray(new RDN[0]));
		X500Principal grantedSubject;
		try {
			grantedSubject = new X500Principal(bcGrantedSubject.getEncoded());
		} catch (IOException e) {
			throw new CertProfileException(e);
		} 
		return new SubjectInfo(grantedSubject, null);
	}

	private static String getSubjectFieldFirstValue(X500Name subject, String type, int index)
	{
		RDN[] rdns = subject.getRDNs(new ASN1ObjectIdentifier(type));
		if(index < 0 || rdns == null || rdns.length <= index)
		{
			return null;
		}
		
		RDN rdn = rdns[index];
		return IETFUtils.valueToString(rdn.getFirst().getValue());
	}
	
	private void verifySubjectDNOccurence(X500Name requestedSubject) throws BadCertTemplateException
	{
		ASN1ObjectIdentifier[] types = requestedSubject.getAttributeTypes();
		List<SubjectRdnOccurrenceType> occurences = conf.getSubjectRdnOccurrences().getSubjectRdnOccurrence();

		for(ASN1ObjectIdentifier type : types)
		{
			SubjectRdnOccurrenceType occu = null;
			for(SubjectRdnOccurrenceType occurence : occurences)
			{
				if(occurence.getType().equals(type))
				{
					occu = occurence;
					break;
				}
			}
			if(occu == null)
			{
				throw new BadCertTemplateException("Subject DN of type " + type.getId() + " is not allowed");
			}
			
			RDN[] rdns = requestedSubject.getRDNs(type);
			if(rdns.length > occu.getMaxOccurs() || rdns.length < occu.getMinOccurs())
			{
				throw new BadCertTemplateException("Occurrence of subject DN of type " + type.getId() + 
						" not within the allowed range. " + rdns.length + 
						" is not within [" +occu.getMinOccurs() + ", " + occu.getMaxOccurs() + "]");
			}
		}
		
		for(SubjectRdnOccurrenceType occurence : occurences)
		{
			if(occurence.getMinOccurs() == 0)
			{
				continue;
			}
			
			boolean present = false;
			for(ASN1ObjectIdentifier type : types) 
			{
				if(occurence.getType().equals(type))
				{
					return;
				}
			}
			
			if(!present)
			{
				throw new BadCertTemplateException("Requied subject DN of type " + occurence.getType() + " is not present");
			}
		}
	}

}
