/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.api.profile;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.ca.api.profile.internal.X509Util;
import org.xipki.security.common.EnvironmentParameterResolver;

public abstract class AbstractCertProfile implements CertProfile {	
	private final List<ASN1ObjectIdentifier> forwardDNs;

	protected abstract Set<KeyUsage> getKeyUsage();
	
	protected abstract boolean isCa();
	
	protected abstract Integer getPathLenBasicConstraint();
	
	protected abstract void checkSubjectContent(X500Name requestedSubject) throws BadCertTemplateException;

	protected abstract Map<ASN1ObjectIdentifier, ExtensionOccurrence> getAdditionalExtensionOccurences();
	
	protected AbstractCertProfile()
	{
		List<ASN1ObjectIdentifier> _forwardDNs = new ArrayList<ASN1ObjectIdentifier>(25);

		_forwardDNs.add(ObjectIdentifiers.DN_C);
		_forwardDNs.add(ObjectIdentifiers.DN_DC);
		_forwardDNs.add(ObjectIdentifiers.DN_ST);
		_forwardDNs.add(ObjectIdentifiers.DN_L);
		_forwardDNs.add(ObjectIdentifiers.DN_O);
		_forwardDNs.add(ObjectIdentifiers.DN_OU);
		_forwardDNs.add(ObjectIdentifiers.DN_T);
		_forwardDNs.add(ObjectIdentifiers.DN_SURNAME);
		_forwardDNs.add(ObjectIdentifiers.DN_INITIALS);
		_forwardDNs.add(ObjectIdentifiers.DN_GIVENNAME);
		_forwardDNs.add(ObjectIdentifiers.DN_SERIALNUMBER);
		_forwardDNs.add(ObjectIdentifiers.DN_NAME);
		_forwardDNs.add(ObjectIdentifiers.DN_CN);
		_forwardDNs.add(ObjectIdentifiers.DN_UID);
		_forwardDNs.add(ObjectIdentifiers.DN_DMD_NAME);
		_forwardDNs.add(ObjectIdentifiers.DN_EmailAddress);
		_forwardDNs.add(ObjectIdentifiers.DN_UnstructuredName);
		_forwardDNs.add(ObjectIdentifiers.DN_UnstructuredAddress);
		_forwardDNs.add(ObjectIdentifiers.DN_POSTAL_CODE);
		_forwardDNs.add(ObjectIdentifiers.DN_BUSINESS_CATEGORY);
		_forwardDNs.add(ObjectIdentifiers.DN_POSTAL_ADDRESS);
		_forwardDNs.add(ObjectIdentifiers.DN_TELEPHONE_NUMBER);
		_forwardDNs.add(ObjectIdentifiers.DN_PSEUDONYM);
		_forwardDNs.add(ObjectIdentifiers.DN_STREET);
		
		forwardDNs = Collections.unmodifiableList(_forwardDNs);
	}	
	
	protected Set<RDNOccurrence> getSubjectDNSequence()
	{
		return null;
	}

	@Override
	public Date getNotBefore(Date notBefore) {
		Date now = new Date();
		if(notBefore != null && notBefore.after(now))
		{
			return notBefore;
		}
		else
		{
			return now;
		}
	}


	@Override
	public boolean isOnlyForRA() {
		return false;
	}	
	
	@Override
	public SubjectInfo getSubject(X500Name requestedSubject)
			throws CertProfileException, BadCertTemplateException 
	{
		verifySubjectDNOccurence(requestedSubject);
		checkSubjectContent(requestedSubject);
		
		RDN[] requstedRDNs = requestedSubject.getRDNs();
		
		Set<RDNOccurrence> occurences = getSubjectDNSequence();

		List<RDN> rdns = new LinkedList<RDN>();
		
		for(ASN1ObjectIdentifier type : forwardDNs)
		{
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
			if(occurrence != null && (n < occurrence.getMinOccurs() || n > occurrence.getMaxOccurs()))
			{
				throw new BadCertTemplateException("Number of SubjectDN field " + type.getId() + 
						" not within [" + occurrence.getMinOccurs() + ", " + occurrence.getMaxOccurs() + "]");
			}
			
			if(thisRDNs == null)
			{
				continue;
			}
			
			for(RDN thisRDN : thisRDNs)
			{
				String text = IETFUtils.valueToString(thisRDN.getFirst().getValue());
				rdns.add(createSubjectRDN(text, type));
			}
		}
		
		X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
		return new SubjectInfo(grantedSubject, null);
	}
	
	private static RDNOccurrence getRDNOccurrence(Set<RDNOccurrence> occurences, ASN1ObjectIdentifier type)
	{
		for(RDNOccurrence occurence : occurences)
		{
			if(occurence.getType().equals(type))
			{
				return occurence;
			}
		}
		return null;
	}
	
	private static RDN[] getRDNs(RDN[] rdns, ASN1ObjectIdentifier type)
	{
		List<RDN> ret = new ArrayList<RDN>(1);
		for(int i = 0; i < rdns.length; i++)
		{
			RDN rdn = rdns[i];
			if(rdn.getFirst().getType().equals(type))
			{
				ret.add(rdn);
			}
		}
		
		if(ret.isEmpty())
		{
			return null;
		}
		else
		{
			return ret.toArray(new RDN[0]);
		}
	}
	
	@SuppressWarnings("unused")
	private EnvironmentParameterResolver paramterResolver;
	@Override
	public void setEnvironmentParamterResolver(
			EnvironmentParameterResolver paramterResolver)
	{
		this.paramterResolver = paramterResolver;
	}

	@Override
	public ExtensionTuples getExtensions(X500Name requestedSubject,
			Extensions requestedExtensions)
	throws CertProfileException, BadCertTemplateException
	{
		ExtensionTuples tuples = new ExtensionTuples();
		
		Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurences = 
				new HashMap<ASN1ObjectIdentifier, ExtensionOccurrence>(getAdditionalExtensionOccurences());
		
		// BasicConstraints
		ASN1ObjectIdentifier extensionType = Extension.basicConstraints;
		
		ExtensionOccurrence occurence = occurences.remove(extensionType);
		if(occurence != null)
		{
			ExtensionTuple extension = createBasicConstraints(occurence.isCritical());
			checkAndAddExtension(extensionType, occurence, extension, tuples);
		}
		
		// KeyUsage
		extensionType = Extension.keyUsage;
		occurence = occurences.remove(extensionType);
		if(occurence != null)
		{
			ExtensionTuple extension = createKeyUsage(occurence.isCritical());
			checkAndAddExtension(extensionType, occurence, extension, tuples);
		}

		// ExtendedKeyUsage
		extensionType = Extension.extendedKeyUsage;
		occurence = occurences.remove(extensionType);
		if(occurence != null)
		{
			ExtensionTuple extension = createExtendedKeyUsage(occurence.isCritical());
			checkAndAddExtension(extensionType, occurence, extension, tuples);
		}

		if(! occurences.isEmpty())
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
	
	private static void checkAndAddExtension(ASN1ObjectIdentifier type, ExtensionOccurrence occurence,
			ExtensionTuple extension, ExtensionTuples tuples)
	throws CertProfileException
	{
		if(extension != null)
		{
			tuples.addExtension(extension);
		}
		else if(occurence.isRequired())
		{
			throw new CertProfileException("Could not add required extension " + type.getId());
		}
	}

	private ExtensionTuple createBasicConstraints(boolean critical)
	throws CertProfileException
	{
		BasicConstraints value = X509Util.createBasicConstraints(isCa(), getPathLenBasicConstraint());
		return createExtension(Extension.basicConstraints, critical, value);
	}
	
	private ExtensionTuple createKeyUsage(boolean critical)
			throws CertProfileException
	{
		org.bouncycastle.asn1.x509.KeyUsage value = X509Util.createKeyUsage(getKeyUsage());
		return createExtension(Extension.keyUsage, critical, value);
	}

	private ExtensionTuple createExtendedKeyUsage(boolean critical)
			throws CertProfileException
	{		
		ExtendedKeyUsage value = X509Util.createExtendedUsage(getExtendedKeyUsages());
		return createExtension(Extension.extendedKeyUsage, critical, value);
	}

	private static ExtensionTuple createExtension(ASN1ObjectIdentifier type, boolean critical, ASN1Object value)
	throws CertProfileException  
	{
		return (value == null) ? null : new ExtensionTuple(type, critical, value);
	}
	
	@Override
	public boolean incSerialNumberIfSubjectExists() {
		return false;
	}

	@Override
	public ExtensionOccurrence getOccurenceOfSubjectKeyIdentifier() {
		return ExtensionOccurrence.NONCRITICAL_REQUIRED;
	}

	@Override
	public ExtensionOccurrence getOccurenceOfCRLDistributinPoints() {
		return ExtensionOccurrence.NONCRITICAL_OPTIONAL;
	}

	@Override
	public ExtensionOccurrence getOccurenceOfAuthorityInfoAccess() {
		return ExtensionOccurrence.NONCRITICAL_OPTIONAL;
	}

	protected Set<ASN1ObjectIdentifier> getExtendedKeyUsages() {
		return null;
	}	

	@Override
	public void checkPublicKey(SubjectPublicKeyInfo publicKey)
			throws BadCertTemplateException 
	{		
	}
	
	@Override
	public void initialize(String data) throws CertProfileException {
	}

	private void verifySubjectDNOccurence(X500Name requestedSubject) throws BadCertTemplateException
	{
		Set<RDNOccurrence> occurences = getSubjectDNSequence();
		if(occurences == null)
		{
			return;
		}
		
		ASN1ObjectIdentifier[] types = requestedSubject.getAttributeTypes();		
		for(ASN1ObjectIdentifier type : types)
		{
			RDNOccurrence occu = null;
			for(RDNOccurrence occurence : occurences)
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
		
		for(RDNOccurrence occurence : occurences)
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
	
	protected static String getSubjectFieldFirstValue(X500Name subject, ASN1ObjectIdentifier type, int index)
	{
		RDN[] rdns = subject.getRDNs(type);
		if(index < 0 || rdns == null || rdns.length <= index)
		{
			return null;
		}
		
		RDN rdn = rdns[index];
		return IETFUtils.valueToString(rdn.getFirst().getValue());
	}
	
	private RDN createSubjectRDN(String text, ASN1ObjectIdentifier type)
	throws BadCertTemplateException
	{		
		ASN1Encodable dnValue;
		if(ObjectIdentifiers.DN_SERIALNUMBER.equals(type) ||
		   ObjectIdentifiers.DN_C.equals(type))
		{
			dnValue = new DERPrintableString(text);
		}
		else
		{
			dnValue = new DERUTF8String(text);
		}
		
		RDN rdn = new RDN(type, dnValue);
		
		return rdn;
	}
}
