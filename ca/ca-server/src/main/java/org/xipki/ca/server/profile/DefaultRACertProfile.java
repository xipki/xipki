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

package org.xipki.ca.server.profile;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.ca.api.profile.BadCertTemplateException;
import org.xipki.ca.api.profile.CertProfile;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.ExtensionTuple;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.security.common.EnvironmentParameterResolver;

/**
 * This profile will be used if the requestor is registered as RA. It will be accepted by all 
 * CAs without explicit configuration. It accepts all from the request except the 
 * extensions AuthorityKeyIdentifier, SubjectKeyIdentifier, CRLDistributionPoint and AuthorityInfoAccess.
 *
 */
public class DefaultRACertProfile implements CertProfile
{
	private static final Set<ASN1ObjectIdentifier> extensionsProcessedByCA = new HashSet<ASN1ObjectIdentifier>();
	static
	{
		extensionsProcessedByCA.add(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier);
		extensionsProcessedByCA.add(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier);
		extensionsProcessedByCA.add(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess);
		extensionsProcessedByCA.add(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints);
	}
	
	public DefaultRACertProfile() {
	}

	@Override
	public void initialize(String data) throws CertProfileException {
	}

	@Override
	public void setEnvironmentParamterResolver(
			EnvironmentParameterResolver paramterResolver) 
	{
	}

	@Override
	public Date getNotBefore(Date notBefore){
		return notBefore;
	}

	@Override
	public Integer getValidity() {
		return null;
	}

	@Override
	public SubjectInfo getSubject(X500Name requestedSubject)
			throws CertProfileException, BadCertTemplateException 
	{
		return new SubjectInfo(requestedSubject, (String) null);
	}

	@Override
	public ExtensionTuples getExtensions(X500Name requestedSubject,
			Extensions requestedExtensions) 
	throws CertProfileException, BadCertTemplateException 
	{
		ExtensionTuples tuples = new ExtensionTuples();
		if(requestedExtensions != null)
		{
			ASN1ObjectIdentifier[] types = requestedExtensions.getExtensionOIDs();
			for(ASN1ObjectIdentifier type : types)
			{
				if(extensionsProcessedByCA.contains(type))
				{
					continue;
				}
				
				org.bouncycastle.asn1.x509.Extension extension = requestedExtensions.getExtension(type);
				
				ExtensionTuple extensionTuple = new ExtensionTuple(type, extension.isCritical(), extension.getParsedValue());
				tuples.addExtension(extensionTuple);
			}
		}
		
		return tuples;
	}

	@Override
	public boolean isOnlyForRA() {
		return true;
	}

	@Override
	public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier() {
		return ExtensionOccurrence.NONCRITICAL_OPTIONAL;
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

	@Override
	public void checkPublicKey(SubjectPublicKeyInfo publicKey)
			throws BadCertTemplateException
	{		
	}
}
