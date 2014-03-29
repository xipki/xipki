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

package org.xipki.ca.certprofile.example;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.ca.api.profile.BadCertTemplateException;
import org.xipki.ca.api.profile.CertProfile;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.ExtensionTuple;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.KeyUsage;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.ca.certprofile.example.internal.X509Util;
import org.xipki.security.common.EnvironmentParameterResolver;

public abstract class AbstractCertProfile implements CertProfile {
	protected abstract void checkSubjectContent(X500Name requestedSubject) throws BadCertTemplateException;

	@Override
	public void initialize(String data) throws CertProfileException {	
	}

	protected abstract Set<KeyUsage> getKeyUsage();
	
	protected abstract boolean isCa();
	
	protected abstract Integer getPathLenBasicConstraint();
	
	protected abstract Map<ASN1ObjectIdentifier, ExtensionOccurrence> getAdditionalExtensionOccurences();
		
	@Override
	public boolean isOnlyForRA() {
		return false;
	}	
	
	@Override
	public SubjectInfo getSubject(X500Name requestedSubject)
			throws CertProfileException, BadCertTemplateException 
	{
		checkSubjectContent(requestedSubject);
		return new SubjectInfo(requestedSubject, null);
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
	public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier() {
		return ExtensionOccurrence.NONCRITICAL_REQUIRED;
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
	public boolean incSerialNumberIfSubjectExists() {
		return false;
	}
	

	@Override
	public void checkPublicKey(SubjectPublicKeyInfo publicKey)
			throws BadCertTemplateException 
	{		
	}
}
