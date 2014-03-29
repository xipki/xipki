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

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.api.profile.BadCertTemplateException;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.KeyUsage;

public class CertProfile_SubCA extends AbstractCertProfile {	
	private final Set<KeyUsage> keyUsages;
	private final Map<ASN1ObjectIdentifier, ExtensionOccurrence> extensionOccurences;
	
	public CertProfile_SubCA()
	{
		// KeyUsages
		Set<KeyUsage> _keyUsages = new HashSet<KeyUsage>();
		_keyUsages.add(KeyUsage.keyCertSign);
		_keyUsages.add(KeyUsage.cRLSign);
		keyUsages = Collections.unmodifiableSet(_keyUsages);
		
		// Extensions
		Map<ASN1ObjectIdentifier, ExtensionOccurrence> _extensionOccurences = 
				new HashMap<ASN1ObjectIdentifier, ExtensionOccurrence>();
		_extensionOccurences.put(Extension.keyUsage, ExtensionOccurrence.CRITICAL_REQUIRED);
		_extensionOccurences.put(Extension.basicConstraints, ExtensionOccurrence.CRITICAL_REQUIRED);
		extensionOccurences = Collections.unmodifiableMap(_extensionOccurences);
	}	
	
	@Override
	public Date getNotBefore(Date notBefore){
		return new Date();
	}
	
	@Override
	public Integer getValidity() {
		return 365 * 5;
	}

	@Override
	protected void checkSubjectContent(X500Name requestedSubject) throws BadCertTemplateException
	{
	}

	@Override
	protected boolean isCa() {
		return true;
	}

	@Override
	protected Integer getPathLenBasicConstraint() {
		return 0;
	}

	@Override
	protected Set<KeyUsage> getKeyUsage() {
		return keyUsages;
	}

	@Override
	protected Map<ASN1ObjectIdentifier, ExtensionOccurrence> getAdditionalExtensionOccurences() {
		return extensionOccurences;
	}
}
