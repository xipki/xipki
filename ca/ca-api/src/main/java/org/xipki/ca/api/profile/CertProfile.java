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

import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.common.EnvironmentParameterResolver;

public interface CertProfile {
	
	boolean isOnlyForRA();

	void initialize(String data) throws CertProfileException;
	
	void setEnvironmentParamterResolver(EnvironmentParameterResolver paramterResolver);

	Date getNotBefore(Date notBefore);
	
	Integer getValidity();
	
	void checkPublicKey(SubjectPublicKeyInfo publicKey) throws BadCertTemplateException;

	SubjectInfo getSubject(X500Name requestedSubject) throws CertProfileException, BadCertTemplateException;
	
	ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier();
	
	ExtensionOccurrence getOccurenceOfSubjectKeyIdentifier();
	
	ExtensionOccurrence getOccurenceOfCRLDistributinPoints();
	
	ExtensionOccurrence getOccurenceOfAuthorityInfoAccess();
	
	ExtensionTuples getExtensions(
			X500Name requestedSubject,
			Extensions requestedExtensions)
	throws CertProfileException, BadCertTemplateException;
}
