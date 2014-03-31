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

package org.xipki.ca.common;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.xipki.security.common.ParamChecker;

public class X509CertificateWithMetaInfo {
	private final X509Certificate cert;
	private final String subject;
	private final byte[] encodedCert;
	
	public X509CertificateWithMetaInfo(X509Certificate cert)
	{
		this(cert, null, null);
	}
	
	public X509CertificateWithMetaInfo(X509Certificate cert, String subject, byte[] encodedCert)
	{
		ParamChecker.assertNotNull("cert", cert);

		this.cert = cert;
		
		if(subject == null)
		{
			this.subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()).toString();
		}
		else
		{
			this.subject = subject;
		}
				
		if(encodedCert == null)
		{
			try {
				this.encodedCert = cert.getEncoded();
			} catch (CertificateEncodingException e) {
				throw new RuntimeCryptoException("could not encode certificate: " + e.getMessage());
			}
		}
		else
		{
			this.encodedCert = encodedCert;
		}
	}

	public X509Certificate getCert() {
		return cert;
	}

	public byte[] getEncodedCert() {
		return encodedCert;
	}	
	
	public String getSubject()
	{
		return subject;
	}
	
	@Override
	public String toString()
	{
		return cert.toString();
	}

}
