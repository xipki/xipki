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

package org.xipki.ca.server;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.security.api.ConcurrentContentSigner;

public class CrlSigner {
	private final ConcurrentContentSigner signer;
	private final byte[] subjectKeyIdentifier;

	private final int period;
	private final int overlap;	
	private boolean includeCertsInCrl;
	
	public CrlSigner(ConcurrentContentSigner signer, int period, int overlap) 
		throws OperationException
	{
		super();
		this.signer = signer;
		this.period = period;
		this.overlap = overlap;
		
		if(signer == null)
		{
			subjectKeyIdentifier = null;
		}
		else
		{
			byte[] encodedSkiValue = signer.getCertificate().getExtensionValue(
					Extension.subjectKeyIdentifier.getId());
			if(encodedSkiValue == null)
			{
				throw new OperationException(ErrorCode.System_Failure, 
						"CA certificate does not have required extension SubjectKeyIdentifier");
			}
			ASN1OctetString ski;
			try {
				ski = (ASN1OctetString) X509ExtensionUtil.fromExtensionValue(encodedSkiValue);
			} catch (IOException e) {
				throw new OperationException(ErrorCode.System_Failure, e.getMessage());
			}		
			this.subjectKeyIdentifier = ski.getOctets();
		}
	}

	public ConcurrentContentSigner getSigner() {
		return signer;
	}

	public int getPeriod() {
		return period;
	}

	public int getOverlap() {
		return overlap;
	}

	public boolean includeCertsInCrl() {
		return includeCertsInCrl;
	}

	public void setIncludeCertsInCrl(boolean includeCertsInCrl) 
	{
		this.includeCertsInCrl = includeCertsInCrl;		
	}

	public byte[] getSubjectKeyIdentifier() {
		return subjectKeyIdentifier == null ? null : Arrays.clone(subjectKeyIdentifier);
	}

}
