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

package org.xipki.ca.client.api;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.cmp.client.type.EnrollCertEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType;
import org.xipki.ca.cmp.client.type.RevocateCertRequestType;
import org.xipki.ca.common.CertIDOrError;
import org.xipki.ca.common.EnrollCertResult;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;

public interface RAWorker
{	
	Set<String> getCaNames();
	
	EnrollCertResult requestCert(CertificationRequest p10Request, String profile, String caName)
	throws RAWorkerException, PKIErrorException;

	EnrollCertResult requestCerts(EnrollCertRequestType.Type type, 
			Map<String, EnrollCertEntryType> enrollCertEntries, String caName)
	throws RAWorkerException, PKIErrorException;

	EnrollCertResult requestCerts(EnrollCertRequestType request, String caName)
	throws RAWorkerException, PKIErrorException;
	
	CertIDOrError revocateCert(X500Name issuer, BigInteger serial, int reason)
	throws RAWorkerException, PKIErrorException;
	
	CertIDOrError revocateCert(X509Certificate cert, int reason)
	throws RAWorkerException, PKIErrorException;

	Map<String, CertIDOrError> revocateCerts(RevocateCertRequestType request)
	throws RAWorkerException, PKIErrorException;
	
	X509CRL downloadCRL(String caName)
	throws RAWorkerException, PKIErrorException;

	X509CRL generateCRL(String caName)
	throws RAWorkerException, PKIErrorException;

    /**
     * Gets ca name by issuer.
     *
     * @param issuer X500Name issuer
     * @return ca name
     * @throws RAWorkerException if ca name or issuer unknown or invalid.
     */
    String getCaNameByIssuer(X500Name issuer)
    throws RAWorkerException;

	EnrollCertResult requestCert(CertReqMsg certReqMsg, String extCertReqId, String caName)
	throws RAWorkerException, PKIErrorException;
	
	CertReqMsg getCertReqMsgWithAppliedCertProfile(CertRequest request, String certProfile,
			ProofOfPossession popo)
	throws RAWorkerException;
	
	byte[] envelope(CertReqMsg certReqMsg, String caName) throws RAWorkerException;

}
