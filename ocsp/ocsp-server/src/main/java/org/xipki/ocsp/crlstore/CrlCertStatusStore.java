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

package org.xipki.ocsp.crlstore;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ocsp.IssuerHashNameAndKey;
import org.xipki.ocsp.api.CertRevocationInfo;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusStore;
import org.xipki.ocsp.api.CertStatusStoreException;
import org.xipki.ocsp.api.HashAlgoType;
import org.xipki.security.common.CustomObjectIdentifiers;
import org.xipki.security.common.ParamChecker;

public class CrlCertStatusStore implements CertStatusStore {
	private final Map<BigInteger, CrlCertStatusInfo> certStatusInfoMap
		= new ConcurrentHashMap<BigInteger, CrlCertStatusInfo>();

	private final boolean unknownSerialAsGood;
	private final X509Certificate caCert;
	private final Date thisUpdate;
	private final Date nextUpdate;
	private final boolean useUpdateDatesFromCRL;
	private final Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap = 
			new ConcurrentHashMap<HashAlgoType, IssuerHashNameAndKey>();
	
	public CrlCertStatusStore(X509CRL crl, X509Certificate caCert, boolean useUpdateDatesFromCRL,
			boolean unknownSerialAsGood)
			throws CertStatusStoreException
	{
		this(crl, caCert, null, useUpdateDatesFromCRL, unknownSerialAsGood);
	}
		
	public CrlCertStatusStore(X509CRL crl, X509Certificate caCert, X509Certificate issuerCert,
			boolean useUpdateDatesFromCRL, boolean unknownSerialAsGood)
			throws CertStatusStoreException
	{
		ParamChecker.assertNotNull("crl", crl);
		ParamChecker.assertNotNull("caCert", caCert);	

		X500Principal issuer = crl.getIssuerX500Principal();
		
		boolean caAsCrlIssuer = true;
		if(! caCert.getSubjectX500Principal().equals(issuer))
		{
			caAsCrlIssuer = false;
			if(issuerCert != null)
			{
				if(! issuerCert.getSubjectX500Principal().equals(issuer))
				{
					throw new IllegalArgumentException("The issuerCert and crl do not match");
				}
			}
			else
			{
				throw new IllegalArgumentException("issuerCert could not be null");
			}
		}

		this.unknownSerialAsGood = unknownSerialAsGood;
		this.useUpdateDatesFromCRL = useUpdateDatesFromCRL;
		thisUpdate = crl.getThisUpdate();
		nextUpdate = crl.getNextUpdate();
		this.caCert = caCert;

		HashCalculator hashCalculator;
		try {
			hashCalculator = new HashCalculator();
		} catch (NoSuchAlgorithmException e) {
			throw new CertStatusStoreException(e);
		}

		byte[] encodedCaCert;
		try {
			encodedCaCert = caCert.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new CertStatusStoreException(e);
		}
		
		Certificate bcCaCert = Certificate.getInstance(encodedCaCert);
		byte[] encodedName;
		try {
			encodedName = bcCaCert.getSubject().getEncoded("DER");
		} catch (IOException e) {
			throw new CertStatusStoreException(e);
		}

		byte[] encodedKey = bcCaCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
		
		for(HashAlgoType hashAlgo : HashAlgoType.values())
		{
			byte[] issuerNameHash = hashCalculator.hash(hashAlgo, encodedName);
			byte[] issuerKeyHash = hashCalculator.hash(hashAlgo, encodedKey);
			IssuerHashNameAndKey issuerHash = new IssuerHashNameAndKey(hashAlgo, issuerNameHash, issuerKeyHash);
			issuerHashMap.put(hashAlgo, issuerHash);
		}

		try{
			crl.verify((caAsCrlIssuer ? caCert : issuerCert).getPublicKey());
		}catch(Exception e)
		{
			throw new CertStatusStoreException(e);
		}

		X500Name caName = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
		
		// extract the certificate
		boolean certsIncluded = false;
		Set<Certificate> certs = new HashSet<Certificate>();
		String oidExtnCerts = CustomObjectIdentifiers.id_crl_certset;
		byte[] extnValue = crl.getExtensionValue(oidExtnCerts);
		if(extnValue != null)
		{
			extnValue = removingTagAndLenFromExtensionValue(extnValue);
			certsIncluded = true;
			ASN1Set asn1Set = DERSet.getInstance(extnValue);
			int n = asn1Set.size();
			for(int i = 0; i < n; i++)
			{
				ASN1Encodable asn1 = asn1Set.getObjectAt(i);
				Certificate bcCert = Certificate.getInstance(asn1);
				if(! caName.equals(bcCert.getIssuer()))
				{
					throw new CertStatusStoreException("Invalid entry in CRL Extension certs");
				}
				
				certs.add(bcCert);
			}
		}
			
		Set<? extends X509CRLEntry> revokedCertList = crl.getRevokedCertificates();
		if(revokedCertList != null)
		{
			for(X509CRLEntry revokedCert : revokedCertList)
			{
				X500Principal thisIssuer = revokedCert.getCertificateIssuer();
				if(thisIssuer != null)
				{
					if(caCert.getSubjectX500Principal().equals(thisIssuer) == false)
					{
						throw new CertStatusStoreException("Invalid CRLEntry");
					}
				}
				
				BigInteger serialNumber = revokedCert.getSerialNumber();
				byte[] encodedExtnValue = revokedCert.getExtensionValue(Extension.reasonCode.getId());
				DEREnumerated enumerated = DEREnumerated.getInstance(
						DEROctetString.getInstance(encodedExtnValue).getOctets());
				int reasonCode = enumerated.getValue().intValue();
				Date revTime = revokedCert.getRevocationDate();
					
				Date invalidityTime = null;
				extnValue = revokedCert.getExtensionValue(Extension.invalidityDate.getId());	
				
				if(extnValue != null)
				{
					extnValue = removingTagAndLenFromExtensionValue(extnValue);
					DERGeneralizedTime gTime = DERGeneralizedTime.getInstance(extnValue);
					try {
						invalidityTime = gTime.getDate();
					} catch (ParseException e) {
						throw new CertStatusStoreException(e);
					}
				}
	
				Certificate cert = null;
				if(certsIncluded)
				{
					for(Certificate bcCert : certs)
					{
						if(bcCert.getIssuer().equals(caName) &&
								bcCert.getSerialNumber().getPositiveValue().equals(serialNumber))
						{
							cert = bcCert;
							break;
						}
					}
					
					if(cert == null)
					{
						throw new CertStatusStoreException("Could not find certificate (issuer = '" + caName + 
								"', serialNumber = '" + serialNumber + "')");
					}
					certs.remove(cert);
				}
				
				Map<HashAlgoType, byte[]> certHashes = (cert == null) ? null : getCertHashes(hashCalculator, cert);
				
				CertRevocationInfo revocationInfo = new CertRevocationInfo(reasonCode, revTime, invalidityTime);
				CrlCertStatusInfo crlCertStatusInfo = CrlCertStatusInfo.getRevocatedCertStatusInfo(
						revocationInfo, certHashes);
				certStatusInfoMap.put(serialNumber, crlCertStatusInfo);
			}
		}
			
		for(Certificate cert : certs)
		{
			CrlCertStatusInfo crlCertStatusInfo = CrlCertStatusInfo.getGoodCertStatusInfo(
					getCertHashes(hashCalculator, cert));
			certStatusInfoMap.put(cert.getSerialNumber().getPositiveValue(), crlCertStatusInfo);
		}
	}
	
	private static Map<HashAlgoType, byte[]> getCertHashes(HashCalculator hashCalculator, Certificate cert)
	throws CertStatusStoreException
	{
		byte[] encodedCert;
		try {
			encodedCert = cert.getEncoded();
		} catch (IOException e) {
			throw new CertStatusStoreException(e);
		}
		
		Map<HashAlgoType, byte[]> certHashes = new ConcurrentHashMap<HashAlgoType, byte[]>();
		for(HashAlgoType hashAlgo : HashAlgoType.values())
		{
			byte[] certHash = hashCalculator.hash(hashAlgo, encodedCert);
			certHashes.put(hashAlgo, certHash);
		}
		
		return certHashes;
	}
		
	@Override
	public CertStatusInfo getCertStatus(
			HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash,
			BigInteger serialNumber,
			boolean includeCertHash)
	throws CertStatusStoreException
	{		
		Date thisUpdate;
		Date nextUpdate = null;

		if(useUpdateDatesFromCRL)
		{
			thisUpdate = this.thisUpdate;
			
			if(this.nextUpdate != null)
			{
				// this.nextUpdate is still in the future (10 seconds buffer)
				if(this.nextUpdate.getTime() > System.currentTimeMillis() + 10 * 1000)
				{
					nextUpdate = this.nextUpdate;  
				}
			}
		}
		else
		{
			thisUpdate = new Date();
		}
		
		IssuerHashNameAndKey issuerHashNameAndKey = issuerHashMap.get(hashAlgo);
		if(issuerHashNameAndKey.match(hashAlgo, issuerNameHash, issuerKeyHash) == false)
		{
			return CertStatusInfo.getIssuerUnknownCertStatusInfo(thisUpdate, nextUpdate);
		}
		
		CrlCertStatusInfo certStatusInfo = certStatusInfoMap.get(serialNumber);
		
		// SerialNumber is unknown
		if(certStatusInfo == null)
		{
			return unknownSerialAsGood ?
					CertStatusInfo.getGoodCertStatusInfo(hashAlgo, null, thisUpdate, nextUpdate) :
					CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, nextUpdate);
		}
		
		return certStatusInfo.getCertStatusInfo(hashAlgo, thisUpdate, nextUpdate);
	}

	private static byte[] removingTagAndLenFromExtensionValue(byte[] encodedExtensionValue)
	{
		DEROctetString derOctet = (DEROctetString) DEROctetString.getInstance(encodedExtensionValue);
		return derOctet.getOctets();
	}

	public X509Certificate getCaCert() {
		return caCert;
	}
}
