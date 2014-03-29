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

package org.xipki.security.shell;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.util.Enumeration;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.security.NopPasswordResolver;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p10.Pkcs10RequestGenerator;

@Command(scope = "keytool", name = "req-p12", description="Generate PKCS#10 request with PKCS#12 keystore")
public class P12CertRequestGenCommand extends OsgiCommandSupport {
	@Option(name = "-subject",
			required = false, 
			description = "Subject in the PKCS#10 request. The default is the subject of self-signed certifite.")
    protected String            subject;

	@Option(name = "-p12",
			required = true, description = "Required. PKCS#12 keystore file")
    protected String            p12File;

	@Option(name = "-pwd", aliases = { "--password" },
			required = true, description = "Required. Password of the PKCS#12 file")
    protected String            password;
	
	@Option(name = "-hash",
			required = false, description = "Hash algorithm name. The default is SHA256")
    protected String            hashAlgo;

	@Option(name = "-out",
			required = true, description = "Required. Output file name")
    protected String            outputFilename;
	
	private SecurityFactory securityFactory;
	
	public SecurityFactory getSecurityFactory() {
		return securityFactory;
	}

	public void setSecurityFactory(SecurityFactory securityFactory) {
		this.securityFactory = securityFactory;
	}
	
    @Override
    protected Object doExecute() throws Exception {
    	Pkcs10RequestGenerator p10Gen = new Pkcs10RequestGenerator();
    	
    	if(hashAlgo == null)
    	{
    		hashAlgo = "SHA256";
    	}
    	
    	ASN1ObjectIdentifier sigAlgOid;
    	
    	boolean ec = isEcKey(p12File, password.toCharArray());
    	
    	hashAlgo = hashAlgo.trim().toUpperCase();
    	
    	if("SHA256".equalsIgnoreCase(hashAlgo) || "SHA-256".equalsIgnoreCase(hashAlgo))
    	{
    		sigAlgOid = ec ? X9ObjectIdentifiers.ecdsa_with_SHA256 : PKCSObjectIdentifiers.sha256WithRSAEncryption;
    	}
    	else if("SHA384".equalsIgnoreCase(hashAlgo) || "SHA-384".equalsIgnoreCase(hashAlgo))
    	{
    		sigAlgOid = ec ? X9ObjectIdentifiers.ecdsa_with_SHA384 : PKCSObjectIdentifiers.sha384WithRSAEncryption;
    	}
    	else if("SHA512".equalsIgnoreCase(hashAlgo) || "SHA-512".equalsIgnoreCase(hashAlgo))
    	{
    		sigAlgOid = ec ? X9ObjectIdentifiers.ecdsa_with_SHA512 : PKCSObjectIdentifiers.sha512WithRSAEncryption;
    	}
    	else
    	{
    		throw new Exception("Unsupported hash algorithm " + hashAlgo);
    	}
    	
    	String signerConf = SecurityFactoryImpl.getKeystoreSignerConf(p12File, password, sigAlgOid.getId(), 1);
		ConcurrentContentSigner identifiedSigner = 
				securityFactory.createSigner("PKCS12", signerConf, null, NopPasswordResolver.INSTANCE); 
    	
		Certificate cert = Certificate.getInstance(identifiedSigner.getCertificate().getEncoded());    	
		
    	X500Name subjectDN;
    	if(subject != null)
    	{
    		subjectDN = new X500Name(subject);
    	}
    	else
    	{
    		subjectDN = cert.getSubject();
    	}
    	
    	SubjectPublicKeyInfo subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();
		
		ContentSigner signer = identifiedSigner.borrowContentSigner();
		
		PKCS10CertificationRequest p10Req;
		try{
			p10Req  = p10Gen.generateRequest(signer, subjectPublicKeyInfo, subjectDN);
		}finally
		{
			identifiedSigner.returnContentSigner(signer);
		}
    	
		File file = new File(outputFilename);
    	IoCertUtil.save(file, p10Req.getEncoded());
    	System.out.println("Saved PKCS#10 request in " + file.getPath());
    	
    	return null;
    }
    
    private static boolean isEcKey(String p12File, char[] password)
		throws SignerException, FileNotFoundException
	{
    	FileInputStream fIn = new FileInputStream(p12File);
    	
		try{
			KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
			ks.load(fIn, password);

			String keyname = null;
			Enumeration<String> aliases = ks.aliases();
			while(aliases.hasMoreElements())
			{
				String alias = aliases.nextElement();
				if(ks.isKeyEntry(alias))
				{
					keyname = alias;
					break;
				}
			}
			
			if(keyname == null)
			{
				throw new SignerException("Could not find private key");
			}

			return ks.getCertificate(keyname).getPublicKey() instanceof ECPublicKey;
		}catch(KeyStoreException e)
		{
			throw new SignerException(e);
		} catch (NoSuchProviderException e) {
			throw new SignerException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new SignerException(e);
		} catch (CertificateException e) {
			throw new SignerException(e);
		} catch (IOException e) {
			throw new SignerException(e);
		} catch (ClassCastException e)
		{
			throw new SignerException(e);
		} finally
		{
			try {
				fIn.close();
			} catch (IOException e) {
			}
		}
	}


}
