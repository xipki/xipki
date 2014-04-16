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

package org.xipki.security.shell;

import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.PrivateKey;

import java.io.File;

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
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.NopPasswordResolver;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p10.Pkcs10RequestGenerator;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11ModulePool;

@Command(scope = "keytool", name = "req", description="Generate PKCS#10 request with PKCS#11 device")
public class P11CertRequestGenCommand extends OsgiCommandSupport {
	@Option(name = "-subject",
			required = false, 
			description = "Subject in the PKCS#10 request. The default is the subject of self-signed certifite.")
    protected String            subject;

	@Option(name = "-slot",
			required = true, description = "Required. Slot index of the PKCS#11 token")
    protected Integer           slotIndex;
	
	@Option(name = "-key-id",
			required = false, description = "Id of the private key in the PKCS#11 token. Either keyId or keyLabel must be specified")
    protected String            keyId;
	
	@Option(name = "-key-label",
			required = false, description = "Label of the private key in the PKCS#11 token. Either keyId or keyLabel must be specified")
    protected String            keyLabel;

	@Option(name = "-pwd", aliases = { "--password" },
			required = false, description = "Password to access the PKCS#11 token")
    protected String            password;
	
	@Option(name = "-hash",
			required = false, description = "Hash algorithm name. The default is SHA256")
    protected String            hashAlgo;

	@Option(name = "-out",
			required = true, description = "Required. Output file name")
    protected String            outputFilename;
	
	private SecurityFactory securityFactory;
	
	public void setSecurityFactory(SecurityFactory securityFactory) {
		this.securityFactory = securityFactory;
	}
	
    @Override
    protected Object doExecute() throws Exception {
    	if(hashAlgo == null)
    	{
    		hashAlgo = "SHA256";
    	}
    	
    	Pkcs11KeyIdentifier keyIdentifier;
    	if(keyId != null && keyLabel == null)
    	{    		
    		keyIdentifier = new Pkcs11KeyIdentifier(Hex.decode(keyId));
    	}
    	else if(keyId == null && keyLabel != null)
    	{
    		keyIdentifier = new Pkcs11KeyIdentifier(keyLabel);
    	}
    	else
    	{
    		throw new Exception("Exactly one of keyId or keyLabel should be specified");
    	}    	
    	
		IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(
				securityFactory.getPkcs11Module());
		
		IaikExtendedSlot slot = null;
		try{
			slot = module.getSlot(new PKCS11SlotIdentifier(slotIndex, null), 
					password == null ? null : password.toCharArray());
		}catch(SignerException e)
		{
			System.err.println("ERROR:  " + e.getMessage());
			return null;
		}
		
		char[] keyLabelChars = (keyLabel == null) ?
				null : keyLabel.toCharArray();
		
		PrivateKey privKey = slot.getPrivateObject(null, null, keyIdentifier.getKeyId(), keyLabelChars);
		if(privKey == null)
		{
			System.err.println("Could not find private key " + keyIdentifier);
			return null;
		}
    	
		boolean ec = privKey instanceof ECDSAPrivateKey;

		Pkcs10RequestGenerator p10Gen = new Pkcs10RequestGenerator();

    	ASN1ObjectIdentifier sigAlgOid;
    	
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
    	
    	PKCS11SlotIdentifier slotId = new PKCS11SlotIdentifier(slotIndex, null);
    	String signerConf = SecurityFactoryImpl.getPkcs11SignerConf(
    					securityFactory.getPkcs11Module(), 
    					slotId, keyIdentifier, password, 
    					sigAlgOid.getId(), 1);
    	
		ConcurrentContentSigner identifiedSigner = 
				securityFactory.createSigner("PKCS11", signerConf, null, NopPasswordResolver.INSTANCE); 
		
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
    
}
