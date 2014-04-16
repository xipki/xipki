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

import iaik.pkcs.pkcs11.objects.DSAPublicKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikExtendedSlot;
import org.xipki.security.p11.iaik.IaikP11ModulePool;

@Command(scope = "keytool", name = "list", description="List PKCS#11 device objects")
public class P11ListSlotCommand extends OsgiCommandSupport {
	@Option(name = "-pwd", aliases = { "--password" },
			required = false, description = "Password of the PKCS#11 token")
    protected char[]            password;
	
	private SecurityFactory securityFactory;
	
	public SecurityFactory getSecurityFactory() {
		return securityFactory;
	}

	public void setSecurityFactory(SecurityFactory securityFactory) {
		this.securityFactory = securityFactory;
	}
	
    @Override
    protected Object doExecute() throws Exception {
		IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(
				securityFactory.getPkcs11Module());
    	List<PKCS11SlotIdentifier> slotIds = new ArrayList<PKCS11SlotIdentifier>(module.getAllSlotIds());
    	Collections.sort(slotIds);
    	
		int n = slotIds.size();
		
		String defaultPkcs11Lib = securityFactory.getPkcs11Module();
		StringBuilder sb = new StringBuilder();
		sb.append("PKCS#11 library: ").append(defaultPkcs11Lib).append("\n");
		sb.append(n + " slots are configured\n");
		System.out.println(sb.toString());
		
		for(PKCS11SlotIdentifier slotId : slotIds)
		{
			sb = new StringBuilder();
			sb.append("\nslot[").append(slotId.getSlotIndex()).append("]: ").append(slotId.getSlotId()).append("\n");
			
			IaikExtendedSlot slot = null;
			try{
				slot = module.getSlot(slotId, password);
			}catch(SignerException e)
			{
				sb.append("\tError:  ").append(e.getMessage()).append("\n");
			}

			System.out.println(sb.toString());
			
			if(slot == null)
			{
				continue;
			}
			
			List<PrivateKey> allPrivateObjects = slot.getAllPrivateObjects(null, null);			
			int size = allPrivateObjects.size();
			
			List<ComparablePrivateKey> privateKeys = 
					new ArrayList<P11ListSlotCommand.ComparablePrivateKey>(size);
			for(int i = 0; i < size; i++)
			{
				PrivateKey key = allPrivateObjects.get(i);
				byte[] id = key.getId().getByteArrayValue();
				
				if(id == null)
				{					
					continue;
				}

				char[] label = key.getLabel().getCharArrayValue();
				ComparablePrivateKey privKey = new ComparablePrivateKey(id, label, key);
				privateKeys.add(privKey);
			}
				
			Collections.sort(privateKeys);
			size = privateKeys.size();
			
			for(int i = 0; i < size; i++)
			{
				sb = new StringBuilder();
				
				ComparablePrivateKey privKey = privateKeys.get(i);
				
				PublicKey pubKey = slot.getPublicKeyObject(null, null, privKey.getKeyId(), privKey.getKeyLabel());
				sb.append("\t")
					.append(i+1)
					.append(". ")
					.append(privKey.getKeyLabelAsText())
					.append(" (").append("id: ")
					.append(Hex.toHexString(privKey.getKeyId()).toUpperCase())
					.append(")\n");
				
				sb.append("\t\tAlgorithm: ")
					.append(getKeyAlgorithm(pubKey))
					.append("\n");
				
				X509PublicKeyCertificate cert = slot.getCertificateObject(privKey.getKeyId(), privKey.getKeyLabel());
				if(cert == null)
				{
					sb.append("\t\tCertificate: NONE\n");
				}
				else
				{
					byte[] bytes = cert.getSubject().getByteArrayValue();					
					String subject;
					try{
						X500Principal x500Prin = new X500Principal(bytes);
						subject = x500Prin.getName();
					}catch(Exception e)
					{
						subject = new String(bytes);
					}
					
					bytes = cert.getIssuer().getByteArrayValue();					
					String issuer;
					try{
						X500Principal x500Prin = new X500Principal(bytes);
						issuer = x500Prin.getName();
					}catch(Exception e)
					{
						issuer = new String(bytes);
					}
					
					BigInteger serialNumber = new BigInteger(1, cert.getSerialNumber().getByteArrayValue());
					sb.append("\t\tCertificate:\n");
					sb.append("\t\t\tSubject: ")
						.append(subject)
						.append("\n");
					sb.append("\t\t\tIssuer: ")
						.append(issuer)
						.append("\n");
					sb.append("\t\t\tSerialNumber: ")
						.append(serialNumber)
						.append("\n");
				}
				
				System.out.println(sb.toString());
			}
		}
		
        return null;
    }
    
    private static String getKeyAlgorithm(PublicKey key)
    {
    	if(key instanceof RSAPublicKey)
    	{
    		return "RSA";
    	}
    	else if(key instanceof ECDSAPublicKey)
    	{
    		byte[] paramBytes = ((ECDSAPublicKey) key).getEcdsaParams().getByteArrayValue();
    		if(paramBytes.length < 50)
    		{
    			try{
    				ASN1ObjectIdentifier curveId = (ASN1ObjectIdentifier) ASN1ObjectIdentifier.fromByteArray(paramBytes);
    				String curveName = getCurveName(curveId);
    				return "EC (named curve " + curveName + ")";  
    			}catch(Exception e)
    			{		
    				return "EC";
    			}
    		}
    		else
    		{
        		return "EC (specified curve)";
    		}
    	}
    	else if(key instanceof DSAPublicKey)
    	{
    		return "DSA";
    	}
    	else 
    	{
    		return "UNKNOWN";
    	}
    }
    
    private static String getCurveName(ASN1ObjectIdentifier curveId)
    {
    	String curveName = X962NamedCurves.getName(curveId);

        if (curveName == null)
        {
        	curveName = SECNamedCurves.getName(curveId);
        }

        if (curveName == null)
        {
        	curveName = TeleTrusTNamedCurves.getName(curveId);
        }

        if (curveName == null)
        {
        	curveName = NISTNamedCurves.getName(curveId);
        }
        
        return curveName;
    }
    
    private static class ComparablePrivateKey implements Comparable<ComparablePrivateKey>
    {
    	private final byte[] keyId;
    	private final char[] keyLabel;
    	private final PrivateKey privateKey;
    	
    	public ComparablePrivateKey(byte[] keyId, char[] keyLabel, PrivateKey privateKey) {
    		this.keyId = keyId;
    		this.keyLabel = keyLabel;
    		this.privateKey = privateKey;
		}
    	
		@Override
		public int compareTo(ComparablePrivateKey o) {
			if(keyLabel == null)
			{
				if(o.keyLabel == null)
				{
					return 0;
				}
				else
				{
					return 1;
				}
			}
			else
			{
				if(o.keyLabel == null)
				{
					return -1;
				}
				else
				{
					return new String(keyLabel).compareTo(new String(o.keyLabel));
				}
			}
		}

		public byte[] getKeyId() {
			return keyId;
		}

		public char[] getKeyLabel() {
			return keyLabel;
		}
		
		public String getKeyLabelAsText() {
			return keyLabel == null ? null : new String(keyLabel);
		}

		@SuppressWarnings("unused")
		public PrivateKey getPrivateKey() {
			return privateKey;
		}
    }

}
