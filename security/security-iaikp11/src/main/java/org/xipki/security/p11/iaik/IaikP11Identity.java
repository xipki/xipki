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

package org.xipki.security.p11.iaik;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.ParamChecker;

class IaikP11Identity implements Comparable<IaikP11Identity>
{
	private final PKCS11SlotIdentifier slotId;
	private final Pkcs11KeyIdentifier keyId;
	
	private final X509Certificate certificate;
	private final PublicKey publicKey;	
	private final int signatureKeyBitLength;
	
	public IaikP11Identity(
			PKCS11SlotIdentifier slotId,
			Pkcs11KeyIdentifier keyId,
			X509Certificate certificate,
			PublicKey publicKey) 
	{
		super();
		
		ParamChecker.assertNotNull("slotId", slotId);
		ParamChecker.assertNotNull("keyId", keyId);
		
		if(certificate == null && publicKey == null)
		{
			throw new IllegalArgumentException("Neither certificate nor publicKey is non-null");
		}		
		
		this.slotId = slotId;
		this.keyId = keyId;
		this.certificate = certificate;
		this.publicKey = publicKey == null ? certificate.getPublicKey() : publicKey;

		if(this.publicKey instanceof RSAPublicKey)
		{
			signatureKeyBitLength = ((RSAPublicKey) this.publicKey).getModulus().bitLength();
		}
		else if(this.publicKey instanceof ECPublicKey)
		{
			signatureKeyBitLength = ((ECPublicKey) this.publicKey).getParams().getCurve().getField().getFieldSize();
		}
		else
		{
			throw new IllegalArgumentException("Currently only RSA and EC public key are supported, but not " +
					this.publicKey.getAlgorithm() + " (class: " + this.publicKey.getClass().getName() + ")");
		}
	}

	public Pkcs11KeyIdentifier getKeyId() {
		return keyId;
	}
	
	public X509Certificate getCertificate() {
		return certificate;
	}
	
	public PublicKey getPublicKey() {
		return publicKey == null ? certificate.getPublicKey() : publicKey;
	}
	
	public PKCS11SlotIdentifier getSlotId() {
		return slotId;
	}
	
	public boolean match(PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
	{
		if(this.slotId.equals(slotId) == false)
		{
			return false;
		}
		
		return this.keyId.equals(keyId);
	}

	public boolean match(PKCS11SlotIdentifier slotId, String keyLabel)
	{
		if(keyLabel == null)
		{
			return false;
		}
		
		return this.slotId.equals(slotId) && keyLabel.equals(keyId.getKeyLabel());
	}
	
	public byte[] CKM_RSA_PKCS(IaikExtendedModule module, char[] password, 			
			byte[] encodedDigestInfo) throws SignerException 
	{
		if(publicKey instanceof RSAPublicKey == false)
		{
			throw new SignerException("Operation CKM_RSA_PKCS is not allowed for " + 
					publicKey.getAlgorithm() + " public key");
		}

		IaikExtendedSlot slot = module.getSlot(slotId, password);
		if(slot == null)
		{
			throw new SignerException("Could not find slot " + slotId);
		}
		
		return slot.CKM_RSA_PKCS(encodedDigestInfo, keyId);
	}

	public byte[] CKM_RSA_X_509(IaikExtendedModule module, char[] password,  
			byte[] hash) throws SignerException
	{
		if(publicKey instanceof RSAPublicKey == false)
		{
			throw new SignerException("Operation CKM_RSA_X_509 is not allowed for " + 
					publicKey.getAlgorithm() + " public key");
		}

		IaikExtendedSlot slot = module.getSlot(slotId, password);
		if(slot == null)
		{
			throw new SignerException("Could not find slot " + slotId);
		}
		
		return slot.CKM_RSA_X509(hash, keyId);
	}

	public byte[] CKM_ECDSA(IaikExtendedModule module, char[] password,
			byte[] hash)
			throws SignerException
	{
		if(publicKey instanceof ECPublicKey == false)
		{
			throw new SignerException("Operation CKM_ECDSA is not allowed for " + publicKey.getAlgorithm() + " public key");
		}
		
		IaikExtendedSlot slot = module.getSlot(slotId, password);
		if(slot == null)
		{
			throw new SignerException("Could not find slot " + slotId);
		}

		byte[] truncatedDigest = leftmost(hash, signatureKeyBitLength);	

		byte[] signature = slot.CKM_ECDSA(truncatedDigest, keyId);
		return convertToX962Signature(signature);
	}
	
	
    private static byte[] convertToX962Signature(byte[] signature) throws SignerException
    {
        byte[] ba = new byte[signature.length/2];
        ASN1EncodableVector sigder = new ASN1EncodableVector();

        System.arraycopy(signature, 0, ba, 0, ba.length);
        sigder.add(new DERInteger(new BigInteger(1, ba)));

        System.arraycopy(signature, ba.length, ba, 0, ba.length);
        sigder.add(new DERInteger(new BigInteger(1, ba)));
        
        DERSequence seq = new DERSequence(sigder);
        try {
			return seq.getEncoded();
		} catch (IOException e) {
			throw new SignerException("IOException, message: " + e.getMessage(), e);
		}
    }
	
    private static byte[] leftmost(byte[] bytes, int bitCount)
    {
        int byteLenKey = (bitCount + 7)/8;

        if (bitCount >= (bytes.length<<3))
        {
            return bytes;
        }

	    byte[] truncatedBytes = new byte[byteLenKey];
	    System.arraycopy(bytes, 0, truncatedBytes, 0, byteLenKey);
	
	    if (bitCount%8 > 0) // shift the bits to the right
	    {
	        int shiftBits = 8-(bitCount%8);
	
	        for(int i = byteLenKey - 1; i > 0; i--)
	        {
	            truncatedBytes[i] = (byte) (
	                            (byte2int(truncatedBytes[i]) >>> shiftBits) |
	                            ((byte2int(truncatedBytes[i-1]) << (8-shiftBits)) & 0xFF));
	        }
	        truncatedBytes[0] = (byte)(byte2int(truncatedBytes[0])>>>shiftBits);
	    }
	
	    return truncatedBytes;
    }

    private static int byte2int(byte b)
    {
            return b >= 0 ? b : 256 + b;
    }

	@Override
	public int compareTo(IaikP11Identity o) {		
		return keyId.compareTo(o.keyId);
	}

}
