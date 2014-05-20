/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.security;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.operator.bc.BcDigestProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;

/**
 * utility class for converting java.security RSA objects into their
 * org.bouncycastle.crypto counterparts.
 */
public class SignerUtil
{
    static public RSAKeyParameters generateRSAPublicKeyParameter(
        RSAPublicKey key)
    {
        return new RSAKeyParameters(false, key.getModulus(), key.getPublicExponent());

    }

    static public RSAKeyParameters generateRSAPrivateKeyParameter(
        RSAPrivateKey key)
    {
        if (key instanceof RSAPrivateCrtKey)
        {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey)key;

            return new RSAPrivateCrtKeyParameters(k.getModulus(),
                k.getPublicExponent(), k.getPrivateExponent(),
                k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient());
        }
        else
        {
            RSAPrivateKey k = key;

            return new RSAKeyParameters(true, k.getModulus(), k.getPrivateExponent());
        }
    }

    static public PSSSigner createPSSRSASigner(AlgorithmIdentifier sigAlgId)
    throws OperatorCreationException
    {
        return createPSSRSASigner(sigAlgId, null);
    }

    static public PSSSigner createPSSRSASigner(AlgorithmIdentifier sigAlgId, AsymmetricBlockCipher cipher)
    throws OperatorCreationException
    {
        if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm()) == false)
        {
            throw new OperatorCreationException("Signature algorithm " + sigAlgId.getAlgorithm() + " is not allowed");
        }

        BcDigestProvider digestProvider = BcDefaultDigestProvider.INSTANCE;
        AlgorithmIdentifier digAlgId;
        try
        {
            digAlgId = SignerUtil.extractDigesetAlgorithmIdentifier(sigAlgId);
        } catch (NoSuchAlgorithmException e)
        {
            throw new OperatorCreationException(e.getMessage(), e);
        }
        Digest dig = digestProvider.get(digAlgId);
        if(cipher == null)
        {
            cipher = new RSABlindedEngine();
        }

        RSASSAPSSparams param = RSASSAPSSparams.getInstance(sigAlgId.getParameters());

        AlgorithmIdentifier mfgDigAlgId = AlgorithmIdentifier.getInstance(
                param.getMaskGenAlgorithm().getParameters());
        Digest mfgDig = digestProvider.get(mfgDigAlgId);

        int saltSize = param.getSaltLength().intValue();
        int trailerField = param.getTrailerField().intValue();

        return new PSSSigner(cipher, dig, mfgDig, saltSize, getTrailer(trailerField));
    }

    static private byte getTrailer(
            int trailerField)
    {
        if (trailerField == 1)
        {
            return org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT;
        }

        throw new IllegalArgumentException("unknown trailer field");
    }

    static public RSASSAPSSparams createPSSRSAParams(ASN1ObjectIdentifier digestAlgOID)
    throws NoSuchAlgorithmException
    {
        int saltSize;
        if(X509ObjectIdentifiers.id_SHA1.equals(digestAlgOID))
        {
            saltSize = 20;
        }
        else if(NISTObjectIdentifiers.id_sha224.equals(digestAlgOID))
        {
            saltSize = 28;
        }
        else if(NISTObjectIdentifiers.id_sha256.equals(digestAlgOID))
        {
            saltSize = 32;
        }
        else if(NISTObjectIdentifiers.id_sha384.equals(digestAlgOID))
        {
            saltSize = 48;
        }
        else if(NISTObjectIdentifiers.id_sha512.equals(digestAlgOID))
        {
            saltSize = 64;
        }
        else
        {
            throw new NoSuchAlgorithmException(
                    "Unknown digest algorithm " + digestAlgOID);
        }

        AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(digestAlgOID, DERNull.INSTANCE);
        return new RSASSAPSSparams(
            digAlgId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, digAlgId),
            new ASN1Integer(saltSize),
            RSASSAPSSparams.DEFAULT_TRAILER_FIELD);
    }

    static public AlgorithmIdentifier buildRSAPSSAlgorithmIdentifier(
            ASN1ObjectIdentifier digAlgOid)
    throws NoSuchAlgorithmException
    {
        RSASSAPSSparams params = createPSSRSAParams(digAlgOid);
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, params);
    }

    static public AlgorithmIdentifier buildDSASigAlgorithmIdentifier(AlgorithmIdentifier digAlgId)
    throws NoSuchAlgorithmException
    {
        ASN1ObjectIdentifier digAlgOid = digAlgId.getAlgorithm();
        ASN1ObjectIdentifier sid;
        if(X509ObjectIdentifiers.id_SHA1.equals(digAlgOid))
        {
            sid = X9ObjectIdentifiers.id_dsa_with_sha1;
        }
        else if(NISTObjectIdentifiers.id_sha224.equals(digAlgOid))
        {
            sid = NISTObjectIdentifiers.dsa_with_sha224;
        }
        else if(NISTObjectIdentifiers.id_sha256.equals(digAlgOid))
        {
            sid = NISTObjectIdentifiers.dsa_with_sha256;
        }
        else if(NISTObjectIdentifiers.id_sha384.equals(digAlgOid))
        {
            sid = NISTObjectIdentifiers.dsa_with_sha384;
        }
        else if(NISTObjectIdentifiers.id_sha512.equals(digAlgOid))
        {
            sid = NISTObjectIdentifiers.dsa_with_sha512;
        }
        else
        {
            throw new NoSuchAlgorithmException("No signature algorithm for DSA with digest algorithm " + digAlgOid.getId());
        }
        return new AlgorithmIdentifier(sid, DERNull.INSTANCE);
    }

    static public String getSignatureAlgoName(AlgorithmIdentifier sigAlgId)
    {
        ASN1ObjectIdentifier algOid = sigAlgId.getAlgorithm();

        if(X9ObjectIdentifiers.ecdsa_with_SHA1.equals(algOid))
        {
            return "SHA1withECDSA";
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA224.equals(algOid))
        {
            return "SHA224withECDSA";
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA256.equals(algOid))
        {
            return "SHA256withECDSA";
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA384.equals(algOid))
        {
            return "SHA384withECDSA";
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA512.equals(algOid))
        {
            return "SHA512withECDSA";
        }
        else if(PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(algOid))
        {
            return "SHA1withRSA";
        }
        else if(PKCSObjectIdentifiers.sha224WithRSAEncryption.equals(algOid))
        {
            return "SHA224withRSA";
        }
        else if(PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(algOid))
        {
            return "SHA256withRSA";
        }
        else if(PKCSObjectIdentifiers.sha384WithRSAEncryption.equals(algOid))
        {
            return "SHA384withRSA";
        }
        else if(PKCSObjectIdentifiers.sha512WithRSAEncryption.equals(algOid))
        {
            return "SHA512withRSA";
        }
        else if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid))
        {
            return null;
        }
        else
        {
            return null;
        }
    }

    static public AlgorithmIdentifier extractDigesetAlgorithmIdentifier(AlgorithmIdentifier sigAlgId)
    throws NoSuchAlgorithmException
    {
        ASN1ObjectIdentifier algOid = sigAlgId.getAlgorithm();

        ASN1ObjectIdentifier digestAlgOid;
        if(X9ObjectIdentifiers.ecdsa_with_SHA1.equals(algOid))
        {
            digestAlgOid = X509ObjectIdentifiers.id_SHA1;
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA224.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha224;
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA256.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha256;
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA384.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha384;
        }
        else if(X9ObjectIdentifiers.ecdsa_with_SHA512.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha512;
        }
        else if(PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = X509ObjectIdentifiers.id_SHA1;
        }
        else if(PKCSObjectIdentifiers.sha224WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha224;
        }
        else if(PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha256;
        }
        else if(PKCSObjectIdentifiers.sha384WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha384;
        }
        else if(PKCSObjectIdentifiers.sha512WithRSAEncryption.equals(algOid))
        {
            digestAlgOid = NISTObjectIdentifiers.id_sha512;
        }
        else if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid))
        {
            ASN1Encodable asn1Encodable = sigAlgId.getParameters();
            RSASSAPSSparams param = RSASSAPSSparams.getInstance(asn1Encodable);
            digestAlgOid = param.getHashAlgorithm().getAlgorithm();
        }
        else
        {
            throw new NoSuchAlgorithmException("Unknown signature algorithm" + algOid.getId());
        }

        return new AlgorithmIdentifier(digestAlgOid, DERNull.INSTANCE);
    }

    public static  boolean verifyPOP(CertificationRequest p10Request)
    {
        PKCS10CertificationRequest p10Req = new PKCS10CertificationRequest(p10Request);
        return verifyPOP(p10Req);
    }

    public static  boolean verifyPOP(PKCS10CertificationRequest p10Request)
    {
        try
        {
            SubjectPublicKeyInfo pkInfo = p10Request.getSubjectPublicKeyInfo();
            PublicKey pk = KeyUtil.generatePublicKey(pkInfo);

            ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(pk);
            return p10Request.isSignatureValid(cvp);
        } catch (OperatorCreationException e)
        {
            return false;
        } catch (InvalidKeyException e)
        {
            return false;
        } catch (PKCSException e)
        {
            return false;
        } catch (NoSuchAlgorithmException e)
        {
            return false;
        } catch (InvalidKeySpecException e)
        {
            return false;
        } catch (IOException e)
        {
            return false;
        }
    }

    public static byte[] leftmost(byte[] bytes, int bitCount)
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

}

