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

package org.xipki.ocsp.client.api;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public class RequestOptions
{
    private static final Map<String, AlgorithmIdentifier> sigAlgsMap = new HashMap<>();

    static
    {
        String algoName = "SHA1withRSA";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA256withRSA";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA384withRSA";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA512withRSA";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA1withECDSA";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA256withECDSA";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA384withECDSA";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA512withECDSA";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA1withRSAandMGF1";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA256withRSAandMGF1";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA384withRSAandMGF1";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA512withRSAandMGF1";
        sigAlgsMap.put(algoName.toUpperCase(), createAlgId(algoName));

    }

    private boolean useNonce = true;
    private boolean useHttpGetForRequest = false;
    private ASN1ObjectIdentifier hashAlgorithmId = NISTObjectIdentifiers.id_sha256;
    private List<AlgorithmIdentifier> preferredSignatureAlgorithms;

    public RequestOptions()
    {
    }

    public boolean isUseNonce()
    {
        return useNonce;
    }

    public void setUseNonce(boolean useNonce)
    {
        this.useNonce = useNonce;
    }

    public ASN1ObjectIdentifier getHashAlgorithmId()
    {
        return hashAlgorithmId;
    }

    public void setHashAlgorithmId(ASN1ObjectIdentifier hashAlgorithmId)
    {
        this.hashAlgorithmId = hashAlgorithmId;
    }

    public List<AlgorithmIdentifier> getPreferredSignatureAlgorithms()
    {
        return preferredSignatureAlgorithms;
    }

    public void setPreferredSignatureAlgorithms(List<AlgorithmIdentifier> preferredSignatureAlgorithms)
    {
        this.preferredSignatureAlgorithms = preferredSignatureAlgorithms;
    }

    public void setPreferredSignatureAlgorithms2(List<String> preferredSignatureAlgorithmNames)
    {
        if(preferredSignatureAlgorithmNames == null || preferredSignatureAlgorithmNames.isEmpty())
        {
            this.preferredSignatureAlgorithms = null;
        }

        for(String algoName : preferredSignatureAlgorithmNames)
        {
            AlgorithmIdentifier sigAlgId = sigAlgsMap.get(algoName.toUpperCase());
            if(sigAlgId == null)
            {
                // ignore it
                continue;
            }

            if(this.preferredSignatureAlgorithms == null)
            {
                this.preferredSignatureAlgorithms = new ArrayList<>(preferredSignatureAlgorithmNames.size());
            }
            this.preferredSignatureAlgorithms.add(sigAlgId);
        }
    }

    public boolean isUseHttpGetForRequest()
    {
        return useHttpGetForRequest;
    }

    public void setUseHttpGetForRequest(boolean useHttpGetForRequest)
    {
        this.useHttpGetForRequest = useHttpGetForRequest;
    }

    private static AlgorithmIdentifier createAlgId(String algoName)
    {
        ASN1ObjectIdentifier algOid = null;
        if("SHA1withRSA".equalsIgnoreCase(algoName))
        {
            algOid = PKCSObjectIdentifiers.sha1WithRSAEncryption;
        }
        else if("SHA256withRSA".equalsIgnoreCase(algoName))
        {
            algOid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
        }
        else if("SHA384withRSA".equalsIgnoreCase(algoName))
        {
            algOid = PKCSObjectIdentifiers.sha384WithRSAEncryption;
        }
        else if("SHA512withRSA".equalsIgnoreCase(algoName))
        {
            algOid = PKCSObjectIdentifiers.sha512WithRSAEncryption;
        }
        else if("SHA1withECDSA".equalsIgnoreCase(algoName))
        {
            algOid = X9ObjectIdentifiers.ecdsa_with_SHA1;
        }
        else if("SHA256withECDSA".equalsIgnoreCase(algoName))
        {
            algOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
        }
        else if("SHA384withECDSA".equalsIgnoreCase(algoName))
        {
            algOid = X9ObjectIdentifiers.ecdsa_with_SHA384;
        }
        else if("SHA512withECDSA".equalsIgnoreCase(algoName))
        {
            algOid = X9ObjectIdentifiers.ecdsa_with_SHA512;
        }
        else if("SHA1withRSAandMGF1".equalsIgnoreCase(algoName) ||
                "SHA256withRSAandMGF1".equalsIgnoreCase(algoName) ||
                "SHA384withRSAandMGF1".equalsIgnoreCase(algoName) ||
                "SHA512withRSAandMGF1".equalsIgnoreCase(algoName))
        {
            algOid = PKCSObjectIdentifiers.id_RSASSA_PSS;
        }
        else
        {
            throw new RuntimeException("Unsupported algorithm " + algoName); // should not happen
        }

        ASN1Encodable params;
        if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid))
        {
            ASN1ObjectIdentifier digestAlgOid = null;
            if("SHA1withRSAandMGF1".equalsIgnoreCase(algoName))
            {
                digestAlgOid = X509ObjectIdentifiers.id_SHA1;
            }
            else if("SHA256withRSAandMGF1".equalsIgnoreCase(algoName))
            {
                digestAlgOid = NISTObjectIdentifiers.id_sha256;
            }
            else if("SHA384withRSAandMGF1".equalsIgnoreCase(algoName))
            {
                digestAlgOid = NISTObjectIdentifiers.id_sha384;
            }
            else // if("SHA512withRSAandMGF1".equalsIgnoreCase(algoName))
            {
                digestAlgOid = NISTObjectIdentifiers.id_sha512;
            }
            params = createPSSRSAParams(digestAlgOid);
        }
        else
        {
            params = DERNull.INSTANCE;
        }

        return new AlgorithmIdentifier(algOid, params);

    }

    static public RSASSAPSSparams createPSSRSAParams(ASN1ObjectIdentifier digestAlgOID)
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
            throw new RuntimeException("Unknown digest algorithm " + digestAlgOID);
        }

        AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(digestAlgOID, DERNull.INSTANCE);
        return new RSASSAPSSparams(
            digAlgId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, digAlgId),
            new ASN1Integer(saltSize),
            RSASSAPSSparams.DEFAULT_TRAILER_FIELD);
    }

}
