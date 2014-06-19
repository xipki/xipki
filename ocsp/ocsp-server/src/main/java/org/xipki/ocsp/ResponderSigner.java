/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ocsp;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class ResponderSigner
{
    private final Map<String, ConcurrentContentSigner> algoSignerMap;
    private final List<ConcurrentContentSigner> signers;

    private final X509CertificateHolder certificateHolder;
    private final X509Certificate certificate;
    private final X509Certificate[] certificateChain;

    private final X500Name responderId;

    public ResponderSigner(List<ConcurrentContentSigner> signers)
    throws CertificateEncodingException, IOException
    {
        ParamChecker.assertNotEmpty("signers", signers);

        this.signers = signers;
        this.certificateChain = signers.get(0).getCertificateChain();
        this.certificate = certificateChain[0];

        this.certificateHolder = new X509CertificateHolder(this.certificate.getEncoded());
        this.responderId = this.certificateHolder.getSubject();
        algoSignerMap = new HashMap<>();
        for(ConcurrentContentSigner signer : signers)
        {
            String algoName = getSignatureAlgorithmName(signer.getAlgorithmIdentifier());
            algoSignerMap.put(algoName, signer);
        }
    }

    public ConcurrentContentSigner getFirstSigner()
    {
        return signers.get(0);
    }

    public ConcurrentContentSigner getSigner(ASN1Sequence preferredSigAlgs)
    {
        if(preferredSigAlgs == null)
        {
            return signers.get(0);
        }

        int size = preferredSigAlgs.size();
        for(int i = 0; i < size; i++)
        {
            ASN1Sequence algObj = (ASN1Sequence) preferredSigAlgs.getObjectAt(i);
            AlgorithmIdentifier sigAlgId = AlgorithmIdentifier.getInstance(algObj.getObjectAt(0));
            String algoName = getSignatureAlgorithmName(sigAlgId);
            if(algoSignerMap.containsKey(algoName))
            {
                return algoSignerMap.get(algoName);
            }
        }
        return null;
    }

    private static String getSignatureAlgorithmName(AlgorithmIdentifier sigAlgId)
    {
        String algoName;
        ASN1ObjectIdentifier algOid = sigAlgId.getAlgorithm();
        if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid))
        {
            ASN1Encodable asn1Encodable = sigAlgId.getParameters();
            RSASSAPSSparams param = RSASSAPSSparams.getInstance(asn1Encodable);
            ASN1ObjectIdentifier digestAlgOid = param.getHashAlgorithm().getAlgorithm();
            algoName = digestAlgOid.getId() + "WITHRSAANDMGF1";
        }
        else
        {
            algoName = algOid.getId();
        }

        return algoName;
    }

    public X500Name getResponderId()
    {
        return responderId;
    }

    public X509Certificate getCertificate()
    {
        return certificate;
    }

    public X509Certificate[] getCertificateChain()
    {
        return certificateChain;
    }

    public X509CertificateHolder getCertificateHolder()
    {
        return certificateHolder;
    }

    public boolean isHealthy()
    {
        for(ConcurrentContentSigner signer : signers)
        {
            if(signer.isHealthy() == false)
            {
                return false;
            }
        }

        return true;
    }

}
