/*
 * Copyright (c) 2015 Lijun Liao
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

package org.xipki.scep4j.message;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.xipki.scep4j.crypto.HashAlgoType;
import org.xipki.scep4j.exception.MessageEncodingException;
import org.xipki.scep4j.util.ScepUtil;

/**
 * @author Lijun Liao
 */

public class NextCAMessage
{
    private X509Certificate caCert;
    private List<X509Certificate> raCerts;

    public NextCAMessage()
    {
    }

    public X509Certificate getCaCert()
    {
        return caCert;
    }

    public void setCaCert(
            final X509Certificate caCert)
    {
        this.caCert = caCert;
    }

    public List<X509Certificate> getRaCerts()
    {
        return raCerts;
    }

    public void setRaCerts(
            final List<X509Certificate> raCerts)
    {
        if(raCerts == null || raCerts.isEmpty())
        {
            this.raCerts = null;
        } else
        {
            this.raCerts = Collections.unmodifiableList(
                    new ArrayList<X509Certificate>(raCerts));
        }
    }

    public ContentInfo encode(
            final PrivateKey signingKey,
            final X509Certificate signerCert,
            final X509Certificate[] cmsCertSet)
    throws MessageEncodingException
    {
        try
        {
            byte[] degenratedSignedDataBytes;
            try
            {
                CMSSignedDataGenerator degenerateSignedData = new CMSSignedDataGenerator();
                degenerateSignedData.addCertificate(new X509CertificateHolder(caCert.getEncoded()));
                if(raCerts != null && raCerts.isEmpty() == false)
                {
                    for(X509Certificate m : raCerts)
                    {
                        degenerateSignedData.addCertificate(new X509CertificateHolder(m.getEncoded()));
                    }
                }

                degenratedSignedDataBytes = degenerateSignedData.generate(new CMSAbsentContent()).getEncoded();
            } catch(CertificateEncodingException e)
            {
                throw new MessageEncodingException(e.getMessage(), e);
            }

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            // I don't known which hash algorithm is supported by the client, use SHA-1
            String signatureAlgo = getSignatureAlgorithm(signingKey, HashAlgoType.SHA1);
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgo).build(signingKey);

            // signerInfo
            JcaSignerInfoGeneratorBuilder signerInfoBuilder = new JcaSignerInfoGeneratorBuilder(
                    new BcDigestCalculatorProvider());

            signerInfoBuilder.setSignedAttributeGenerator(
                    new DefaultSignedAttributeTableGenerator());

            SignerInfoGenerator signerInfo = signerInfoBuilder.build(signer, signerCert);
            generator.addSignerInfoGenerator(signerInfo);

            CMSTypedData cmsContent = new CMSProcessableByteArray(
                    CMSObjectIdentifiers.signedData,
                    degenratedSignedDataBytes);

            // certificateSet
            ScepUtil.addCmsCertSet(generator, cmsCertSet);
            return generator.generate(cmsContent, true).toASN1Structure();
        }catch(CMSException e)
        {
            throw new MessageEncodingException(e);
        }catch(CertificateEncodingException e)
        {
            throw new MessageEncodingException(e);
        }catch(IOException e)
        {
            throw new MessageEncodingException(e);
        }catch(OperatorCreationException e)
        {
            throw new MessageEncodingException(e);
        }
    }

    private static String getSignatureAlgorithm(
            final PrivateKey key,
            final HashAlgoType hashAlgo)
    {
        String algorithm = key.getAlgorithm();
        if("RSA".equalsIgnoreCase(algorithm))
        {
            return hashAlgo.getName() + "withRSA";
        } else
        {
            throw new UnsupportedOperationException("getSignatureAlgorithm() for non-RSA is not supported yet.");
        }
    }

}
