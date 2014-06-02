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

package org.xipki.ocsp;

import java.util.HashSet;
import java.util.Set;

import org.xipki.ocsp.conf.jaxb.NonceType;
import org.xipki.ocsp.conf.jaxb.RequestType;
import org.xipki.ocsp.conf.jaxb.RequestType.HashAlgorithms;
import org.xipki.security.common.HashAlgoType;

class RequestOptions
{
    static final Set<HashAlgoType> supportedHashAlgorithms = new HashSet<HashAlgoType>();

    static
    {
        supportedHashAlgorithms.add(HashAlgoType.SHA1);
        supportedHashAlgorithms.add(HashAlgoType.SHA224);
        supportedHashAlgorithms.add(HashAlgoType.SHA256);
        supportedHashAlgorithms.add(HashAlgoType.SHA384);
        supportedHashAlgorithms.add(HashAlgoType.SHA512);
    }

    private final boolean signatureRequired;
    private final boolean validateSignature;

    private final boolean nonceRequired;
    private final int nonceMinLen;
    private final int nonceMaxLen;
    private final Set<HashAlgoType> hashAlgos;

    public RequestOptions(RequestType conf)
    throws OcspResponderException
    {
        NonceType nonceConf = conf.getNonce();

        signatureRequired = conf.isSignatureRequired();
        validateSignature = conf.isValidateSignature();

        int minLen = 4;
        int maxLen = 32;
        // Request nonce
        if(nonceConf != null)
        {
            nonceRequired = nonceConf.isRequired();
            if(nonceConf.getMinLen() != null)
            {
                minLen = nonceConf.getMinLen();
            }

            if(nonceConf.getMaxLen() != null)
            {
                maxLen = nonceConf.getMaxLen();
            }
        }
        else
        {
            nonceRequired = false;
        }

        this.nonceMinLen = minLen;
        this.nonceMaxLen = maxLen;

        // Request hash algorithms
        hashAlgos = new HashSet<HashAlgoType>();

        HashAlgorithms reqHashAlgosConf = conf.getHashAlgorithms();
        if(reqHashAlgosConf != null)
        {
            for(String token : reqHashAlgosConf.getAlgorithm())
            {
                HashAlgoType algo = HashAlgoType.getHashAlgoType(token);
                if(algo != null && supportedHashAlgorithms.contains(algo))
                {
                    hashAlgos.add(algo);
                }
                else
                {
                    throw new OcspResponderException("Hash algorithm " + token + " is unsupported");
                }
            }
        }
        else
        {
            hashAlgos.addAll(supportedHashAlgorithms);
        }

    }

    public Set<HashAlgoType> getHashAlgos()
    {
        return hashAlgos;
    }

    public boolean isSignatureRequired()
    {
        return signatureRequired;
    }

    public boolean isValidateSignature()
    {
        return validateSignature;
    }

    public boolean isNonceRequired()
    {
        return nonceRequired;
    }

    public int getNonceMinLen()
    {
        return nonceMinLen;
    }

    public int getNonceMaxLen()
    {
        return nonceMaxLen;
    }

    public boolean allows(HashAlgoType hashAlgo)
    {
        return hashAlgos.contains(hashAlgo);
    }

}
