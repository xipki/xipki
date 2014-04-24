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

package org.xipki.security.test;

import java.io.OutputStream;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.security.PasswordResolverImpl;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;

public abstract class Pkcs12_RSA_Test
{
    protected abstract ASN1ObjectIdentifier getSignatureAlgorithm();

    private static final SecurityFactory securityFactory = new SecurityFactoryImpl();

    protected Pkcs12_RSA_Test()
    {
        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    protected String getPkcs12File()
    {
        return "src/test/resources/C.TSL.SIG1.p12";
    }

    protected String getCertificateFile()
    {
        return "src/test/resources/C.TSL.SIG1.der";
    }

    protected String getPassword()
    {
        return "1234";
    }

    private String getSignerConf()
    {
        CmpUtf8Pairs conf = new CmpUtf8Pairs("password", getPassword());
        conf.putUtf8Pair("algo", getSignatureAlgorithm().getId());
        conf.putUtf8Pair("keystore", "file:" + getPkcs12File());
        return conf.getEncoded();
    }

    private ConcurrentContentSigner signer;

    private ConcurrentContentSigner getSigner()
    throws Exception
    {
        if(signer == null)
        {
            String certFile = getCertificateFile();
            X509Certificate cert = IoCertUtil.parseCert(certFile);
            PasswordResolver passwordResolver = new PasswordResolverImpl();

            String signerConf = getSignerConf();
            signer = securityFactory.createSigner("PKCS12", signerConf, cert, passwordResolver);
        }
        return signer;
    }

    @Test
    public void testSignAndVerify()
    throws Exception
    {
        byte[] data = new byte[1234];
        for(int i = 0; i < data.length; i++)
        {
            data[i] = (byte) (i & 0xFF);
        }

        byte[] signatureValue = sign(data);
        boolean signatureValid = verify(data, signatureValue, getSigner().getCertificate());
        Assert.assertTrue("Signature invalid", signatureValid);
    }

    protected byte[] sign(byte[] data)
    throws Exception
    {
        ConcurrentContentSigner signer = getSigner();
        ContentSigner cSigner = signer.borrowContentSigner();
        try
        {
            OutputStream signatureStream = cSigner.getOutputStream();
            signatureStream.write(data);
            return cSigner.getSignature();
        } finally
        {
            signer.returnContentSigner(cSigner);
        }
    }

    protected boolean verify(byte[] data, byte[] signatureValue, X509Certificate cert)
    throws Exception
    {
        Signature signature = Signature.getInstance(getSignatureAlgorithm().getId());
        signature.initVerify(cert.getPublicKey());
        signature.update(data);
        return signature.verify(signatureValue);
    }
}
