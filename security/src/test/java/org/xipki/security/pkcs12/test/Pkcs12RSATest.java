/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs12.test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.pkcs12.SoftTokenContentSignerBuilder;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public abstract class Pkcs12RSATest {

    private ConcurrentContentSigner signer;

    protected Pkcs12RSATest() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    protected abstract AlgorithmIdentifier getSignatureAlgorithm();

    protected String getPkcs12File() {
        return "src/test/resources/test1.p12";
    }

    protected String getCertificateFile() {
        return "src/test/resources/test1.der";
    }

    protected String getPassword() {
        return "1234";
    }

    private ConcurrentContentSigner getSigner() throws Exception {
        if (signer != null) {
            return signer;
        }

        String certFile = getCertificateFile();
        X509Certificate cert = X509Util.parseCert(certFile);

        InputStream ks = new FileInputStream(getPkcs12File());
        char[] password = getPassword().toCharArray();
        SoftTokenContentSignerBuilder builder = new SoftTokenContentSignerBuilder("PKCS12", ks,
                password, null, password, new X509Certificate[]{cert});
        signer = builder.createSigner(getSignatureAlgorithm(), 1, new SecureRandom());
        return signer;
    }

    @Test
    public void testSignAndVerify() throws Exception {
        byte[] data = new byte[1234];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i & 0xFF);
        }

        byte[] signatureValue = sign(data);
        boolean signatureValid = verify(data, signatureValue, getSigner().getCertificate());
        Assert.assertTrue("Signature invalid", signatureValid);
    }

    protected byte[] sign(byte[] data) throws Exception {
        return getSigner().sign(data);
    }

    protected boolean verify(byte[] data, byte[] signatureValue, X509Certificate cert)
            throws Exception {
        Signature signature = Signature.getInstance(getSignatureAlgorithm().getAlgorithm().getId());
        signature.initVerify(cert.getPublicKey());
        signature.update(data);
        return signature.verify(signatureValue);
    }

}
