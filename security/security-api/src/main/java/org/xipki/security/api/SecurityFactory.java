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

package org.xipki.security.api;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;

public interface SecurityFactory
{
    String getPkcs11Provider();
    String getPkcs11Module();

    ConcurrentContentSigner createSigner(
            String type, String conf, X509Certificate cert, PasswordResolver passwordResolver)
    throws SignerException, PasswordResolverException;

    ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey) throws InvalidKeyException;

    ContentVerifierProvider getContentVerifierProvider(X509Certificate cert) throws InvalidKeyException;

    ContentVerifierProvider getContentVerifierProvider(X509CertificateHolder cert) throws InvalidKeyException;

    PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws InvalidKeyException;

    byte[] generateSelfSignedRSAKeyStore(
            BigInteger serial, String subject, String keystoreType, char[] password, String keyLabel,
            int keysize, BigInteger publicExponent)
    throws SignerException;

    boolean verifyPOPO(CertificationRequest p10Req);
}
