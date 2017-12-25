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

package org.xipki.ocsp.server.impl;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.ParamUtil;
import org.xipki.ocsp.server.impl.type.ResponderID;
import org.xipki.ocsp.server.impl.type.TaggedCertSequence;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class ResponderSigner {

    private final Map<String, ConcurrentContentSigner> algoSignerMap;

    private final List<ConcurrentContentSigner> signers;

    private final TaggedCertSequence sequenceOfCertificate;

    private final X509Certificate certificate;

    private final TaggedCertSequence sequenceOfCertificateChain;

    private final X509Certificate[] certificateChain;

    private final ResponderID responderIdByName;

    private final ResponderID responderIdByKey;

    private final boolean macSigner;

    ResponderSigner(final List<ConcurrentContentSigner> signers)
            throws CertificateException, IOException {
        this.signers = ParamUtil.requireNonEmpty("signers", signers);
        ConcurrentContentSigner firstSigner = signers.get(0);
        this.macSigner = firstSigner.isMac();

        if (this.macSigner) {
            this.responderIdByName = null;
            this.certificate = null;
            this.certificateChain = null;
            this.sequenceOfCertificate = null;
            this.sequenceOfCertificateChain = null;

            byte[] keySha1 = firstSigner.getSha1DigestOfMacKey();
            this.responderIdByKey = new ResponderID(keySha1);
        } else {
            X509Certificate[] tmpCertificateChain = firstSigner.getCertificateChain();
            if (tmpCertificateChain == null || tmpCertificateChain.length == 0) {
                throw new CertificateException("no certificate is bound with the signer");
            }
            int len = tmpCertificateChain.length;
            if (len > 1) {
                X509Certificate cert = tmpCertificateChain[len - 1];
                if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                    len--;
                }
            }
            this.certificateChain = new X509Certificate[len];
            System.arraycopy(tmpCertificateChain, 0, this.certificateChain, 0, len);

            this.certificate = certificateChain[0];

            byte[] encodedCertificate = this.certificate.getEncoded();
            Certificate bcCertificate = Certificate.getInstance(encodedCertificate);
            this.sequenceOfCertificate = new TaggedCertSequence(encodedCertificate);

            byte[][] encodedCertificateChain = new byte[this.certificateChain.length][];
            encodedCertificateChain[0] = encodedCertificate;
            for (int i = 1; i < certificateChain.length; i++) {
                encodedCertificateChain[i] = this.certificateChain[i].getEncoded();
            }
            this.sequenceOfCertificateChain = new TaggedCertSequence(encodedCertificateChain);

            this.responderIdByName = new ResponderID(bcCertificate.getSubject());
            byte[] keySha1 = HashAlgoType.SHA1.hash(
                    bcCertificate.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
            this.responderIdByKey = new ResponderID(keySha1);
        }

        algoSignerMap = new HashMap<>();
        for (ConcurrentContentSigner signer : signers) {
            String algoName = signer.getAlgorithmName();
            algoSignerMap.put(algoName, signer);
        }
    } // constructor

    public boolean isMacSigner() {
        return macSigner;
    }

    public ConcurrentContentSigner firstSigner() {
        return signers.get(0);
    }

    public ConcurrentContentSigner getSignerForPreferredSigAlgs(
            final List<AlgorithmIdentifier> prefSigAlgs) {
        if (prefSigAlgs == null) {
            return signers.get(0);
        }

        for (AlgorithmIdentifier sigAlgId : prefSigAlgs) {
            String algoName = getSignatureAlgorithmName(sigAlgId);
            if (algoSignerMap.containsKey(algoName)) {
                return algoSignerMap.get(algoName);
            }
        }
        return null;
    }

    public ResponderID getResponderId(final boolean byName) {
        return byName ? responderIdByName :  responderIdByKey;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public X509Certificate[] certificateChain() {
        return certificateChain;
    }

    public TaggedCertSequence sequenceOfCertificate() {
        return sequenceOfCertificate;
    }

    public TaggedCertSequence sequenceOfCertificateChain() {
        return sequenceOfCertificateChain;
    }

    public boolean isHealthy() {
        for (ConcurrentContentSigner signer : signers) {
            if (!signer.isHealthy()) {
                return false;
            }
        }

        return true;
    }

    private static String getSignatureAlgorithmName(final AlgorithmIdentifier sigAlgId) {
        ASN1ObjectIdentifier algOid = sigAlgId.getAlgorithm();
        if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid)) {
            return algOid.getId();
        }

        ASN1Encodable asn1Encodable = sigAlgId.getParameters();
        RSASSAPSSparams param = RSASSAPSSparams.getInstance(asn1Encodable);
        ASN1ObjectIdentifier digestAlgOid = param.getHashAlgorithm().getAlgorithm();
        return digestAlgOid.getId() + "WITHRSAANDMGF1";
    }

}
