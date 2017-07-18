/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class ResponderSigner {

    private final Map<String, ConcurrentContentSigner> algoSignerMap;

    private final List<ConcurrentContentSigner> signers;

    private final byte[] encodedSequenceOfCertificate;

    private final X509Certificate certificate;

    private final byte[] encodedSequenceOfCertificateChain;

    private final X509Certificate[] certificateChain;

    private final byte[] responderIdByName;

    private final byte[] responderIdByKey;

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
            this.encodedSequenceOfCertificate = null;
            this.encodedSequenceOfCertificateChain = null;

            byte[] keySha1 = firstSigner.getSha1DigestOfMacKey();
            this.responderIdByKey = new ResponderID(new DEROctetString(keySha1)).getEncoded();
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

            Certificate bcCertificate = Certificate.getInstance(this.certificate.getEncoded());
            this.encodedSequenceOfCertificate =
                    new DERTaggedObject(true, 0, new DERSequence(bcCertificate)).getEncoded();

            ASN1Encodable[] bcCertificateChain = new Certificate[this.certificateChain.length];
            bcCertificateChain[0] = bcCertificate;
            for (int i = 1; i < certificateChain.length; i++) {
                bcCertificateChain[i] = Certificate.getInstance(
                        this.certificateChain[i].getEncoded());
            }
            this.encodedSequenceOfCertificateChain =
                    new DERTaggedObject(true, 0, new DERSequence(bcCertificateChain)).getEncoded();

            this.responderIdByName = new ResponderID(bcCertificate.getSubject()).getEncoded();
            byte[] keySha1 = HashAlgoType.SHA1.hash(
                    bcCertificate.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
            this.responderIdByKey = new ResponderID(new DEROctetString(keySha1)).getEncoded();
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

    public byte[] getResponder(final boolean byName) {
        return byName ? responderIdByName :  responderIdByKey;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public X509Certificate[] certificateChain() {
        return certificateChain;
    }

    public byte[] encodedSequenceOfCertificate() {
        return encodedSequenceOfCertificate;
    }

    public byte[] encodedSequenceOfCertificateChain() {
        return encodedSequenceOfCertificateChain;
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
