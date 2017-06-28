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

package org.xipki.security;

import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.xipki.password.PasswordResolver;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface ConcurrentContentSigner {

    String getName();

    AlgorithmIdentifier getAlgorithmIdentifier();

    /**
     * Returns the algorithm code in XiPKI context.
     * @return algorithm code
     */
    AlgorithmCode algorithmCode();

    boolean isMac();

    byte[] getSha1DigestOfMacKey();

    /**
     * Get the signing key.
     * @return the signing key if possible. {@code null} may be returned.
     */
    Key getSigningKey();

    /**
     *
     * @param publicKey
     *          Public key of this signer. Must not be {@code null}.
     */
    void setPublicKey(PublicKey publicKey);

    PublicKey getPublicKey();

    X509Certificate getCertificate();

    X509CertificateHolder getCertificateAsBcObject();

    /**
     *
     * @param certchain
     *          Certificate chain of this signer. Could be {@code null}.
     */
    void setCertificateChain(X509Certificate[] certchain);

    X509Certificate[] getCertificateChain();

    X509CertificateHolder[] getCertificateChainAsBcObjects();

    /**
     *
     * @param conf
     *          Configuration. Could be {@code null}.
     * @param passwordResolver
     *          Password resolver. Could be {@code null}.
     * @throws XiSecurityException
     */
    void initialize(String conf, PasswordResolver passwordResolver)
            throws XiSecurityException;

    /**
     *
     * @param builder
     *          Signing key builder. Must not be {@code null}.
     */
    POPOSigningKey build(ProofOfPossessionSigningKeyBuilder builder)
            throws NoIdleSignerException;

    /**
     *
     * @param builder
     *          Protected PKI message builder. Must not be {@code null}.
     */
    ProtectedPKIMessage build(ProtectedPKIMessageBuilder builder)
            throws NoIdleSignerException, CMPException;

    /**
     *
     * @param builder
     *          CRL builder. Must not be {@code null}.
     */
    X509CRLHolder build(X509v2CRLBuilder builder) throws NoIdleSignerException;

    /**
     *
     * @param builder
     *          Certificate builder. Must not be {@code null}.
     */
    X509CertificateHolder build(X509v3CertificateBuilder builder)
            throws NoIdleSignerException;

    /**
     * @param builder
     *          OCSP request builder. Must not be {@code null}.
     * @param chain
     *          Certificates to be embedded in the response. Could be {@code null}.
     *
     */
    OCSPReq build(OCSPReqBuilder builder, X509CertificateHolder[] chain)
            throws NoIdleSignerException, OCSPException;

    /**
     *
     * @param builder
     *          Basic OCSP response builder. Must not be {@code null}.
     * @param chain
     *          Certificates to be embedded in the response. Could be {@code null}.
     * @param producedAt
     *          When the OCSP response is produced. Must not be {@code null}.
     */
    BasicOCSPResp build(BasicOCSPRespBuilder builder,
            X509CertificateHolder[] chain, Date producedAt)
            throws NoIdleSignerException, OCSPException;

    /**
     *
     * @param builder
     *          PKCS#10 request builder. Must not be {@code null}.
     * @return
     * @throws NoIdleSignerException
     */
    PKCS10CertificationRequest build(PKCS10CertificationRequestBuilder builder)
            throws NoIdleSignerException;

    /**
     *
     * @param data
     *          Data to be signed. Must not be {@code null}.
     */
    byte[] sign(byte[] data) throws NoIdleSignerException, IOException;

    boolean isHealthy();

    void shutdown();

}
