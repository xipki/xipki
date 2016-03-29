/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.commons.security.impl.p11;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.util.AlgorithmUtil;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.commons.security.impl.DefaultConcurrentContentSigner;
import org.xipki.commons.security.provider.P11PrivateKey;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11ContentSignerBuilder {

    private final PublicKey publicKey;

    private final X509Certificate[] certificateChain;

    private final P11CryptService cryptService;

    private final SecurityFactory securityFactory;

    private final P11EntityIdentifier identityId;

    public P11ContentSignerBuilder(
            final P11CryptService cryptService,
            final SecurityFactory securityFactory,
            final P11EntityIdentifier identityId,
            final X509Certificate[] certificateChain)
    throws SecurityException, P11TokenException {
        this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
        this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);
        this.identityId = ParamUtil.requireNonNull("identityId", identityId);

        P11Identity identity = cryptService.getIdentity(identityId);
        X509Certificate signerCertInP11 = identity.getCertificate();
        PublicKey publicKeyInP11;
        if (signerCertInP11 != null) {
            publicKeyInP11 = signerCertInP11.getPublicKey();
        } else {
            publicKeyInP11 = identity.getPublicKey();
        }

        if (publicKeyInP11 == null) {
            throw new SecurityException("public key with " + identityId + " does not exist");
        }

        Set<Certificate> caCerts = new HashSet<>();

        X509Certificate cert;
        final int n = (certificateChain == null)
                ? 0
                : certificateChain.length;

        if (n > 0) {
            cert = certificateChain[0];
            if (n > 1) {
                for (int i = 1; i < n; i++) {
                    caCerts.add(certificateChain[i]);
                }
            }
            this.publicKey = cert.getPublicKey();
        } else {
            this.publicKey = publicKeyInP11;
            cert = signerCertInP11;
        }

        if (cert != null) {
            Certificate[] certsInKeystore = identity.getCertificateChain();
            if (certsInKeystore != null && certsInKeystore.length > 1) {
                for (int i = 1; i < certsInKeystore.length; i++) {
                    caCerts.add(certsInKeystore[i]);
                }
            }

            this.certificateChain = X509Util.buildCertPath(cert, caCerts);
        } else {
            this.certificateChain = null;
        }
    } // constructor

    public ConcurrentContentSigner createSigner(
            final AlgorithmIdentifier signatureAlgId,
            final int parallelism)
    throws SecurityException, P11TokenException {
        ParamUtil.requireMin("parallelism", parallelism, 1);

        if (publicKey instanceof RSAPublicKey) {
            if (!AlgorithmUtil.isRSASignatureAlgoId(signatureAlgId)) {
                throw new SecurityException(
                        "the given algorithm is not a valid RSA signature algorithm '"
                        + signatureAlgId.getAlgorithm().getId() + "'");
            }
        } else if (publicKey instanceof ECPublicKey) {
            if (!AlgorithmUtil.isECSigAlg(signatureAlgId)) {
                throw new SecurityException(
                        "the given algorithm is not a valid EC signature algirthm '"
                        + signatureAlgId.getAlgorithm().getId() + "'");
            }
        } else if (publicKey instanceof DSAPublicKey) {
            if (!AlgorithmUtil.isDSASigAlg(signatureAlgId)) {
                throw new SecurityException(
                        "the given algorithm is not a valid DSA signature algirthm '"
                        + signatureAlgId.getAlgorithm().getId() + "'");
            }
        } else {
            throw new SecurityException("unsupported key " + publicKey.getClass().getName());
        }

        List<ContentSigner> signers = new ArrayList<>(parallelism);
        for (int i = 0; i < parallelism; i++) {
            ContentSigner signer;
            if (publicKey instanceof RSAPublicKey) {
                signer = createRSAContentSigner(signatureAlgId);
            } else if (publicKey instanceof ECPublicKey) {
                signer = createECContentSigner(signatureAlgId);
            } else if (publicKey instanceof DSAPublicKey) {
                signer = createDSAContentSigner(signatureAlgId);
            } else {
                throw new SecurityException("unsupported key " + publicKey.getClass().getName());
            }
            signers.add(signer);
        } // end for

        PrivateKey privateKey = new P11PrivateKey(cryptService, identityId);
        DefaultConcurrentContentSigner concurrentSigner =
                new DefaultConcurrentContentSigner(signers, privateKey);
        if (certificateChain != null) {
            concurrentSigner.setCertificateChain(certificateChain);
        } else {
            concurrentSigner.setPublicKey(publicKey);
        }

        return concurrentSigner;
    } // method createSigner

    // CHECKSTYLE:SKIP
    private ContentSigner createRSAContentSigner(AlgorithmIdentifier signatureAlgId)
    throws SecurityException, P11TokenException {
        if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm())) {
            return new P11RSAPSSContentSigner(cryptService, identityId, signatureAlgId,
                    securityFactory.getRandom4Sign());
        } else {
            return new P11RSAContentSigner(cryptService, identityId, signatureAlgId);
        }
    }

    // CHECKSTYLE:SKIP
    private ContentSigner createECContentSigner(AlgorithmIdentifier signatureAlgId)
    throws SecurityException, P11TokenException {
        return new P11ECDSAContentSigner(cryptService, identityId, signatureAlgId,
                AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId));
    }

    // CHECKSTYLE:SKIP
    private ContentSigner createDSAContentSigner(AlgorithmIdentifier signatureAlgId)
    throws SecurityException, P11TokenException {
        return new P11DSAContentSigner(cryptService, identityId, signatureAlgId,
                AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId));
    }

}
