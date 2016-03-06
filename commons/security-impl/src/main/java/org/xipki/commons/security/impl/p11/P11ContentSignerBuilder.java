/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
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

    private final P11SlotIdentifier slot;

    private final P11KeyIdentifier keyId;

    public P11ContentSignerBuilder(
            final P11CryptService cryptService,
            final SecurityFactory securityFactory,
            final P11SlotIdentifier slot,
            final P11KeyIdentifier keyId,
            final X509Certificate[] certificateChain)
    throws SignerException {
        this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
        this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);
        this.slot = ParamUtil.requireNonNull("slot", slot);
        this.keyId = ParamUtil.requireNonNull("keyId", keyId);

        X509Certificate signerCertInP11 = cryptService.getCertificate(slot, keyId);
        PublicKey publicKeyInP11;
        if (signerCertInP11 != null) {
            publicKeyInP11 = signerCertInP11.getPublicKey();
        } else {
            publicKeyInP11 = cryptService.getPublicKey(slot, keyId);
        }

        if (publicKeyInP11 == null) {
            throw new SignerException("public key with " + keyId + " does not exist");
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
            Certificate[] certsInKeystore = cryptService.getCertificates(slot, keyId);
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
    throws OperatorCreationException, NoSuchPaddingException {
        ParamUtil.requireMin("parallelism", parallelism, 1);

        if (publicKey instanceof RSAPublicKey) {
            if (!AlgorithmUtil.isRSASignatureAlgoId(signatureAlgId)) {
                throw new OperatorCreationException(
                        "the given algorithm is not a valid RSA signature algorithm '"
                        + signatureAlgId.getAlgorithm().getId() + "'");
            }
        } else if (publicKey instanceof ECPublicKey) {
            if (!AlgorithmUtil.isECSigAlg(signatureAlgId)) {
                throw new OperatorCreationException(
                        "the given algorithm is not a valid EC signature algirthm '"
                        + signatureAlgId.getAlgorithm().getId() + "'");
            }
        } else if (publicKey instanceof DSAPublicKey) {
            if (!AlgorithmUtil.isDSASigAlg(signatureAlgId)) {
                throw new OperatorCreationException(
                        "the given algorithm is not a valid DSA signature algirthm '"
                        + signatureAlgId.getAlgorithm().getId() + "'");
            }
        } else {
            throw new OperatorCreationException("unsupported key "
                    + publicKey.getClass().getName());
        }

        List<ContentSigner> signers = new ArrayList<>(parallelism);

        try {
            for (int i = 0; i < parallelism; i++) {
                ContentSigner signer;
                if (publicKey instanceof RSAPublicKey) {
                    if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm())) {
                        signer = new P11RSAPSSContentSigner(cryptService, slot, keyId,
                                signatureAlgId, securityFactory.getRandom4Sign());
                    } else {
                        signer = new P11RSAContentSigner(cryptService, slot, keyId,
                                signatureAlgId);
                    }
                } else if (publicKey instanceof ECPublicKey) {
                    if (AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId)) {
                        signer = new P11ECDSAPlainContentSigner(cryptService, slot, keyId,
                                signatureAlgId);
                    } else {
                        signer = new P11ECDSAX962ContentSigner(cryptService, slot, keyId,
                                signatureAlgId);
                    }
                } else if (publicKey instanceof DSAPublicKey) {
                    if (AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId)) {
                        signer = new P11DSAPlainContentSigner(cryptService, slot, keyId,
                                signatureAlgId);
                    } else {
                        signer = new P11DSAX962ContentSigner(cryptService, slot, keyId,
                                signatureAlgId);
                    }
                } else {
                    throw new OperatorCreationException("unsupported key "
                            + publicKey.getClass().getName());
                }
                signers.add(signer);
            } // end for
        } catch (NoSuchAlgorithmException ex) {
            throw new OperatorCreationException("no such algorithm", ex);
        }

        PrivateKey privateKey;
        try {
            privateKey = new P11PrivateKey(cryptService, slot, keyId);
        } catch (InvalidKeyException ex) {
            throw new OperatorCreationException(
                    "could not construct P11PrivateKey: " + ex.getMessage(), ex);
        }

        DefaultConcurrentContentSigner concurrentSigner =
                new DefaultConcurrentContentSigner(signers, privateKey);
        if (certificateChain != null) {
            concurrentSigner.setCertificateChain(certificateChain);
        } else {
            concurrentSigner.setPublicKey(publicKey);
        }

        return concurrentSigner;
    } // method createSigner

}
