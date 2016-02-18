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

package org.xipki.commons.security.api;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface SecurityFactory {

    String DEFAULT_P11MODULE_NAME = "default";

    Set<String> getPkcs11ModuleNames();

    String getDefaultPkcs11ModuleName();

    PasswordResolver getPasswordResolver();

    KeyCertPair createPrivateKeyAndCert(
            String type,
            String conf,
            X509Certificate cert)
    throws SignerException;

    ConcurrentContentSigner createSigner(
            String type,
            String conf,
            X509Certificate cert)
    throws SignerException;

    ConcurrentContentSigner createSigner(
            String type,
            String conf,
            X509Certificate[] certs)
    throws SignerException;

    ConcurrentContentSigner createSigner(
            String type,
            String confWithoutAlgo,
            String hashAlgo,
            SignatureAlgoControl sigAlgoControl,
            X509Certificate cert)
    throws SignerException;

    ConcurrentContentSigner createSigner(
            String type,
            String confWithoutAlgo,
            String hashAlgo,
            SignatureAlgoControl sigAlgoControl,
            X509Certificate[] certs)
    throws SignerException;

    ContentVerifierProvider getContentVerifierProvider(
            PublicKey publicKey)
    throws InvalidKeyException;

    ContentVerifierProvider getContentVerifierProvider(
            X509Certificate cert)
    throws InvalidKeyException;

    ContentVerifierProvider getContentVerifierProvider(
            X509CertificateHolder cert)
    throws InvalidKeyException;

    PublicKey generatePublicKey(
            SubjectPublicKeyInfo subjectPublicKeyInfo)
    throws InvalidKeyException;

    boolean verifyPopo(
            CertificationRequest p10Req);

    P11CryptService getP11CryptService(
            String moduleName)
    throws SignerException;

    PublicKey getPkcs11PublicKey(
            String moduleName,
            P11SlotIdentifier slotId,
            P11KeyIdentifier keyId)
    throws InvalidKeyException;

    String getPkcs11Provider();

    SecureRandom getRandom4Sign();

    SecureRandom getRandom4Key();

}
