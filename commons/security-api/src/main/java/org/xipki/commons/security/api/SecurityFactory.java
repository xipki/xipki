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
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Module;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11WritableSlot;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface SecurityFactory {

    String DEFAULT_P11MODULE_NAME = "default";

    Set<String> getPkcs11ModuleNames();

    P11Module getP11Module(
            @Nonnull String moduleName)
    throws SecurityException, P11TokenException;

    P11WritableSlot getP11WritablSlot(
            @Nonnull String moduleName,
            int slotIndex)
    throws SecurityException, P11TokenException;

    PasswordResolver getPasswordResolver();

    KeyCertPair createPrivateKeyAndCert(
            @Nonnull String type,
            @Nullable String conf,
            @Nullable X509Certificate cert)
    throws SecurityException;

    ConcurrentContentSigner createSigner(
            @Nonnull String type,
            @Nullable String conf,
            @Nullable X509Certificate cert)
    throws SecurityException;

    ConcurrentContentSigner createSigner(
            @Nonnull String type,
            @Nullable String conf,
            @Nullable X509Certificate[] certs)
    throws SecurityException;

    ConcurrentContentSigner createSigner(
            @Nonnull String type,
            @Nonnull String confWithoutAlgo,
            @Nonnull String hashAlgo,
            @Nullable SignatureAlgoControl sigAlgoControl,
            @Nullable X509Certificate cert)
    throws SecurityException;

    ConcurrentContentSigner createSigner(
            @Nonnull String type,
            @Nonnull String confWithoutAlgo,
            @Nonnull String hashAlgo,
            @Nonnull SignatureAlgoControl sigAlgoControl,
            @Nullable X509Certificate[] certs)
    throws SecurityException;

    ContentVerifierProvider getContentVerifierProvider(
            @Nonnull PublicKey publicKey)
    throws InvalidKeyException;

    ContentVerifierProvider getContentVerifierProvider(
            @Nonnull X509Certificate cert)
    throws InvalidKeyException;

    ContentVerifierProvider getContentVerifierProvider(
            @Nonnull X509CertificateHolder cert)
    throws InvalidKeyException;

    boolean verifyPopo(
            @Nonnull PKCS10CertificationRequest p10Request);

    boolean verifyPopo(
            @Nonnull CertificationRequest p10Req);

    PublicKey generatePublicKey(
            @Nonnull SubjectPublicKeyInfo subjectPublicKeyInfo)
    throws InvalidKeyException;

    P11CryptService getP11CryptService(
            @Nonnull String moduleName)
    throws SecurityException, P11TokenException;

    PublicKey getPkcs11PublicKey(
            @Nonnull String moduleName,
            @Nonnull P11EntityIdentifier entityId)
    throws InvalidKeyException, P11TokenException;

    byte[] extractMinimalKeyStore(
            @Nonnull String keystoreType,
            @Nonnull byte[] keystoreBytes,
            @Nullable String keyname,
            @Nonnull char[] password,
            @Nullable X509Certificate[] newCertChain)
    throws KeyStoreException;

    SecureRandom getRandom4Sign();

    SecureRandom getRandom4Key();

}
