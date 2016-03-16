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
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class AbstractSecurityFactory implements SecurityFactory {

    @Override
    public ConcurrentContentSigner createSigner(
            final String type,
            final String conf,
            final X509Certificate cert)
    throws SecurityException {
        X509Certificate[] certs = (cert == null)
                ? null
                : new X509Certificate[]{cert};
        return createSigner(type, conf, certs);
    }

    @Override
    public ConcurrentContentSigner createSigner(
            final String type,
            final String confWithoutAlgo,
            final String hashAlgo,
            final SignatureAlgoControl sigAlgoControl,
            final X509Certificate cert)
    throws SecurityException {
        X509Certificate[] certs = (cert == null)
                ? null
                : new X509Certificate[]{cert};
        return createSigner(type, confWithoutAlgo, hashAlgo, sigAlgoControl, certs);
    }

    @Override
    public ContentVerifierProvider getContentVerifierProvider(
            final X509Certificate cert)
    throws InvalidKeyException {
        ParamUtil.requireNonNull("cert", cert);
        return getContentVerifierProvider(cert.getPublicKey());
    }

    @Override
    public ContentVerifierProvider getContentVerifierProvider(
            final X509CertificateHolder cert)
    throws InvalidKeyException {
        ParamUtil.requireNonNull("cert", cert);
        PublicKey publicKey = generatePublicKey(cert.getSubjectPublicKeyInfo());
        return getContentVerifierProvider(publicKey);
    }

}
