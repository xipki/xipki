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

package org.xipki.pki.scep.transaction;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class TransactionId {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String id;

    public TransactionId(
            final String id) {
        this.id = ParamUtil.requireNonBlank("id", id);
    }

    private TransactionId(
            final byte[] bytes) {
        ParamUtil.requireNonNull("bytes", bytes);
        ParamUtil.requireMin("bytes.length", bytes.length, 1);
        this.id = Hex.toHexString(bytes);
    }

    public String getId() {
        return id;
    }

    public static TransactionId randomTransactionId() {
        byte[] bytes = new byte[20];
        RANDOM.nextBytes(bytes);
        return new TransactionId(bytes);
    }

    public static TransactionId sha1TransactionId(
            final SubjectPublicKeyInfo spki)
    throws InvalidKeySpecException {
        ParamUtil.requireNonNull("spki", spki);

        byte[] encoded;
        try {
            encoded = spki.getEncoded();
        } catch (IOException ex) {
            throw new InvalidKeySpecException("IOException while ");
        }

        return sha1TransactionId(encoded);
    }

    public static TransactionId sha1TransactionId(
            final byte[] content) {
        ParamUtil.requireNonNull("content", content);

        SHA1Digest dgst = new SHA1Digest();
        dgst.update(content, 0, content.length);
        final int size = 20;
        byte[] digest = new byte[size];
        dgst.doFinal(digest, 0);
        return new TransactionId(digest);
    }

}
