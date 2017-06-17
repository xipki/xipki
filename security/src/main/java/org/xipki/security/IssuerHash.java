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
import java.util.Arrays;

import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IssuerHash {
    private final HashAlgoType hashAlgo;

    private final byte[] issuerNameHash;

    private final byte[] issuerKeyHash;

    public IssuerHash(final HashAlgoType hashAlgo, final byte[] issuerNameHash,
            final byte[] issuerKeyHash) {
        this.hashAlgo = ParamUtil.requireNonNull("hashAlgo", hashAlgo);
        this.issuerNameHash = ParamUtil.requireNonNull("issuerNameHash", issuerNameHash);
        this.issuerKeyHash = ParamUtil.requireNonNull("issuerKeyHash", issuerKeyHash);

        final int len = hashAlgo.length();
        ParamUtil.requireRange("issuerNameHash.length", issuerNameHash.length, len, len);
        ParamUtil.requireRange("issuerKeyHash.length", issuerKeyHash.length, len, len);
    }

    public IssuerHash(final HashAlgoType hashAlgo, final Certificate issuerCert)
            throws IOException {
        this.hashAlgo = ParamUtil.requireNonNull("hashAlgo", hashAlgo);
        ParamUtil.requireNonNull("issuerCert", issuerCert);

        byte[] encodedName = issuerCert.getSubject().getEncoded();
        byte[] encodedKey = issuerCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        this.issuerNameHash = HashCalculator.hash(hashAlgo, encodedName);
        this.issuerKeyHash = HashCalculator.hash(hashAlgo, encodedKey);
    }

    public HashAlgoType hashAlgo() {
        return hashAlgo;
    }

    public byte[] issuerNameHash() {
        return Arrays.copyOf(issuerNameHash, issuerNameHash.length);
    }

    public byte[] issuerKeyHash() {
        return Arrays.copyOf(issuerKeyHash, issuerKeyHash.length);
    }

    public boolean match(final HashAlgoType hashAlgo, final byte[] issuerNameHash,
            final byte[] issuerKeyHash) {
        ParamUtil.requireNonNull("hashAlgo", hashAlgo);
        ParamUtil.requireNonNull("issuerNameHash", issuerNameHash);
        ParamUtil.requireNonNull("issuerKeyHash", issuerKeyHash);

        return this.hashAlgo == hashAlgo
                && Arrays.equals(this.issuerNameHash, issuerNameHash)
                && Arrays.equals(this.issuerKeyHash, issuerKeyHash);
    }

}
