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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.scep.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * @author Lijun Liao
 */

public enum HashAlgoType {

    MD5   (16, "1.2.840.113549.2.5", "MD5"),
    SHA1  (20, "1.3.14.3.2.26", "SHA1"),
    SHA256(32, "2.16.840.1.101.3.4.2.1", "SHA256"),
    SHA512(64, "2.16.840.1.101.3.4.2.3", "SHA512");

    private final int length;

    private final String oid;

    private final String name;

    private HashAlgoType(
            final int length,
            final String oid,
            final String name) {
        this.length = length;
        this.oid = oid;
        this.name = name;
    }

    public int getLength() {
        return length;
    }

    public String getOid() {
        return oid;
    }

    public String getName() {
        return name;
    }

    public String hexDigest(
            final byte[] content) {
        byte[] dgst = digest(content);
        return (dgst == null)
                ? null
                : Hex.toHexString(dgst).toUpperCase();
    }

    public byte[] digest(
            final byte[] content) {
        Digest digest;
        if (this == SHA1) {
            digest = new SHA1Digest();
        } else if (this == SHA256) {
            digest = new SHA256Digest();
        } else if (this == SHA512) {
            digest = new SHA512Digest();
        } else if (this == MD5) {
            digest = new MD5Digest();
        } else {
            throw new RuntimeException("should not reach here");
        }
        byte[] ret = new byte[length];
        digest.doFinal(ret, 0);
        return ret;
    }

    public static HashAlgoType getHashAlgoType(
            String nameOrOid) {
        for (HashAlgoType hashAlgo : values()) {
            if (hashAlgo.oid.equals(nameOrOid)) {
                return hashAlgo;
            }

            if (nameOrOid.indexOf('-') != -1) {
                nameOrOid = nameOrOid.replace("-", "");
            }

            if (hashAlgo.name.equalsIgnoreCase(nameOrOid)) {
                return hashAlgo;
            }
        }

        return null;
    }

}
