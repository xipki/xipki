/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
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

package org.xipki.ca.server.publisher;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * @author Lijun Liao
 */

class IssuerEntry
{
    private final int id;
    private final String subject;
    private final byte[] sha1Fp;
    private final byte[] cert;

    IssuerEntry(int id, String subject, String hexSha1Fp, String b64Cert)
    {
        super();
        this.id = id;
        this.subject = subject;
        this.sha1Fp = Hex.decode(hexSha1Fp);
        this.cert = Base64.decode(b64Cert);
    }

    int getId()
    {
        return id;
    }

    String getSubject()
    {
        return subject;
    }

    boolean matchSha1Fp(byte[] sha1Fp)
    {
        return Arrays.equals(this.sha1Fp, sha1Fp);
    }

    boolean matchCert(byte[] encodedCert)
    {
        return Arrays.equals(this.cert, encodedCert);
    }
}
