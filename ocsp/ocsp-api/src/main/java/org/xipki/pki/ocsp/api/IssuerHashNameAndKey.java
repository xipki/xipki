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

package org.xipki.pki.ocsp.api;

import java.util.Arrays;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IssuerHashNameAndKey {

    private final HashAlgoType algo;

    private final byte[] issuerNameHash;

    private final byte[] issuerKeyHash;

    public IssuerHashNameAndKey(
            final HashAlgoType algo,
            final byte[] issuerNameHash,
            final byte[] issuerKeyHash) {
        ParamUtil.assertNotNull("algo", algo);

        int len = algo.getLength();
        if (issuerNameHash == null || issuerNameHash.length != len) {
            throw new IllegalArgumentException("issuerNameash is invalid");
        }

        if (issuerKeyHash == null || issuerKeyHash.length != len) {
            throw new IllegalArgumentException("issuerKeyHash is invalid");
        }

        this.algo = algo;
        this.issuerNameHash = Arrays.copyOf(issuerNameHash, len);
        this.issuerKeyHash = Arrays.copyOf(issuerKeyHash, len);
    }

    public boolean match(
            final HashAlgoType pAlgo,
            final byte[] pIssuerNameHash,
            final byte[] pIssuerKeyHash) {
        return this.algo == pAlgo
                && Arrays.equals(this.issuerNameHash, pIssuerNameHash)
                && Arrays.equals(this.issuerKeyHash, pIssuerKeyHash);
    }

}
