/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.pki.ocsp.server.impl;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ocsp.api.IssuerHashNameAndKey;
import org.xipki.security.api.CRLReason;
import org.xipki.security.api.CertRevocationInfo;
import org.xipki.security.api.HashAlgoType;

/**
 * @author Lijun Liao
 */

public class IssuerEntry {
    private final int id;
    private final Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap;
    private final Date notBefore;

    private CertRevocationInfo revocationInfo;

    public IssuerEntry(
            final int id,
            final Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap,
            final Date caNotBefore) {
        ParamUtil.assertNotEmpty("issuerHashMap", issuerHashMap);
        ParamUtil.assertNotNull("caNotBefore", caNotBefore);

        this.id = id;
        this.issuerHashMap = issuerHashMap;
        this.notBefore = caNotBefore;
    }

    public int getId() {
        return id;
    }

    public boolean matchHash(
            final HashAlgoType hashAlgo,
            final byte[] issuerNameHash,
            final byte[] issuerKeyHash) {
        IssuerHashNameAndKey issuerHash = issuerHashMap.get(hashAlgo);
        return (issuerHash == null)
                ? false
                : issuerHash.match(hashAlgo, issuerNameHash, issuerKeyHash);
    }

    public void setRevocationInfo(
            final Date revocationTime) {
        ParamUtil.assertNotNull("revocationTime", revocationTime);
        this.revocationInfo = new CertRevocationInfo(CRLReason.CA_COMPROMISE, revocationTime, null);
    }

    public CertRevocationInfo getRevocationInfo() {
        return revocationInfo;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    Collection<IssuerHashNameAndKey> getIssuerHashNameAndKeys() {
        return Collections.unmodifiableCollection(issuerHashMap.values());
    }
}
