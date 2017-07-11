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

package org.xipki.pki.ocsp.server.impl.store.db;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ocsp.CrlID;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.Base64;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CrlInfo {

    public static final String BASE_CRL_NUMBER = "base-crl-number";

    public static final String CRL_ID = "crl-id";

    public static final String CRL_NUMBER = "crl-number";

    public static final String NEXT_UPDATE = "next-update";

    public static final String THIS_UPDATE = "this-update";

    public static final String USE_CRL_UPDATES = "use-crl-updates";

    private BigInteger crlNumber;

    private BigInteger baseCrlNumber;

    private Date thisUpdate;

    private Date nextUpdate;

    private boolean useCrlUpdates;

    private CrlID crlId;

    public CrlInfo(String conf) {
        ConfPairs pairs = new ConfPairs(conf);
        String str = getNotBlankValue(pairs, CRL_NUMBER);
        this.crlNumber = new BigInteger(str, 16);

        str = pairs.value(BASE_CRL_NUMBER);
        if (StringUtil.isNotBlank(str)) {
            this.baseCrlNumber = new BigInteger(str, 16);
        }

        str = getNotBlankValue(pairs, THIS_UPDATE);
        this.thisUpdate = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);

        str = getNotBlankValue(pairs, NEXT_UPDATE);
        this.nextUpdate = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);

        str = getNotBlankValue(pairs, CRL_ID);
        this.crlId = CrlID.getInstance(Base64.decodeFast(str));

        str = getNotBlankValue(pairs, USE_CRL_UPDATES);
        this.useCrlUpdates = Boolean.parseBoolean(str);
    }

    private static final String getNotBlankValue(ConfPairs pairs, String name) {
        String str = pairs.value(name);
        if (StringUtil.isBlank(str)) {
            throw new IllegalArgumentException(name + " is not specified");
        }
        return str;
    }

    public CrlInfo(BigInteger crlNumber, BigInteger baseCrlNumber, boolean useCrlUpdate,
            Date thisUpdate, Date nextUpdate, CrlID crlId) {
        this.crlNumber = ParamUtil.requireNonNull("crlNumber", crlNumber);
        this.baseCrlNumber = baseCrlNumber;
        this.useCrlUpdates = useCrlUpdate;
        this.thisUpdate = ParamUtil.requireNonNull("thisUpdate", thisUpdate);
        this.nextUpdate = ParamUtil.requireNonNull("nextUpdate", nextUpdate);
        this.crlId = ParamUtil.requireNonNull("crlId", crlId);
    }

    public String getEncoded() throws IOException {
        ConfPairs pairs = new ConfPairs();
        pairs.putPair(CRL_NUMBER, crlNumber.toString(16));
        if (baseCrlNumber != null) {
            pairs.putPair(BASE_CRL_NUMBER, baseCrlNumber.toString(16));
        }
        pairs.putPair(USE_CRL_UPDATES, Boolean.toString(useCrlUpdates));
        pairs.putPair(THIS_UPDATE, DateUtil.toUtcTimeyyyyMMddhhmmss(thisUpdate));
        pairs.putPair(NEXT_UPDATE, DateUtil.toUtcTimeyyyyMMddhhmmss(nextUpdate));
        pairs.putPair(CRL_ID, Base64.encodeToString(crlId.getEncoded()));
        return pairs.getEncoded();
    }

    public BigInteger crlNumber() {
        return crlNumber;
    }

    public void setCrlNumber(BigInteger crlNumber) {
        this.crlNumber = ParamUtil.requireNonNull("crlNumber", crlNumber);
    }

    public BigInteger baseCrlNumber() {
        return baseCrlNumber;
    }

    public void setBaseCrlNumber(BigInteger baseCrlNumber) {
        this.baseCrlNumber = baseCrlNumber;
    }

    public Date thisUpdate() {
        return thisUpdate;
    }

    public void setThisUpdate(Date thisUpdate) {
        this.thisUpdate = ParamUtil.requireNonNull("thisUpdate", thisUpdate);
    }

    public Date nextUpdate() {
        return nextUpdate;
    }

    public void setNextUpdate(Date nextUpdate) {
        this.nextUpdate = ParamUtil.requireNonNull("nextUpdate", nextUpdate);
    }

    public boolean isUseCrlUpdates() {
        return useCrlUpdates;
    }

    public void setUseCrlUpdates(boolean useCrlUpdates) {
        this.useCrlUpdates = useCrlUpdates;
    }

    public CrlID crlId() {
        return crlId;
    }

    public void setCrlId(CrlID crlId) {
        this.crlId = crlId;
    }

}
