/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ocsp.server.impl.store.db;

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
