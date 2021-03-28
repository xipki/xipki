/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ocsp.server.store;

import static org.xipki.util.Args.notNull;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ocsp.CrlID;
import org.xipki.util.Base64;
import org.xipki.util.ConfPairs;
import org.xipki.util.DateUtil;
import org.xipki.util.StringUtil;

/**
 * CRL information.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CrlInfo {

  public static final String BASE_CRL_NUMBER = "base-crl-number";

  public static final String CRL_ID = "crl-id";

  public static final String CRL_NUMBER = "crl-number";

  public static final String NEXT_UPDATE = "next-update";

  public static final String THIS_UPDATE = "this-update";

  private final BigInteger crlNumber;

  private BigInteger baseCrlNumber;

  private final Date thisUpdate;

  private final Date nextUpdate;

  private final CrlID crlId;

  private String encoded;

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
    initEncoded();
  } // constructor

  private static String getNotBlankValue(ConfPairs pairs, String name) {
    String str = pairs.value(name);
    if (StringUtil.isBlank(str)) {
      throw new IllegalArgumentException(name + " is not specified");
    }
    return str;
  }

  public CrlInfo(BigInteger crlNumber, BigInteger baseCrlNumber,
      Date thisUpdate, Date nextUpdate, CrlID crlId) {
    this.crlNumber = notNull(crlNumber, "crlNumber");
    this.baseCrlNumber = baseCrlNumber;
    this.thisUpdate = notNull(thisUpdate, "thisUpdate");
    this.nextUpdate = notNull(nextUpdate, "nextUpdate");
    this.crlId = notNull(crlId, "crlId");
    initEncoded();
  }

  private void initEncoded() {
    ConfPairs pairs = new ConfPairs();
    pairs.putPair(CRL_NUMBER, crlNumber.toString(16));
    if (baseCrlNumber != null) {
      pairs.putPair(BASE_CRL_NUMBER, baseCrlNumber.toString(16));
    }
    pairs.putPair(THIS_UPDATE, DateUtil.toUtcTimeyyyyMMddhhmmss(thisUpdate));
    pairs.putPair(NEXT_UPDATE, DateUtil.toUtcTimeyyyyMMddhhmmss(nextUpdate));
    byte[] encodedCrlId;
    try {
      encodedCrlId = crlId.getEncoded();
    } catch (IOException ex) {
      throw new IllegalArgumentException("error encoding CrlID");
    }
    pairs.putPair(CRL_ID, Base64.encodeToString(encodedCrlId));
    this.encoded = pairs.getEncoded();
  } // method initEncoded

  public String getEncoded() {
    return encoded;
  }

  public BigInteger getCrlNumber() {
    return crlNumber;
  }

  public BigInteger getBaseCrlNumber() {
    return baseCrlNumber;
  }

  public Date getThisUpdate() {
    return thisUpdate;
  }

  public Date getNextUpdate() {
    return nextUpdate;
  }

  public CrlID getCrlId() {
    return crlId;
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof CrlInfo)) {
      return false;
    }
    return ((CrlInfo) obj).encoded.equals(encoded);
  }

}
