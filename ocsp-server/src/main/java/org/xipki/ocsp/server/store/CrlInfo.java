// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store;

import org.bouncycastle.asn1.ocsp.CrlID;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;

/**
 * CRL information.
 *
 * @author Lijun Liao (xipki)
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

  private final Instant thisUpdate;

  private final Instant nextUpdate;

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
                 Instant thisUpdate, Instant nextUpdate, CrlID crlId) {
    this.crlNumber = Args.notNull(crlNumber, "crlNumber");
    this.baseCrlNumber = baseCrlNumber;
    this.thisUpdate = Args.notNull(thisUpdate, "thisUpdate");
    this.nextUpdate = Args.notNull(nextUpdate, "nextUpdate");
    this.crlId = Args.notNull(crlId, "crlId");
    initEncoded();
  }

  private void initEncoded() {
    ConfPairs pairs = new ConfPairs()
        .putPair(CRL_NUMBER, crlNumber.toString(16))
        .putPair(THIS_UPDATE, DateUtil.toUtcTimeyyyyMMddhhmmss(thisUpdate))
        .putPair(NEXT_UPDATE, DateUtil.toUtcTimeyyyyMMddhhmmss(nextUpdate));
    if (baseCrlNumber != null) {
      pairs.putPair(BASE_CRL_NUMBER, baseCrlNumber.toString(16));
    }

    byte[] encodedCrlId;
    try {
      encodedCrlId = crlId.getEncoded();
    } catch (IOException ex) {
      throw new IllegalArgumentException("error encoding CrlID");
    }
    pairs.putPair(CRL_ID, Base64.getEncoder().encodeToString(encodedCrlId));
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

  public Instant getThisUpdate() {
    return thisUpdate;
  }

  public Instant getNextUpdate() {
    return nextUpdate;
  }

  public CrlID getCrlId() {
    return crlId;
  }

  @Override
  public int hashCode() {
    return encoded.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof CrlInfo)) {
      return false;
    }
    return ((CrlInfo) obj).encoded.equals(encoded);
  }

}
