// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.security.pkix.CertRevocationInfo;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Cert List Info information.
 *
 * @author Lijun Liao (xipki)
 */

public class CertListInfo implements JsonEncodable {

  private final BigInteger serialNumber;

  private final Instant notBefore;

  private final Instant notAfter;

  private final String subject;

  private final CertRevocationInfo revocationInfo;

  public CertListInfo(BigInteger serialNumber, String subject, Instant notBefore,
                      Instant notAfter, CertRevocationInfo revocationInfo) {
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.notBefore = Args.notNull(notBefore, "notBefore");
    this.notAfter  = Args.notNull(notAfter, "notAfter");
    this.subject   = Args.notNull(subject, "subject");
    this.revocationInfo = revocationInfo;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public Instant notBefore() {
    return notBefore;
  }

  public Instant notAfter() {
    return notAfter;
  }

  public String subject() {
    return subject;
  }

  public CertRevocationInfo getRevocationInfo() {
    return revocationInfo;
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    ret.put("serialNumber", serialNumber);
    ret.put("notBefore", notBefore);
    ret.put("notAfter", notAfter);
    ret.put("subject", subject);
    if (revocationInfo != null) {
      ret.put("revocationInfo", revocationInfo);
    }
    return ret;
  }

  public static CertListInfo parse(JsonMap json) throws CodecException {
    BigInteger sn = json.getNnBigInteger("serialNumber");
    String subject = json.getNnString("subject");
    Instant notBefore = json.getNnInstant("notBefore");
    Instant notAfter = json.getNnInstant("notAfter");
    JsonMap m = json.getMap("revocationInfo");
    CertRevocationInfo revInfo = null;
    if (m != null) {
      revInfo = CertRevocationInfo.parse(m);
    }

    return new CertListInfo(sn, subject, notBefore, notAfter, revInfo);
  }

}
