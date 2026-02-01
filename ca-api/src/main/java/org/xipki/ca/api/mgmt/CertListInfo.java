// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Certificate list container.
 *
 * @author Lijun Liao (xipki)
 */

public class CertListInfo implements JsonEncodable {

  private final BigInteger serialNumber;

  private final Instant notBefore;

  private final Instant notAfter;

  private final String subject;

  public CertListInfo(BigInteger serialNumber, String subject,
                      Instant notBefore, Instant notAfter) {
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.notBefore = Args.notNull(notBefore, "notBefore");
    this.notAfter  = Args.notNull(notAfter, "notAfter");
    this.subject   = Args.notNull(subject, "subject");
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

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    ret.put("serialNumber", serialNumber);
    ret.put("notBefore", notBefore);
    ret.put("notAfter", notAfter);
    ret.put("subject", subject);
    return ret;
  }

  public static CertListInfo parse(JsonMap json) throws CodecException {
    return new CertListInfo(json.getNnBigInteger("serialNumber"),
        json.getNnString("subject"),
        json.getNnInstant("notBefore"),
        json.getNnInstant("notAfter"));
  }
}
