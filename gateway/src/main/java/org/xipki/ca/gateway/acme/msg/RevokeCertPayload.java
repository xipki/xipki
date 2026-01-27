// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class RevokeCertPayload implements JsonEncodable {

  private final Integer reason;

  private final String certificate;

  public RevokeCertPayload(Integer reason, String certificate) {
    this.reason = reason;
    this.certificate = certificate;
  }

  public Integer getReason() {
    return reason;
  }

  public String getCertificate() {
    return certificate;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("reason", reason).put("certificate", certificate);
  }

  public static RevokeCertPayload parse(JsonMap json) throws CodecException {
    return new RevokeCertPayload(json.getInt("reason"),
        json.getString("certificate"));
  }

}
