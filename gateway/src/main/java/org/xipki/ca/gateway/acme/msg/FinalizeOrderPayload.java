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
public class FinalizeOrderPayload implements JsonEncodable {

  private final String csr;

  public FinalizeOrderPayload(String csr) {
    this.csr = csr;
  }

  public String getCsr() {
    return csr;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("csr", csr);
  }

  public static FinalizeOrderPayload parse(JsonMap json)
      throws CodecException {
    return new FinalizeOrderPayload(json.getString("csr"));
  }

}
