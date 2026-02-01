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
public class JoseMessage implements JsonEncodable {

  private final String protected_;

  private final String payload;

  private final String signature;

  public JoseMessage(String protected_, String payload, String signature) {
    this.protected_ = protected_;
    this.payload = payload;
    this.signature = signature;
  }

  public String getProtected() {
    return protected_;
  }

  public String payload() {
    return payload;
  }

  public String signature() {
    return signature;
  }

  public JoseMessage copy() {
    return new JoseMessage(protected_, payload, signature);
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("protected", protected_)
        .put("payload", payload).put("signature", signature);
  }

  public static JoseMessage parse(JsonMap json) throws CodecException {
    return new JoseMessage(json.getString("protected"),
        json.getString("payload"), json.getString("signature"));
  }

}
