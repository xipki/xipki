// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class ChallengeResponse implements JsonEncodable {

  private final ChallengeStatus status;

  private final String type;

  private final String url;

  private final String token;

  private final String validated;

  public ChallengeResponse(ChallengeStatus status, String type, String url,
                           String token, String validated) {
    this.status = status;
    this.type = type;
    this.url = url;
    this.token = token;
    this.validated = validated;
  }

  public String getType() {
    return type;
  }

  public String getUrl() {
    return url;
  }

  public String getToken() {
    return token;
  }

  public ChallengeStatus getStatus() {
    return status;
  }

  public String getValidated() {
    return validated;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEnum("status", status).put("type", type)
        .put("url", url).put("token", token).put("validated", validated);
  }

  public static ChallengeResponse parse(JsonMap json) throws CodecException {
    ChallengeStatus status = json.getEnum("status", ChallengeStatus.class);
    return new ChallengeResponse(status, json.getString("type"),
        json.getString("url"), json.getString("token"),
        json.getString("validated"));
  }

}
