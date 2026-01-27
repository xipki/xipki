// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.Identifier;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AuthzResponse implements JsonEncodable {

  private final AuthzStatus status;

  private final String expires;

  private final Identifier identifier;

  private final List<ChallengeResponse> challenges;

  public AuthzResponse(
      AuthzStatus status, String expires, Identifier identifier,
      List<ChallengeResponse> challenges) {
    this.status = status;
    this.expires = expires;
    this.identifier = identifier;
    this.challenges = challenges;
  }

  public AuthzStatus getStatus() {
    return status;
  }

  public String getExpires() {
    return expires;
  }

  public Identifier getIdentifier() {
    return identifier;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEnum("status", status).put("expires", expires)
        .put("identifier", identifier).putEncodables("challenges", challenges);
  }

  public static AuthzResponse parse(JsonMap json) throws CodecException {
    AuthzStatus status = json.getEnum("status", AuthzStatus.class);

    JsonMap map = json.getMap("identifier");
    Identifier identifier = (map == null) ? null : Identifier.parse(map);

    JsonList list = json.getList("challenges");
    List<ChallengeResponse> challenges = null;
    if (list != null) {
      challenges = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        challenges.add(ChallengeResponse.parse(v));
      }
    }

    return new AuthzResponse(status, json.getString("expires"),
        identifier, challenges);
  }

}
