// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.AuthzResponse;
import org.xipki.ca.gateway.acme.msg.ChallengeResponse;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.extra.misc.CompareUtil;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeAuthz implements JsonEncodable {

  private final int subId;

  private final AcmeIdentifier identifier;

  private AuthzStatus status;

  private Instant expires;

  private List<AcmeChallenge> challenges;

  private AcmeOrder order;

  public AcmeAuthz(int subId, AcmeIdentifier identifier) {
    this.subId = subId;
    this.identifier = Args.notNull(identifier, "identifier");
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap().put("subId", subId)
        .put("identifier", identifier).putEnum("status", status)
        .put("expires", expires == null ? null : expires.getEpochSecond());

    if (challenges != null) {
      JsonList challMaps = new JsonList();
      for (AcmeChallenge m : challenges) {
        challMaps.add(m.toCodec());
      }
      ret.put("challenges", challMaps);
    }
    return ret;
  }

  public static AcmeAuthz parse(JsonMap json) throws CodecException {
    int subId = json.getNnInt("subId");

    AcmeIdentifier identifier = AcmeIdentifier.parse(
        json.getNnMap("identifier"));
    AuthzStatus status = json.getEnum("status", AuthzStatus.class);

    Long l = json.getLong("expires");
    Instant expires = (l == null) ? null : Instant.ofEpochSecond(l);

    JsonList challMaps = json.getList("challenges");

    AcmeAuthz authz = new AcmeAuthz(subId, identifier);
    List<AcmeChallenge> challenges = null;
    if (challMaps != null) {
      challenges = new ArrayList<>(challMaps.size());
      for (JsonMap m : challMaps.toMapList()) {
        AcmeChallenge chall = AcmeChallenge.parse(m);
        chall.setAuthz(authz);
        challenges.add(chall);
      }
    }

    authz.status = status;
    authz.expires = expires;
    authz.challenges = challenges;
    return authz;
  }

  public AcmeOrder getOrder() {
    return order;
  }

  public void setOrder(AcmeOrder order) {
    this.order = order;
  }

  public int getSubId() {
    return subId;
  }

  public AuthzStatus getStatus() {
    return status;
  }

  public void setStatus(AuthzStatus status) {
    markOrder();
    this.status = status;
  }

  public Instant getExpires() {
    return expires;
  }

  public void setExpires(Instant expires) {
    markOrder();
    this.expires = expires;
  }

  public AcmeIdentifier getIdentifier() {
    return identifier;
  }

  public List<AcmeChallenge> getChallenges() {
    return challenges;
  }

  public void setChallenges(List<AcmeChallenge> challenges) {
    markOrder();
    this.challenges = challenges;
    if (challenges != null) {
      for (AcmeChallenge chall : challenges) {
        chall.setAuthz(this);
      }
    }
  }

  void markOrder() {
    if (order != null) {
      order.markMe();
    }
  }

  public AuthzResponse toResponse(String baseUrl, long orderId) {
    List<ChallengeResponse> challResps = new ArrayList<>(challenges.size());
    for (AcmeChallenge chall : challenges) {
      challResps.add(chall.toChallengeResponse(baseUrl, orderId, subId));
    }
    return new AuthzResponse(status, expires.toString(),
        identifier.toIdentifier(), challResps);
  }

  public String getUrl(String baseUrl) {
    AuthzId authzId = new AuthzId(order.getId(), subId);
    return baseUrl + "authz/" + authzId.toIdText();
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof AcmeAuthz)) {
      return false;
    }

    AcmeAuthz b = (AcmeAuthz) other;
    return status == b.status && subId == b.subId
        && CompareUtil.equals(expires,    b.expires)
        && CompareUtil.equals(identifier, b.identifier)
        && CompareUtil.equals(challenges, b.challenges);
  }

  public AcmeAuthz copy() {
    AcmeAuthz copy = new AcmeAuthz(subId, identifier);
    copy.status  = status;
    copy.expires = expires;
    if (challenges != null) {
      copy.challenges = new ArrayList<>(challenges.size());
      for (AcmeChallenge chall : challenges) {
        copy.challenges.add(chall.copy());
      }
    }

    return copy;
  }

  public static String encodeAuthzs(List<AcmeAuthz> authzs)
      throws CodecException {
    JsonList maps = new JsonList();
    for (AcmeAuthz m : authzs) {
      maps.add(m.toCodec());
    }
    return JsonBuilder.toJson(maps);
  }

  public static List<AcmeAuthz> decodeAuthzs(String encoded)
      throws CodecException {
    JsonList list = JsonParser.parseList(encoded, false);
    List<AcmeAuthz> ret = new ArrayList<>(list.size());
    for (JsonMap map : list.toMapList()) {
      ret.add(AcmeAuthz.parse(map));
    }
    return ret;
  }

}
