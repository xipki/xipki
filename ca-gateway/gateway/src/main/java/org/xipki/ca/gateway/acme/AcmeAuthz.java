// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.AuthzResponse;
import org.xipki.ca.gateway.acme.msg.ChallengeResponse;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;
import org.xipki.util.JSON;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeAuthz {

  private final int subId;

  private final AcmeIdentifier identifier;

  private AuthzStatus status;
  private Instant expires;

  private List<AcmeChallenge> challenges;

  private AcmeOrder order;

  public AcmeAuthz(int subId, AcmeIdentifier identifier) {
    this.subId = Args.notNull(subId, "subId");
    this.identifier = Args.notNull(identifier, "identifier");
  }

  public Map<String, Object> encode() {
    Map<String, Object> map = new HashMap<>();
    map.put("subId", subId);
    map.put("identifier", identifier.encode());
    if (status != null) {
      map.put("status", status.name());
    }
    if (expires != null) {
      map.put("expires", expires.getEpochSecond());
    }

    if (challenges != null) {
      List<Map<String, Object>> challMaps = new ArrayList<>(challenges.size());
      for (AcmeChallenge m : challenges) {
        challMaps.add(m.encode());
      }
      map.put("challenges", challMaps);
    }
    return map;
  }

  public static AcmeAuthz decode(Map<String, Object> encoded) {
    int subId = AcmeUtils.getInt(encoded, "subId");
    AcmeIdentifier identifier = AcmeIdentifier.decode((Map<String, Object>) encoded.get("identifier"));
    String str = (String) encoded.get("status");
    AuthzStatus status = (str == null) ? null : AuthzStatus.valueOf(str);
    Long l = AcmeUtils.getLong(encoded, "expires");
    Instant expires = (l == null) ? null : Instant.ofEpochSecond(l);
    List<Map<String, Object>> challMaps = (List<Map<String, Object>>) encoded.get("challenges");

    AcmeAuthz authz = new AcmeAuthz(subId, identifier);
    List<AcmeChallenge> challenges = null;
    if (challMaps != null) {
      challenges = new ArrayList<>(challMaps.size());
      for (Map<String, Object> m : challMaps) {
        AcmeChallenge chall = AcmeChallenge.decode(m);
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
    AuthzResponse resp = new AuthzResponse();
    resp.setExpires(expires.toString());
    resp.setStatus(status);
    resp.setIdentifier(identifier.toIdentifier());
    List<ChallengeResponse> challResps = new ArrayList<>(challenges.size());
    resp.setChallenges(challResps);
    for (AcmeChallenge chall : challenges) {
      challResps.add(chall.toChallengeResponse(baseUrl, orderId, subId));
    }
    return resp;
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
        && CompareUtil.equalsObject(expires, b.expires)
        && CompareUtil.equalsObject(identifier, b.identifier)
        && CompareUtil.equalsObject(challenges, b.challenges);
  }

  public AcmeAuthz copy() {
    AcmeAuthz copy = new AcmeAuthz(subId, identifier);
    copy.status = status;
    copy.expires = expires;
    if (challenges != null) {
      copy.challenges = new ArrayList<>(challenges.size());
      for (AcmeChallenge chall : challenges) {
        copy.challenges.add(chall.copy());
      }
    }

    return copy;
  }

  public static String encodeAuthzs(List<AcmeAuthz> authzs) {
    List<Map<String, Object>> maps = new ArrayList<>(authzs.size());
    for (AcmeAuthz m : authzs) {
      maps.add(m.encode());
    }
    return JSON.toJson(maps);
  }

  public static List<AcmeAuthz> decodeAuthzs(String encoded) {
    List<Map<String, Object>> list = JSON.parseObject(encoded, List.class);
    List<AcmeAuthz> ret = new ArrayList<>(list.size());
    for (Map<String, Object> map : list) {
      ret.add(AcmeAuthz.decode(map));
    }
    return ret;
  }

}
