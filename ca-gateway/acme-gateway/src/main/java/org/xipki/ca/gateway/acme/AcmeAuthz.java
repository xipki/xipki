// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.AuthzResponse;
import org.xipki.ca.gateway.acme.msg.ChallengeResponse;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeAuthz {

  private int subId;

  private AcmeIdentifier identifier;

  private AuthzStatus status;
  private Instant expires;

  private List<AcmeChallenge> challenges;

  private AcmeOrder order;

  private AcmeAuthz() {
  }

  public AcmeAuthz(int subId, AcmeIdentifier identifier) {
    this.subId = Args.notNull(subId, "subId");
    this.identifier = Args.notNull(identifier, "identifier");
  }

  /**
   * Do not use this method. Only for JSON deserializer.
   */
  @Deprecated
  public void setSubId(int subId) {
    this.subId = subId;
  }

  /**
   * Do not use this method. Only for JSON deserializer.
   */
  @Deprecated
  public void setIdentifier(AcmeIdentifier identifier) {
    this.identifier = identifier;
  }

  public AcmeOrder order() {
    return order;
  }

  public void order(AcmeOrder order) {
    this.order = order;
  }

  public int getSubId() {
    return subId;
  }

  public AuthzStatus getStatus() {
    return status;
  }

  /**
   * Do not use this method. Only for JSON deserializer.
   */
  @Deprecated
  public void setStatus(AuthzStatus status) {
    this.status = status;
  }

  public void status(AuthzStatus status) {
    markOrder();
    setStatus(status);
  }

  public Instant getExpires() {
    return expires;
  }

  /**
   * Do not use this method. Only for JSON deserializer.
   */
  @Deprecated
  public void setExpires(Instant expires) {
    this.expires = expires;
  }

  public void expires(Instant expires) {
    markOrder();
    setExpires(expires);
  }

  public AcmeIdentifier getIdentifier() {
    return identifier;
  }

  public List<AcmeChallenge> getChallenges() {
    return challenges;
  }

  /**
   * Do not use this method. Only for JSON deserializer.
   */
  @Deprecated
  public void setChallenges(List<AcmeChallenge> challenges) {
    this.challenges = challenges;
    if (challenges != null) {
      for (AcmeChallenge chall : challenges) {
        chall.authz(this);
      }
    }
  }

  public void challenges(List<AcmeChallenge> challenges) {
    markOrder();
    setChallenges(challenges);
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

}
