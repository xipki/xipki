// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.AuthzResponse;
import org.xipki.ca.gateway.acme.msg.ChallengeResponse;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.util.AcmeUtils;
import org.xipki.util.CompareUtil;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeAuthz {

  private long id;

  private transient String idStr;

  private AuthzStatus status;
  private Instant expires;
  private AcmeIdentifier identifier;

  private List<AcmeChallenge> challenges;

  private transient AcmeOrder order;

  public void setOrder(AcmeOrder order) {
    this.order = order;
  }

  public long getId() {
    return id;
  }

  public void setId(long id) {
    markOrder();
    this.id = id;
    this.idStr = AcmeUtils.toBase64(id);
  }

  public String getIdStr() {
    return idStr;
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

  public void setIdentifier(AcmeIdentifier identifier) {
    markOrder();
    this.identifier = identifier;
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

  public AuthzResponse toResponse(String baseUrl) {
    AuthzResponse resp = new AuthzResponse();
    resp.setExpires(expires.toString());
    resp.setStatus(status);
    resp.setIdentifier(identifier.toIdentifier());
    List<ChallengeResponse> challResps = new ArrayList<>(challenges.size());
    resp.setChallenges(challResps);
    for (AcmeChallenge chall : challenges) {
      challResps.add(chall.toChallengeResponse(id, baseUrl));
    }
    return resp;
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof AcmeAuthz)) {
      return false;
    }

    AcmeAuthz b = (AcmeAuthz) other;
    return status == b.status && id == b.id
        && CompareUtil.equalsObject(expires, b.expires)
        && CompareUtil.equalsObject(identifier, b.identifier)
        && CompareUtil.equalsObject(challenges, b.challenges);
  }

  public AcmeAuthz copy() {
    AcmeAuthz copy = new AcmeAuthz();
    copy.id = id;
    copy.idStr = idStr;
    copy.status = status;
    copy.expires = expires;
    copy.identifier = identifier;
    if (challenges != null) {
      copy.challenges = new ArrayList<>(challenges.size());
      for (AcmeChallenge chall : challenges) {
        copy.challenges.add(chall.copy());
      }
    }
    return copy;
  }

}
