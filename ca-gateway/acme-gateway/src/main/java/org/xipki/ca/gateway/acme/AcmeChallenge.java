// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.ChallengeResponse;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.util.CompareUtil;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeChallenge {

  private final int subId;

  private final String expectedAuthorization;

  private ChallengeStatus status;

  private String type;

  private String token;

  private Instant validated;

  private transient AcmeAuthz authz;

  public AcmeChallenge(int subId, String expectedAuthorization) {
    this.subId = subId;
    this.expectedAuthorization = expectedAuthorization;
  }

  public AcmeAuthz getAuthz() {
    return authz;
  }

  public void setAuthz(AcmeAuthz authz) {
    this.authz = authz;
  }

  public int getSubId() {
    return subId;
  }

  public Instant getValidated() {
    return validated;
  }

  public void setValidated(Instant validated) {
    markOrder();
    this.validated = validated;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    markOrder();
    this.type = type;
  }

  public String getToken() {
    return token;
  }

  public void setToken(String token) {
    markOrder();
    this.token = token;
  }

  public ChallengeStatus getStatus() {
    return status;
  }

  public void setStatus(ChallengeStatus status) {
    markOrder();
    this.status = status;
  }

  public String getExpectedAuthorization() {
    return expectedAuthorization;
  }

  private void markOrder() {
    if (authz != null) {
      authz.markOrder();
    }
  }

  public ChallengeResponse toChallengeResponse(String baseUrl, long orderId, int authzId) {
    ChallengeResponse resp = new ChallengeResponse();
    if (validated != null) {
      resp.setValidated(validated.truncatedTo(ChronoUnit.SECONDS).toString());
    }

    ChallId challId = new ChallId(orderId, authzId, subId);
    resp.setUrl(baseUrl + "chall/" + challId.toIdText());
    resp.setStatus(status);
    resp.setType(type);
    resp.setToken(token);
    return resp;
  }

  public AcmeChallenge copy() {
    AcmeChallenge copy = new AcmeChallenge(subId, expectedAuthorization);
    copy.status = status;
    copy.type = type;
    copy.token = token;
    copy.validated = validated;
    return copy;
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof AcmeChallenge)) {
      return false;
    }

    AcmeChallenge b = (AcmeChallenge) obj;
    return subId == b.subId && status == b.status
        && CompareUtil.equalsObject(type, b.type)
        && CompareUtil.equalsObject(token, b.token)
        && CompareUtil.equalsObject(validated, b.validated)
        && CompareUtil.equalsObject(expectedAuthorization, b.expectedAuthorization);
  }

}
