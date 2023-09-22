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

  private int subId;

  private String expectedAuthorization;

  private ChallengeStatus status;

  private String type;

  private String token;

  private Instant validated;

  private AcmeAuthz authz;

  private AcmeChallenge() {
  }

  public AcmeChallenge(int subId, String expectedAuthorization) {
    this.subId = subId;
    this.expectedAuthorization = expectedAuthorization;
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
  public void setExpectedAuthorization(String expectedAuthorization) {
    this.expectedAuthorization = expectedAuthorization;
  }

  public AcmeAuthz authz() {
    return authz;
  }

  public void authz(AcmeAuthz authz) {
    this.authz = authz;
  }

  public int getSubId() {
    return subId;
  }

  public Instant getValidated() {
    return validated;
  }

  /**
   * Do not use this method. Only for JSON deserializer.
   */
  @Deprecated
  public void setValidated(Instant validated) {
    this.validated = validated;
  }

  public void validated(Instant validated) {
    markOrder();
    setValidated(validated);
  }

  public String getType() {
    return type;
  }

  /**
   * Do not use this method. Only for JSON deserializer.
   */
  @Deprecated
  public void setType(String type) {
    this.type = type;
  }

  public void type(String type) {
    markOrder();
    setType(type);
  }

  public String getToken() {
    return token;
  }

  /**
   * Do not use this method. Only for JSON deserializer.
   */
  @Deprecated
  public void setToken(String token) {
    this.token = token;
  }

  public void token(String token) {
    markOrder();
    setToken(token);
  }

  public ChallengeStatus getStatus() {
    return status;
  }

  /**
   * Do not use this method. Only for JSON deserializer.
   */
  @Deprecated
  public void setStatus(ChallengeStatus status) {
    this.status = status;
  }

  public void status(ChallengeStatus status) {
    markOrder();
    setStatus(status);
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
