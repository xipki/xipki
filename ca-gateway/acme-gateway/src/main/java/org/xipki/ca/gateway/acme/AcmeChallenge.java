// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.ChallengeResponse;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.ca.gateway.acme.util.AcmeUtils;
import org.xipki.util.CompareUtil;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeChallenge {

  private int subId;

  private ChallengeStatus status;

  private String type;

  private String token;

  private Instant validated;

  private String expectedAuthorization;

  private transient AcmeAuthz authz;

  public void setAuthz(AcmeAuthz authz) {
    this.authz = authz;
  }

  public int getSubId() {
    return subId;
  }

  public void setSubId(int subId) {
    markOrder();
    this.subId = subId;
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

  public void setExpectedAuthorization(String expectedAuthorization) {
    markOrder();
    this.expectedAuthorization = expectedAuthorization;
  }

  private void markOrder() {
    if (authz != null) {
      authz.markOrder();
    }
  }

  public ChallengeResponse toChallengeResponse(long authzId, String baseUrl) {
    ChallengeResponse resp = new ChallengeResponse();
    if (validated != null) {
      resp.setValidated(validated.truncatedTo(ChronoUnit.SECONDS).toString());
    }

    resp.setUrl(baseUrl + "chall/" + AcmeUtils.toBase64(authzId) + "/" + AcmeUtils.toBase64(subId));
    resp.setStatus(status);
    resp.setType(type);
    resp.setToken(token);
    return resp;
  }

  public AcmeChallenge copy() {
    AcmeChallenge copy = new AcmeChallenge();
    copy.subId = subId;
    copy.status = status;
    copy.type = type;
    copy.token = token;
    copy.validated = validated;
    copy.expectedAuthorization = expectedAuthorization;
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
