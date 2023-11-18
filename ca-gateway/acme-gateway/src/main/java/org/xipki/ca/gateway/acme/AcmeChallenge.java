// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.ChallengeResponse;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeChallenge {

  private final int subId;

  private final String expectedAuthorization;

  private final String type;

  private final String token;

  private Instant validated;

  private ChallengeStatus status;

  private AcmeAuthz authz;

  public AcmeChallenge(String type, int subId, String token, String expectedAuthorization, ChallengeStatus status) {
    this.subId = subId;
    this.expectedAuthorization = Args.notBlank(expectedAuthorization, "expectedAuthorization");
    this.type = Args.notBlank(type, "type");
    this.token = Args.notBlank(token, "token");
    this.status = Args.notNull(status, "status");
  }

  public Map<String, Object> encode() {
    Map<String, Object> map = new HashMap<>();
    map.put("subId", subId);
    map.put("type", type);
    map.put("token", token);
    map.put("expectedAuthorization", expectedAuthorization);
    map.put("status", status.name());
    if (validated != null) {
      map.put("validated", validated.getEpochSecond());
    }
    return map;
  }

  public static AcmeChallenge decode(Map<String, Object> encoded) {
    int subId = AcmeUtils.getInt(encoded, "subId");
    String type = (String) encoded.get("type");
    String token = (String) encoded.get("token");
    String expectedAuthorization = (String) encoded.get("expectedAuthorization");
    ChallengeStatus status = ChallengeStatus.valueOf((String) encoded.get("status"));

    AcmeChallenge chall = new AcmeChallenge(type, subId, token, expectedAuthorization, status);
    Long l = AcmeUtils.getLong(encoded, "validated");
    if (l != null) {
      chall.validated = Instant.ofEpochSecond(l);
    }
    return chall;
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

  public String getToken() {
    return token;
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
    AcmeChallenge copy = new AcmeChallenge(type, subId, token, expectedAuthorization, status);
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
