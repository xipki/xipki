// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.ChallengeResponse;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CompareUtil;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeChallenge implements JsonEncodable {

  private final int subId;

  private final String expectedAuthorization;

  private final String type;

  private final String token;

  private Instant validated;

  private ChallengeStatus status;

  private AcmeAuthz authz;

  public AcmeChallenge(String type, int subId, String token,
                       String expectedAuthorization, ChallengeStatus status) {
    this.subId = subId;
    this.expectedAuthorization = Args.notBlank(expectedAuthorization,
        "expectedAuthorization");
    this.type = Args.notBlank(type, "type");
    this.token = Args.notBlank(token, "token");
    this.status = Args.notNull(status, "status");
  }

  @Override
  public JsonMap toCodec() {
    Long validatedSec = validated == null ? null : validated.getEpochSecond();
    return new JsonMap()
        .put("subId", subId)
        .put("type", type)
        .put("token", token)
        .put("expectedAuthorization", expectedAuthorization)
        .put("status", status.name())
        .put("validated", validatedSec);
  }

  public static AcmeChallenge parse(JsonMap json) throws CodecException {
    int subId = json.getNnInt("subId");
    String type = json.getNnString("type");
    String token = json.getNnString("token");
    String expectedAuthorization = json.getNnString("expectedAuthorization");
    ChallengeStatus status =
        ChallengeStatus.valueOf(json.getNnString("status"));

    AcmeChallenge chall = new AcmeChallenge(type, subId, token,
        expectedAuthorization, status);
    Long l = json.getLong("validated");
    if (l != null) {
      chall.validated = Instant.ofEpochSecond(l);
    }
    return chall;
  }

  public AcmeAuthz authz() {
    return authz;
  }

  public void setAuthz(AcmeAuthz authz) {
    this.authz = authz;
  }

  public int subId() {
    return subId;
  }

  public Instant validated() {
    return validated;
  }

  public void setValidated(Instant validated) {
    markOrder();
    this.validated = validated;
  }

  public String type() {
    return type;
  }

  public String token() {
    return token;
  }

  public ChallengeStatus status() {
    return status;
  }

  public void setStatus(ChallengeStatus status) {
    markOrder();
    this.status = status;
  }

  public String expectedAuthorization() {
    return expectedAuthorization;
  }

  private void markOrder() {
    if (authz != null) {
      authz.markOrder();
    }
  }

  public ChallengeResponse toChallengeResponse(
      String baseUrl, long orderId, int authzId) {
    ChallId challId = new ChallId(orderId, authzId, subId);
    String url = baseUrl + "chall/" + challId.toIdText();

    String validatedStr = null;
    if (validated != null) {
      validatedStr = validated.truncatedTo(ChronoUnit.SECONDS).toString();
    }

    return new ChallengeResponse(status, type, url, token, validatedStr);
  }

  public AcmeChallenge copy() {
    AcmeChallenge copy = new AcmeChallenge(type, subId, token,
        expectedAuthorization, status);
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
        && CompareUtil.equals(type, b.type)
        && CompareUtil.equals(token, b.token)
        && CompareUtil.equals(validated, b.validated)
        && CompareUtil.equals(expectedAuthorization, b.expectedAuthorization);
  }

}
