// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.ChallengeResponse;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeChallenge {

  private String label;

  private ChallengeStatus status;

  private String type;

  private String token;

  private Instant validated;

  private String expectedAuthorization;

  public String getLabel() {
    return label;
  }

  public void setLabel(String label) {
    this.label = label;
  }

  public Instant getValidated() {
    return validated;
  }

  public void setValidated(Instant validated) {
    this.validated = validated;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getToken() {
    return token;
  }

  public void setToken(String token) {
    this.token = token;
  }

  public ChallengeStatus getStatus() {
    return status;
  }

  public void setStatus(ChallengeStatus status) {
    this.status = status;
  }

  public String getExpectedAuthorization() {
    return expectedAuthorization;
  }

  public void setExpectedAuthorization(String expectedAuthorization) {
    this.expectedAuthorization = expectedAuthorization;
  }

  public ChallengeResponse toChallengeResponse(String baseUrl) {
    ChallengeResponse resp = new ChallengeResponse();
    if (validated != null) {
      resp.setValidated(validated.truncatedTo(ChronoUnit.SECONDS).toString());
    }

    resp.setUrl(baseUrl + "chall/" + label);
    resp.setStatus(status);
    resp.setType(type);
    resp.setToken(token);
    return resp;
  }

}
