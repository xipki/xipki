package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.ChallengeStatus;

public class ChallengeResponse {

  private ChallengeStatus status;

  private String type;

  private String url;

  private String token;

  private String validated;

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url;
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

  public String getValidated() {
    return validated;
  }

  public void setValidated(String validated) {
    this.validated = validated;
  }
}
