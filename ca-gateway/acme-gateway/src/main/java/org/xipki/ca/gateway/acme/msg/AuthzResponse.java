package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.Identifier;

public class AuthzResponse {

  private AuthzStatus status;
  private String expires;
  private Identifier identifier;

  private ChallengeResponse[] challenges;

  public AuthzStatus getStatus() {
    return status;
  }

  public void setStatus(AuthzStatus status) {
    this.status = status;
  }

  public String getExpires() {
    return expires;
  }

  public void setExpires(String expires) {
    this.expires = expires;
  }

  public Identifier getIdentifier() {
    return identifier;
  }

  public void setIdentifier(Identifier identifier) {
    this.identifier = identifier;
  }

  public ChallengeResponse[] getChallenges() {
    return challenges;
  }

  public void setChallenges(ChallengeResponse[] challenges) {
    this.challenges = challenges;
  }
}
