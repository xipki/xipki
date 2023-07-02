package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.AuthzResponse;
import org.xipki.ca.gateway.acme.msg.ChallengeResponse;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.Identifier;

import java.time.Instant;

public class AcmeAuthz {

  private String label;

  private AuthzStatus status;
  private Instant expires;
  private Identifier identifier;

  private AcmeChallenge[] challenges;

  public String getLabel() {
    return label;
  }

  public void setLabel(String label) {
    this.label = label;
  }

  public AuthzStatus getStatus() {
    return status;
  }

  public void setStatus(AuthzStatus status) {
    this.status = status;
  }

  public Instant getExpires() {
    return expires;
  }

  public void setExpires(Instant expires) {
    this.expires = expires;
  }

  public Identifier getIdentifier() {
    return identifier;
  }

  public void setIdentifier(Identifier identifier) {
    this.identifier = identifier;
  }

  public AcmeChallenge[] getChallenges() {
    return challenges;
  }

  public void setChallenges(AcmeChallenge[] challenges) {
    this.challenges = challenges;
  }

  public AuthzResponse toResponse(String baseUrl) {
    AuthzResponse resp = new AuthzResponse();
    resp.setExpires(expires.toString());
    resp.setStatus(status);
    resp.setIdentifier(identifier);
    ChallengeResponse[] challResps = new ChallengeResponse[challenges.length];
    resp.setChallenges(challResps);
    for (int i = 0; i < challenges.length; i++) {
      challResps[i] = challenges[i].toChallengeResponse(baseUrl);
    }
    return resp;
  }

}
