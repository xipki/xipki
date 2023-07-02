package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.OrderResponse;
import org.xipki.ca.gateway.acme.type.Identifier;
import org.xipki.ca.gateway.acme.type.OrderStatus;

import java.time.Instant;

public class AcmeOrder {

  private OrderStatus status = OrderStatus.pending;

  private String certProfile;

  private String label;

  private AcmeAuthz[] authzs;

  private Instant notBefore;

  private Instant notAfter;

  private Instant expires;

  private byte[] csr;

  private byte[] cert;

  public OrderStatus getStatus() {
    return status;
  }

  public void setStatus(OrderStatus status) {
    this.status = status;
  }

  public String getCertProfile() {
    return certProfile;
  }

  public void setCertProfile(String certProfile) {
    this.certProfile = certProfile;
  }

  public byte[] getCert() {
    return cert;
  }

  public void setCert(byte[] cert) {
    this.cert = cert;
  }

  public String getLabel() {
    return label;
  }

  public void setLabel(String label) {
    this.label = label;
  }

  public Instant getExpires() {
    return expires;
  }

  public void setExpires(Instant expires) {
    this.expires = expires;
  }

  public byte[] getCsr() {
    return csr;
  }

  public void setCsr(byte[] csr) {
    this.csr = csr;
  }

  public AcmeAuthz[] getAuthzs() {
    return authzs;
  }

  public void setAuthzs(AcmeAuthz[] authzs) {
    this.authzs = authzs;
  }

  public Instant getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(Instant notBefore) {
    this.notBefore = notBefore;
  }

  public Instant getNotAfter() {
    return notAfter;
  }

  public void setNotAfter(Instant notAfter) {
    this.notAfter = notAfter;
  }

  public String getLocation(String baseUrl) {
    return baseUrl + "order/" + label;
  }

  public OrderResponse toResponse(String baseUrl) {
    OrderResponse resp = new OrderResponse();
    resp.setStatus(status);

    resp.setExpires(expires.toString());
    resp.setFinalize(baseUrl + "finalize/" + label);

    String[] authzUrls = new String[authzs.length];
    Identifier[] identifiers = new Identifier[authzs.length];
    for (int i = 0; i < authzs.length; i++) {
      authzUrls[i] = baseUrl + "authz/" + authzs[i].getLabel();
      identifiers[i] = authzs[i].getIdentifier();
    }
    resp.setAuthorizations(authzUrls);
    resp.setIdentifiers(identifiers);
    if (status == OrderStatus.valid) {
      resp.setCertificate(baseUrl + "cert/" + label);
    }
    return resp;
  }

  public AcmeAuthz getAuthz(String label) {
    for (AcmeAuthz authz : authzs) {
      if (authz.getLabel().equals(label)) {
        return authz;
      }
    }
    return null;
  }

}
