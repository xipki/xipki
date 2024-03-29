// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.Identifier;
import org.xipki.ca.gateway.acme.type.OrderStatus;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class OrderResponse {

  private OrderStatus status;
  private String expires;
  private String notBefore;
  private String notAfter;
  private List<Identifier> identifiers;
  private List<String> authorizations;
  private String finalize;

  private String certificate;

  public OrderStatus getStatus() {
    return status;
  }

  public void setStatus(OrderStatus status) {
    this.status = status;
  }

  public String getExpires() {
    return expires;
  }

  public void setExpires(String expires) {
    this.expires = expires;
  }

  public String getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(String notBefore) {
    this.notBefore = notBefore;
  }

  public String getNotAfter() {
    return notAfter;
  }

  public void setNotAfter(String notAfter) {
    this.notAfter = notAfter;
  }

  public List<Identifier> getIdentifiers() {
    return identifiers;
  }

  public void setIdentifiers(List<Identifier> identifiers) {
    this.identifiers = identifiers;
  }

  public List<String> getAuthorizations() {
    return authorizations;
  }

  public void setAuthorizations(List<String> authorizations) {
    this.authorizations = authorizations;
  }

  public String getFinalize() {
    return finalize;
  }

  public void setFinalize(String finalize) {
    this.finalize = finalize;
  }

  public String getCertificate() {
    return certificate;
  }

  public void setCertificate(String certificate) {
    this.certificate = certificate;
  }
}
