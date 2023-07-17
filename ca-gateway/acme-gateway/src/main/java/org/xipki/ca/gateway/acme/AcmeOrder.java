// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.OrderResponse;
import org.xipki.ca.gateway.acme.type.*;
import org.xipki.ca.gateway.acme.util.AcmeUtils;
import org.xipki.security.HashAlgo;
import org.xipki.util.Args;
import org.xipki.util.Base64Url;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeOrder {

  private boolean inDb;

  private boolean marked;

  private AcmeOrder mark;

  private OrderStatus status = OrderStatus.pending;

  private final long accountId;

  private final long id;

  private final String idStr;

  private List<AcmeAuthz> authzs;

  private Instant expires;

  private CertReqMeta certReqMeta;

  private byte[] csr;

  private String certSha256;

  private byte[] cert;

  private final AcmeDataSource dataSource;

  public AcmeOrder(long accountId, long id, AcmeDataSource dataSource) {
    this.accountId = accountId;
    this.id = id;
    this.idStr = AcmeUtils.toBase64(id);
    this.dataSource = Args.notNull(dataSource, "dataSource");
  }

  public boolean isInDb() {
    return inDb;
  }

  public long getAccountId() {
    return accountId;
  }

  public OrderStatus getStatus() {
    return status;
  }

  public void setStatus(OrderStatus status) {
    markMe();
    this.status = status;
  }

  public void setInDb(boolean inDb) {
    this.inDb = inDb;
  }

  public CertReqMeta getCertReqMeta() {
    return certReqMeta;
  }

  public void setCertReqMeta(CertReqMeta certReqMeta) {
    markMe();
    this.certReqMeta = certReqMeta;
  }

  public byte[] getCert() {
    return cert;
  }

  public String getCertSha256() {
    if (certSha256 != null) {
      return certSha256;
    }

    if (cert == null) {
      return null;
    }

    certSha256 = Base64Url.encodeToStringNoPadding(HashAlgo.SHA256.hash(cert));
    return certSha256;
  }

  public void setCertSha256(String certSha256) {
    this.certSha256 = certSha256;
  }

  public void setCert(byte[] cert) {
    markMe();
    this.cert = cert;
    if (cert == null) {
      this.certSha256 = null;
    } else {
      this.certSha256 = Base64Url.encodeToStringNoPadding(HashAlgo.SHA256.hash(cert));
    }
  }

  public long getId() {
    return id;
  }

  public String idText() {
    return idStr + " (" + id + ")";
  }

  public Instant getExpires() {
    return expires;
  }

  public void setExpires(Instant expires) {
    markMe();
    this.expires = expires;
  }

  public byte[] getCsr() {
    return csr;
  }

  public void setCsr(byte[] csr) {
    markMe();
    this.csr = csr;
  }

  public List<AcmeAuthz> getAuthzs() {
    return authzs;
  }

  public void setAuthzs(List<AcmeAuthz> authzs) {
    markMe();
    this.authzs = authzs;
    if (authzs != null) {
      for (AcmeAuthz authz : authzs) {
        authz.setOrder(this);
      }
    }
  }

  public String getLocation(String baseUrl) {
    return baseUrl + "order/" + idStr;
  }

  public OrderResponse toResponse(String baseUrl) {
    OrderResponse resp = new OrderResponse();
    resp.setStatus(status);

    resp.setExpires(expires.toString());
    resp.setFinalize(baseUrl + "finalize/" + idStr);

    List<String> authzUrls = new ArrayList<>(authzs.size());
    List<Identifier> identifiers = new ArrayList<>(authzs.size());
    for (AcmeAuthz authz : authzs) {
      AuthzId authzId = new AuthzId(id, authz.getSubId());
      authzUrls.add(baseUrl + "authz/" + authzId.toIdText());
      identifiers.add(authz.getIdentifier().toIdentifier());
    }
    resp.setAuthorizations(authzUrls);
    resp.setIdentifiers(identifiers);
    if (status == OrderStatus.valid) {
      resp.setCertificate(baseUrl + "cert/" + idStr);
    }
    return resp;
  }

  public AcmeAuthz getAuthz(int authzId) {
    for (AcmeAuthz authz : authzs) {
      if (authz.getSubId() == authzId) {
        return authz;
      }
    }
    return null;
  }

  public void updateStatus() {
    if (status == OrderStatus.valid || status == OrderStatus.invalid) {
      return;
    }

    // check the authz
    for (AcmeAuthz authz : authzs) {
      for (AcmeChallenge chall : authz.getChallenges()) {
        if (chall.getStatus() == ChallengeStatus.valid) {
          authz.setStatus(AuthzStatus.valid);
          break;
        } else if (chall.getStatus() == ChallengeStatus.invalid) {
          authz.setStatus(AuthzStatus.invalid);
          status = OrderStatus.invalid;
          return;
        }
      }
    }

    if (status == OrderStatus.ready || status == OrderStatus.processing) {
      return;
    }

    boolean allAuthzsValidated = true;
    for (AcmeAuthz authz : authzs) {
      if (authz.getStatus() != AuthzStatus.valid) {
        allAuthzsValidated = false;
        break;
      }
    }

    if (allAuthzsValidated) {
      status = OrderStatus.ready;
    }
  }

  public void mark() {
    marked = true;
  }

  public synchronized void flush() throws AcmeSystemException {
    updateStatus();

    if (inDb) {
      if (mark != null) {
        dataSource.updateOrder(mark, this);
      }
    } else {
      // not saved in database.
      dataSource.addNewOrder(this);
      inDb = true;
    }

    mark = null;
  }

  synchronized void markMe() {
    if (!inDb || mark != null) {
      return;
    }

    AcmeOrder copy = new AcmeOrder(accountId, id, dataSource);

    if (authzs != null) {
      copy.authzs = new ArrayList<>(authzs.size());
      for (AcmeAuthz authz : authzs) {
        copy.authzs.add(authz.copy());
      }
    }

    // cert
    if (cert != null) {
      copy.cert = cert; // no deep copy here
    }

    // csr
    if (csr != null) {
      copy.csr = csr; // no deep copy here
    }

    copy.expires = expires;
    if (certReqMeta != null) {
      copy.certReqMeta = certReqMeta.copy();
    }

    copy.inDb = inDb;
    copy.status = status;
    copy.marked = marked;

    this.mark = copy;
  }

}
