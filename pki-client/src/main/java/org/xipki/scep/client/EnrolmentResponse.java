// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.scep.message.PkiMessage;
import org.xipki.security.scep.transaction.FailInfo;
import org.xipki.security.scep.transaction.MessageType;
import org.xipki.security.scep.transaction.PkiStatus;
import org.xipki.security.scep.util.ScepUtil;
import org.xipki.util.codec.Args;

import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

/**
 * Response of certificate enrolment.
 *
 * @author Lijun Liao (xipki)
 */

public final class EnrolmentResponse {

  private final PkiMessage pkcsRep;

  private List<X509Cert> certificates;

  public EnrolmentResponse(PkiMessage pkcsRep) throws ScepClientException {
    MessageType messageType = Args.notNull(pkcsRep, "pkcsRep")
        .messageType();
    if (MessageType.CertRep != messageType) {
      throw new ScepClientException(
          "messageType must not be other than CertRep: " + messageType);
    }
    this.pkcsRep = pkcsRep;

    if (PkiStatus.SUCCESS != pkcsRep.pkiStatus()) {
      return;
    }

    ASN1Encodable messageData = pkcsRep.messageData();
    if (!(messageData instanceof ContentInfo)) {
      throw new ScepClientException("pkcsRep is not a ContentInfo");
    }

    SignedData sd = SignedData.getInstance(
        ((ContentInfo) messageData).getContent());
    ASN1Set asn1Certs = sd.getCertificates();
    if (asn1Certs == null || asn1Certs.size() == 0) {
      throw new ScepClientException("no certificate is embedded in pkcsRep");
    }

    try {
      this.certificates = Collections.unmodifiableList(
          ScepUtil.getCertsFromSignedData(sd));
    } catch (CertificateException ex) {
      throw new ScepClientException(ex);
    }
  }

  /**
   * Returns true for a pending response, false otherwise.
   *
   * @return true for a pending response, false otherwise.
   */
  public boolean isPending() {
    return pkcsRep.pkiStatus() == PkiStatus.PENDING;
  }

  public boolean isFailure() {
    return pkcsRep.pkiStatus() == PkiStatus.FAILURE;
  }

  public boolean isSuccess() {
    return pkcsRep.pkiStatus() == PkiStatus.SUCCESS;
  }

  public List<X509Cert> certificates() {
    if (isSuccess()) {
      return certificates;
    }
    throw new IllegalStateException();
  }

  public FailInfo failInfo() {
    if (isFailure()) {
      return pkcsRep.failInfo();
    }
    throw new IllegalStateException();
  }

  public String failInfoText() {
    if (isFailure()) {
      return pkcsRep.failInfoText();
    }
    throw new IllegalStateException();
  }

  public PkiMessage pkcsRep() {
    return pkcsRep;
  }

}
