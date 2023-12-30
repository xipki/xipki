// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.xipki.scep.message.PkiMessage;
import org.xipki.scep.transaction.FailInfo;
import org.xipki.scep.transaction.MessageType;
import org.xipki.scep.transaction.PkiStatus;
import org.xipki.scep.util.ScepUtil;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;

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
    MessageType messageType = Args.notNull(pkcsRep, "pkcsRep").getMessageType();
    if (MessageType.CertRep != messageType) {
      throw new ScepClientException("messageType must not be other than CertRep: " + messageType);
    }
    this.pkcsRep = pkcsRep;

    if (PkiStatus.SUCCESS != pkcsRep.getPkiStatus()) {
      return;
    }

    ASN1Encodable messageData = pkcsRep.getMessageData();
    if (!(messageData instanceof ContentInfo)) {
      throw new ScepClientException("pkcsRep is not a ContentInfo");
    }

    SignedData sd = SignedData.getInstance(((ContentInfo) messageData).getContent());
    ASN1Set asn1Certs = sd.getCertificates();
    if (asn1Certs == null || asn1Certs.size() == 0) {
      throw new ScepClientException("no certificate is embedded in pkcsRep");
    }

    try {
      this.certificates = Collections.unmodifiableList(ScepUtil.getCertsFromSignedData(sd));
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
    return pkcsRep.getPkiStatus() == PkiStatus.PENDING;
  }

  public boolean isFailure() {
    return pkcsRep.getPkiStatus() == PkiStatus.FAILURE;
  }

  public boolean isSuccess() {
    return pkcsRep.getPkiStatus() == PkiStatus.SUCCESS;
  }

  public List<X509Cert> getCertificates() {
    if (isSuccess()) {
      return certificates;
    }
    throw new IllegalStateException();
  }

  public FailInfo getFailInfo() {
    if (isFailure()) {
      return pkcsRep.getFailInfo();
    }
    throw new IllegalStateException();
  }

  public String getFailInfoText() {
    if (isFailure()) {
      return pkcsRep.getFailInfoText();
    }
    throw new IllegalStateException();
  }

  public PkiMessage getPkcsRep() {
    return pkcsRep;
  }

}
