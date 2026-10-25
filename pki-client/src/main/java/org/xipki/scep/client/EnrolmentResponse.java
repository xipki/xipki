// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.pkix.asn1.cms.CertificateChoice;
import org.xipki.pkix.asn1.cms.ContentInfo;
import org.xipki.pkix.asn1.cms.SignedData;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.message.PkiMessage;
import org.xipki.pkix.scep.transaction.FailInfo;
import org.xipki.pkix.scep.transaction.MessageType;
import org.xipki.pkix.scep.transaction.PkiStatus;
import org.xipki.pkix.scep.util.ScepUtil;

import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

/**
 * Enrolment Response payload.
 *
 * @author Lijun Liao (xipki)
 */
public final class EnrolmentResponse {

  private final PkiMessage pkcsRep;

  private List<X509Cert> certificates;

  public EnrolmentResponse(PkiMessage pkcsRep) throws ScepClientException {
    MessageType messageType = Args.notNull(pkcsRep, "pkcsRep").messageType();
    if (MessageType.CertRep != messageType) {
      throw new ScepClientException("messageType must not be other than CertRep: " + messageType);
    }
    this.pkcsRep = pkcsRep;

    if (PkiStatus.SUCCESS != pkcsRep.pkiStatus()) {
      return;
    }

    Asn1Primitive messageData = pkcsRep.messageData();

    ContentInfo content;
    try {
      content = ContentInfo.fromAsn1(messageData.asSequence());
    } catch (CodecException e) {
      throw new ScepClientException("pkcsRep is not a ContentInfo", e);
    }
    try {
      SignedData sd = SignedData.fromAsn1(content.getContent().asSequence());
      CertificateChoice.Set0 asn1Certs = sd.getCertificates();
      if (asn1Certs == null || asn1Certs.isEmpty()) {
        throw new ScepClientException("no certificate is embedded in pkcsRep");
      }

      this.certificates = Collections.unmodifiableList(ScepUtil.getCertsFromSignedData(sd));
    } catch (CertificateException | CodecException ex) {
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
