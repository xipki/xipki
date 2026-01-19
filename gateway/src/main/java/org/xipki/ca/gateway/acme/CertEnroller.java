// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.acme.type.CertReqMeta;
import org.xipki.ca.gateway.acme.type.OrderStatus;
import org.xipki.ca.sdk.EnrollCertsRequest;
import org.xipki.ca.sdk.EnrollOrPollCertsResponse;
import org.xipki.ca.sdk.SdkClient;
import org.xipki.ca.sdk.X500NameType;
import org.xipki.security.exception.OperationException;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.type.EmbedCertsMode;

import java.io.IOException;
import java.util.Iterator;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class CertEnroller implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(CertEnroller.class);

  private final AcmeRepo repo;

  private final SdkClient sdk;

  public CertEnroller(AcmeRepo repo, SdkClient sdk) {
    this.repo = Args.notNull(repo, "repo");
    this.sdk = Args.notNull(sdk, "sdk");
  }

  private boolean stopMe;

  @Override
  public void run() {
    while (!stopMe) {
      try {
        singleRun();
      } catch (Throwable t) {
        LogUtil.error(LOG, t, "expected error");
      }

      try {
        Thread.sleep(1000); // sleep for 1 second.
      } catch (InterruptedException e) {
      }
    }
  }

  public void singleRun() throws AcmeSystemException {
    Iterator<Long> orderIds = repo.getOrdersToEnroll();

    while (orderIds.hasNext()) {
      Long orderId = orderIds.next();
      if (orderId == null) {
        continue;
      }

      String orderIdStr = AcmeUtils.toBase64(orderId) + " (" + orderId + ")";
      LOG.info("try to enroll certificate for order {}", orderIdStr);

      AcmeOrder order = repo.getOrder(orderId);
      if (order == null) {
        LOG.error("found no order for id {}", orderIdStr);
        continue;
      }

      byte[] csr = order.getCsr();
      if (csr == null) {
        // if the order is read from database, csr is null in the object,
        // even present in the database
        csr = repo.getCsr(orderId);
      }

      if (csr == null) {
        LOG.error("found not CSR for order {}", orderIdStr);
        continue;
      }

      EnrollCertsRequest.Entry entry = new EnrollCertsRequest.Entry();
      CertReqMeta certReqMeta = order.getCertReqMeta();
      entry.setNotBefore(certReqMeta.getNotBefore());
      entry.setNotAfter(certReqMeta.getNotAfter());
      entry.setCertprofile(certReqMeta.getCertProfile());

      if (certReqMeta.getSubject() == null) {
        entry.setP10req(csr);
      } else {
        entry.setSubject(new X500NameType(certReqMeta.getSubject()));

        CertificationRequest p10Req;
        try {
          p10Req = GatewayUtil.parseCsrInRequest(csr);
          Extensions extensions = X509Util.getExtensions(
              p10Req.getCertificationRequestInfo());
          if (extensions != null) {
            entry.setExtensions(extensions.getEncoded());
          }
          entry.setSubjectPublicKey(p10Req.getCertificationRequestInfo()
              .getSubjectPublicKeyInfo().getEncoded());
        } catch (IOException | OperationException e) {
          throw new AcmeSystemException(e);
        }
      }

      EnrollCertsRequest sdkReq = new EnrollCertsRequest();
      sdkReq.setCaCertMode(EmbedCertsMode.NONE);
      sdkReq.setEntries(new EnrollCertsRequest.Entry[]{entry});

      LOG.info("start enrolling certificate for order {}", orderIdStr);
      try {
        EnrollOrPollCertsResponse sdkResp =
            sdk.enrollCerts(certReqMeta.getCa(), sdkReq);
        EnrollOrPollCertsResponse.Entry sdkRespEntry = sdkResp.getEntries()[0];
        byte[] certBytes = sdkRespEntry.getCert();
        boolean valid = certBytes != null;
        if (valid) {
          // check the certificate
          try {
            Certificate.getInstance(certBytes);
          } catch (Exception ex) {
            LogUtil.error(LOG, ex, "Error parsing enrolled " +
                "certificate for order " + orderIdStr);
            valid = false;
          }
        } else {
          LOG.error("CA returned error for the order {}: {}",
              orderIdStr, sdkRespEntry.getError());
        }

        if (valid) {
          LOG.info("enrolled certificate for order {}", orderIdStr);
          order.setCert(certBytes);
          order.setStatus(OrderStatus.valid);
        } else {
          order.setStatus(OrderStatus.invalid);
        }

        repo.flushOrderIfNotCached(order);
      } catch (Throwable t) {
        LogUtil.error(LOG, t);
        order.setStatus(OrderStatus.invalid);
      }
    }
  }

  public void close() {
    stopMe = true;
  }

}
