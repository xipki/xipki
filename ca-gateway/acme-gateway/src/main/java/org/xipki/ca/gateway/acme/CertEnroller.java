package org.xipki.ca.gateway.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.acme.type.OrderStatus;
import org.xipki.ca.sdk.*;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;

import java.util.Collections;
import java.util.Iterator;

public class CertEnroller implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(CertEnroller.class);

  private final AcmeRepo acmeRepo;

  private final SdkClient sdk;

  private final String ca;

  public CertEnroller(AcmeRepo acmeRepo, SdkClient sdk, String ca) {
    this.acmeRepo = Args.notNull(acmeRepo, "acmeRepo");
    this.sdk = Args.notNull(sdk, "sdk");
    this.ca = Args.notNull(ca, "ca");
  }

  private boolean stopMe;

  @Override
  public void run() {
    while (!stopMe) {
      Iterator<String> orderLabels = acmeRepo.getOrdersToEnroll();
      if (!orderLabels.hasNext()) {
        try {
          Thread.sleep(1000); // sleep for 1 second.
        } catch (InterruptedException e) {
        }
      }

      while (orderLabels.hasNext()) {
        String orderLabel = orderLabels.next();
        if (orderLabel == null) {
          continue;
        }

        AcmeOrder order = acmeRepo.getOrder(orderLabel);
        if (order == null || order.getStatus() != OrderStatus.processing) {
          continue;
        }

        if (order.getCsr() == null) {
          LOG.error("TODO: log me");
          order.setStatus(OrderStatus.invalid);
          continue;
        }

        EnrollCertRequestEntry entry = new EnrollCertRequestEntry();
        if (order.getNotBefore() != null) {
          entry.setNotBefore(order.getNotBefore().getEpochSecond());
        }

        if (order.getNotAfter() != null) {
          entry.setNotAfter(order.getNotAfter().getEpochSecond());
        }
        entry.setCertprofile(order.getCertProfile());
        entry.setP10req(order.getCsr());

        EnrollCertsRequest sdkReq = new EnrollCertsRequest();
        sdkReq.setCaCertMode(CertsMode.NONE);
        sdkReq.setEntries(Collections.singletonList(entry));

        LOG.info("enrolling certificate for order {}", orderLabel);
        try {
          EnrollOrPollCertsResponse sdkResp = sdk.enrollCerts(ca, sdkReq);
          EnrollOrPullCertResponseEntry sdkRespEntry = sdkResp.getEntries().get(0);
          byte[] certBytes = sdkRespEntry.getCert();

          if (certBytes != null) {
            order.setCert(certBytes);
            order.setStatus(OrderStatus.valid);
          } else {
            order.setStatus(OrderStatus.invalid);
          }
        } catch (Throwable t) {
          LogUtil.error(LOG, t);
          order.setStatus(OrderStatus.invalid);
        }
      }
    }
  }

  public void close() {
    stopMe = true;
  }

}
