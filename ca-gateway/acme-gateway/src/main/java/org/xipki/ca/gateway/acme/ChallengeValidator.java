package org.xipki.ca.gateway.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.ca.gateway.acme.type.OrderStatus;
import org.xipki.util.Args;

import java.time.Instant;
import java.util.Iterator;

public class ChallengeValidator implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(CertEnroller.class);

  private final AcmeRepo acmeRepo;

  public ChallengeValidator(AcmeRepo acmeRepo) {
    this.acmeRepo = Args.notNull(acmeRepo, "acmeRepo");
  }

  private boolean stopMe;

  @Override
  public void run() {
    while (!stopMe) {
      Iterator<String> orderLabels = acmeRepo.getOrdersToValidate();
      if (!orderLabels.hasNext()) {
        try {
          Thread.sleep(1000); // sleep for 1 second.
        } catch (InterruptedException e) {
        }
        continue;
      }

      while (orderLabels.hasNext()) {
        String orderLabel = orderLabels.next();
        LOG.debug("validate challenge for order {}", orderLabel);
        if (orderLabel == null) {
          continue;
        }

        AcmeOrder order = acmeRepo.getOrder(orderLabel);
        if (order == null) {
          continue;
        }

        AcmeAuthz[] authzs = order.getAuthzs();
        for (AcmeAuthz authz : authzs) {
          AcmeChallenge chall = null;
          for (AcmeChallenge chall0 : authz.getChallenges()) {
            if (chall0.getStatus() == ChallengeStatus.processing) {
              chall = chall0;
              break;
            }
          }

          if (chall == null) {
            continue;
          }

          // TODO: verify the challenge
          LOG.info("validated challenge {}:{} for identifier {}: {}", chall.getType(), chall.getLabel(),
              authz.getIdentifier().getType(), authz.getIdentifier().getValue());

          chall.setValidated(Instant.now());
          chall.setStatus(ChallengeStatus.valid);
          authz.setStatus(AuthzStatus.valid);
        }

        boolean allAuthzsValidated = true;
        for (AcmeAuthz authz : authzs) {
          if (authz.getStatus() != AuthzStatus.valid) {
            allAuthzsValidated = false;
            break;
          }
        }

        if (allAuthzsValidated) {
          order.setStatus(OrderStatus.ready);
        }
      }
    }
  }

  public void close() {
    stopMe = true;
  }

}
