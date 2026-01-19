// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.ca.server.CertStore.SerialWithId;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.exception.ErrorCode;
import org.xipki.security.exception.OperationException;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.audit.AuditEvent;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.LogUtil;

import java.io.Closeable;
import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * X509CA revoker module.
 *
 * @author Lijun Liao (xipki)
 */

public class X509RemoverModule extends X509CaModule implements Closeable {

  private class ExpiredCertsRemover implements Runnable {

    private boolean inProcess;

    @Override
    public void run() {
      int keepDays = caInfo.getKeepExpiredCertDays();
      if (keepDays < 0) {
        return;
      }

      if (inProcess) {
        return;
      }

      inProcess = true;
      final Instant expiredAt = Instant.now().minus(
          keepDays + 1, ChronoUnit.DAYS);

      try {
        LOG.debug("revoking expired certificates");
        AuditEvent event = newAuditEvent(
            CaAuditConstants.TYPE_remove_expired_certs, null);
        boolean successful = false;
        try {
          int num = removeExpiredCerts0(expiredAt, event);
          LOG.info("removed {} certificates expired at {} of CA {}", num,
              expiredAt, caIdent);
          successful = true;
        } finally {
          finish(event, successful);
        }
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not remove expired certificates");
      } finally {
        inProcess = false;
      }
    } // method run

  } // class ExpiredCertsRemover

  private final boolean masterMode;

  private final CertStore certstore;

  private final CaIdNameMap caIdNameMap;

  private final X509PublisherModule publisherModule;

  private ScheduledFuture<?> expiredCertsRemover;

  X509RemoverModule(CaManagerImpl caManager, CaInfo caInfo,
                    CertStore certstore, X509PublisherModule publisherModule) {
    super(caInfo);

    this.caIdNameMap = caManager.idNameMap();
    this.certstore = certstore;
    this.masterMode = caManager.isMasterMode();
    this.publisherModule = publisherModule;

    if (!masterMode) {
      return;
    }

    ScheduledThreadPoolExecutor executor =
        caManager.getScheduledThreadPoolExecutor();

    Random random = new Random();
    final int minutesOfDay = 24 * 60;
    this.expiredCertsRemover = executor.scheduleAtFixedRate(
        new ExpiredCertsRemover(),
        minutesOfDay + random.nextInt(60), minutesOfDay,
        TimeUnit.MINUTES);
  } // constructor

  public CertWithDbId removeCert(SerialWithId serialNumber, AuditEvent event)
      throws OperationException {
    return removeCert0(serialNumber.getId(), serialNumber.getSerial(), event);
  }

  public CertWithDbId removeCert(BigInteger serialNumber, AuditEvent event)
      throws OperationException {
    return removeCert0(0, serialNumber, event);
  }

  private CertWithDbId removeCert0(
      long certId, BigInteger serialNumber, AuditEvent event)
      throws OperationException {
    if (caInfo.isSelfSigned()
        && caInfo.getSerialNumber().equals(serialNumber)) {
      throw new OperationException(ErrorCode.NOT_PERMITTED,
          "could not remove CA certificate");
    }

    boolean successful = true;
    try {
      event.addEventData(CaAuditConstants.NAME_serial,
          LogUtil.formatCsn(serialNumber));
      CertWithRevocationInfo certWithRevInfo = (certId == 0)
          ? certstore.getCertWithRevocationInfo(caIdent.getId(),
              serialNumber, caIdNameMap)
          : certstore.getCertWithRevocationInfo(certId, caIdNameMap);

      if (certWithRevInfo == null) {
        return null;
      }

      CertWithDbId certToRemove = certWithRevInfo.getCert();
      boolean succ = publisherModule.publishCertRemoved(certToRemove);
      if (!succ) {
        return null;
      }

      certstore.removeCert(certWithRevInfo.getCert().getCertId());
      successful = (certToRemove != null);
      return certToRemove;
    } finally {
      setEventStatus(event, successful);
    }
  } // method removeCertificate

  private int removeExpiredCerts0(Instant expiredAtTime, AuditEvent event)
      throws OperationException {
    Args.notNull(expiredAtTime, "expiredtime");
    if (!masterMode) {
      throw new OperationException(ErrorCode.NOT_PERMITTED,
          "CA could not remove expired certificates in slave mode");
    }

    event.addEventData(CaAuditConstants.NAME_expired_at, expiredAtTime);
    final int numEntries = 100;

    final long expiredAt = expiredAtTime.getEpochSecond();

    int sum = 0;
    while (true) {
      List<SerialWithId> serials = certstore.getExpiredUnrevokedSerialNumbers(
          caIdent, expiredAt, numEntries);

      if (CollectionUtil.isEmpty(serials)) {
        return sum;
      }

      for (SerialWithId serial : serials) {
        // do not delete CA's own certificate
        if ((caInfo.isSelfSigned()
            && caInfo.getSerialNumber().equals(serial.getSerial()))) {
          continue;
        }

        try {
          if (removeCert(serial, event) != null) {
            sum++;
          }
        } catch (OperationException ex) {
          LOG.info("removed {} expired certificates of CA {}",
              sum, caIdent.getName());
          LogUtil.error(LOG, ex, "could not remove expired certificate " +
              "with serial" + serial.getSerial());
          throw ex;
        }
      } // end for
    } // end while (true)
  } // method removeExpirtedCerts

  @Override
  public void close() {
    if (expiredCertsRemover != null) {
      expiredCertsRemover.cancel(false);
      expiredCertsRemover = null;
    }
  }

}
