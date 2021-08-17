/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server;

import org.xipki.audit.AuditEvent;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.server.db.CertStore;
import org.xipki.ca.server.db.CertStore.SerialWithId;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;

import java.io.Closeable;
import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.xipki.ca.api.OperationException.ErrorCode.NOT_PERMITTED;
import static org.xipki.util.Args.notNull;

/**
 * X509CA revoker module.
 *
 * @author Lijun Liao
 */

public class X509RemoverModule extends X509CaModule implements Closeable {

  private class ExpiredCertsRemover implements Runnable {

    private boolean inProcess;

    @Override
    public void run() {
      int keepDays = caInfo.getKeepExpiredCertInDays();
      if (keepDays < 0) {
        return;
      }

      if (inProcess) {
        return;
      }

      inProcess = true;
      final Date expiredAt = new Date(System.currentTimeMillis() - MS_PER_DAY * (keepDays + 1));

      try {
        String msgId = CaAuditConstants.MSGID_ca_routine;

        LOG.debug("revoking expired certificates");
        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_remove_expired_certs, msgId);
        boolean successful = false;
        try {
          int num = removeExpiredCerts0(expiredAt, event, msgId);
          LOG.info("removed {} certificates expired at {} of CA {}", num, expiredAt, caIdent);
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

  public X509RemoverModule(CaManagerImpl caManager, CaInfo caInfo, CertStore certstore,
      X509PublisherModule publisherModule) {
    super(caInfo);

    this.caIdNameMap = caManager.idNameMap();
    this.certstore = certstore;
    this.masterMode = caManager.isMasterMode();
    this.publisherModule = publisherModule;

    if (!masterMode) {
      return;
    }

    ScheduledThreadPoolExecutor executor = caManager.getScheduledThreadPoolExecutor();

    Random random = new Random();
    final int minutesOfDay = 24 * 60;
    this.expiredCertsRemover = executor.scheduleAtFixedRate(new ExpiredCertsRemover(),
        minutesOfDay + random.nextInt(60), minutesOfDay, TimeUnit.MINUTES);
  } // constructor

  public CertWithDbId removeCert(SerialWithId serialNumber, String msgId)
      throws OperationException {
    return removeCert0(serialNumber.getId(), serialNumber.getSerial(), msgId);
  }

  public CertWithDbId removeCert(BigInteger serialNumber, String msgId) throws OperationException {
    return removeCert0(0, serialNumber, msgId);
  }

  private CertWithDbId removeCert0(long certId, BigInteger serialNumber, String msgId)
      throws OperationException {
    if (caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber)) {
      throw new OperationException(NOT_PERMITTED, "could not remove CA certificate");
    }

    AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_remove_cert, msgId);
    boolean successful = true;
    try {
      event.addEventData(CaAuditConstants.NAME_serial, LogUtil.formatCsn(serialNumber));
      CertWithRevocationInfo certWithRevInfo = (certId == 0)
          ? certstore.getCertWithRevocationInfo(caIdent.getId(), serialNumber, caIdNameMap)
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
      finish(event, successful);
    }
  } // method removeCertificate

  private int removeExpiredCerts0(Date expiredAtTime, AuditEvent event, String msgId)
      throws OperationException {
    notNull(expiredAtTime, "expiredtime");
    if (!masterMode) {
      throw new OperationException(NOT_PERMITTED,
          "CA could not remove expired certificates in slave mode");
    }

    event.addEventData(CaAuditConstants.NAME_expired_at, expiredAtTime);
    final int numEntries = 100;

    final long expiredAt = expiredAtTime.getTime() / 1000;

    int sum = 0;
    while (true) {
      List<SerialWithId> serials = certstore.getExpiredUnrevokedSerialNumbers(
            caIdent, expiredAt, numEntries);
      if (CollectionUtil.isEmpty(serials)) {
        return sum;
      }

      for (SerialWithId serial : serials) {
        // do not delete CA's own certificate
        if ((caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serial.getSerial()))) {
          continue;
        }

        try {
          if (removeCert(serial, msgId) != null) {
            sum++;
          }
        } catch (OperationException ex) {
          LOG.info("removed {} expired certificates of CA {}", sum, caIdent.getName());
          LogUtil.error(LOG, ex, "could not remove expired certificate with serial"
              + serial.getSerial());
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
