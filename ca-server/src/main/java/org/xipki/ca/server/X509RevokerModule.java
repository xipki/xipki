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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.server.db.CertStore;
import org.xipki.ca.server.db.CertStore.SerialWithId;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.util.CollectionUtil;
import org.xipki.util.DateUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.Validity;

import java.io.Closeable;
import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.xipki.ca.api.OperationException.ErrorCode.NOT_PERMITTED;
import static org.xipki.ca.api.OperationException.ErrorCode.SYSTEM_FAILURE;
import static org.xipki.ca.server.CaAuditConstants.*;
import static org.xipki.util.Args.notNull;

/**
 * X509CA revoker module.
 *
 * @author Lijun Liao
 */

public class X509RevokerModule extends X509CaModule implements Closeable {

  private class SuspendedCertsRevoker implements Runnable {

    private boolean inProcess;

    @Override
    public void run() {
      if (caInfo.revokeSuspendedCertsControl() == null) {
        return;
      }

      if (inProcess) {
        return;
      }

      inProcess = true;
      try {
        LOG.debug("revoking suspended certificates");
        int num = revokeSuspendedCerts();
        if (num == 0) {
          LOG.debug("revoked {} suspended certificates of CA '{}'", num, caIdent);
        } else {
          LOG.info("revoked {} suspended certificates of CA '{}'", num, caIdent);
        }
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not revoke suspended certificates");
      } finally {
        inProcess = false;
      }
    } // method run

  } // class SuspendedCertsRevoker

  private static final Logger LOG = LoggerFactory.getLogger(X509RevokerModule.class);

  private final boolean masterMode;

  private final CertStore certstore;

  private final CaIdNameMap caIdNameMap;

  private final X509PublisherModule publisherModule;

  private ScheduledFuture<?> suspendedCertsRevoker;

  public X509RevokerModule(CaManagerImpl caManager, CaInfo caInfo, CertStore certstore,
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
    this.suspendedCertsRevoker = executor.scheduleAtFixedRate(new SuspendedCertsRevoker(),
        random.nextInt(60), 60, TimeUnit.MINUTES);
  } // constructor

  public CertWithRevocationInfo revokeCert(BigInteger serialNumber, CrlReason reason,
      Date invalidityTime, String msgId) throws OperationException {
    if (caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber)) {
      throw new OperationException(NOT_PERMITTED,
          "insufficient permission to revoke CA certificate");
    }

    if (reason == null) {
      reason = CrlReason.UNSPECIFIED;
    }

    switch (reason) {
      case CA_COMPROMISE:
      case AA_COMPROMISE:
      case REMOVE_FROM_CRL:
        throw new OperationException(NOT_PERMITTED, "insufficient permission to revoke certificate "
            + "with reason " + reason.getDescription());
      case UNSPECIFIED:
      case KEY_COMPROMISE:
      case AFFILIATION_CHANGED:
      case SUPERSEDED:
      case CESSATION_OF_OPERATION:
      case CERTIFICATE_HOLD:
      case PRIVILEGE_WITHDRAWN:
        break;
      default:
        throw new IllegalStateException("unknown CRL reason " + reason);
    } // switch (reason)

    AuditEvent event = newPerfAuditEvent(TYPE_revoke_cert, msgId);
    boolean successful = true;
    try {
      CertWithRevocationInfo ret = revokeCertificate0(serialNumber, reason,
          invalidityTime, false, event);
      successful = (ret != null);
      return ret;
    } finally {
      finish(event, successful);
    }
  } // method revokeCertificate

  public CertWithDbId unrevokeCert(BigInteger serialNumber, String msgId)
      throws OperationException {
    if (caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber)) {
      throw new OperationException(NOT_PERMITTED,
          "insufficient permission to unrevoke CA certificate");
    }

    AuditEvent event = newPerfAuditEvent(TYPE_unrevoke_cert, msgId);
    boolean successful = false;
    try {
      CertWithDbId ret = unrevokeCert0(serialNumber, false, event);
      successful = true;
      return ret;
    } finally {
      finish(event, successful);
    }
  } // method unrevokeCertificate

  private CertWithRevocationInfo revokeCertificate0(BigInteger serialNumber, CrlReason reason,
      Date invalidityTime, boolean force, AuditEvent event) throws OperationException {
    String hexSerial = LogUtil.formatCsn(serialNumber);
    event.addEventData(NAME_serial, hexSerial);
    event.addEventData(NAME_reason, reason.getDescription());
    if (invalidityTime != null) {
      event.addEventData(NAME_invalidity_time,
          DateUtil.toUtcTimeyyyyMMddhhmmss(invalidityTime));
    }

    LOG.info("     START revokeCertificate: ca={}, serialNumber={}, reason={}, invalidityTime={}",
        caIdent.getName(), hexSerial, reason.getDescription(), invalidityTime);

    CertWithRevocationInfo revokedCert;

    CertRevocationInfo revInfo = new CertRevocationInfo(reason, new Date(), invalidityTime);
    revokedCert = certstore.revokeCert(caIdent, serialNumber, revInfo, force, caIdNameMap);
    if (revokedCert == null) {
      return null;
    }

    publisherModule.publishCertRevoked(revokedCert);

    if (LOG.isInfoEnabled()) {
      LOG.info("SUCCESSFUL revokeCertificate: ca={}, serialNumber={}, reason={}, invalidityTime={},"
          + " revocationResult=REVOKED", caIdent.getName(), hexSerial, reason.getDescription(),
          invalidityTime);
    }

    return revokedCert;
  } // method revokeCertificate0

  private CertWithRevocationInfo revokeSuspendedCert(SerialWithId serialNumber, CrlReason reason)
          throws OperationException {
    AuditEvent event = newPerfAuditEvent(TYPE_revoke_suspendedCert, MSGID_ca_routine);

    boolean successful = false;
    try {
      CertWithRevocationInfo ret = revokeSuspendedCert0(serialNumber, reason, event);
      successful = (ret != null);
      return ret;
    } finally {
      finish(event, successful);
    }
  }

  private CertWithRevocationInfo revokeSuspendedCert0(SerialWithId serialNumber, CrlReason reason,
      AuditEvent event) throws OperationException {
    String hexSerial = LogUtil.formatCsn(serialNumber.getSerial());

    event.addEventData(NAME_serial, hexSerial);
    event.addEventData(NAME_reason, reason.getDescription());

    if (LOG.isInfoEnabled()) {
      LOG.info("     START revokeSuspendedCert: ca={}, serialNumber={}, reason={}",
          caIdent.getName(), hexSerial, reason.getDescription());
    }

    CertWithRevocationInfo revokedCert = certstore.revokeSuspendedCert(caIdent,
        serialNumber, reason, caIdNameMap);
    if (revokedCert == null) {
      return null;
    }

    publisherModule.publishCertRevoked(revokedCert);

    if (LOG.isInfoEnabled()) {
      LOG.info("SUCCESSFUL revokeSuspendedCert: ca={}, serialNumber={}, reason={}",
          caIdent.getName(), hexSerial, reason.getDescription());
    }

    return revokedCert;
  } // method revokeSuspendedCert0

  private CertWithDbId unrevokeCert0(BigInteger serialNumber, boolean force, AuditEvent event)
      throws OperationException {
    String hexSerial = LogUtil.formatCsn(serialNumber);
    event.addEventData(NAME_serial, hexSerial);

    LOG.info("     START unrevokeCertificate: ca={}, serialNumber={}", caIdent.getName(),
        hexSerial);

    CertWithDbId unrevokedCert = certstore.unrevokeCert(caIdent, serialNumber, force, caIdNameMap);
    if (unrevokedCert == null) {
      return null;
    }

    publisherModule.publishCertUnrevoked(unrevokedCert);

    LOG.info("SUCCESSFUL unrevokeCertificate: ca={}, serialNumber={}, revocationResult=UNREVOKED",
        caIdent.getName(), hexSerial);

    return unrevokedCert;
  } // doUnrevokeCertificate

  public void revokeCa(CertRevocationInfo revocationInfo, String msgId) throws OperationException {
    notNull(revocationInfo, "revocationInfo");
    caInfo.setRevocationInfo(revocationInfo);

    if (caInfo.isSelfSigned()) {
      AuditEvent event = newPerfAuditEvent(TYPE_revoke_cert, msgId);
      boolean successful = true;
      try {
        CertWithRevocationInfo ret = revokeCertificate0(caInfo.getSerialNumber(),
            revocationInfo.getReason(), revocationInfo.getInvalidityTime(), true, event);
        successful = (ret != null);
      } finally {
        finish(event, successful);
      }
    }

    boolean succ = publisherModule.publishCaRevoked(revocationInfo);
    if (!succ) {
      throw new OperationException(SYSTEM_FAILURE, "could not publish event caRevoked of "
          + "CA " + caIdent + " to at least one publisher");
    }
  } // method revokeCa

  public void unrevokeCa(String msgId) throws OperationException {
    caInfo.setRevocationInfo(null);
    if (caInfo.isSelfSigned()) {
      AuditEvent event = newPerfAuditEvent(TYPE_unrevoke_cert, msgId);
      boolean successful = false;
      try {
        unrevokeCert0(caInfo.getSerialNumber(), true, event);
        successful = true;
      } finally {
        finish(event, successful);
      }
    }

    boolean succ = publisherModule.publishCaUnrevoked();
    if (!succ) {
      throw new OperationException(SYSTEM_FAILURE, "could not event caUnrevoked of CA " + caIdent
          + " to at least one publisher");
    }

  } // method unrevokeCa

  private int revokeSuspendedCerts() throws OperationException {
    LOG.debug("revoking suspended certificates");
    AuditEvent event = newPerfAuditEvent(TYPE_revoke_suspendedCert, MSGID_ca_routine);
    boolean successful = false;
    try {
      int num = revokeSuspendedCerts0();
      LOG.info("revoked {} suspended certificates of CA {}", num, caIdent.getName());
      successful = true;
      return num;
    } finally {
      finish(event, successful);
    }
  }

  private int revokeSuspendedCerts0() throws OperationException {
    if (!masterMode) {
      throw new OperationException(NOT_PERMITTED,
          "CA could not remove expired certificates in slave mode");
    }

    final int numEntries = 100;

    Validity val = caInfo.revokeSuspendedCertsControl().getUnchangedSince();
    long ms;
    switch (val.getUnit()) {
      case MINUTE:
        ms = val.getValidity() * MS_PER_MINUTE;
        break;
      case HOUR:
        ms = val.getValidity() * MS_PER_HOUR;
        break;
      case DAY:
        ms = val.getValidity() * MS_PER_DAY;
        break;
      case WEEK:
        ms = val.getValidity() * MS_PER_WEEK;
        break;
      case YEAR:
        ms = val.getValidity() * 365 * MS_PER_DAY;
        break;
      default:
        throw new IllegalStateException(
            "should not reach here, unknown Validity Unit " + val.getUnit());
    }
    final long latestLastUpdatedAt = (System.currentTimeMillis() - ms) / 1000; // seconds
    final CrlReason reason = caInfo.revokeSuspendedCertsControl().getTargetReason();

    int sum = 0;
    while (true) {
      List<SerialWithId> serials =
          certstore.getSuspendedCertSerials(caIdent, latestLastUpdatedAt, numEntries);
      if (CollectionUtil.isEmpty(serials)) {
        return sum;
      }

      for (SerialWithId serial : serials) {
        boolean revoked;
        try {
          revoked = revokeSuspendedCert(serial, reason) != null;
          if (revoked) {
            sum++;
          }
        } catch (OperationException ex) {
          LOG.info("revoked {} suspended certificates of CA {}", sum, caIdent.getName());
          LogUtil.error(LOG, ex, "could not revoke suspended certificate with serial" + serial);
          throw ex;
        } // end try
      } // end for
    } // end while (true)
  } // method removeExpirtedCerts

  @Override
  public void close() {
    if (suspendedCertsRevoker != null) {
      suspendedCertsRevoker.cancel(false);
      suspendedCertsRevoker = null;
    }
  }

}
