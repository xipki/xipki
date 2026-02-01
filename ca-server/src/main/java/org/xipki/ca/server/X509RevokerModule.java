// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.ca.server.CertStore.SerialWithId;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.exception.ErrorCode;
import org.xipki.security.exception.OperationException;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.audit.AuditEvent;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.extra.type.Validity.Unit;

import java.io.Closeable;
import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.xipki.ca.sdk.CaAuditConstants.NAME_invalidity_time;
import static org.xipki.ca.sdk.CaAuditConstants.NAME_reason;
import static org.xipki.ca.sdk.CaAuditConstants.NAME_serial;
import static org.xipki.ca.sdk.CaAuditConstants.TYPE_revoke_ca;
import static org.xipki.ca.sdk.CaAuditConstants.TYPE_revoke_suspendedCert;
import static org.xipki.ca.sdk.CaAuditConstants.TYPE_suspend_ca;
import static org.xipki.ca.sdk.CaAuditConstants.TYPE_unsuspend_ca;

/**
 * X509CA revoker module.
 *
 * @author Lijun Liao (xipki)
 */

public class X509RevokerModule extends X509CaModule implements Closeable {

  private class SuspendedCertsRevoker implements Runnable {

    private boolean inProcess;

    @Override
    public void run() {
      if (caInfo.revokeSuspendedCertsControl() == null
          || !caInfo.revokeSuspendedCertsControl().isEnabled()) {
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
          LOG.debug("revoked {} suspended certificates of CA '{}'",
              num, caIdent);
        } else {
          LOG.info("revoked {} suspended certificates of CA '{}'",
              num, caIdent);
        }
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not revoke suspended certificates");
      } finally {
        inProcess = false;
      }
    } // method run

  } // class SuspendedCertsRevoker

  private static final Logger LOG =
      LoggerFactory.getLogger(X509RevokerModule.class);

  private final boolean masterMode;

  private final CertStore certstore;

  private final CaIdNameMap caIdNameMap;

  private final X509PublisherModule publisherModule;

  private ScheduledFuture<?> suspendedCertsRevoker;

  X509RevokerModule(CaManagerImpl caManager, CaInfo caInfo,
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
        caManager.scheduledThreadPoolExecutor();

    Random random = new Random();
    this.suspendedCertsRevoker = executor.scheduleAtFixedRate(
        new SuspendedCertsRevoker(),
        random.nextInt(60), 60, TimeUnit.MINUTES);
  } // constructor

  public CertWithRevocationInfo revokeCert(
      BigInteger serialNumber, CrlReason reason, Instant invalidityTime,
      AuditEvent event) throws OperationException {
    if (caInfo.isSelfSigned()
        && caInfo.serialNumber().equals(serialNumber)) {
      throw new OperationException(ErrorCode.NOT_PERMITTED,
          "insufficient permission to revoke CA certificate");
    }

    if (reason == null) {
      reason = CrlReason.UNSPECIFIED;
    }

    switch (reason) {
      case CA_COMPROMISE:
      case AA_COMPROMISE:
      case REMOVE_FROM_CRL:
        throw new OperationException(ErrorCode.NOT_PERMITTED,
            "insufficient permission to revoke certificate with reason " +
            reason.description());
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

    boolean successful = true;
    try {
      CertWithRevocationInfo ret = revokeCertificate0(
          serialNumber, reason, invalidityTime, false, event);
      successful = (ret != null);
      return ret;
    } finally {
      setEventStatus(event, successful);
    }
  } // method revokeCertificate

  public CertWithDbId unsuspendCert(BigInteger serialNumber, AuditEvent event)
      throws OperationException {
    if (caInfo.isSelfSigned()
        && caInfo.serialNumber().equals(serialNumber)) {
      throw new OperationException(ErrorCode.NOT_PERMITTED,
          "insufficient permission to unsuspend CA certificate");
    }

    boolean successful = false;
    try {
      CertWithDbId ret = unsuspendCert0(serialNumber, false, event);
      successful = true;
      return ret;
    } finally {
      setEventStatus(event, successful);
    }
  } // method unsuspendCert

  private CertWithRevocationInfo revokeCertificate0(
      BigInteger serialNumber, CrlReason reason, Instant invalidityTime,
      boolean force, AuditEvent event)
      throws OperationException {
    String hexSerial = LogUtil.formatCsn(serialNumber);
    event.addEventData(NAME_serial, hexSerial);
    event.addEventData(NAME_reason, reason.description());
    if (invalidityTime != null) {
      event.addEventData(NAME_invalidity_time,
          DateUtil.toUtcTimeyyyyMMddhhmmss(invalidityTime));
    }

    LOG.info("     START revokeCertificate: ca={}, serialNumber={}, " +
            "reason={}, invalidityTime={}",
        caIdent.name(), hexSerial, reason.description(), invalidityTime);

    CertWithRevocationInfo revokedCert;

    CertRevocationInfo revInfo =
        new CertRevocationInfo(reason, Instant.now(), invalidityTime);

    revokedCert = certstore.revokeCert(caIdent, serialNumber, revInfo,
        force, caIdNameMap);

    if (revokedCert == null) {
      return null;
    }

    publisherModule.publishCertRevoked(revokedCert);

    if (LOG.isInfoEnabled()) {
      LOG.info("SUCCESSFUL revokeCertificate: ca={}, serialNumber={}, " +
              "reason={}, invalidityTime={}, revocationResult=REVOKED",
          caIdent.name(), hexSerial, reason.description(),
          invalidityTime);
    }

    return revokedCert;
  } // method revokeCertificate0

  private CertWithRevocationInfo revokeSuspendedCert(
      SerialWithId serialNumber, CrlReason reason) throws OperationException {
    boolean successful = false;
    AuditEvent event = newAuditEvent(TYPE_revoke_suspendedCert, null);
    try {
      CertWithRevocationInfo ret =
          revokeSuspendedCert0(serialNumber, reason, event);
      successful = (ret != null);
      return ret;
    } finally {
      finish(event, successful);
    }
  }

  private CertWithRevocationInfo revokeSuspendedCert0(
      SerialWithId serialNumber, CrlReason reason, AuditEvent event)
      throws OperationException {
    String hexSerial = LogUtil.formatCsn(serialNumber.serial());

    event.addEventData(NAME_serial, hexSerial);
    event.addEventData(NAME_reason, reason.description());

    if (LOG.isInfoEnabled()) {
      LOG.info("     START revokeSuspendedCert: ca={}, serialNumber={}, " +
              "reason={}",
          caIdent.name(), hexSerial, reason.description());
    }

    CertWithRevocationInfo revokedCert = certstore.revokeSuspendedCert(
        caIdent, serialNumber, reason, caIdNameMap);
    if (revokedCert == null) {
      return null;
    }

    publisherModule.publishCertRevoked(revokedCert);

    if (LOG.isInfoEnabled()) {
      LOG.info("SUCCESSFUL revokeSuspendedCert: ca={}, serialNumber={}, " +
              "reason={}",
          caIdent.name(), hexSerial, reason.description());
    }

    return revokedCert;
  } // method revokeSuspendedCert0

  private CertWithDbId unsuspendCert0(
      BigInteger serialNumber, boolean force, AuditEvent event)
      throws OperationException {
    String hexSerial = LogUtil.formatCsn(serialNumber);
    event.addEventData(NAME_serial, hexSerial);

    LOG.info("     START unsuspendertificate: ca={}, serialNumber={}",
        caIdent.name(), hexSerial);

    CertWithDbId unrevokedCert =
        certstore.unsuspendCert(caIdent, serialNumber, force, caIdNameMap);
    if (unrevokedCert == null) {
      return null;
    }

    publisherModule.publishCertUnrevoked(unrevokedCert);

    LOG.info("SUCCESSFUL unsuspendCertificate: ca={}, serialNumber={}",
        caIdent.name(), hexSerial);

    return unrevokedCert;
  } // doUnrevokeCertificate

  public void revokeCa(RequestorInfo requestor,
                       CertRevocationInfo revocationInfo)
      throws OperationException {
    caInfo.setRevocationInfo(Args.notNull(revocationInfo, "revocationInfo"));

    if (caInfo.isSelfSigned()) {
      AuditEvent event = newAuditEvent(
          revocationInfo.reason() == CrlReason.CERTIFICATE_HOLD
              ? TYPE_suspend_ca :TYPE_revoke_ca,
          requestor);
      boolean successful = true;
      try {
        CertWithRevocationInfo ret = revokeCertificate0(
            caInfo.serialNumber(), revocationInfo.reason(),
            revocationInfo.invalidityTime(), true, event);
        successful = (ret != null);
      } finally {
        finish(event, successful);
      }
    }

    boolean succ = publisherModule.publishCaRevoked(revocationInfo);
    if (!succ) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "could not publish event caRevoked of CA " + caIdent +
              " to at least one publisher");
    }
  } // method revokeCa

  public void unrevokeCa(RequestorInfo requestor) throws OperationException {
    caInfo.setRevocationInfo(null);
    if (caInfo.isSelfSigned()) {
      AuditEvent event = newAuditEvent(TYPE_unsuspend_ca, requestor);
      boolean successful = false;
      try {
        unsuspendCert0(caInfo.serialNumber(), true, event);
        successful = true;
      } finally {
        finish(event, successful);
      }
    }

    boolean succ = publisherModule.publishCaUnrevoked();
    if (!succ) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "could not event caUnrevoked of CA " + caIdent +
              " to at least one publisher");
    }

  } // method unrevokeCa

  private int revokeSuspendedCerts() throws OperationException {
    LOG.debug("revoking suspended certificates");
    AuditEvent event = newAuditEvent(TYPE_revoke_suspendedCert, null);
    boolean successful = false;
    try {
      int num = revokeSuspendedCerts0();
      LOG.info("revoked {} suspended certificates of CA {}",
          num, caIdent.name());
      successful = true;
      return num;
    } finally {
      finish(event, successful);
    }
  }

  private int revokeSuspendedCerts0() throws OperationException {
    if (!masterMode) {
      throw new OperationException(ErrorCode.NOT_PERMITTED,
          "CA could not remove expired certificates in slave mode");
    }

    final int numEntries = 100;

    RevokeSuspendedControl control = caInfo.revokeSuspendedCertsControl();

    Validity val = control.unchangedSince();
    int validity = val.validity();
    Unit unit = val.unit();
    long durationMinutes = (unit == Unit.MINUTE) ? validity
        : (unit == Unit.HOUR) ? validity * 60L
        : (unit == Unit.DAY)  ? (long) validity * 24 * 60
        : (unit == Unit.WEEK) ? (long) validity * 7 * 24 * 60
        : (unit == Unit.YEAR) ? (long) validity * 365 * 24 * 60
        : -1;

    if (durationMinutes == -1) {
        throw new IllegalStateException(
            "should not reach here, unknown Validity Unit " + val.unit());
    }

    final Instant latestLastUpdatedAt =
        Instant.now().minus(durationMinutes, ChronoUnit.MINUTES);
    final CrlReason reason = control.targetReason();

    int sum = 0;
    while (true) {
      List<SerialWithId> serials = certstore.getSuspendedCertSerials(
          caIdent, latestLastUpdatedAt, numEntries);

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
          LOG.info("revoked {} suspended certificates of CA {}",
              sum, caIdent.name());
          LogUtil.error(LOG, ex, "could not revoke suspended " +
              "certificate with serial" + serial);
          throw ex;
        } // end try
      } // end for
    } // end while (true)
  } // method revokeSuspendedCerts0

  @Override
  public void close() {
    if (suspendedCertsRevoker != null) {
      suspendedCertsRevoker.cancel(false);
      suspendedCertsRevoker = null;
    }
  }

}
