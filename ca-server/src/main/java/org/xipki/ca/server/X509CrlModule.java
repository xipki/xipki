// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.OIDs;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.OperationException;
import org.xipki.security.pkix.CrlReason;
import org.xipki.security.pkix.KeyUsage;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.pkix.X509Crl;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.sign.Signer;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.audit.AuditEvent;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.type.HourMinute;

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.xipki.ca.sdk.CaAuditConstants.NAME_basecrl_number;
import static org.xipki.ca.sdk.CaAuditConstants.NAME_crl_number;
import static org.xipki.ca.sdk.CaAuditConstants.NAME_crl_type;
import static org.xipki.ca.sdk.CaAuditConstants.NAME_next_update;
import static org.xipki.ca.sdk.CaAuditConstants.NAME_num;
import static org.xipki.ca.sdk.CaAuditConstants.TYPE_cleanup_crl;
import static org.xipki.ca.sdk.CaAuditConstants.TYPE_downlaod_crl4number;
import static org.xipki.ca.sdk.CaAuditConstants.TYPE_download_crl;
import static org.xipki.ca.sdk.CaAuditConstants.TYPE_gen_crl;
import static org.xipki.security.exception.ErrorCode.CRL_FAILURE;
import static org.xipki.security.exception.ErrorCode.INVALID_EXTENSION;
import static org.xipki.security.exception.ErrorCode.NOT_PERMITTED;
import static org.xipki.security.exception.ErrorCode.SYSTEM_FAILURE;
import static org.xipki.security.exception.ErrorCode.SYSTEM_UNAVAILABLE;

/**
 * X509CA CRL module.
 *
 * @author Lijun Liao (xipki)
 */

public class X509CrlModule extends X509CaModule implements Closeable {

  private class CrlGenerationService implements Runnable {

    @Override
    public void run() {
      CrlControl crlControl = caInfo.crlControl();
      if (crlControl == null) {
        return;
      }

      if (crlGenInProcess.get()) {
        return;
      }

      crlGenInProcess.set(true);

      try {
        run0();
      } catch (Throwable th) {
        LogUtil.error(LOG, th);
      } finally {
        crlGenInProcess.set(false);
      }
    } // method run

    private void run0() throws OperationException {
      CrlControl control = caInfo.crlControl();
      // In seconds
      long lastIssueTimeOfFullCrl =
          certstore.getThisUpdateOfCurrentCrl(caIdent, false);
      Instant now = Instant.now();

      boolean createFullCrlNow;
      if (lastIssueTimeOfFullCrl == 0L) {
        // still no CRL available. Create a new FullCRL
        createFullCrlNow = true;
      } else {
        Instant nearestScheduledCrlIssueTime = getScheduledCrlGenTimeNotAfter(
            Instant.ofEpochSecond(lastIssueTimeOfFullCrl));
        Instant nextScheduledCrlIssueTime = nearestScheduledCrlIssueTime.plus(
            (long) control.fullCrlIntervals() * control.intervalHours(),
            ChronoUnit.HOURS);
        // whether the next scheduled CRL should be generated before now.
        createFullCrlNow = nextScheduledCrlIssueTime.isBefore(now);

        if (createFullCrlNow) {
          // delay: shardId * 10 seconds
          if (Duration.between(nextScheduledCrlIssueTime, now).getSeconds()
              < shardId * 10L) {
            // wait, other instances with lower shardId may also generate the
            // CRL.
            createFullCrlNow = false;
          }
        }
      }

      boolean createDeltaCrlNow = false;
      if (control.deltaCrlIntervals() > 0 && !createFullCrlNow) {
        // if no CRL will be issued, check whether it is time to generate
        // DeltaCRL. In seconds
        long lastIssueTimeOfDeltaCrl =
            certstore.getThisUpdateOfCurrentCrl(caIdent, true);
        long lastIssueTime =
            Math.max(lastIssueTimeOfDeltaCrl, lastIssueTimeOfFullCrl);

        Instant nearestScheduledCrlIssueTime = getScheduledCrlGenTimeNotAfter(
            Instant.ofEpochSecond(lastIssueTime));

        Instant nextScheduledCrlIssueTime = nearestScheduledCrlIssueTime.plus(
            (long) control.deltaCrlIntervals() * control.intervalHours(),
            ChronoUnit.HOURS);
        // whether the next scheduled CRL should be generated before now.
        createDeltaCrlNow = nextScheduledCrlIssueTime.isBefore(now);

        if (createDeltaCrlNow) {
          // delay: shardId * 10 seconds
          if (Duration.between(nextScheduledCrlIssueTime, now).getSeconds()
              < shardId * 10L) {
            // wait, other instances with lower shardId may also generate the
            // CRL.
            createDeltaCrlNow = false;
          }
        }
      }

      if (!(createFullCrlNow || createDeltaCrlNow)) {
        LOG.debug("No CRL is needed to be created");
        return;
      }

      int intervals;
      if (createDeltaCrlNow) {
        intervals = control.deltaCrlIntervals();
      } else {
        if (!control.isExtendedNextUpdate()
            && control.deltaCrlIntervals() > 0) {
          intervals = control.deltaCrlIntervals();
        } else {
          intervals = control.fullCrlIntervals();
        }
      }

      Instant scheduledCrlGenTime = getScheduledCrlGenTimeNotAfter(now);
      Instant nextUpdate = scheduledCrlGenTime.plus(
          (long) intervals * control.intervalHours(),
          ChronoUnit.HOURS);
      // add overlap
      nextUpdate = control.overlap().add(nextUpdate);

      try {
        scheduledGenerateCrl(createDeltaCrlNow, now, nextUpdate);
      } catch (Throwable th) {
        LogUtil.error(LOG, th);
      }
    } // method run0

  } // class CrlGenerationService

  private final X509Cert caCert;

  private final int shardId;

  private final CertStore certstore;

  private final CaManagerImpl caManager;

  private final AtomicBoolean crlGenInProcess = new AtomicBoolean(false);

  private ScheduledFuture<?> crlGenerationService;

  private final X509PublisherModule publisher;

  X509CrlModule(CaManagerImpl caManager, CaInfo caInfo,
                CertStore certstore, X509PublisherModule publisher)
      throws OperationException {
    super(caInfo);

    this.shardId = caManager.shardId();
    this.publisher = publisher;
    this.caManager = Args.notNull(caManager, "caManager");
    this.caCert = caInfo.cert();
    this.certstore = Args.notNull(certstore, "certstore");

    if (caInfo.crlControl() != null) {
      X509Cert crlSignerCert;
      if (caInfo.crlSignerName() != null) {
        crlSignerCert = getCrlSigner().certificate();
      } else {
        // CA signs the CRL
        crlSignerCert = caCert;
      }

      if (!crlSignerCert.hasKeyusage(KeyUsage.cRLSign)) {
        final String msg = "CRL signer does not have keyusage cRLSign";
        LOG.error(msg);
        throw new OperationException(SYSTEM_FAILURE, msg);
      }
    }

    Random random = new Random();
    ScheduledThreadPoolExecutor executor =
        caManager.scheduledThreadPoolExecutor();
    // CRL generation services
    this.crlGenerationService = executor.scheduleAtFixedRate(
        new CrlGenerationService(),
        60 + random.nextInt(60), 60, TimeUnit.SECONDS);
  } // constructor

  @Override
  public void close() {
    if (crlGenerationService != null) {
      crlGenerationService.cancel(false);
      crlGenerationService = null;
    }
  }

  public X509Crl getCurrentCrl(RequestorInfo requstor)
      throws OperationException {
    return getCrl(requstor, null);
  }

  public X509Crl getCrl(RequestorInfo requestor, BigInteger crlNumber)
      throws OperationException {
    LOG.info("     START getCrl: ca={}, crlNumber={}",
        caIdent.name(), crlNumber);
    boolean successful = false;

    AuditEvent event = newAuditEvent(crlNumber == null ? TYPE_download_crl
        : TYPE_downlaod_crl4number, requestor);

    if (crlNumber != null) {
      event.addEventData(NAME_crl_number, crlNumber);
    }

    try {
      byte[] encodedCrl = certstore.getEncodedCrl(caIdent, crlNumber);
      if (encodedCrl == null) {
        return null;
      }

      try {
        X509Crl crl = X509Util.parseCrl(encodedCrl);
        successful = true;
        if (LOG.isInfoEnabled()) {
          LOG.info("SUCCESSFUL getCrl: ca={}, thisUpdate={}",
              caIdent.name(), crl.thisUpdate());
        }
        return crl;
      } catch (CRLException | RuntimeException ex) {
        throw new OperationException(SYSTEM_FAILURE, ex);
      }
    } finally {
      if (!successful) {
        LOG.info("    FAILED getCrl: ca={}", caIdent.name());
      }
      finish(event, successful);
    }
  } // method getCrl

  public CertificateList getBcCurrentCrl(RequestorInfo requestor)
      throws OperationException {
    return getBcCrl(requestor, null);
  }

  public CertificateList getBcCrl(RequestorInfo requestor, BigInteger crlNumber)
      throws OperationException {
    LOG.info("     START getCrl: ca={}, crlNumber={}",
        caIdent.name(), crlNumber);
    boolean successful = false;

    AuditEvent event0 = newAuditEvent(crlNumber == null ? TYPE_download_crl
        : TYPE_downlaod_crl4number, requestor);

    if (crlNumber != null) {
      event0.addEventData(NAME_crl_number, crlNumber);
    }

    try {
      byte[] encodedCrl = certstore.getEncodedCrl(caIdent, crlNumber);
      if (encodedCrl == null) {
        return null;
      }

      try {
        CertificateList crl = CertificateList.getInstance(encodedCrl);
        successful = true;
        if (LOG.isInfoEnabled()) {
          LOG.info("SUCCESSFUL getCrl: ca={}, thisUpdate={}",
              caIdent.name(), crl.getThisUpdate().getTime());
        }
        return crl;
      } catch (RuntimeException ex) {
        throw new OperationException(SYSTEM_FAILURE, ex);
      }
    } finally {
      if (!successful) {
        LOG.info("    FAILED getCrl: ca={}", caIdent.name());
      }
      finish(event0, successful);
    }
  } // method getCrl

  private void cleanupCrlsWithoutException() {
    try {
      int numCrls = caInfo.numCrls();
      LOG.info("     START cleanupCrls: ca={}, numCrls={}",
          caIdent.name(), numCrls);

      AuditEvent event0 = newAuditEvent(TYPE_cleanup_crl, null);
      boolean succ = false;
      try {
        int num = (numCrls <= 0) ? 0
            : certstore.cleanupCrls(caIdent, caInfo.numCrls());
        succ = true;
        event0.addEventData(NAME_num, num);
        LOG.info("SUCCESSFUL cleanupCrls: ca={}, num={}",
            caIdent.name(), num);
      } finally {
        if (!succ) {
          LOG.info("    FAILED cleanupCrls: ca={}", caIdent.name());
        }
        finish(event0, succ);
      }
    } catch (Throwable th) {
      LOG.warn("could not cleanup CRLs.{}: {}",
          th.getClass().getName(), th.getMessage());
    }
  }

  public X509Crl generateCrlOnDemand(RequestorInfo requestor)
      throws OperationException {
    CrlControl control = Optional.ofNullable(caInfo.crlControl())
        .orElseThrow(() -> new OperationException(
            NOT_PERMITTED, "CA could not generate CRL"));

    if (crlGenInProcess.get()) {
      throw new OperationException(SYSTEM_UNAVAILABLE, "TRY_LATER");
    }

    crlGenInProcess.set(true);
    try {
      Instant thisUpdate = Instant.now();
      Instant nearestScheduledIssueTime =
          getScheduledCrlGenTimeNotAfter(thisUpdate);

      int intervals;
      if (!control.isExtendedNextUpdate()
          && control.deltaCrlIntervals() > 0) {
        intervals = control.deltaCrlIntervals();
      } else {
        intervals = control.fullCrlIntervals();
      }

      Instant nextUpdate = nearestScheduledIssueTime.plus(
          (long) intervals * control.intervalHours(),
          ChronoUnit.HOURS);
      // add overlap
      nextUpdate = control.overlap().add(nextUpdate);

      return generateCrl(false, requestor, false, thisUpdate, nextUpdate);
    } finally {
      crlGenInProcess.set(false);
    }
  } // method generateCrlOnDemand

  private void scheduledGenerateCrl(
      boolean deltaCrl, Instant thisUpdate, Instant nextUpdate)
      throws OperationException {
    AuditEvent event = newAuditEvent(TYPE_gen_crl, null);
    try {
      generateCrl0(true, deltaCrl, thisUpdate, nextUpdate, event);
      finish(event, true);
    } catch (OperationException ex) {
      finish(event, false);
      throw ex;
    }
  }

  private X509Crl generateCrl(
      boolean scheduled, RequestorInfo requestor, boolean deltaCrl,
      Instant thisUpdate, Instant nextUpdate)
      throws OperationException {
    AuditEvent event = newAuditEvent(TYPE_gen_crl, requestor);
    try {
      X509Crl ret = generateCrl0(scheduled, deltaCrl, thisUpdate,
                    nextUpdate, event);
      finish(event, true);
      return ret;
    } catch (OperationException ex) {
      finish(event, false);
      throw ex;
    }
  }

  private X509Crl generateCrl0(
      boolean scheduled, boolean deltaCrl,
      Instant thisUpdate, Instant nextUpdate, AuditEvent event)
      throws OperationException {
    CrlControl control = Optional.ofNullable(caInfo.crlControl())
        .orElseThrow(() -> new OperationException(
            NOT_PERMITTED, "CRL generation is not allowed"));

    BigInteger baseCrlNumber = null;
    if (deltaCrl) {
      baseCrlNumber = Optional.ofNullable(caInfo.getMaxFullCrlNumber())
          .orElseThrow(() -> new OperationException(SYSTEM_FAILURE,
              "Should not happen. No FullCRL is available while " +
              "generating DeltaCRL"));
    }

    LOG.info("     START generateCrl: ca={}, deltaCRL={}, thisUpdate={}, " +
            "nextUpdate={}, baseCRLNumber={}",
        caIdent.name(), deltaCrl, thisUpdate, nextUpdate,
        deltaCrl ? baseCrlNumber : "-");
    event.addEventData(NAME_crl_type, (deltaCrl ? "DELTA_CRL" : "FULL_CRL"));

    if (nextUpdate == null) {
      event.addEventData(NAME_next_update, "null");
    } else {
      event.addEventData(NAME_next_update,
          DateUtil.toUtcTimeyyyyMMddhhmmss(nextUpdate));
      if (nextUpdate.getEpochSecond() - thisUpdate.getEpochSecond() < 10 * 60) {
        // less than 10 minutes
        throw new OperationException(CRL_FAILURE,
            "nextUpdate and thisUpdate are too close");
      }
    }

    boolean successful = false;

    try {
      SignerEntry crlSigner = getCrlSigner();
      PublicCaInfo pci = caInfo.publicCaInfo();

      boolean indirectCrl = (crlSigner != null);
      X500Name crlIssuer = indirectCrl
          ? crlSigner.certificate().subject()
          : pci.subject();

      X509v2CRLBuilder crlBuilder =
          new X509v2CRLBuilder(crlIssuer, Date.from(thisUpdate));
      if (nextUpdate != null) {
        crlBuilder.setNextUpdate(Date.from(nextUpdate));
      }

      final int numEntries = 100;

      CrlControl crlControl = caInfo.crlControl();

      boolean withExpiredCerts = crlControl.isIncludeExpiredcerts();

      // 10 minutes buffer
      Instant notExpiredAt = withExpiredCerts
          ? Instant.ofEpochSecond(0)
          : thisUpdate.minus(600L, ChronoUnit.SECONDS);

      // we have to cache the serial entries to sort them
      List<CertRevInfoWithSerial> allRevInfos = new LinkedList<>();

      if (deltaCrl) {
        allRevInfos = certstore.getCertsForDeltaCrl(
            caIdent, baseCrlNumber, notExpiredAt);
      } else {
        long startId = 1;

        List<CertRevInfoWithSerial> revInfos;
        do {
          revInfos = certstore.getRevokedCerts(caIdent, notExpiredAt,
              startId, numEntries);

          allRevInfos.addAll(revInfos);

          long maxId = 1;
          for (CertRevInfoWithSerial revInfo : revInfos) {
            if (revInfo.id() > maxId) {
              maxId = revInfo.id();
            }
          } // end for
          startId = maxId + 1;
        } while (revInfos.size() >= numEntries); // end do

        revInfos.clear();
      }

      if (indirectCrl && allRevInfos.isEmpty()) {
        // add dummy entry, see https://github.com/xipki/xipki/issues/189
        Extensions extensions = new Extensions(
            createCertificateIssuerExtension(pci.subject()));

        crlBuilder.addCRLEntry(BigInteger.ZERO, new Date(0), extensions);
        LOG.debug("added cert ca={} serial=0 to the indirect CRL", caIdent);
      } else {
        // sort the list by SerialNumber ASC
        Collections.sort(allRevInfos);

        boolean isFirstCrlEntry = true;

        for (CertRevInfoWithSerial revInfo : allRevInfos) {
          CrlReason reason = revInfo.reason();
          if (crlControl.isExcludeReason()
              && reason != CrlReason.REMOVE_FROM_CRL) {
            reason = CrlReason.UNSPECIFIED;
          }

          Instant revocationTime = revInfo.revocationTime();
          Instant invalidityTime = revInfo.invalidityTime();

          switch (crlControl.invalidityDateMode()) {
            case forbidden:
              invalidityTime = null;
              break;
            case optional:
              break;
            case required:
              if (invalidityTime == null) {
                invalidityTime = revocationTime;
              }
              break;
            default:
              throw new IllegalStateException("unknown TripleState "
                  + crlControl.invalidityDateMode());
          }

          BigInteger serial = revInfo.serial();
          LOG.debug("added cert ca={} serial={} to CRL", caIdent, serial);

          if (!indirectCrl || !isFirstCrlEntry) {
            if (invalidityTime != null) {
              crlBuilder.addCRLEntry(serial, Date.from(revocationTime),
                  reason.code(), Date.from(invalidityTime));
            } else {
              crlBuilder.addCRLEntry(serial,
                  Date.from(revocationTime), reason.code());
            }
            continue;
          }

          List<Extension> extensions = new ArrayList<>(3);
          if (reason != CrlReason.UNSPECIFIED) {
            Extension ext = createReasonExtension(reason.code());
            extensions.add(ext);
          }
          if (invalidityTime != null) {
            Extension ext = createInvalidityDateExtension(invalidityTime);
            extensions.add(ext);
          }

          Extension ext = createCertificateIssuerExtension(pci.subject());
          extensions.add(ext);

          crlBuilder.addCRLEntry(serial, Date.from(revocationTime),
              new Extensions(extensions.toArray(new Extension[0])));
          isFirstCrlEntry = false;
        }

        allRevInfos.clear(); // free the memory
      }

      BigInteger crlNumber = caInfo.nextCrlNumber();
      event.addEventData(NAME_crl_number, crlNumber);
      if (baseCrlNumber != null) {
        event.addEventData(NAME_basecrl_number, baseCrlNumber);
      }

      try {
        // AuthorityKeyIdentifier
        byte[] akiValues = indirectCrl
            ? crlSigner.certificate().subjectKeyId()
            : pci.subjectKeyIdentifier();
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(akiValues);
        crlBuilder.addExtension(OIDs.Extn.authorityKeyIdentifier, false, aki);

        // add extension CRL Number
        crlBuilder.addExtension(OIDs.Extn.cRLNumber, false,
            new ASN1Integer(crlNumber));

        // IssuingDistributionPoint
        if (indirectCrl) {
          IssuingDistributionPoint idp = new IssuingDistributionPoint(
              null, // distributionPoint,
              false, // onlyContainsUserCerts,
              false, // onlyContainsCACerts,
              null, // onlySomeReasons,
              true, // indirectCRL,
              false); // onlyContainsAttributeCerts

          crlBuilder.addExtension(OIDs.Extn.issuingDistributionPoint,
              true, idp);
        }

        // Delta CRL Indicator
        if (deltaCrl) {
          crlBuilder.addExtension(OIDs.Extn.deltaCRLIndicator, true,
              new ASN1Integer(baseCrlNumber));
        }

        // freshestCRL
        List<String> deltaCrlUris = pci.caUris().deltaCrlUris();
        if (control.deltaCrlIntervals() > 0
            && CollectionUtil.isNotEmpty(deltaCrlUris)) {
          CRLDistPoint cdp = CaUtil.createCrlDistributionPoints(
              deltaCrlUris, pci.subject(), crlIssuer);

          crlBuilder.addExtension(OIDs.Extn.freshestCRL, false, cdp);
        }

        if (withExpiredCerts) {
          DERGeneralizedTime statusSince =
              new DERGeneralizedTime(Date.from(caCert.notBefore()));
          crlBuilder.addExtension(OIDs.Extn.expiredCertsOnCRL,
              false, statusSince);
        }
      } catch (CertIOException ex) {
        LogUtil.error(LOG, ex, "crlBuilder.addExtension");
        throw new OperationException(INVALID_EXTENSION, ex);
      }

      ConcurrentSigner concurrentSigner = (crlSigner == null)
          ? caInfo.getSigner(null) : crlSigner.signer();

      Signer signer0;
      try {
        signer0 = concurrentSigner.borrowSigner();
      } catch (NoIdleSignerException ex) {
        throw new OperationException(SYSTEM_FAILURE,
            "NoIdleSignerException: " + ex.getMessage());
      }

      X509Crl crl;
      try {
        crl = new X509Crl(crlBuilder.build(signer0.x509Signer()));
      } finally {
        concurrentSigner.requiteSigner(signer0);
      }

      // check again
      if (scheduled) {
        long lastIssueTimeOfFullCrl =
            certstore.getThisUpdateOfCurrentCrl(caIdent, deltaCrl);
        if (lastIssueTimeOfFullCrl > thisUpdate.getEpochSecond() - 10) {
          // CRL generated in the last time by other instance, ignore my own.
          successful = true;
          LOG.info("IGNORE generateCrl: ca={}", caIdent.name());
          return null;
        }
      }

      caInfo.setNextCrlNumber(crlNumber.longValue() + 1);
      caManager.commitNextCrlNo(caIdent, caInfo.getNextCrlNumber());
      publisher.publishCrl(crl);

      successful = true;
      LOG.info("SUCCESSFUL generateCrl: ca={}, crlNumber={}, thisUpdate={}",
          caIdent.name(), crlNumber, crl.thisUpdate());

      if (!deltaCrl) {
        // clean up the CRL
        cleanupCrlsWithoutException();
      }
      return crl;
    } finally {
      if (!successful) {
        LOG.info("    FAILED generateCrl: ca={}", caIdent.name());
      }
    }
  } // method generateCrl

  /**
   * Gets the nearest scheduled CRL generation time which is not after the
   * given {@code time}.
   *
   * @param date the reference time
   * @return the nearest scheduled time
   */
  private Instant getScheduledCrlGenTimeNotAfter(Instant date) {
    ZonedDateTime cal = ZonedDateTime.ofInstant(date, ZoneOffset.UTC);
    // time less than one day
    int minutesInDay = cal.getHour() * 60 + cal.getMinute();
    int intervalMinutes = caInfo.crlControl().intervalHours() * 60;

    HourMinute hm = caInfo.crlControl().intervalDayTime();
    int hmInMinutes = hm.hour() * 60 + hm.minute();

    Instant midNight = ZonedDateTime.of(cal.getYear(), cal.getMonthValue(),
        cal.getDayOfMonth(), 0, 0, 0, 0,
        cal.getZone()).toInstant();

    if (minutesInDay == hmInMinutes) {
      // If time == hm
      return midNight.plus(hmInMinutes, ChronoUnit.MINUTES);
    } else if (minutesInDay < hmInMinutes) {
      // If time is before hm, use the previous interval
      return midNight.plus(hmInMinutes - intervalMinutes,
          ChronoUnit.MINUTES);
    } else {
      // If time is after hm, use the nearest interval before reference time
      for (int i = 0;;i++) {
        if (minutesInDay < (hmInMinutes + (i + 1) * intervalMinutes)) {
          return midNight.plus(hmInMinutes +
              (long) i * intervalMinutes, ChronoUnit.MINUTES);
        }
      }
    }
  }

  SignerEntry getCrlSigner() {
    if (caInfo.crlControl() == null) {
      return null;
    }

    String crlSignerName = caInfo.crlSignerName();
    return (crlSignerName == null) ? null
        : caManager.getSignerWrapper(crlSignerName);
  }

  boolean healthy() {
    SignerEntry signer = getCrlSigner();
    if (signer != null) {
      return signer.signerIsHealthy();
    }
    return true;
  }

  private static Extension createReasonExtension(int reasonCode) {
    CRLReason crlReason = CRLReason.lookup(reasonCode);
    try {
      return new Extension(OIDs.Extn.reasonCode, false, crlReason.getEncoded());
    } catch (IOException ex) {
      throw new IllegalArgumentException(
          "error encoding reason: " + ex.getMessage(), ex);
    }
  }

  private static Extension createInvalidityDateExtension(
      Instant invalidityDate) {
    try {
      ASN1GeneralizedTime asnTime =
          new ASN1GeneralizedTime(Date.from(invalidityDate));
      return new Extension(OIDs.Extn.invalidityDate, false,
          asnTime.getEncoded());
    } catch (IOException ex) {
      throw new IllegalArgumentException(
          "error encoding reason: " + ex.getMessage(), ex);
    }
  }

  private static Extension createCertificateIssuerExtension(
      X500Name certificateIssuer) {
    try {
      GeneralNames generalNames =
          new GeneralNames(new GeneralName(certificateIssuer));
      return new Extension(OIDs.Extn.certificateIssuer, true,
          generalNames.getEncoded());
    } catch (IOException ex) {
      throw new IllegalArgumentException(
          "error encoding reason: " + ex.getMessage(), ex);
    }
  }

}
