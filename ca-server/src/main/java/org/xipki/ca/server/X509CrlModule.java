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

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.xipki.audit.AuditEvent;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CrlControl.HourMinute;
import org.xipki.ca.server.db.CertStore;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.KeyUsage;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.DateUtil;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.LogUtil;

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.util.*;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.xipki.ca.api.OperationException.ErrorCode.*;
import static org.xipki.ca.server.CaAuditConstants.*;
import static org.xipki.util.Args.notNull;

/**
 * X509CA CRL module.
 *
 * @author Lijun Liao
 */

public class X509CrlModule extends X509CaModule implements Closeable {

  private class CrlGenerationService implements Runnable {

    @Override
    public void run() {
      CrlControl crlControl = caInfo.getCrlControl();
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
      CrlControl control = caInfo.getCrlControl();
      // In seconds
      long lastIssueTimeOfFullCrl = certstore.getThisUpdateOfCurrentCrl(caIdent, false);
      Date now = new Date();

      boolean createFullCrlNow = false;
      if (lastIssueTimeOfFullCrl == 0L) {
        // still no CRL available. Create a new FullCRL
        createFullCrlNow = true;
      } else {
        Date nearestScheduledCrlIssueTime = getScheduledCrlGenTimeNotAfter(
            new Date(lastIssueTimeOfFullCrl * 1000));
        Date nextScheduledCrlIssueTime = new Date(
            nearestScheduledCrlIssueTime.getTime() + control.getFullCrlIntervals() * MS_PER_DAY);
        if (!nextScheduledCrlIssueTime.after(now)) {
          // at least one interval was skipped
          createFullCrlNow = true;
        }
      }

      boolean createDeltaCrlNow = false;
      if (control.getDeltaCrlIntervals() > 0 && !createFullCrlNow) {
        // if no CRL will be issued, check whether it is time to generate DeltaCRL
        // In seconds
        long lastIssueTimeOfDeltaCrl = certstore.getThisUpdateOfCurrentCrl(caIdent, true);
        long lastIssueTime = Math.max(lastIssueTimeOfDeltaCrl, lastIssueTimeOfFullCrl);

        Date nearestScheduledCrlIssueTime = getScheduledCrlGenTimeNotAfter(
            new Date(lastIssueTime * 1000));
        Date nextScheduledCrlIssueTime = new Date(
            nearestScheduledCrlIssueTime.getTime() + control.getDeltaCrlIntervals() * MS_PER_DAY);
        if (!nextScheduledCrlIssueTime.after(now)) {
          // at least one interval was skipped
          createDeltaCrlNow = true;
        }
      }

      if (!(createFullCrlNow || createDeltaCrlNow)) {
        LOG.debug("No CRL is needed to be created");
        return;
      }

      int intervals;
      if (createDeltaCrlNow) {
        intervals = control.getDeltaCrlIntervals();
      } else {
        if (!control.isExtendedNextUpdate() && control.getDeltaCrlIntervals() > 0) {
          intervals = control.getDeltaCrlIntervals();
        } else {
          intervals = control.getFullCrlIntervals();
        }
      }

      Date nextUpdate =
          new Date(getScheduledCrlGenTimeNotAfter(now).getTime()
              + (intervals + control.getOverlapDays()) * MS_PER_DAY);

      try {
        generateCrl(createDeltaCrlNow, now, nextUpdate, MSGID_ca_routine);
      } catch (Throwable th) {
        LogUtil.error(LOG, th);
      }
    } // method run0

  } // class CrlGenerationService

  private final X509Cert caCert;

  private final CertStore certstore;

  private final CaManagerImpl caManager;

  private final AtomicBoolean crlGenInProcess = new AtomicBoolean(false);

  private ScheduledFuture<?> crlGenerationService;

  private final X509PublisherModule publisher;

  public X509CrlModule(CaManagerImpl caManager, CaInfo caInfo, CertStore certstore,
      X509PublisherModule publisher) throws OperationException {
    super(caInfo);

    this.publisher = publisher;
    this.caManager = notNull(caManager, "caManager");
    this.caCert = caInfo.getCert();
    this.certstore = notNull(certstore, "certstore");

    if (caInfo.getCrlControl() != null) {
      X509Cert crlSignerCert;
      if (caInfo.getCrlSignerName() != null) {
        crlSignerCert = getCrlSigner().getDbEntry().getCertificate();
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

    if (!caManager.isMasterMode()) {
      return;
    }

    Random random = new Random();
    ScheduledThreadPoolExecutor executor = caManager.getScheduledThreadPoolExecutor();
    // CRL generation services
    this.crlGenerationService = executor.scheduleAtFixedRate(new CrlGenerationService(),
        60 + random.nextInt(60), 60, TimeUnit.SECONDS);
  } // constructor

  @Override
  public void close() {
    if (crlGenerationService != null) {
      crlGenerationService.cancel(false);
      crlGenerationService = null;
    }
  }

  public X509CRLHolder getCurrentCrl(String msgId) throws OperationException {
    return getCrl(null, msgId);
  }

  public X509CRLHolder getCrl(BigInteger crlNumber, String msgId) throws OperationException {
    LOG.info("     START getCrl: ca={}, crlNumber={}", caIdent.getName(), crlNumber);
    boolean successful = false;

    AuditEvent event0 = newPerfAuditEvent(
            crlNumber == null ? TYPE_download_crl : TYPE_downlaod_crl4number, msgId);
    if (crlNumber != null) {
      event0.addEventData(NAME_crl_number, crlNumber);
    }

    try {
      byte[] encodedCrl = certstore.getEncodedCrl(caIdent, crlNumber);
      if (encodedCrl == null) {
        return null;
      }

      try {
        X509CRLHolder crl = X509Util.parseCrl(encodedCrl);
        successful = true;
        if (LOG.isInfoEnabled()) {
          LOG.info("SUCCESSFUL getCrl: ca={}, thisUpdate={}", caIdent.getName(),
              crl.getThisUpdate());
        }
        return crl;
      } catch (CRLException | RuntimeException ex) {
        throw new OperationException(SYSTEM_FAILURE, ex);
      }
    } finally {
      if (!successful) {
        LOG.info("    FAILED getCrl: ca={}", caIdent.getName());
      }
      finish(event0, successful);
    }
  } // method getCrl

  public CertificateList getBcCurrentCrl(String msgId) throws OperationException {
    return getBcCrl(null, msgId);
  }

  public CertificateList getBcCrl(BigInteger crlNumber, String msgId) throws OperationException {
    LOG.info("     START getCrl: ca={}, crlNumber={}", caIdent.getName(), crlNumber);
    boolean successful = false;

    AuditEvent event0 = newPerfAuditEvent(
            crlNumber == null ? TYPE_download_crl : TYPE_downlaod_crl4number, msgId);
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
          LOG.info("SUCCESSFUL getCrl: ca={}, thisUpdate={}", caIdent.getName(),
              crl.getThisUpdate().getTime());
        }
        return crl;
      } catch (RuntimeException ex) {
        throw new OperationException(SYSTEM_FAILURE, ex);
      }
    } finally {
      if (!successful) {
        LOG.info("    FAILED getCrl: ca={}", caIdent.getName());
      }
      finish(event0, successful);
    }
  } // method getCrl

  private void cleanupCrlsWithoutException(String msgId) {
    try {
      int numCrls = caInfo.getNumCrls();
      LOG.info("     START cleanupCrls: ca={}, numCrls={}", caIdent.getName(), numCrls);

      boolean succ = false;
      AuditEvent event0 = newPerfAuditEvent(TYPE_cleanup_crl, msgId);

      try {
        int num = (numCrls <= 0) ? 0 : certstore.cleanupCrls(caIdent, caInfo.getNumCrls());
        succ = true;
        event0.addEventData(NAME_num, num);
        LOG.info("SUCCESSFUL cleanupCrls: ca={}, num={}", caIdent.getName(), num);
      } catch (RuntimeException ex) {
        throw new OperationException(SYSTEM_FAILURE, ex);
      } finally {
        if (!succ) {
          LOG.info("    FAILED cleanupCrls: ca={}", caIdent.getName());
        }
        finish(event0, succ);
      }
    } catch (Throwable th) {
      LOG.warn("could not cleanup CRLs.{}: {}", th.getClass().getName(), th.getMessage());
    }
  }

  public X509CRLHolder generateCrlOnDemand(String msgId) throws OperationException {
    CrlControl control = caInfo.getCrlControl();
    if (control == null) {
      throw new OperationException(NOT_PERMITTED, "CA could not generate CRL");
    }

    if (crlGenInProcess.get()) {
      throw new OperationException(SYSTEM_UNAVAILABLE, "TRY_LATER");
    }

    crlGenInProcess.set(true);
    try {
      Date thisUpdate = new Date();
      Date nearestScheduledIssueTime = getScheduledCrlGenTimeNotAfter(thisUpdate);

      int intervals;
      if (!control.isExtendedNextUpdate() && control.getDeltaCrlIntervals() > 0) {
        intervals = control.getDeltaCrlIntervals();
      } else {
        intervals = control.getFullCrlIntervals();
      }

      Date nextUpdate = new Date(nearestScheduledIssueTime.getTime()
          + (intervals + control.getOverlapDays()) * MS_PER_DAY);

      return generateCrl(false, thisUpdate, nextUpdate, msgId);
    } finally {
      crlGenInProcess.set(false);
    }
  } // method generateCrlOnDemand

  private X509CRLHolder generateCrl(boolean deltaCrl, Date thisUpdate, Date nextUpdate,
      String msgId) throws OperationException {
    boolean successful = false;
    AuditEvent event = newPerfAuditEvent(TYPE_gen_crl, msgId);
    try {
      X509CRLHolder crl = generateCrl0(deltaCrl, thisUpdate, nextUpdate, event, msgId);
      successful = true;
      return crl;
    } finally {
      finish(event, successful);
    }
  }

  private X509CRLHolder generateCrl0(boolean deltaCrl, Date thisUpdate, Date nextUpdate,
      AuditEvent event, String msgId) throws OperationException {
    CrlControl control = caInfo.getCrlControl();
    if (control == null) {
      throw new OperationException(NOT_PERMITTED, "CRL generation is not allowed");
    }

    BigInteger baseCrlNumber = null;
    if (deltaCrl) {
      baseCrlNumber = caInfo.getMaxFullCrlNumber();
      if (baseCrlNumber == null) {
        throw new OperationException(SYSTEM_FAILURE,
            "Should not happen. No FullCRL is available while generating DeltaCRL");
      }
    }

    LOG.info("     START generateCrl: ca={}, deltaCRL={}, nextUpdate={}, baseCRLNumber={}",
        caIdent.getName(), deltaCrl, nextUpdate, deltaCrl ? baseCrlNumber : "-");
    event.addEventData(NAME_crl_type, (deltaCrl ? "DELTA_CRL" : "FULL_CRL"));

    if (nextUpdate == null) {
      event.addEventData(NAME_next_update, "null");
    } else {
      event.addEventData(NAME_next_update,
          DateUtil.toUtcTimeyyyyMMddhhmmss(nextUpdate));
      if (nextUpdate.getTime() - thisUpdate.getTime() < 10 * 60 * MS_PER_SECOND) {
        // less than 10 minutes
        throw new OperationException(CRL_FAILURE, "nextUpdate and thisUpdate are too close");
      }
    }

    boolean successful = false;

    try {
      SignerEntryWrapper crlSigner = getCrlSigner();
      PublicCaInfo pci = caInfo.getPublicCaInfo();

      boolean indirectCrl = (crlSigner != null);
      X500Name crlIssuer = indirectCrl ? crlSigner.getSubject() : pci.getSubject();

      X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crlIssuer, thisUpdate);
      if (nextUpdate != null) {
        crlBuilder.setNextUpdate(nextUpdate);
      }

      final int numEntries = 100;

      CrlControl crlControl = caInfo.getCrlControl();

      boolean withExpiredCerts = crlControl.isIncludeExpiredcerts();

      // 10 minutes buffer
      Date notExpiredAt = withExpiredCerts
                          ? new Date(0) : new Date(thisUpdate.getTime() - 600L * MS_PER_SECOND);

      // we have to cache the serial entries to sort them
      List<CertRevInfoWithSerial> allRevInfos = new LinkedList<>();

      if (deltaCrl) {
        allRevInfos = certstore.getCertsForDeltaCrl(caIdent, baseCrlNumber, notExpiredAt);
      } else {
        long startId = 1;

        List<CertRevInfoWithSerial> revInfos;
        do {
          revInfos = certstore.getRevokedCerts(caIdent, notExpiredAt, startId, numEntries);
          allRevInfos.addAll(revInfos);

          long maxId = 1;
          for (CertRevInfoWithSerial revInfo : revInfos) {
            if (revInfo.getId() > maxId) {
              maxId = revInfo.getId();
            }
          } // end for
          startId = maxId + 1;
        } while (revInfos.size() >= numEntries); // end do

        revInfos.clear();
      }

      if (indirectCrl && allRevInfos.isEmpty()) {
        // add dummy entry, see https://github.com/xipki/xipki/issues/189
        Extensions extensions = new Extensions(createCertificateIssuerExtension(pci.getSubject()));
        crlBuilder.addCRLEntry(BigInteger.ZERO, new Date(0), extensions);
        LOG.debug("added cert ca={} serial=0 to the indirect CRL", caIdent);
      } else {
        // sort the list by SerialNumber ASC
        Collections.sort(allRevInfos);

        boolean isFirstCrlEntry = true;

        for (CertRevInfoWithSerial revInfo : allRevInfos) {
          CrlReason reason = revInfo.getReason();
          if (crlControl.isExcludeReason() && reason != CrlReason.REMOVE_FROM_CRL) {
            reason = CrlReason.UNSPECIFIED;
          }

          Date revocationTime = revInfo.getRevocationTime();
          Date invalidityTime = revInfo.getInvalidityTime();

          switch (crlControl.getInvalidityDateMode()) {
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
              throw new IllegalStateException(
                  "unknown TripleState " + crlControl.getInvalidityDateMode());
          }

          BigInteger serial = revInfo.getSerial();
          LOG.debug("added cert ca={} serial={} to CRL", caIdent, serial);

          if (!indirectCrl || !isFirstCrlEntry) {
            if (invalidityTime != null) {
              crlBuilder.addCRLEntry(serial, revocationTime, reason.getCode(),
                  invalidityTime);
            } else {
              crlBuilder.addCRLEntry(serial, revocationTime, reason.getCode());
            }
            continue;
          }

          List<Extension> extensions = new ArrayList<>(3);
          if (reason != CrlReason.UNSPECIFIED) {
            Extension ext = createReasonExtension(reason.getCode());
            extensions.add(ext);
          }
          if (invalidityTime != null) {
            Extension ext = createInvalidityDateExtension(invalidityTime);
            extensions.add(ext);
          }

          Extension ext = createCertificateIssuerExtension(pci.getSubject());
          extensions.add(ext);

          crlBuilder.addCRLEntry(serial, revocationTime,
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
            ? crlSigner.getSigner().getCertificate().getSubjectKeyId()
            : pci.getSubjectKeyIdentifer();
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(akiValues);
        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);

        // add extension CRL Number
        crlBuilder.addExtension(Extension.cRLNumber, false, new ASN1Integer(crlNumber));

        // IssuingDistributionPoint
        if (indirectCrl) {
          IssuingDistributionPoint idp = new IssuingDistributionPoint(
              null, // distributionPoint,
              false, // onlyContainsUserCerts,
              false, // onlyContainsCACerts,
              null, // onlySomeReasons,
              true, // indirectCRL,
              false); // onlyContainsAttributeCerts

          crlBuilder.addExtension(Extension.issuingDistributionPoint, true, idp);
        }

        // Delta CRL Indicator
        if (deltaCrl) {
          crlBuilder.addExtension(Extension.deltaCRLIndicator, true,
              new ASN1Integer(baseCrlNumber));
        }

        // freshestCRL
        List<String> deltaCrlUris = pci.getCaUris().getDeltaCrlUris();
        if (control.getDeltaCrlIntervals() > 0 && CollectionUtil.isNotEmpty(deltaCrlUris)) {
          CRLDistPoint cdp = CaUtil.createCrlDistributionPoints(deltaCrlUris, pci.getSubject(),
              crlIssuer);
          crlBuilder.addExtension(Extension.freshestCRL, false, cdp);
        }

        if (withExpiredCerts) {
          DERGeneralizedTime statusSince = new DERGeneralizedTime(caCert.getNotBefore());
          crlBuilder.addExtension(Extension.expiredCertsOnCRL, false, statusSince);
        }
      } catch (CertIOException ex) {
        LogUtil.error(LOG, ex, "crlBuilder.addExtension");
        throw new OperationException(INVALID_EXTENSION, ex);
      }

      @SuppressWarnings("resource")
      ConcurrentContentSigner concurrentSigner = (crlSigner == null)
          ? caInfo.getSigner(null) : crlSigner.getSigner();

      ConcurrentBagEntrySigner signer0;
      try {
        signer0 = concurrentSigner.borrowSigner();
      } catch (NoIdleSignerException ex) {
        throw new OperationException(SYSTEM_FAILURE, "NoIdleSignerException: " + ex.getMessage());
      }

      X509CRLHolder crl;
      try {
        crl = crlBuilder.build(signer0.value());
      } finally {
        concurrentSigner.requiteSigner(signer0);
      }

      caInfo.getCaEntry().setNextCrlNumber(crlNumber.longValue() + 1);
      caManager.commitNextCrlNo(caIdent, caInfo.getCaEntry().getNextCrlNumber());
      publisher.publishCrl(crl);

      successful = true;
      LOG.info("SUCCESSFUL generateCrl: ca={}, crlNumber={}, thisUpdate={}", caIdent.getName(),
          crlNumber, crl.getThisUpdate());

      if (!deltaCrl) {
        // clean up the CRL
        cleanupCrlsWithoutException(msgId);
      }
      return crl;
    } finally {
      if (!successful) {
        LOG.info("    FAILED generateCrl: ca={}", caIdent.getName());
      }
    }
  } // method generateCrl

  /**
   * Gets the nearest scheduled CRL generation time which is not after the given {@code time}.
   * @param time the reference time
   * @return the nearest scheduled time
   */
  private Date getScheduledCrlGenTimeNotAfter(Date time) {
    Calendar cal = Calendar.getInstance(TIMEZONE_UTC);
    cal.setTime(time);
    HourMinute hm =  caInfo.getCrlControl().getIntervalDayTime();
    cal.set(Calendar.HOUR_OF_DAY, hm.getHour());
    cal.set(Calendar.MINUTE, hm.getMinute());
    cal.set(Calendar.SECOND, 0);
    cal.set(Calendar.MILLISECOND, 0);

    long t1 = time.getTime() / 1000;
    long tcal = cal.getTimeInMillis() / 1000;
    return (t1 >= tcal) ? cal.getTime() : new Date(cal.getTimeInMillis() - MS_PER_DAY);
  }

  SignerEntryWrapper getCrlSigner() {
    if (caInfo.getCrlControl() == null) {
      return null;
    }

    String crlSignerName = caInfo.getCrlSignerName();
    if (crlSignerName == null) {
      return null;
    }

    return caManager.getSignerWrapper(crlSignerName);
  }

  boolean healthCheck(HealthCheckResult parentResult) {
    boolean healthy = true;
    SignerEntryWrapper signer = getCrlSigner();
    if (signer != null && signer.getSigner() != null) {
      boolean crlSignerHealthy = signer.isHealthy();
      healthy = crlSignerHealthy;

      HealthCheckResult crlSignerHealth = new HealthCheckResult();
      crlSignerHealth.setName("CRLSigner");
      crlSignerHealth.setHealthy(crlSignerHealthy);
      parentResult.addChildCheck(crlSignerHealth);
    }
    return healthy;
  }

  private static Extension createReasonExtension(int reasonCode) {
    CRLReason crlReason = CRLReason.lookup(reasonCode);
    try {
      return new Extension(Extension.reasonCode, false, crlReason.getEncoded());
    } catch (IOException ex) {
      throw new IllegalArgumentException("error encoding reason: " + ex.getMessage(), ex);
    }
  }

  private static Extension createInvalidityDateExtension(Date invalidityDate) {
    try {
      ASN1GeneralizedTime asnTime = new ASN1GeneralizedTime(invalidityDate);
      return new Extension(Extension.invalidityDate, false, asnTime.getEncoded());
    } catch (IOException ex) {
      throw new IllegalArgumentException("error encoding reason: " + ex.getMessage(), ex);
    }
  }

  private static Extension createCertificateIssuerExtension(X500Name certificateIssuer) {
    try {
      GeneralNames generalNames = new GeneralNames(new GeneralName(certificateIssuer));
      return new Extension(Extension.certificateIssuer, true, generalNames.getEncoded());
    } catch (IOException ex) {
      throw new IllegalArgumentException("error encoding reason: " + ex.getMessage(), ex);
    }
  }

}
