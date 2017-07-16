/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.SimpleTimeZone;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.audit.AuditStatus;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.pki.ca.api.BadCertTemplateException;
import org.xipki.pki.ca.api.BadFormatException;
import org.xipki.pki.ca.api.NameId;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.api.X509CertWithDbId;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.api.profile.CertprofileException;
import org.xipki.pki.ca.api.profile.ExtensionValue;
import org.xipki.pki.ca.api.profile.ExtensionValues;
import org.xipki.pki.ca.api.profile.x509.SpecialX509CertprofileBehavior;
import org.xipki.pki.ca.api.profile.x509.SubjectInfo;
import org.xipki.pki.ca.api.profile.x509.X509CertVersion;
import org.xipki.pki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.pki.ca.server.impl.cmp.CmpRequestorEntryWrapper;
import org.xipki.pki.ca.server.impl.cmp.CmpRequestorInfo;
import org.xipki.pki.ca.server.impl.store.CertificateStore;
import org.xipki.pki.ca.server.impl.store.X509CertWithRevocationInfo;
import org.xipki.pki.ca.server.impl.util.CaUtil;
import org.xipki.pki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.CertListInfo;
import org.xipki.pki.ca.server.mgmt.api.CertListOrderBy;
import org.xipki.pki.ca.server.mgmt.api.CmpControl;
import org.xipki.pki.ca.server.mgmt.api.RequestorInfo;
import org.xipki.pki.ca.server.mgmt.api.ValidityMode;
import org.xipki.pki.ca.server.mgmt.api.x509.CrlControl;
import org.xipki.pki.ca.server.mgmt.api.x509.CrlControl.HourMinute;
import org.xipki.pki.ca.server.mgmt.api.x509.CrlControl.UpdateMode;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.ConcurrentBagEntrySigner;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.CrlReason;
import org.xipki.security.FpIdCalculator;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityConstants;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509Ca {

    private static class GrantedCertTemplate {
        private final ConcurrentContentSigner signer;
        private final Extensions extensions;
        private final IdentifiedX509Certprofile certprofile;
        private final Date grantedNotBefore;
        private final Date grantedNotAfter;
        private final X500Name requestedSubject;
        private final SubjectPublicKeyInfo grantedPublicKey;
        private final byte[] grantedPublicKeyData;
        private final long fpPublicKey;
        private final String warning;

        private X500Name grantedSubject;
        private String grantedSubjectText;
        private long fpSubject;

        public GrantedCertTemplate(Extensions extensions, IdentifiedX509Certprofile certprofile,
                Date grantedNotBefore, Date grantedNotAfter, X500Name requestedSubject,
                SubjectPublicKeyInfo grantedPublicKey, long fpPublicKey,
                byte[] grantedPublicKeyData, ConcurrentContentSigner signer, String warning) {
            this.extensions = extensions;
            this.certprofile = certprofile;
            this.grantedNotBefore = grantedNotBefore;
            this.grantedNotAfter = grantedNotAfter;
            this.requestedSubject = requestedSubject;
            this.grantedPublicKey = grantedPublicKey;
            this.grantedPublicKeyData = grantedPublicKeyData;
            this.fpPublicKey = fpPublicKey;
            this.signer = signer;
            this.warning = warning;
        }

        public void setGrantedSubject(X500Name subject) {
            this.grantedSubject = subject;
            this.grantedSubjectText = X509Util.getRfc4519Name(subject);
            this.fpSubject = X509Util.fpCanonicalizedName(subject);
        }

    }

    private class ExpiredCertsRemover implements Runnable {

        private boolean inProcess;

        @Override
        public void run() {
            int keepDays = caInfo.leepExpiredCertInDays();
            if (keepDays < 0) {
                return;
            }

            if (inProcess) {
                return;
            }

            inProcess = true;
            final Date expiredAt = new Date(
                    System.currentTimeMillis() - DAY_IN_MS * (keepDays + 1));

            try {
                int num = removeExpirtedCerts(expiredAt, CaAuditConstants.MSGID_CA_routine);
                LOG.info("removed {} certificates expired at {}", num, expiredAt.toString());
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not remove expired certificates");
            } finally {
                inProcess = false;
            }
        } // method run

    } // class ExpiredCertsRemover

    private class CrlGenerationService implements Runnable {

        @Override
        public void run() {
            X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
            if (crlSigner == null
                    || crlSigner.crlControl().updateMode() != UpdateMode.interval) {
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
            final long signWindowMin = 20;

            Date thisUpdate = new Date();
            long minSinceCrlBaseTime = (thisUpdate.getTime() - caInfo.crlBaseTime().getTime())
                    / MS_PER_MINUTE;

            CrlControl control = getCrlSigner().crlControl();
            int interval;

            if (control.intervalMinutes() != null && control.intervalMinutes() > 0) {
                long intervalMin = control.intervalMinutes();
                interval = (int) (minSinceCrlBaseTime / intervalMin);

                long baseTimeInMin = interval * intervalMin;
                if (minSinceCrlBaseTime - baseTimeInMin > signWindowMin) {
                    // only generate CRL within the time window
                    return;
                }
            } else if (control.intervalDayTime() != null) {
                HourMinute hm = control.intervalDayTime();
                Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                cal.setTime(thisUpdate);
                int minute = cal.get(Calendar.HOUR_OF_DAY) * 60 + cal.get(Calendar.MINUTE);
                int scheduledMinute = hm.hour() * 60 + hm.minute();
                if (minute < scheduledMinute || minute - scheduledMinute > signWindowMin) {
                    return;
                }
                interval = (int) (minSinceCrlBaseTime % MINUTE_PER_DAY);
            } else {
                throw new RuntimeException("should not reach here, neither interval minutes"
                        + " nor dateTime is specified");
            }

            boolean deltaCrl;
            if (interval % control.fullCrlIntervals() == 0) {
                deltaCrl = false;
            } else if (control.deltaCrlIntervals() > 0
                    && interval % control.deltaCrlIntervals() == 0) {
                deltaCrl = true;
            } else {
                return;
            }

            if (deltaCrl && !certstore.hasCrl(caIdent)) {
                // DeltaCRL will be generated only if fullCRL exists
                return;
            }

            long nowInSecond = thisUpdate.getTime() / MS_PER_SECOND;
            long thisUpdateOfCurrentCrl = certstore.getThisUpdateOfCurrentCrl(caIdent);
            if (nowInSecond - thisUpdateOfCurrentCrl <= (signWindowMin + 5) * 60) {
                // CRL was just generated within SIGN_WINDOW_MIN + 5 minutes
                return;
            }

            // find out the next interval for fullCRL and deltaCRL
            int nextFullCrlInterval = 0;
            int nextDeltaCrlInterval = 0;

            for (int i = interval + 1;; i++) {
                if (i % control.fullCrlIntervals() == 0) {
                    nextFullCrlInterval = i;
                    break;
                }

                if (nextDeltaCrlInterval != 0 && control.deltaCrlIntervals() != 0
                        && i % control.deltaCrlIntervals() == 0) {
                    nextDeltaCrlInterval = i;
                }
            }

            int intervalOfNextUpdate;
            if (deltaCrl) {
                intervalOfNextUpdate = nextDeltaCrlInterval == 0 ? nextFullCrlInterval
                        : Math.min(nextFullCrlInterval, nextDeltaCrlInterval);
            } else {
                if (nextDeltaCrlInterval == 0) {
                    intervalOfNextUpdate = nextFullCrlInterval;
                } else {
                    intervalOfNextUpdate = control.isExtendedNextUpdate() ? nextFullCrlInterval
                            : Math.min(nextFullCrlInterval, nextDeltaCrlInterval);
                }
            }

            Date nextUpdate;
            if (control.intervalMinutes() != null) {
                int minutesTillNextUpdate = (intervalOfNextUpdate - interval)
                        * control.intervalMinutes() + control.overlapMinutes();
                nextUpdate = new Date(MS_PER_SECOND * (nowInSecond + minutesTillNextUpdate * 60));
            } else {
                HourMinute hm = control.intervalDayTime();
                Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                cal.setTime(new Date(nowInSecond * MS_PER_SECOND));
                cal.add(Calendar.DAY_OF_YEAR, (intervalOfNextUpdate - interval));
                cal.set(Calendar.HOUR_OF_DAY, hm.hour());
                cal.set(Calendar.MINUTE, hm.minute());
                cal.add(Calendar.MINUTE, control.overlapMinutes());
                cal.set(Calendar.SECOND, 0);
                cal.set(Calendar.MILLISECOND, 0);
                nextUpdate = cal.getTime();
            }

            long maxIdOfDeltaCrlCache;
            try {
                maxIdOfDeltaCrlCache = certstore.getMaxIdOfDeltaCrlCache(caIdent);
                generateCrl(deltaCrl, thisUpdate, nextUpdate, CaAuditConstants.MSGID_CA_routine);
            } catch (Throwable th) {
                LogUtil.error(LOG, th);
                return;
            }

            try {
                certstore.clearDeltaCrlCache(caIdent, maxIdOfDeltaCrlCache);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not clear DeltaCRLCache of CA " + caIdent);
            }
        } // method run0

    } // class CrlGenerationService

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
                int num = revokeSuspendedCerts(CaAuditConstants.MSGID_CA_routine);
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

    private static final long MS_PER_SECOND = 1000L;

    private static final long MS_PER_MINUTE = 60000L;

    private static final int MINUTE_PER_DAY = 24 * 60;

    private static final long DAY_IN_MS = MS_PER_MINUTE * MINUTE_PER_DAY;

    private static final long MAX_CERT_TIME_MS = 253402300799982L; //9999-12-31-23-59-59

    private static final Logger LOG = LoggerFactory.getLogger(X509Ca.class);

    private final X509CaInfo caInfo;

    private final NameId caIdent;

    private final X509Cert caCert;

    private final CertificateStore certstore;

    private final CaIdNameMap caIdNameMap;

    private final boolean masterMode;

    private final CaManagerImpl caManager;

    private Boolean tryNssToVerify;

    private AtomicBoolean crlGenInProcess = new AtomicBoolean(false);

    private ScheduledFuture<?> crlGenerationService;

    private ScheduledFuture<?> expiredCertsRemover;

    private ScheduledFuture<?> suspendedCertsRevoker;

    private AuditServiceRegister auditServiceRegister;

    private final ConcurrentSkipListSet<Long> publicKeyCertsInProcess
        = new ConcurrentSkipListSet<>();

    private final ConcurrentSkipListSet<Long> subjectCertsInProcess
        = new ConcurrentSkipListSet<>();

    public X509Ca(final CaManagerImpl caManager, final X509CaInfo caInfo,
            final CertificateStore certstore)
            throws OperationException {
        this.caManager = ParamUtil.requireNonNull("caManager", caManager);
        this.masterMode = caManager.isMasterMode();
        this.caIdNameMap = caManager.idNameMap();
        this.caInfo = ParamUtil.requireNonNull("caInfo", caInfo);
        this.caIdent = caInfo.ident();
        this.caCert = caInfo.certificate();
        this.certstore = ParamUtil.requireNonNull("certstore", certstore);

        if (caInfo.isSignerRequired()) {
            try {
                caInfo.initSigner(caManager.securityFactory());
            } catch (XiSecurityException ex) {
                LogUtil.error(LOG, ex, "security.createSigner caSigner for CA " + caIdent);
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
            }
        }

        X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
        if (crlSigner != null) {
            // CA signs the CRL
            if (caManager.crlSignerWrapper(caInfo.crlSignerName()) == null
                    && !X509Util.hasKeyusage(caCert.cert(), KeyUsage.cRLSign)) {
                final String msg = "CRL signer does not have keyusage cRLSign";
                LOG.error(msg);
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, msg);
            }
        }

        if (!masterMode) {
            return;
        }

        for (IdentifiedX509CertPublisher publisher : publishers()) {
            publisher.caAdded(caCert);
        }

        Random random = new Random();
        // CRL generation services
        this.crlGenerationService = caManager.scheduledThreadPoolExecutor().scheduleAtFixedRate(
                new CrlGenerationService(), 60 + random.nextInt(60), 60, TimeUnit.SECONDS);

        final int minutesOfDay = 24 * 60;
        this.expiredCertsRemover = caManager.scheduledThreadPoolExecutor().scheduleAtFixedRate(
                new ExpiredCertsRemover(), minutesOfDay + random.nextInt(60), minutesOfDay,
                TimeUnit.MINUTES);

        this.suspendedCertsRevoker = caManager.scheduledThreadPoolExecutor().scheduleAtFixedRate(
                new SuspendedCertsRevoker(), random.nextInt(60), 60, TimeUnit.MINUTES);
    } // constructor

    public X509CaInfo caInfo() {
        return caInfo;
    }

    public CmpControl cmpControl() {
        String name = caInfo.cmpControlName();
        return (name == null) ? null : caManager.cmpControlObject(name);
    }

    public X509Certificate getCertificate(final BigInteger serialNumber)
            throws CertificateException, OperationException {
        X509CertificateInfo certInfo = certstore.getCertificateInfoForSerial(caIdent,
                caCert, serialNumber, caIdNameMap);
        return (certInfo == null) ? null : certInfo.cert().cert();
    }

    /**
     *
     * @param subjectName Subject of the certificate.
     * @param transactionId <code>null</code> for all transactionIds.
     */
    public List<X509Certificate> getCertificate(final X500Name subjectName,
            final byte[] transactionId) throws OperationException {
        return certstore.getCertificate(subjectName, transactionId);
    }

    public KnowCertResult knowsCertificate(final X509Certificate cert) throws OperationException {
        ParamUtil.requireNonNull("cert", cert);
        if (!caInfo.subject().equals(X509Util.getRfc4519Name(cert.getIssuerX500Principal()))) {
            return KnowCertResult.UNKNOWN;
        }

        return certstore.knowsCertForSerial(caIdent, cert.getSerialNumber());
    }

    public X509CertWithRevocationInfo getCertWithRevocationInfo(final BigInteger serialNumber)
            throws CertificateException, OperationException {
        return certstore.getCertWithRevocationInfo(caIdent, serialNumber, caIdNameMap);
    }

    public byte[] getCertRequest(final BigInteger serialNumber)
            throws OperationException {
        return certstore.getCertRequest(caIdent, serialNumber);
    }

    public void checkCsr(CertificationRequest csr)
            throws OperationException {
        ParamUtil.requireNonNull("csr", csr);
        if (!caManager.securityFactory().verifyPopo(
                csr, cmpControl().popoAlgoValidator())) {
            LOG.warn("could not validate POP for the pkcs#10 requst");
            throw new OperationException(ErrorCode.BAD_POP);
        }
    }

    public List<CertListInfo> listCertificates(final X500Name subjectPattern, final Date validFrom,
            final Date validTo, final CertListOrderBy orderBy, final int numEntries)
            throws OperationException {
        return certstore.listCertificates(caIdent, subjectPattern, validFrom,
                validTo, orderBy, numEntries);
    }

    public NameId authenticateUser(final String user, final byte[] password)
            throws OperationException {
        return certstore.authenticateUser(user.toUpperCase(), password);
    }

    public NameId getUserIdent(final int userId) throws OperationException {
        return certstore.getUserIdent(userId);
    }

    public ByUserRequestorInfo getByUserRequestor(final NameId userIdent)
            throws OperationException {
        CaHasUserEntry caHasUser = certstore.getCaHasUser(caIdent, userIdent);
        return (caHasUser == null) ? null : caManager.createByUserRequestor(caHasUser);
    }

    public X509CRL getCurrentCrl()
            throws OperationException {
        return getCrl(null);
    }

    public X509CRL getCrl(final BigInteger crlNumber)
            throws OperationException {
        LOG.info("     START getCrl: ca={}, crlNumber={}", caIdent, crlNumber);
        boolean successful = false;

        try {
            byte[] encodedCrl = certstore.getEncodedCrl(caIdent, crlNumber);
            if (encodedCrl == null) {
                return null;
            }

            try {
                X509CRL crl = X509Util.parseCrl(encodedCrl);
                successful = true;
                if (LOG.isInfoEnabled()) {
                    String timeStr = new Time(crl.getThisUpdate()).getTime();
                    LOG.info("SUCCESSFUL getCrl: ca={}, thisUpdate={}", caIdent, timeStr);
                }
                return crl;
            } catch (CRLException | CertificateException ex) {
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
            } catch (RuntimeException ex) {
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
            }
        } finally {
            if (!successful) {
                LOG.info("    FAILED getCrl: ca={}", caIdent);
            }
        }
    } // method getCrl

    public CertificateList getBcCurrentCrl()
            throws OperationException {
        return getBcCrl(null);
    }

    public CertificateList getBcCrl(final BigInteger crlNumber)
            throws OperationException {
        LOG.info("     START getCrl: ca={}, crlNumber={}", caIdent, crlNumber);
        boolean successful = false;

        try {
            byte[] encodedCrl = certstore.getEncodedCrl(caIdent, crlNumber);
            if (encodedCrl == null) {
                return null;
            }

            try {
                CertificateList crl = CertificateList.getInstance(encodedCrl);
                successful = true;
                if (LOG.isInfoEnabled()) {
                    LOG.info("SUCCESSFUL getCrl: ca={}, thisUpdate={}", caIdent,
                            crl.getThisUpdate().getTime());
                }
                return crl;
            } catch (RuntimeException ex) {
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
            }
        } finally {
            if (!successful) {
                LOG.info("    FAILED getCrl: ca={}", caIdent);
            }
        }
    } // method getCrl

    private void cleanupCrlsWithoutException(final String msgId)
            throws OperationException {
        try {
            cleanupCrls(msgId);
        } catch (Throwable th) {
            LOG.warn("could not cleanup CRLs.{}: {}", th.getClass().getName(), th.getMessage());
        }
    }

    private void cleanupCrls(final String msgId) throws OperationException {
        int numCrls = caInfo.numCrls();
        LOG.info("     START cleanupCrls: ca={}, numCrls={}", caIdent, numCrls);

        boolean successful = false;
        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_cleanup_CRL, msgId);

        try {
            int num = (numCrls <= 0) ? 0
                    : certstore.cleanupCrls(caIdent, caInfo.numCrls());
            successful = true;
            event.addEventData(CaAuditConstants.NAME_num, num);
            LOG.info("SUCCESSFUL cleanupCrls: ca={}, num={}", caIdent, num);
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
        } finally {
            if (!successful) {
                LOG.info("    FAILED cleanupCrls: ca={}", caIdent);
            }
            finish(event, successful);
        }
    } // method cleanupCrls

    public X509CRL generateCrlOnDemand(final String msgId)
            throws OperationException {
        X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
        if (crlSigner == null) {
            throw new OperationException(ErrorCode.NOT_PERMITTED, "CA could not generate CRL");
        }

        if (crlGenInProcess.get()) {
            throw new OperationException(ErrorCode.SYSTEM_UNAVAILABLE, "TRY_LATER");
        }

        crlGenInProcess.set(true);
        try {
            Date thisUpdate = new Date();
            Date nextUpdate = getCrlNextUpdate(thisUpdate);
            if (nextUpdate != null && !nextUpdate.after(thisUpdate)) {
                nextUpdate = null;
            }

            long maxIdOfDeltaCrlCache = certstore.getMaxIdOfDeltaCrlCache(caIdent);
            X509CRL crl = generateCrl(false, thisUpdate, nextUpdate, msgId);
            if (crl == null) {
                return null;
            }

            try {
                certstore.clearDeltaCrlCache(caIdent, maxIdOfDeltaCrlCache);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not clear DeltaCRLCache of CA " + caIdent);
            }
            return crl;
        } finally {
            crlGenInProcess.set(false);
        }
    } // method generateCrlOnDemand

    private X509CRL generateCrl(final boolean deltaCrl, final Date thisUpdate,
            final Date nextUpdate, final String msgId) throws OperationException {
        boolean successful = false;
        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_gen_CRL, msgId);
        try {
            X509CRL crl = generateCrl0(deltaCrl, thisUpdate, nextUpdate, event, msgId);
            successful = true;
            return crl;
        } finally {
            finish(event, successful);
        }
    }

    private X509CRL generateCrl0(final boolean deltaCrl, final Date thisUpdate,
            final Date nextUpdate, final AuditEvent event, final String msgId)
            throws OperationException {
        X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
        if (crlSigner == null) {
            throw new OperationException(ErrorCode.NOT_PERMITTED, "CRL generation is not allowed");
        }

        LOG.info("     START generateCrl: ca={}, deltaCRL={}, nextUpdate={}", caIdent, deltaCrl,
                nextUpdate);
        event.addEventData(CaAuditConstants.NAME_crlType, deltaCrl ? "DELTA_CRL" : "FULL_CRL");

        if (nextUpdate == null) {
            event.addEventData(CaAuditConstants.NAME_nextUpdate, "null");
        } else {
            event.addEventData(CaAuditConstants.NAME_nextUpdate,
                    DateUtil.toUtcTimeyyyyMMddhhmmss(nextUpdate));
            if (nextUpdate.getTime() - thisUpdate.getTime() < 10 * 60 * MS_PER_SECOND) {
                // less than 10 minutes
                throw new OperationException(ErrorCode.CRL_FAILURE,
                        "nextUpdate and thisUpdate are too close");
            }
        }

        CrlControl crlControl = crlSigner.crlControl();
        boolean successful = false;

        try {
            ConcurrentContentSigner tmpCrlSigner = crlSigner.signer();
            CrlControl control = crlSigner.crlControl();

            boolean directCrl;
            X500Name crlIssuer;
            if (tmpCrlSigner == null) {
                directCrl = true;
                crlIssuer = caInfo.publicCaInfo().x500Subject();
            } else {
                directCrl = false;
                crlIssuer = X500Name.getInstance(
                        tmpCrlSigner.getCertificate().getSubjectX500Principal().getEncoded());
            }

            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crlIssuer, thisUpdate);
            if (nextUpdate != null) {
                crlBuilder.setNextUpdate(nextUpdate);
            }

            final int numEntries = 100;

            List<CertRevInfoWithSerial> revInfos;
            boolean isFirstCrlEntry = true;

            Date notExpireAt;
            if (control.isIncludeExpiredCerts()) {
                notExpireAt = new Date(0);
            } else {
                // 10 minutes buffer
                notExpireAt = new Date(thisUpdate.getTime() - 600L * MS_PER_SECOND);
            }

            long startId = 1;
            do {
                if (deltaCrl) {
                    revInfos = certstore.getCertsForDeltaCrl(caIdent, startId, numEntries,
                            control.isOnlyContainsCaCerts(), control.isOnlyContainsUserCerts());
                } else {
                    revInfos = certstore.getRevokedCerts(caIdent, notExpireAt, startId,
                            numEntries, control.isOnlyContainsCaCerts(),
                            control.isOnlyContainsUserCerts());
                }

                long maxId = 1;

                for (CertRevInfoWithSerial revInfo : revInfos) {
                    if (revInfo.id() > maxId) {
                        maxId = revInfo.id();
                    }

                    CrlReason reason = revInfo.reason();
                    if (crlControl.isExcludeReason() && reason != CrlReason.REMOVE_FROM_CRL) {
                        reason = CrlReason.UNSPECIFIED;
                    }

                    Date revocationTime = revInfo.revocationTime();
                    Date invalidityTime = revInfo.invalidityTime();

                    switch (crlControl.invalidityDateMode()) {
                    case FORBIDDEN:
                        invalidityTime = null;
                        break;
                    case OPTIONAL:
                        break;
                    case REQUIRED:
                        if (invalidityTime == null) {
                            invalidityTime = revocationTime;
                        }
                        break;
                    default:
                        throw new RuntimeException("unknown TripleState: "
                                + crlControl.invalidityDateMode());
                    }

                    BigInteger serial = revInfo.serial();
                    LOG.debug("added cert ca={} serial={} to CRL", caIdent, serial);

                    if (directCrl || !isFirstCrlEntry) {
                        if (invalidityTime != null) {
                            crlBuilder.addCRLEntry(serial, revocationTime, reason.code(),
                                    invalidityTime);
                        } else {
                            crlBuilder.addCRLEntry(serial, revocationTime, reason.code());
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

                    Extension ext = createCertificateIssuerExtension(
                            caInfo.publicCaInfo().x500Subject());
                    extensions.add(ext);

                    crlBuilder.addCRLEntry(serial, revocationTime,
                            new Extensions(extensions.toArray(new Extension[0])));
                    isFirstCrlEntry = false;
                } // end for

                startId = maxId + 1;
            }
            while (revInfos.size() >= numEntries);
            // end do

            BigInteger crlNumber = caInfo.nextCrlNumber();
            event.addEventData(CaAuditConstants.NAME_crlNumber, crlNumber);

            boolean onlyUserCerts = crlControl.isOnlyContainsUserCerts();
            boolean onlyCaCerts = crlControl.isOnlyContainsCaCerts();
            if (onlyUserCerts && onlyCaCerts) {
                throw new RuntimeException(
                        "should not reach here, onlyUserCerts and onlyCACerts are both true");
            }

            try {
                // AuthorityKeyIdentifier
                byte[] akiValues = directCrl
                        ? caInfo.publicCaInfo().subjectKeyIdentifer()
                        : crlSigner.subjectKeyIdentifier();
                AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(akiValues);
                crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);

                // add extension CRL Number
                crlBuilder.addExtension(Extension.cRLNumber, false, new ASN1Integer(crlNumber));

                // IssuingDistributionPoint
                if (onlyUserCerts || onlyCaCerts || !directCrl) {
                    IssuingDistributionPoint idp = new IssuingDistributionPoint(
                            (DistributionPointName) null, // distributionPoint,
                            onlyUserCerts, // onlyContainsUserCerts,
                            onlyCaCerts, // onlyContainsCACerts,
                            (ReasonFlags) null, // onlySomeReasons,
                            !directCrl, // indirectCRL,
                            false); // onlyContainsAttributeCerts

                    crlBuilder.addExtension(Extension.issuingDistributionPoint, true, idp);
                }

                // freshestCRL
                List<String> deltaCrlUris = caInfo().publicCaInfo().deltaCrlUris();
                if (control.deltaCrlIntervals() > 0 && CollectionUtil.isNonEmpty(deltaCrlUris)) {
                    CRLDistPoint cdp = CaUtil.createCrlDistributionPoints(deltaCrlUris,
                            caInfo.publicCaInfo().x500Subject(), crlIssuer);
                    crlBuilder.addExtension(Extension.freshestCRL, false, cdp);
                }
            } catch (CertIOException ex) {
                LogUtil.error(LOG, ex, "crlBuilder.addExtension");
                throw new OperationException(ErrorCode.INVALID_EXTENSION, ex);
            }

            addXipkiCertset(crlBuilder, deltaCrl, control, notExpireAt, onlyCaCerts, onlyUserCerts);

            ConcurrentContentSigner concurrentSigner = (tmpCrlSigner == null)
                    ? caInfo.getSigner(null) : tmpCrlSigner;

            ConcurrentBagEntrySigner signer0;
            try {
                signer0 = concurrentSigner.borrowContentSigner();
            } catch (NoIdleSignerException ex) {
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, "NoIdleSignerException: "
                        + ex.getMessage());
            }

            X509CRLHolder crlHolder;
            try {
                crlHolder = crlBuilder.build(signer0.value());
            } finally {
                concurrentSigner.requiteContentSigner(signer0);
            }

            try {
                X509CRL crl = X509Util.toX509Crl(crlHolder.toASN1Structure());
                caInfo.caEntry().setNextCrlNumber(crlNumber.longValue() + 1);
                caManager.commitNextCrlNo(caIdent, caInfo.caEntry().nextCrlNumber());
                publishCrl(crl);

                successful = true;
                LOG.info("SUCCESSFUL generateCrl: ca={}, crlNumber={}, thisUpdate={}", caIdent,
                        crlNumber, crl.getThisUpdate());

                if (!deltaCrl) {
                    // clean up the CRL
                    cleanupCrlsWithoutException(msgId);
                }
                return crl;
            } catch (CRLException | CertificateException ex) {
                throw new OperationException(ErrorCode.CRL_FAILURE, ex);
            }
        } finally {
            if (!successful) {
                LOG.info("    FAILED generateCrl: ca={}", caIdent);
            }
        }
    } // method generateCrl

    /**
     * Add XiPKI extension CrlCertSet.
     *
     * <pre>
     * Xipki-CrlCertSet ::= SET OF Xipki-CrlCert
     *
     * Xipki-CrlCert ::= SEQUENCE {
     *         serial            INTEGER
     *         cert        [0] EXPLICIT    Certificate OPTIONAL
     *         profileName [1] EXPLICIT    UTF8String    OPTIONAL
     *         }
     * </pre>
     */
    private void addXipkiCertset(final X509v2CRLBuilder crlBuilder, final boolean deltaCrl,
            final CrlControl control, final Date notExpireAt,
            final boolean onlyCaCerts, final boolean onlyUserCerts) throws OperationException {
        if (deltaCrl || !control.isXipkiCertsetIncluded()) {
            return;
        }

        ASN1EncodableVector vector = new ASN1EncodableVector();
        final int numEntries = 100;
        long startId = 1;

        List<SerialWithId> serials;
        do {
            serials = certstore.getCertSerials(caIdent, notExpireAt, startId, numEntries, false,
                    onlyCaCerts, onlyUserCerts);

            long maxId = 1;
            for (SerialWithId sid : serials) {
                if (sid.id() > maxId) {
                    maxId = sid.id();
                }

                ASN1EncodableVector vec = new ASN1EncodableVector();
                vec.add(new ASN1Integer(sid.serial()));

                Integer profileId = null;

                if (control.isXipkiCertsetCertIncluded()) {
                    X509CertificateInfo certInfo;
                    try {
                        certInfo = certstore.getCertificateInfoForId(caIdent, caCert,
                                sid.id(), caIdNameMap);
                    } catch (CertificateException ex) {
                        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                                "CertificateException: " + ex.getMessage());
                    }

                    Certificate cert = Certificate.getInstance(certInfo.cert().encodedCert());
                    vec.add(new DERTaggedObject(true, 0, cert));

                    if (control.isXipkiCertsetProfilenameIncluded()) {
                        profileId = certInfo.profile().id();
                    }
                } else if (control.isXipkiCertsetProfilenameIncluded()) {
                    profileId = certstore.getCertProfileForId(caIdent, sid.id());
                }

                if (profileId != null) {
                    String profileName = caIdNameMap.certprofileName(profileId);
                    vec.add(new DERTaggedObject(true, 1, new DERUTF8String(profileName)));
                }

                vector.add(new DERSequence(vec));
            } // end for

            startId = maxId + 1;
        }
        while (serials.size() >= numEntries);
        // end do

        try {
            crlBuilder.addExtension(ObjectIdentifiers.id_xipki_ext_crlCertset, false,
                    new DERSet(vector));
        } catch (CertIOException ex) {
            throw new OperationException(ErrorCode.INVALID_EXTENSION,
                    "CertIOException: " + ex.getMessage());
        }
    }

    public X509CertificateInfo regenerateCertificate(final CertTemplateData certTemplate,
            final RequestorInfo requestor, final RequestType reqType, final byte[] transactionId,
            final String msgId) throws OperationException {
        return regenerateCertificates(Arrays.asList(certTemplate), requestor, reqType,
                transactionId, msgId).get(0);
    }

    public List<X509CertificateInfo> regenerateCertificates(
            final List<CertTemplateData> certTemplates, final RequestorInfo requestor,
            final RequestType reqType, final byte[] transactionId, final String msgId)
            throws OperationException {
        return generateCertificates(certTemplates, requestor, true, reqType, transactionId, msgId);
    }

    public boolean publishCertificate(final X509CertificateInfo certInfo) {
        return publishCertificate0(certInfo) == 0;
    }

    /**
     *
     * @param certInfo certificate to be published.
     * @return 0 for published successfully, 1 if could not be published to CA certstore and
     *     any publishers, 2 if could be published to CA certstore but not to all publishers.
     */
    private int publishCertificate0(final X509CertificateInfo certInfo) {
        ParamUtil.requireNonNull("certInfo", certInfo);
        if (certInfo.isAlreadyIssued()) {
            return 0;
        }

        if (!certstore.addCertificate(certInfo)) {
            return 1;
        }

        for (IdentifiedX509CertPublisher publisher : publishers()) {
            if (!publisher.isAsyn()) {
                boolean successful;
                try {
                    successful = publisher.certificateAdded(certInfo);
                } catch (RuntimeException ex) {
                    successful = false;
                    LogUtil.warn(LOG, ex, "could not publish certificate to the publisher "
                            + publisher.ident());
                }

                if (successful) {
                    continue;
                }
            } // end if

            Long certId = certInfo.cert().certId();
            try {
                certstore.addToPublishQueue(publisher.ident(), certId.longValue(), caIdent);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not add entry to PublishQueue");
                return 2;
            }
        } // end for

        return 0;
    } // method publishCertificate0

    public boolean republishCertificates(final List<String> publisherNames, final int numThreads) {
        List<IdentifiedX509CertPublisher> publishers;
        if (publisherNames == null) {
            publishers = publishers();
        } else {
            publishers = new ArrayList<>(publisherNames.size());

            for (String publisherName : publisherNames) {
                IdentifiedX509CertPublisher publisher = null;
                for (IdentifiedX509CertPublisher p : publishers()) {
                    if (p.ident().name().equals(publisherName)) {
                        publisher = p;
                        break;
                    }
                }

                if (publisher == null) {
                    throw new IllegalArgumentException(
                            "could not find publisher " + publisherName + " for CA " + caIdent);
                }
                publishers.add(publisher);
            }
        } // end if

        if (CollectionUtil.isEmpty(publishers)) {
            return true;
        }

        CaStatus status = caInfo.status();

        caInfo.setStatus(CaStatus.INACTIVE);

        boolean onlyRevokedCerts = true;
        for (IdentifiedX509CertPublisher publisher : publishers) {
            if (publisher.publishsGoodCert()) {
                onlyRevokedCerts = false;
            }

            NameId publisherIdent = publisher.ident();
            try {
                LOG.info("clearing PublishQueue for publisher {}", publisherIdent);
                certstore.clearPublishQueue(caIdent, publisherIdent);
                LOG.info(" cleared PublishQueue for publisher {}", publisherIdent);
            } catch (OperationException ex) {
                LogUtil.error(LOG, ex, "could not clear PublishQueue for publisher");
            }
        } // end for

        try {
            for (IdentifiedX509CertPublisher publisher : publishers) {
                boolean successful = publisher.caAdded(caCert);
                if (!successful) {
                    LOG.error("republish CA certificate {} to publisher {} failed", caIdent,
                            publisher.ident());
                    return false;
                }
            }

            if (caInfo.revocationInfo() != null) {
                for (IdentifiedX509CertPublisher publisher : publishers) {
                    boolean successful = publisher.caRevoked(caCert, caInfo.revocationInfo());
                    if (!successful) {
                        LOG.error("republishing CA revocation to publisher {} failed",
                                publisher.ident());
                        return false;
                    }
                }
            } // end if

            CertRepublisher republisher = new CertRepublisher(caIdent, caCert,
                    caIdNameMap, certstore, publishers, onlyRevokedCerts, numThreads);
            return republisher.republish();
        } finally {
            caInfo.setStatus(status);
        }
    } // method republishCertificates

    public boolean clearPublishQueue(final List<String> publisherNames) throws CaMgmtException {
        if (publisherNames == null) {
            try {
                certstore.clearPublishQueue(caIdent, null);
                return true;
            } catch (OperationException ex) {
                throw new CaMgmtException(ex.getMessage(), ex);
            }
        }

        for (String publisherName : publisherNames) {
            NameId publisherIdent = caIdNameMap.publisher(publisherName);
            try {
                certstore.clearPublishQueue(caIdent, publisherIdent);
            } catch (OperationException ex) {
                throw new CaMgmtException(ex.getMessage(), ex);
            }
        }

        return true;
    } // method clearPublishQueue

    public boolean publishCertsInQueue() {
        boolean allSuccessful = true;
        for (IdentifiedX509CertPublisher publisher : publishers()) {
            if (!publishCertsInQueue(publisher)) {
                allSuccessful = false;
            }
        }

        return allSuccessful;
    }

    private boolean publishCertsInQueue(final IdentifiedX509CertPublisher publisher) {
        ParamUtil.requireNonNull("publisher", publisher);
        final int numEntries = 500;

        while (true) {
            List<Long> certIds;
            try {
                certIds = certstore.getPublishQueueEntries(caIdent, publisher.ident(),
                        numEntries);
            } catch (OperationException ex) {
                LogUtil.error(LOG, ex);
                return false;
            }

            if (CollectionUtil.isEmpty(certIds)) {
                break;
            }

            for (Long certId : certIds) {
                X509CertificateInfo certInfo;

                try {
                    certInfo = certstore.getCertificateInfoForId(caIdent, caCert, certId,
                            caIdNameMap);
                } catch (OperationException | CertificateException ex) {
                    LogUtil.error(LOG, ex);
                    return false;
                }

                boolean successful = publisher.certificateAdded(certInfo);
                if (!successful) {
                    LOG.error("republishing certificate id={} failed", certId);
                    return false;
                }

                try {
                    certstore.removeFromPublishQueue(publisher.ident(), certId);
                } catch (OperationException ex) {
                    LogUtil.warn(LOG, ex, "could not remove republished cert id=" + certId
                            + " and publisher=" + publisher.ident());
                    continue;
                }
            } // end for
        } // end while

        return true;
    } // method publishCertsInQueue

    private boolean publishCrl(final X509CRL crl) {
        if (!certstore.addCrl(caIdent, crl)) {
            return false;
        }

        for (IdentifiedX509CertPublisher publisher : publishers()) {
            try {
                publisher.crlAdded(caCert, crl);
            } catch (RuntimeException ex) {
                LogUtil.error(LOG, ex, "could not publish CRL to the publisher "
                        + publisher.ident());
            }
        } // end for

        return true;
    } // method publishCrl

    public X509CertWithRevocationInfo revokeCertificate(final BigInteger serialNumber,
            final CrlReason reason, final Date invalidityTime, final String msgId)
            throws OperationException {
        if (caInfo.isSelfSigned() && caInfo.serialNumber().equals(serialNumber)) {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "insufficient permission to revoke CA certificate");
        }

        CrlReason tmpReason = reason;
        if (tmpReason == null) {
            tmpReason = CrlReason.UNSPECIFIED;
        }

        switch (tmpReason) {
        case CA_COMPROMISE:
        case AA_COMPROMISE:
        case REMOVE_FROM_CRL:
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "Insufficient permission revoke certificate with reason "
                    + tmpReason.description());
        case UNSPECIFIED:
        case KEY_COMPROMISE:
        case AFFILIATION_CHANGED:
        case SUPERSEDED:
        case CESSATION_OF_OPERATION:
        case CERTIFICATE_HOLD:
        case PRIVILEGE_WITHDRAWN:
            break;
        default:
            throw new RuntimeException("unknown CRL reason " + tmpReason);
        } // switch (reason)

        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_revoke_cert, msgId);
        boolean successful = true;
        try {
            X509CertWithRevocationInfo ret = revokeCertificate0(serialNumber, reason,
                    invalidityTime, false, event);
            successful = (ret != null);
            return ret;
        } finally {
            finish(event, successful);
        }
    } // method revokeCertificate

    public X509CertWithDbId unrevokeCertificate(final BigInteger serialNumber, final String msgId)
            throws OperationException {
        if (caInfo.isSelfSigned() && caInfo.serialNumber().equals(serialNumber)) {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "insufficient permission unrevoke CA certificate");
        }

        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_unrevoke_CERT, msgId);
        boolean successful = true;
        try {
            X509CertWithDbId ret = unrevokeCertificate0(serialNumber, false, event);
            successful = true;
            return ret;
        } finally {
            finish(event, successful);
        }
    } // method unrevokeCertificate

    public X509CertWithDbId removeCertificate(final BigInteger serialNumber, String msgId)
            throws OperationException {
        if (caInfo.isSelfSigned() && caInfo.serialNumber().equals(serialNumber)) {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "insufficient permission remove CA certificate");
        }

        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_remove_cert, msgId);
        boolean successful = true;
        try {
            X509CertWithDbId ret = removeCertificate0(serialNumber, event);
            successful = (ret != null);
            return ret;
        } finally {
            finish(event, successful);
        }
    } // method removeCertificate

    private X509CertWithDbId removeCertificate0(final BigInteger serialNumber,
            final AuditEvent event)
            throws OperationException {
        event.addEventData(CaAuditConstants.NAME_serial, LogUtil.formatCsn(serialNumber));
        X509CertWithRevocationInfo certWithRevInfo =
                certstore.getCertWithRevocationInfo(caIdent, serialNumber, caIdNameMap);
        if (certWithRevInfo == null) {
            return null;
        }

        boolean successful = true;
        X509CertWithDbId certToRemove = certWithRevInfo.cert();
        for (IdentifiedX509CertPublisher publisher : publishers()) {
            boolean singleSuccessful;
            try {
                singleSuccessful = publisher.certificateRemoved(caCert, certToRemove);
            } catch (RuntimeException ex) {
                singleSuccessful = false;
                LogUtil.warn(LOG, ex, "could not remove certificate to the publisher "
                        + publisher.ident());
            }

            if (singleSuccessful) {
                continue;
            }

            successful = false;
            X509Certificate cert = certToRemove.cert();
            if (LOG.isErrorEnabled()) {
                LOG.error("removing certificate issuer='{}', serial={}, subject='{}' from publisher"
                    + " {} failed.", X509Util.getRfc4519Name(cert.getIssuerX500Principal()),
                    LogUtil.formatCsn(cert.getSerialNumber()),
                    X509Util.getRfc4519Name(cert.getSubjectX500Principal()), publisher.ident());
            }
        } // end for

        if (!successful) {
            return null;
        }

        certstore.removeCertificate(caIdent, serialNumber);
        return certToRemove;
    } // method removeCertificate0

    private X509CertWithRevocationInfo revokeCertificate0(final BigInteger serialNumber,
            final CrlReason reason, final Date invalidityTime, final boolean force,
            final AuditEvent event) throws OperationException {
        String hexSerial = LogUtil.formatCsn(serialNumber);
        event.addEventData(CaAuditConstants.NAME_serial, hexSerial);
        event.addEventData(CaAuditConstants.NAME_reason, reason.description());
        if (invalidityTime != null) {
            event.addEventData(CaAuditConstants.NAME_invalidityTime,
                    DateUtil.toUtcTimeyyyyMMddhhmmss(invalidityTime));
        }

        LOG.info(
            "     START revokeCertificate: ca={}, serialNumber={}, reason={}, invalidityTime={}",
            caIdent, hexSerial, reason.description(), invalidityTime);

        X509CertWithRevocationInfo revokedCert = null;

        CertRevocationInfo revInfo = new CertRevocationInfo(reason, new Date(), invalidityTime);
        revokedCert = certstore.revokeCertificate(caIdent, serialNumber, revInfo,
                force, shouldPublishToDeltaCrlCache(), caIdNameMap);
        if (revokedCert == null) {
            return null;
        }

        for (IdentifiedX509CertPublisher publisher : publishers()) {
            if (!publisher.isAsyn()) {
                boolean successful;
                try {
                    successful = publisher.certificateRevoked(caCert, revokedCert.cert(),
                            revokedCert.certprofile(), revokedCert.revInfo());
                } catch (RuntimeException ex) {
                    successful = false;
                    LogUtil.error(LOG, ex,
                            "could not publish revocation of certificate to the publisher "
                            + publisher.ident());
                }

                if (successful) {
                    continue;
                }
            } // end if

            Long certId = revokedCert.cert().certId();
            try {
                certstore.addToPublishQueue(publisher.ident(), certId.longValue(), caIdent);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not add entry to PublishQueue");
            }
        } // end for

        if (LOG.isInfoEnabled()) {
            LOG.info("SUCCESSFUL revokeCertificate: ca={}, serialNumber={}, reason={},"
                + " invalidityTime={}, revocationResult=REVOKED",
                caIdent, hexSerial, reason.description(), invalidityTime);
        }

        return revokedCert;
    } // method revokeCertificate0

    private X509CertWithRevocationInfo revokeSuspendedCert(final BigInteger serialNumber,
            final CrlReason reason, final String msgId)
            throws OperationException {
        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_revoke_suspendedCert, msgId);

        boolean successful = false;
        try {
            X509CertWithRevocationInfo ret = revokeSuspendedCert0(serialNumber, reason, event);
            successful = (ret != null);
            return ret;
        } finally {
            finish(event, successful);
        }
    }

    private X509CertWithRevocationInfo revokeSuspendedCert0(final BigInteger serialNumber,
            final CrlReason reason, final AuditEvent event)
            throws OperationException {
        String hexSerial = LogUtil.formatCsn(serialNumber);

        event.addEventData(CaAuditConstants.NAME_serial, hexSerial);
        event.addEventData(CaAuditConstants.NAME_reason, reason.description());

        if (LOG.isInfoEnabled()) {
            LOG.info("     START revokeSuspendedCert: ca={}, serialNumber={}, reason={}",
                caIdent, hexSerial, reason.description());
        }

        X509CertWithRevocationInfo revokedCert = certstore.revokeSuspendedCert(caIdent,
                serialNumber, reason, shouldPublishToDeltaCrlCache(), caIdNameMap);
        if (revokedCert == null) {
            return null;
        }

        for (IdentifiedX509CertPublisher publisher : publishers()) {
            if (!publisher.isAsyn()) {
                boolean successful;
                try {
                    successful = publisher.certificateRevoked(caCert, revokedCert.cert(),
                            revokedCert.certprofile(), revokedCert.revInfo());
                } catch (RuntimeException ex) {
                    successful = false;
                    LogUtil.error(LOG, ex,
                            "could not publish revocation of certificate to the publisher "
                            + publisher.ident());
                }

                if (successful) {
                    continue;
                }
            } // end if

            Long certId = revokedCert.cert().certId();
            try {
                certstore.addToPublishQueue(publisher.ident(), certId.longValue(), caIdent);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not add entry to PublishQueue");
            }
        } // end for

        if (LOG.isInfoEnabled()) {
            LOG.info("SUCCESSFUL revokeSuspendedCert: ca={}, serialNumber={}, reason={}",
                caIdent, hexSerial, reason.description());
        }

        return revokedCert;
    } // method revokeSuspendedCert0

    private X509CertWithDbId unrevokeCertificate0(final BigInteger serialNumber,
            final boolean force, final AuditEvent event) throws OperationException {
        String hexSerial = LogUtil.formatCsn(serialNumber);
        event.addEventData(CaAuditConstants.NAME_serial, hexSerial);

        LOG.info("     START unrevokeCertificate: ca={}, serialNumber={}", caIdent, hexSerial);

        X509CertWithDbId unrevokedCert = certstore.unrevokeCertificate(caIdent,
                serialNumber, force, shouldPublishToDeltaCrlCache(), caIdNameMap);
        if (unrevokedCert == null) {
            return null;
        }

        for (IdentifiedX509CertPublisher publisher : publishers()) {
            if (!publisher.isAsyn()) {
                boolean successful;
                try {
                    successful = publisher.certificateUnrevoked(caCert, unrevokedCert);
                } catch (RuntimeException ex) {
                    successful = false;
                    LogUtil.error(LOG, ex,
                            "could not publish unrevocation of certificate to the publisher "
                            + publisher.ident());
                }

                if (successful) {
                    continue;
                }
            } // end if

            Long certId = unrevokedCert.certId();
            try {
                certstore.addToPublishQueue(publisher.ident(), certId.longValue(), caIdent);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not add entry to PublishQueue");
            }
        } // end for

        LOG.info(
            "SUCCESSFUL unrevokeCertificate: ca={}, serialNumber={}, revocationResult=UNREVOKED",
            caIdent, hexSerial);

        return unrevokedCert;
    } // doUnrevokeCertificate

    private boolean shouldPublishToDeltaCrlCache() {
        X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
        if (crlSigner == null) {
            return false;
        }

        CrlControl control = crlSigner.crlControl();
        if (control.updateMode() == UpdateMode.onDemand) {
            return false;
        }

        int deltaCrlInterval = control.deltaCrlIntervals();
        return deltaCrlInterval != 0 && deltaCrlInterval < control.fullCrlIntervals();
    } // method shouldPublishToDeltaCrlCache

    public void revokeCa(final CertRevocationInfo revocationInfo, final String msgId)
            throws OperationException {
        ParamUtil.requireNonNull("revocationInfo", revocationInfo);
        caInfo.setRevocationInfo(revocationInfo);

        if (caInfo.isSelfSigned()) {
            AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_revoke_cert, msgId);
            boolean successful = true;
            try {
                X509CertWithRevocationInfo ret = revokeCertificate0(caInfo.serialNumber(),
                        revocationInfo.reason(), revocationInfo.invalidityTime(), true,
                        event);
                successful = (ret != null);
            } finally {
                finish(event, successful);
            }
        }

        boolean failed = false;
        for (IdentifiedX509CertPublisher publisher : publishers()) {
            NameId ident = publisher.ident();
            boolean successful = publisher.caRevoked(caCert, revocationInfo);
            if (successful) {
                LOG.info("published event caRevoked of CA {} to publisher {}", caIdent, ident);
            } else {
                failed = true;
                LOG.error("could not publish event caRevoked of CA {} to publisher {}", caIdent,
                        ident);
            }
        }

        if (failed) {
            final String message = "could not event caRevoked of CA " + caIdent
                    + " to at least one publisher";
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, message);
        }
    } // method revokeCa

    public void unrevokeCa(final String msgId) throws OperationException {
        caInfo.setRevocationInfo(null);
        if (caInfo.isSelfSigned()) {
            AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_unrevoke_CERT, msgId);
            boolean successful = true;
            try {
                unrevokeCertificate0(caInfo.serialNumber(), true, event);
                successful = true;
            } finally {
                finish(event, successful);
            }
        }

        boolean failed = false;
        for (IdentifiedX509CertPublisher publisher : publishers()) {
            NameId ident = publisher.ident();
            boolean successful = publisher.caUnrevoked(caCert);
            if (successful) {
                LOG.info("published event caUnrevoked of CA {} to publisher {}", caIdent, ident);
            } else {
                failed = true;
                LOG.error("could not publish event caUnrevoked of CA {} to publisher {}", caIdent,
                        ident);
            }
        }

        if (failed) {
            final String message = "could not event caUnrevoked of CA " + caIdent
                    + " to at least one publisher";
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, message);
        }

    } // method unrevokeCa

    public long addRequest(final byte[] request) throws OperationException {
        return certstore.addRequest(request);
    }

    public void addRequestCert(final long requestId, final long certId) throws OperationException {
        certstore.addRequestCert(requestId, certId);
    }

    private List<IdentifiedX509CertPublisher> publishers() {
        return caManager.identifiedPublishersForCa(caIdent.name());
    }

    public List<X509CertificateInfo> generateCertificates(
            final List<CertTemplateData> certTemplates,
            final RequestorInfo requestor, final RequestType reqType,
            final byte[] transactionId, final String msgId)
            throws OperationException {
        return generateCertificates(certTemplates, requestor, false, reqType,
                transactionId, msgId);
    }

    private List<X509CertificateInfo> generateCertificates(
            final List<CertTemplateData> certTemplates,
            final RequestorInfo requestor, final boolean keyUpdate,
            final RequestType reqType, final byte[] transactionId, final String msgId)
            throws OperationExceptionWithIndex {
        ParamUtil.requireNonEmpty("certTemplates", certTemplates);
        final int n = certTemplates.size();
        List<GrantedCertTemplate> gcts = new ArrayList<>(n);

        for (int i = 0; i < n; i++) {
            CertTemplateData certTemplate = certTemplates.get(i);
            try {
                GrantedCertTemplate gct = createGrantedCertTemplate(certTemplate,
                        requestor, keyUpdate);
                gcts.add(gct);
            } catch (OperationException ex) {
                throw new OperationExceptionWithIndex(i, ex);
            }
        }

        List<X509CertificateInfo> certInfos = new ArrayList<>(n);
        OperationExceptionWithIndex exception = null;

        for (int i = 0; i < n; i++) {
            if (exception != null) {
                break;
            }
            GrantedCertTemplate gct = gcts.get(i);
            final NameId certprofilIdent = gct.certprofile.ident();
            final String subjectText = gct.grantedSubjectText;
            LOG.info("     START generateCertificate: CA={}, profile={}, subject='{}'", caIdent,
                    certprofilIdent, subjectText);

            boolean successful = false;
            try {
                X509CertificateInfo certInfo = generateCertificate(gct, requestor,
                    false, reqType, transactionId, msgId);
                successful = true;
                certInfos.add(certInfo);

                if (LOG.isInfoEnabled()) {
                    String prefix = certInfo.isAlreadyIssued() ? "RETURN_OLD_CERT" : "SUCCESSFUL";
                    X509CertWithDbId cert = certInfo.cert();
                    LOG.info(
                        "{} generateCertificate: CA={}, profile={}, subject='{}', serialNumber={}",
                        prefix, caIdent, certprofilIdent, cert.subject(),
                        LogUtil.formatCsn(cert.cert().getSerialNumber()));
                }
            } catch (OperationException ex) {
                exception = new OperationExceptionWithIndex(i, ex);
            } catch (Throwable th) {
                exception = new OperationExceptionWithIndex(i,
                        new OperationException(ErrorCode.SYSTEM_FAILURE, th));
            } finally {
                if (!successful) {
                    LOG.warn("    FAILED generateCertificate: CA={}, profile={}, subject='{}'",
                            caIdent, certprofilIdent, subjectText);
                }
            }
        }

        if (exception != null) {
            LOG.error("could not generate certificate for request[{}], reverted all generated"
                    + " certificates", exception.index());
            // delete generated certificates
            for (X509CertificateInfo m : certInfos) {
                BigInteger serial = m.cert().cert().getSerialNumber();
                try {
                    removeCertificate(serial, msgId);
                } catch (Throwable thr) {
                    LogUtil.error(LOG, thr, "could not delete certificate serial=" + serial);
                }
            }

            LogUtil.warn(LOG, exception);
            throw exception;
        }

        return certInfos;
    }

    public X509CertificateInfo generateCertificate(final CertTemplateData certTemplate,
            final RequestorInfo requestor, final RequestType reqType, final byte[] transactionId,
            final String msgId)
            throws OperationException {
        ParamUtil.requireNonNull("certTemplate", certTemplate);
        return generateCertificates(Arrays.asList(certTemplate), requestor,
                reqType, transactionId, msgId).get(0);
    }

    private X509CertificateInfo generateCertificate(final GrantedCertTemplate gct,
            final RequestorInfo requestor, final boolean keyUpdate, final RequestType reqType,
            final byte[] transactionId, final String msgId)
            throws OperationException {
        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_gen_cert, msgId);

        boolean successful = false;
        try {
            X509CertificateInfo ret = generateCertificate0(gct, requestor,
                    keyUpdate, reqType, transactionId, event);
            successful = (ret != null);
            return ret;
        } finally {
            finish(event, successful);
        }
    }

    private X509CertificateInfo generateCertificate0(final GrantedCertTemplate gct,
            final RequestorInfo requestor, final boolean keyUpdate, final RequestType reqType,
            final byte[] transactionId, final AuditEvent event)
            throws OperationException {
        ParamUtil.requireNonNull("gct", gct);

        event.addEventData(CaAuditConstants.NAME_reqSubject,
                X509Util.getRfc4519Name(gct.requestedSubject));
        event.addEventData(CaAuditConstants.NAME_certprofile, gct.certprofile.ident().name());
        event.addEventData(CaAuditConstants.NAME_notBefore,
                DateUtil.toUtcTimeyyyyMMddhhmmss(gct.grantedNotBefore));
        event.addEventData(CaAuditConstants.NAME_notAfter,
                DateUtil.toUtcTimeyyyyMMddhhmmss(gct.grantedNotAfter));

        adaptGrantedSubejct(gct);

        IdentifiedX509Certprofile certprofile = gct.certprofile;

        boolean publicKeyCertInProcessExisted = publicKeyCertsInProcess.add(gct.fpPublicKey);
        if (!publicKeyCertInProcessExisted) {
            if (!certprofile.isDuplicateKeyPermitted()) {
                throw new OperationException(ErrorCode.ALREADY_ISSUED,
                        "certificate with the given public key already in process");
            }
        }

        if (!subjectCertsInProcess.add(gct.fpSubject)) {
            if (!certprofile.isDuplicateSubjectPermitted()) {
                if (!publicKeyCertInProcessExisted) {
                    publicKeyCertsInProcess.remove(gct.fpPublicKey);
                }

                throw new OperationException(ErrorCode.ALREADY_ISSUED,
                        "certificate with the given subject " + gct.grantedSubjectText
                        + " already in process");
            }
        }

        try {
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    caInfo.publicCaInfo().x500Subject(), caInfo.nextSerial(),
                    gct.grantedNotBefore, gct.grantedNotAfter, gct.grantedSubject,
                    gct.grantedPublicKey);

            X509CertificateInfo ret;

            try {
                X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
                X509Certificate crlSignerCert = (crlSigner == null) ? null : crlSigner.cert();

                ExtensionValues extensionTuples = certprofile.getExtensions(
                        gct.requestedSubject, gct.grantedSubject, gct.extensions,
                        gct.grantedPublicKey, caInfo.publicCaInfo(), crlSignerCert,
                        gct.grantedNotBefore, gct.grantedNotAfter);
                if (extensionTuples != null) {
                    for (ASN1ObjectIdentifier extensionType : extensionTuples.extensionTypes()) {
                        ExtensionValue extValue = extensionTuples.getExtensionValue(extensionType);
                        certBuilder.addExtension(extensionType, extValue.isCritical(),
                                extValue.value());
                    }
                }

                ConcurrentBagEntrySigner signer0;
                try {
                    signer0 = gct.signer.borrowContentSigner();
                } catch (NoIdleSignerException ex) {
                    throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
                }

                X509CertificateHolder certHolder;
                try {
                    certHolder = certBuilder.build(signer0.value());
                } finally {
                    gct.signer.requiteContentSigner(signer0);
                }

                Certificate bcCert = certHolder.toASN1Structure();
                byte[] encodedCert = bcCert.getEncoded();
                int maxCertSize = gct.certprofile.maxCertSize();
                if (maxCertSize > 0) {
                    int certSize = encodedCert.length;
                    if (certSize > maxCertSize) {
                        throw new OperationException(ErrorCode.NOT_PERMITTED,
                            String.format("certificate exceeds the maximal allowed size: %d > %d",
                                certSize, maxCertSize));
                    }
                }

                X509Certificate cert;
                try {
                    cert = X509Util.toX509Cert(bcCert);
                } catch (CertificateException ex) {
                    String message = "should not happen, could not parse generated certificate";
                    LOG.error(message, ex);
                    throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
                }

                if (!verifySignature(cert)) {
                    throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                            "could not verify the signature of generated certificate");
                }

                X509CertWithDbId certWithMeta = new X509CertWithDbId(cert, encodedCert);
                ret = new X509CertificateInfo(certWithMeta, caIdent, caCert,
                        gct.grantedPublicKeyData, gct.certprofile.ident(), requestor.ident());
                if (requestor instanceof ByUserRequestorInfo) {
                    ret.setUser((((ByUserRequestorInfo) requestor).userId()));
                }
                ret.setReqType(reqType);
                ret.setTransactionId(transactionId);
                ret.setRequestedSubject(gct.requestedSubject);

                if (publishCertificate0(ret) == 1) {
                    throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                            "could not save certificate");
                }
            } catch (BadCertTemplateException ex) {
                throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
            } catch (OperationException ex) {
                throw ex;
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not generate certificate");
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, th);
            }

            if (gct.warning != null) {
                ret.setWarningMessage(gct.warning);
            }

            return ret;
        } finally {
            publicKeyCertsInProcess.remove(gct.fpPublicKey);
            subjectCertsInProcess.remove(gct.fpSubject);
        }
    } // method generateCertificate0

    private void adaptGrantedSubejct(GrantedCertTemplate gct) throws OperationException {
        boolean duplicateSubjectPermitted = caInfo.isDuplicateSubjectPermitted();
        if (duplicateSubjectPermitted && !gct.certprofile.isDuplicateSubjectPermitted()) {
            duplicateSubjectPermitted = false;
        }

        if (duplicateSubjectPermitted) {
            return;
        }

        long fpSubject = X509Util.fpCanonicalizedName(gct.grantedSubject);
        String grantedSubjectText = X509Util.getRfc4519Name(gct.grantedSubject);

        final boolean incSerial = gct.certprofile.incSerialNumberIfSubjectExists();
        final boolean certIssued = certstore.isCertForSubjectIssued(caIdent, fpSubject);
        if (certIssued && !incSerial) {
            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                    "certificate for the given subject " + grantedSubjectText + " already issued");
        }

        if (!certIssued) {
            return;
        }

        X500Name subject = gct.grantedSubject;

        String latestSn;
        try {
            Object[] objs = incSerialNumber(gct.certprofile, subject, null);
            latestSn = certstore.getLatestSerialNumber((X500Name) objs[0]);
        } catch (BadFormatException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
        }

        boolean foundUniqueSubject = false;
        // maximal 100 tries
        for (int i = 0; i < 100; i++) {
            try {
                Object[] objs = incSerialNumber(gct.certprofile, subject, latestSn);
                subject = (X500Name) objs[0];
                if (CompareUtil.equalsObject(latestSn, objs[1])) {
                    break;
                }
                latestSn = (String) objs[1];
            } catch (BadFormatException ex) {
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
            }

            foundUniqueSubject = !certstore.isCertForSubjectIssued(
                    caIdent, X509Util.fpCanonicalizedName(subject));
            if (foundUniqueSubject) {
                break;
            }
        }

        if (!foundUniqueSubject) {
            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                "certificate for the given subject " + grantedSubjectText + " and profile "
                + gct.certprofile.ident()
                + " already issued, and could not create new unique serial number");
        }

        gct.setGrantedSubject(subject);
    }

    private GrantedCertTemplate createGrantedCertTemplate(final CertTemplateData certTemplate,
            final RequestorInfo requestor, final boolean keyUpdate)
            throws OperationException {
        ParamUtil.requireNonNull("certTemplate", certTemplate);
        if (caInfo.revocationInfo() != null) {
            throw new OperationException(ErrorCode.NOT_PERMITTED, "CA is revoked");
        }

        IdentifiedX509Certprofile certprofile = getX509Certprofile(
                certTemplate.certprofileName());

        if (certprofile == null) {
            throw new OperationException(ErrorCode.UNKNOWN_CERT_PROFILE,
                    "unknown cert profile " + certTemplate.certprofileName());
        }

        ConcurrentContentSigner signer = caInfo.getSigner(certprofile.signatureAlgorithms());
        if (signer == null) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "CA does not support any signature algorithm restricted by the cert profile");
        }

        final NameId certprofileIdent = certprofile.ident();
        if (certprofile.version() != X509CertVersion.v3) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "unknown cert version " + certprofile.version());
        }

        if (certprofile.isOnlyForRa()) {
            if (requestor == null || !requestor.isRa()) {
                throw new OperationException(ErrorCode.NOT_PERMITTED,
                        "profile " + certprofileIdent + " not applied to non-RA");
            }
        }

        X500Name requestedSubject = removeEmptyRdns(certTemplate.subject());

        if (!certprofile.isSerialNumberInReqPermitted()) {
            RDN[] rdns = requestedSubject.getRDNs(ObjectIdentifiers.DN_SN);
            if (rdns != null && rdns.length > 0) {
                throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                        "subjectDN SerialNumber in request is not permitted");
            }
        }

        Date now = new Date();
        Date reqNotBefore ;
        if (certTemplate.notBefore() != null && certTemplate.notBefore().after(now)) {
            reqNotBefore = certTemplate.notBefore();
        } else {
            reqNotBefore = now;
        }
        Date grantedNotBefore = certprofile.notBefore(reqNotBefore);
        // notBefore in the past is not permitted
        if (grantedNotBefore.before(now)) {
            grantedNotBefore = now;
        }

        if (certprofile.hasMidnightNotBefore()) {
            grantedNotBefore = setToMidnight(grantedNotBefore, certprofile.timezone());
        }

        if (grantedNotBefore.before(caInfo.notBefore())) {
            grantedNotBefore = caInfo.notBefore();
            if (certprofile.hasMidnightNotBefore()) {
                grantedNotBefore = setToMidnight(grantedNotBefore, certprofile.timezone());
            }
        }

        long time = caInfo.noNewCertificateAfter();
        if (grantedNotBefore.getTime() > time) {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "CA is not permitted to issue certifate after " + new Date(time));
        }

        SubjectPublicKeyInfo grantedPublicKeyInfo;
        try {
            grantedPublicKeyInfo = X509Util.toRfc3279Style(certTemplate.publicKeyInfo());
        } catch (InvalidKeySpecException ex) {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                    "invalid SubjectPublicKeyInfo");
        }

        // public key
        try {
            grantedPublicKeyInfo = certprofile.checkPublicKey(grantedPublicKeyInfo);
        } catch (BadCertTemplateException ex) {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
        }

        Date gsmckFirstNotBefore = null;
        if (certprofile.specialCertprofileBehavior()
                == SpecialX509CertprofileBehavior.gematik_gSMC_K) {
            gsmckFirstNotBefore = grantedNotBefore;

            RDN[] cnRdns = requestedSubject.getRDNs(ObjectIdentifiers.DN_CN);
            if (cnRdns != null && cnRdns.length > 0) {
                String requestedCn = X509Util.rdnValueToString(cnRdns[0].getFirst().getValue());
                Long gsmckFirstNotBeforeInSecond =
                        certstore.getNotBeforeOfFirstCertStartsWithCommonName(requestedCn,
                                certprofileIdent);
                if (gsmckFirstNotBeforeInSecond != null) {
                    gsmckFirstNotBefore = new Date(gsmckFirstNotBeforeInSecond * MS_PER_SECOND);
                }

                // append the commonName with '-' + yyyyMMdd
                SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMdd");
                dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
                String yyyyMMdd = dateF.format(gsmckFirstNotBefore);
                String suffix = "-" + yyyyMMdd;

                // append the -yyyyMMdd to the commonName
                RDN[] rdns = requestedSubject.getRDNs();
                for (int i = 0; i < rdns.length; i++) {
                    if (ObjectIdentifiers.DN_CN.equals(rdns[i].getFirst().getType())) {
                        rdns[i] = new RDN(ObjectIdentifiers.DN_CN,
                                new DERUTF8String(requestedCn + suffix));
                    }
                }
                requestedSubject = new X500Name(rdns);
            } // end if
        } // end if

        // subject
        SubjectInfo subjectInfo;
        try {
            subjectInfo = certprofile.getSubject(requestedSubject);
        } catch (CertprofileException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "exception in cert profile " + certprofileIdent);
        } catch (BadCertTemplateException ex) {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
        }

        X500Name grantedSubject = subjectInfo.grantedSubject();

        // make sure that empty subject is not permitted
        ASN1ObjectIdentifier[] attrTypes = grantedSubject.getAttributeTypes();
        if (attrTypes == null || attrTypes.length == 0) {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                    "empty subject is not permitted");
        }

        // make sure that the grantedSubject does not equal the CA's subject
        if (X509Util.canonicalizName(grantedSubject).equals(
                caInfo.publicCaInfo().c14nSubject())) {
            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                    "certificate with the same subject as CA is not allowed");
        }

        boolean duplicateKeyPermitted = caInfo.isDuplicateKeyPermitted();
        if (duplicateKeyPermitted && !certprofile.isDuplicateKeyPermitted()) {
            duplicateKeyPermitted = false;
        }

        byte[] subjectPublicKeyData = grantedPublicKeyInfo.getPublicKeyData().getBytes();
        long fpPublicKey = FpIdCalculator.hash(subjectPublicKeyData);

        if (keyUpdate) {
            CertStatus certStatus = certstore.getCertStatusForSubject(caIdent, grantedSubject);
            if (certStatus == CertStatus.REVOKED) {
                throw new OperationException(ErrorCode.CERT_REVOKED);
            } else if (certStatus == CertStatus.UNKNOWN) {
                throw new OperationException(ErrorCode.UNKNOWN_CERT);
            }
        } else {
            if (!duplicateKeyPermitted) {
                if (certstore.isCertForKeyIssued(caIdent, fpPublicKey)) {
                    throw new OperationException(ErrorCode.ALREADY_ISSUED,
                            "certificate for the given public key already issued");
                }
            }
            // duplicateSubject check will be processed later
        } // end if(keyUpdate)

        StringBuilder msgBuilder = new StringBuilder();

        if (subjectInfo.warning() != null) {
            msgBuilder.append(", ").append(subjectInfo.warning());
        }

        CertValidity validity = certprofile.validity();

        if (validity == null) {
            validity = caInfo.maxValidity();
        } else if (validity.compareTo(caInfo.maxValidity()) > 0) {
            validity = caInfo.maxValidity();
        }

        Date maxNotAfter = validity.add(grantedNotBefore);
        if (maxNotAfter.getTime() > MAX_CERT_TIME_MS) {
            maxNotAfter = new Date(MAX_CERT_TIME_MS);
        }

        // CHECKSTYLE:SKIP
        Date origMaxNotAfter = maxNotAfter;

        if (certprofile.specialCertprofileBehavior()
                == SpecialX509CertprofileBehavior.gematik_gSMC_K) {
            String str = certprofile.parameter(
                    SpecialX509CertprofileBehavior.PARAMETER_MAXLIFTIME);
            long maxLifetimeInDays = Long.parseLong(str);
            Date maxLifetime = new Date(gsmckFirstNotBefore.getTime()
                    + maxLifetimeInDays * DAY_IN_MS - MS_PER_SECOND);
            if (maxNotAfter.after(maxLifetime)) {
                maxNotAfter = maxLifetime;
            }
        }

        Date grantedNotAfter = certTemplate.notAfter();
        if (grantedNotAfter != null) {
            if (grantedNotAfter.after(maxNotAfter)) {
                grantedNotAfter = maxNotAfter;
                msgBuilder.append(", notAfter modified");
            }
        } else {
            grantedNotAfter = maxNotAfter;
        }

        if (grantedNotAfter.after(caInfo.notAfter())) {
            ValidityMode mode = caInfo.validityMode();
            if (mode == ValidityMode.CUTOFF) {
                grantedNotAfter = caInfo.notAfter();
            } else if (mode == ValidityMode.STRICT) {
                throw new OperationException(ErrorCode.NOT_PERMITTED,
                        "notAfter outside of CA's validity is not permitted");
            } else if (mode == ValidityMode.LAX) {
                // permitted
            } else {
                throw new RuntimeException(
                        "should not reach here, unknown CA ValidityMode " + mode);
            } // end if (mode)
        } // end if (notAfter)

        if (certprofile.hasMidnightNotBefore() && !maxNotAfter.equals(origMaxNotAfter)) {
            Calendar cal = Calendar.getInstance(certprofile.timezone());
            cal.setTime(new Date(grantedNotAfter.getTime() - DAY_IN_MS));
            cal.set(Calendar.HOUR_OF_DAY, 23);
            cal.set(Calendar.MINUTE, 59);
            cal.set(Calendar.SECOND, 59);
            cal.set(Calendar.MILLISECOND, 0);
            grantedNotAfter = cal.getTime();
        }

        String warning = null;
        if (msgBuilder.length() > 2) {
            warning = msgBuilder.substring(2);
        }
        GrantedCertTemplate gct = new GrantedCertTemplate(certTemplate.extensions(), certprofile,
                grantedNotBefore, grantedNotAfter, requestedSubject, grantedPublicKeyInfo,
                fpPublicKey, subjectPublicKeyData, signer, warning);
        gct.setGrantedSubject(grantedSubject);
        return gct;

    } // method createGrantedCertTemplate

    public IdentifiedX509Certprofile getX509Certprofile(final String certprofileName) {
        if (certprofileName == null) {
            return null;
        }

        Set<String> profileNames = caManager.getCertprofilesForCa(caIdent.name());
        return (profileNames == null || !profileNames.contains(certprofileName))
                ? null : caManager.identifiedCertprofile(certprofileName);
    } // method getX509Certprofile

    public boolean supportsCertProfile(final String certprofileName) {
        ParamUtil.requireNonNull("certprofileLocalName", certprofileName);
        Set<String> profileNames = caManager.getCertprofilesForCa(caIdent.name());
        return profileNames.contains(certprofileName.toUpperCase());
    }

    public CmpRequestorInfo getRequestor(final X500Name requestorSender) {
        if (requestorSender == null) {
            return null;
        }

        Set<CaHasRequestorEntry> requestorEntries = caManager.getRequestorsForCa(caIdent.name());
        if (CollectionUtil.isEmpty(requestorEntries)) {
            return null;
        }

        for (CaHasRequestorEntry m : requestorEntries) {
            CmpRequestorEntryWrapper entry = caManager.cmpRequestorWrapper(
                    m.requestorIdent().name());
            if (entry.cert().subjectAsX500Name().equals(requestorSender)) {
                return new CmpRequestorInfo(m, entry.cert());
            }
        }

        return null;
    } // method getRequestor

    public CmpRequestorInfo getRequestor(final X509Certificate requestorCert) {
        if (requestorCert == null) {
            return null;
        }

        Set<CaHasRequestorEntry> requestorEntries =
                caManager.getRequestorsForCa(caIdent.name());
        if (CollectionUtil.isEmpty(requestorEntries)) {
            return null;
        }

        for (CaHasRequestorEntry m : requestorEntries) {
            CmpRequestorEntryWrapper entry = caManager.cmpRequestorWrapper(
                    m.requestorIdent().name());
            if (entry.cert().cert().equals(requestorCert)) {
                return new CmpRequestorInfo(m, entry.cert());
            }
        }

        return null;
    }

    public CaManagerImpl caManager() {
        return caManager;
    }

    private Date getCrlNextUpdate(final Date thisUpdate) {
        ParamUtil.requireNonNull("thisUpdate", thisUpdate);
        CrlControl control = getCrlSigner().crlControl();
        if (control.updateMode() != UpdateMode.interval) {
            return null;
        }

        int intervalsTillNextCrl = 0;
        for (int i = 1;; i++) {
            if (i % control.fullCrlIntervals() == 0) {
                intervalsTillNextCrl = i;
                break;
            } else if (!control.isExtendedNextUpdate() && control.deltaCrlIntervals() > 0) {
                if (i % control.deltaCrlIntervals() == 0) {
                    intervalsTillNextCrl = i;
                    break;
                }
            }
        }

        Date nextUpdate;
        if (control.intervalMinutes() != null) {
            int minutesTillNextUpdate = intervalsTillNextCrl * control.intervalMinutes()
                    + control.overlapMinutes();
            nextUpdate = new Date(MS_PER_SECOND * (thisUpdate.getTime() / MS_PER_SECOND / 60
                    + minutesTillNextUpdate) * 60);
        } else {
            Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            cal.setTime(thisUpdate);
            cal.add(Calendar.DAY_OF_YEAR, intervalsTillNextCrl);
            cal.set(Calendar.HOUR_OF_DAY, control.intervalDayTime().hour());
            cal.set(Calendar.MINUTE, control.intervalDayTime().minute());
            cal.add(Calendar.MINUTE, control.overlapMinutes());
            cal.set(Calendar.SECOND, 0);
            cal.set(Calendar.MILLISECOND, 0);
            nextUpdate = cal.getTime();
        }

        return nextUpdate;
    } // method getCrlNextUpdate

    private int removeExpirtedCerts(final Date expiredAtTime, final String msgId)
            throws OperationException {
        LOG.debug("revoking suspended certificates");
        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_remove_expiredCerts, msgId);
        boolean successful = false;
        try {
            int num = removeExpirtedCerts0(expiredAtTime, event, msgId);
            LOG.info("removed {} expired certificates of CA {}", num, caIdent);
            successful = true;
            return num;
        } finally {
            finish(event, successful);
        }
    }

    private int removeExpirtedCerts0(final Date expiredAtTime, final AuditEvent event,
            final String msgId)
            throws OperationException {
        ParamUtil.requireNonNull("expiredtime", expiredAtTime);
        if (!masterMode) {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "CA could not remove expired certificates in slave mode");
        }

        event.addEventData(CaAuditConstants.NAME_expiredAt, expiredAtTime);
        final int numEntries = 100;

        final long expiredAt = expiredAtTime.getTime() / 1000;

        int sum = 0;
        while (true) {
            List<BigInteger> serials = certstore.getExpiredCertSerials(caIdent, expiredAt,
                    numEntries);
            if (CollectionUtil.isEmpty(serials)) {
                return sum;
            }

            for (BigInteger serial : serials) {
                // do not delete CA's own certificate
                if ((caInfo.isSelfSigned() && caInfo.serialNumber().equals(serial))) {
                    continue;
                }

                try {
                    if (removeCertificate(serial, msgId) != null) {
                        sum++;
                    }
                } catch (OperationException ex) {
                    LOG.info("removed {} expired certificates of CA {}", sum, caIdent);
                    LogUtil.error(LOG, ex, "could not remove expired certificate with serial"
                            + serial);
                    throw ex;
                }
            } // end for
        } // end while (true)
    } // method removeExpirtedCerts

    private int revokeSuspendedCerts(final String msgId) throws OperationException {
        LOG.debug("revoking suspended certificates");
        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_revoke_suspendedCert, msgId);
        boolean successful = false;
        try {
            int num = revokeSuspendedCerts0(event, msgId);
            LOG.info("revoked {} suspended certificates of CA {}", num, caIdent);
            successful = true;
            return num;
        } finally {
            finish(event, successful);
        }
    }

    private int revokeSuspendedCerts0(final AuditEvent event, final String msgId)
            throws OperationException {
        if (!masterMode) {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "CA could not remove expired certificates in slave mode");
        }

        final int numEntries = 100;

        CertValidity val = caInfo.revokeSuspendedCertsControl().unchangedSince();
        long ms;
        switch (val.unit()) {
        case DAY:
            ms = val.validity() * DAY_IN_MS;
            break;
        case HOUR:
            ms = val.validity() * DAY_IN_MS / 24;
            break;
        case YEAR:
            ms = val.validity() * 365 * DAY_IN_MS;
            break;
        default:
            throw new RuntimeException("should not reach here, unknown Validity Unit "
                + val.unit());
        }
        final long latestLastUpdatedAt = (System.currentTimeMillis() - ms) / 1000; // seconds
        final CrlReason reason = caInfo.revokeSuspendedCertsControl().targetReason();

        int sum = 0;
        while (true) {
            List<BigInteger> serials = certstore.getSuspendedCertSerials(caIdent,
                    latestLastUpdatedAt, numEntries);
            if (CollectionUtil.isEmpty(serials)) {
                return sum;
            }

            for (BigInteger serial : serials) {
                boolean revoked = false;
                try {
                    revoked = revokeSuspendedCert(serial, reason, msgId) != null;
                    if (revoked) {
                        sum++;
                    }
                } catch (OperationException ex) {
                    LOG.info("revoked {} suspended certificates of CA {}", sum, caIdent);
                    LogUtil.error(LOG, ex, "could not revoke suspended certificate with serial"
                            + serial);
                    throw ex;
                } // end try
            } // end for
        } // end while (true)
    } // method removeExpirtedCerts

    public HealthCheckResult healthCheck() {
        HealthCheckResult result = new HealthCheckResult("X509CA");

        boolean healthy = true;

        ConcurrentContentSigner signer = caInfo.getSigner(null);
        if (signer != null) {
            boolean caSignerHealthy = signer.isHealthy();
            healthy &= caSignerHealthy;

            HealthCheckResult signerHealth = new HealthCheckResult("Signer");
            signerHealth.setHealthy(caSignerHealthy);
            result.addChildCheck(signerHealth);
        }

        boolean databaseHealthy = certstore.isHealthy();
        healthy &= databaseHealthy;

        HealthCheckResult databaseHealth = new HealthCheckResult("Database");
        databaseHealth.setHealthy(databaseHealthy);
        result.addChildCheck(databaseHealth);

        X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
        if (crlSigner != null && crlSigner.signer() != null) {
            boolean crlSignerHealthy = crlSigner.signer().isHealthy();
            healthy &= crlSignerHealthy;

            HealthCheckResult crlSignerHealth = new HealthCheckResult("CRLSigner");
            crlSignerHealth.setHealthy(crlSignerHealthy);
            result.addChildCheck(crlSignerHealth);
        }

        for (IdentifiedX509CertPublisher publisher : publishers()) {
            boolean ph = publisher.isHealthy();
            healthy &= ph;

            HealthCheckResult publisherHealth = new HealthCheckResult("Publisher");
            publisherHealth.setHealthy(publisher.isHealthy());
            result.addChildCheck(publisherHealth);
        }

        result.setHealthy(healthy);

        return result;
    } // method healthCheck

    public void setAuditServiceRegister(final AuditServiceRegister auditServiceRegister) {
        this.auditServiceRegister = ParamUtil.requireNonNull("auditServiceRegister",
                auditServiceRegister);
    }

    private AuditService auditService() {
        return auditServiceRegister.getAuditService();
    }

    private AuditEvent newPerfAuditEvent(final String eventType, final String msgId) {
        return newAuditEvent(CaAuditConstants.NAME_PERF, eventType, msgId);
    }

    private AuditEvent newAuditEvent(final String name, final String eventType,
            final String msgId) {
        ParamUtil.requireNonNull("name", name);
        ParamUtil.requireNonNull("eventType", eventType);
        ParamUtil.requireNonNull("msgId", msgId);
        AuditEvent event = new AuditEvent(new Date());
        event.setApplicationName(CaAuditConstants.APPNAME);
        event.setName(name);
        event.addEventData(CaAuditConstants.NAME_CA, caIdent.name());
        event.addEventType(eventType);
        event.addEventData(CaAuditConstants.NAME_mid, msgId);
        return event;
    }

    private boolean verifySignature(final X509Certificate cert) {
        ParamUtil.requireNonNull("cert", cert);
        PublicKey caPublicKey = caCert.cert().getPublicKey();
        try {
            final String provider = XiSecurityConstants.PROVIDER_NAME_NSS;

            if (tryNssToVerify == null) {
                // Not for ECDSA
                if (caPublicKey instanceof ECPublicKey) {
                    tryNssToVerify = Boolean.FALSE;
                } else if (Security.getProvider(provider) == null) {
                    LOG.info("security provider {} is not registered", provider);
                    tryNssToVerify = Boolean.FALSE;
                } else {
                    byte[] tbs = cert.getTBSCertificate();
                    byte[] signatureValue = cert.getSignature();
                    String sigAlgName = cert.getSigAlgName();
                    try {
                        Signature verifier = Signature.getInstance(sigAlgName, provider);
                        verifier.initVerify(caPublicKey);
                        verifier.update(tbs);
                        boolean sigValid = verifier.verify(signatureValue);

                        LOG.info("use {} to verify {} signature", provider, sigAlgName);
                        tryNssToVerify = Boolean.TRUE;
                        return sigValid;
                    } catch (Exception ex) {
                        LOG.info("could not use {} to verify {} signature", provider, sigAlgName);
                        tryNssToVerify = Boolean.FALSE;
                    }
                }
            }

            if (tryNssToVerify) {
                byte[] tbs = cert.getTBSCertificate();
                byte[] signatureValue = cert.getSignature();
                String sigAlgName = cert.getSigAlgName();
                Signature verifier = Signature.getInstance(sigAlgName, provider);
                verifier.initVerify(caPublicKey);
                verifier.update(tbs);
                return verifier.verify(signatureValue);
            } else {
                cert.verify(caPublicKey);
                return true;
            }
        } catch (SignatureException | InvalidKeyException | CertificateException
                | NoSuchAlgorithmException | NoSuchProviderException ex) {
            LOG.debug("{} while verifying signature: {}", ex.getClass().getName(), ex.getMessage());
            return false;
        }
    } // method verifySignature

    private X509CrlSignerEntryWrapper getCrlSigner() {
        String crlSignerName = caInfo.crlSignerName();
        X509CrlSignerEntryWrapper crlSigner = (crlSignerName == null) ? null
                : caManager.crlSignerWrapper(crlSignerName);
        return crlSigner;
    }

    public NameId caIdent() {
        return caIdent;
    }

    public String getHexSha1OfCert() {
        return caInfo.caEntry().hexSha1OfCert();
    }

    void shutdown() {
        if (crlGenerationService != null) {
            crlGenerationService.cancel(false);
            crlGenerationService = null;
        }

        if (expiredCertsRemover != null) {
            expiredCertsRemover.cancel(false);
            expiredCertsRemover = null;
        }

        if (suspendedCertsRevoker != null) {
            suspendedCertsRevoker.cancel(false);
            suspendedCertsRevoker = null;
        }

        ScheduledThreadPoolExecutor executor = caManager.scheduledThreadPoolExecutor();
        if (executor != null) {
            executor.purge();
        }
    }

    private static Extension createReasonExtension(final int reasonCode) {
        CRLReason crlReason = CRLReason.lookup(reasonCode);
        try {
            return new Extension(Extension.reasonCode, false, crlReason.getEncoded());
        } catch (IOException ex) {
            throw new IllegalArgumentException("error encoding reason: " + ex.getMessage(), ex);
        }
    }

    private static Extension createInvalidityDateExtension(final Date invalidityDate) {
        try {
            ASN1GeneralizedTime asnTime = new ASN1GeneralizedTime(invalidityDate);
            return new Extension(Extension.invalidityDate, false, asnTime.getEncoded());
        } catch (IOException ex) {
            throw new IllegalArgumentException("error encoding reason: " + ex.getMessage(), ex);
        }
    }

    private static Extension createCertificateIssuerExtension(final X500Name certificateIssuer) {
        try {
            GeneralNames generalNames = new GeneralNames(new GeneralName(certificateIssuer));
            return new Extension(Extension.certificateIssuer, true, generalNames.getEncoded());
        } catch (IOException ex) {
            throw new IllegalArgumentException("error encoding reason: " + ex.getMessage(), ex);
        }
    }

    // remove the RDNs with empty content
    private static X500Name removeEmptyRdns(final X500Name name) {
        RDN[] rdns = name.getRDNs();
        List<RDN> tmpRdns = new ArrayList<>(rdns.length);
        boolean changed = false;
        for (RDN rdn : rdns) {
            String textValue = X509Util.rdnValueToString(rdn.getFirst().getValue());
            if (StringUtil.isBlank(textValue)) {
                changed = true;
            } else {
                tmpRdns.add(rdn);
            }
        }

        return changed ? new X500Name(tmpRdns.toArray(new RDN[0])) : name;
    } // method removeEmptyRdns

    private static Object[] incSerialNumber(final IdentifiedX509Certprofile profile,
            final X500Name origName, final String latestSn) throws BadFormatException {
        RDN[] rdns = origName.getRDNs();

        int commonNameIndex = -1;
        int serialNumberIndex = -1;
        for (int i = 0; i < rdns.length; i++) {
            RDN rdn = rdns[i];
            ASN1ObjectIdentifier type = rdn.getFirst().getType();
            if (ObjectIdentifiers.DN_CN.equals(type)) {
                commonNameIndex = i;
            } else if (ObjectIdentifiers.DN_SERIALNUMBER.equals(type)) {
                serialNumberIndex = i;
            }
        }

        String newSerialNumber = profile.incSerialNumber(latestSn);
        RDN serialNumberRdn = new RDN(ObjectIdentifiers.DN_SERIALNUMBER,
                new DERPrintableString(newSerialNumber));

        X500Name newName;
        if (serialNumberIndex != -1) {
            rdns[serialNumberIndex] = serialNumberRdn;
            newName = new X500Name(rdns);
        } else {
            List<RDN> newRdns = new ArrayList<>(rdns.length + 1);

            if (commonNameIndex == -1) {
                newRdns.add(serialNumberRdn);
            }

            for (int i = 0; i < rdns.length; i++) {
                newRdns.add(rdns[i]);
                if (i == commonNameIndex) {
                    newRdns.add(serialNumberRdn);
                }
            }

            newName = new X500Name(newRdns.toArray(new RDN[0]));
        }

        return new Object[]{newName, newSerialNumber};
    } // method incSerialNumber

    private static Date setToMidnight(final Date date, final TimeZone timezone) {
        Calendar cal = Calendar.getInstance(timezone);
        // the next midnight time
        cal.setTime(new Date(date.getTime() + DAY_IN_MS - 1));
        cal.set(Calendar.HOUR_OF_DAY, 0);
        cal.set(Calendar.MINUTE, 0);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTime();
    }

    private void finish(final AuditEvent event, final boolean successful) {
        event.finish();
        event.setLevel(successful ? AuditLevel.INFO : AuditLevel.ERROR);
        event.setStatus(successful ? AuditStatus.SUCCESSFUL : AuditStatus.FAILED);
        auditService().logEvent(event);
    }

}
