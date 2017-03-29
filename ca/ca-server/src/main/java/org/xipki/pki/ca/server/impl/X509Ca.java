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
import org.xipki.commons.audit.AuditEvent;
import org.xipki.commons.audit.AuditLevel;
import org.xipki.commons.audit.AuditService;
import org.xipki.commons.audit.AuditServiceRegister;
import org.xipki.commons.audit.AuditStatus;
import org.xipki.commons.common.HealthCheckResult;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.CompareUtil;
import org.xipki.commons.common.util.DateUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.CertRevocationInfo;
import org.xipki.commons.security.ConcurrentContentSigner;
import org.xipki.commons.security.CrlReason;
import org.xipki.commons.security.FpIdCalculator;
import org.xipki.commons.security.KeyUsage;
import org.xipki.commons.security.ObjectIdentifiers;
import org.xipki.commons.security.X509Cert;
import org.xipki.commons.security.XiSecurityConstants;
import org.xipki.commons.security.exception.NoIdleSignerException;
import org.xipki.commons.security.exception.XiSecurityException;
import org.xipki.commons.security.util.X509Util;
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

    private class ScheduledExpiredCertsRemover implements Runnable {

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

    } // class ScheduledExpiredCertsRemover

    private class ScheduledCrlGenerationService implements Runnable {

        @Override
        public void run() {
            X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
            if (crlSigner == null
                    || crlSigner.getCrlControl().getUpdateMode() != UpdateMode.interval) {
                return;
            }

            if (crlGenInProcess.get()) {
                return;
            }

            crlGenInProcess.set(true);

            try {
                doRun();
            } catch (Throwable th) {
                LogUtil.error(LOG, th);
            } finally {
                crlGenInProcess.set(false);
            }
        } // method run

        private void doRun() throws OperationException {
            final long signWindowMin = 20;

            Date thisUpdate = new Date();
            long minSinceCrlBaseTime = (thisUpdate.getTime() - caInfo.getCrlBaseTime().getTime())
                    / MS_PER_MINUTE;

            CrlControl control = getCrlSigner().getCrlControl();
            int interval;

            if (control.getIntervalMinutes() != null && control.getIntervalMinutes() > 0) {
                long intervalMin = control.getIntervalMinutes();
                interval = (int) (minSinceCrlBaseTime / intervalMin);

                long baseTimeInMin = interval * intervalMin;
                if (minSinceCrlBaseTime - baseTimeInMin > signWindowMin) {
                    // only generate CRL within the time window
                    return;
                }
            } else if (control.getIntervalDayTime() != null) {
                HourMinute hm = control.getIntervalDayTime();
                Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                cal.setTime(thisUpdate);
                int minute = cal.get(Calendar.HOUR_OF_DAY) * 60 + cal.get(Calendar.MINUTE);
                int scheduledMinute = hm.getHour() * 60 + hm.getMinute();
                if (minute < scheduledMinute || minute - scheduledMinute > signWindowMin) {
                    return;
                }
                interval = (int) (minSinceCrlBaseTime % MINUTE_PER_DAY);
            } else {
                throw new RuntimeException("should not reach here, neither interval minutes"
                        + " nor dateTime is specified");
            }

            boolean deltaCrl;
            if (interval % control.getFullCrlIntervals() == 0) {
                deltaCrl = false;
            } else if (control.getDeltaCrlIntervals() > 0
                    && interval % control.getDeltaCrlIntervals() == 0) {
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
                if (i % control.getFullCrlIntervals() == 0) {
                    nextFullCrlInterval = i;
                    break;
                }

                if (nextDeltaCrlInterval != 0 && control.getDeltaCrlIntervals() != 0
                        && i % control.getDeltaCrlIntervals() == 0) {
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
            if (control.getIntervalMinutes() != null) {
                int minutesTillNextUpdate = (intervalOfNextUpdate - interval)
                        * control.getIntervalMinutes() + control.getOverlapMinutes();
                nextUpdate = new Date(MS_PER_SECOND * (nowInSecond + minutesTillNextUpdate * 60));
            } else {
                HourMinute hm = control.getIntervalDayTime();
                Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                cal.setTime(new Date(nowInSecond * MS_PER_SECOND));
                cal.add(Calendar.DAY_OF_YEAR, (intervalOfNextUpdate - interval));
                cal.set(Calendar.HOUR_OF_DAY, hm.getHour());
                cal.set(Calendar.MINUTE, hm.getMinute());
                cal.add(Calendar.MINUTE, control.getOverlapMinutes());
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
        } // method doRun

    } // class ScheduledCrlGenerationService

    private class ScheduledSuspendedCertsRevoker implements Runnable {

        private boolean inProcess;

        @Override
        public void run() {
            if (caInfo.getRevokeSuspendedCertsControl() == null) {
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

    } // class ScheduledSuspendedCertsRevoker

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
        this.caIdNameMap = caManager.getIdNameMap();
        this.caInfo = ParamUtil.requireNonNull("caInfo", caInfo);
        this.caIdent = caInfo.getIdent();
        this.caCert = caInfo.getCertificate();
        this.certstore = ParamUtil.requireNonNull("certstore", certstore);

        if (caInfo.isSignerRequired()) {
            try {
                caInfo.initSigner(caManager.getSecurityFactory());
            } catch (XiSecurityException ex) {
                LogUtil.error(LOG, ex, "security.createSigner caSigner for CA " + caIdent);
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
            }
        }

        X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
        if (crlSigner != null) {
            // CA signs the CRL
            if (caManager.getCrlSignerWrapper(caInfo.getCrlSignerName()) == null
                    && !X509Util.hasKeyusage(caCert.getCert(), KeyUsage.cRLSign)) {
                final String msg = "CRL signer does not have keyusage cRLSign";
                LOG.error(msg);
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, msg);
            }
        }

        if (!masterMode) {
            return;
        }

        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
            publisher.caAdded(caCert);
        }

        // CRL generation services
        this.crlGenerationService = caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
                new ScheduledCrlGenerationService(), 1, 1, TimeUnit.MINUTES);

        this.expiredCertsRemover = caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
                new ScheduledExpiredCertsRemover(), 1, 1, TimeUnit.DAYS);

        this.suspendedCertsRevoker = caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
                new ScheduledSuspendedCertsRevoker(), 30, 60, TimeUnit.MINUTES);
    } // constructor

    public X509CaInfo getCaInfo() {
        return caInfo;
    }

    public CmpControl getCmpControl() {
        String name = caInfo.getCmpControlName();
        return (name == null) ? null : caManager.getCmpControlObject(name);
    }

    public X509Certificate getCertificate(final BigInteger serialNumber)
            throws CertificateException, OperationException {
        X509CertificateInfo certInfo = certstore.getCertificateInfoForSerial(caIdent,
                caCert, serialNumber, caIdNameMap);
        return (certInfo == null) ? null : certInfo.getCert().getCert();
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
        if (!caInfo.getSubject().equals(X509Util.getRfc4519Name(cert.getIssuerX500Principal()))) {
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
        if (!caManager.getSecurityFactory().verifyPopo(
                csr, getCmpControl().getPopoAlgoValidator())) {
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
        int numCrls = caInfo.getNumCrls();
        LOG.info("     START cleanupCrls: ca={}, numCrls={}", caIdent, numCrls);

        boolean successful = false;
        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_cleanup_CRL, msgId);

        try {
            int num = (numCrls <= 0) ? 0
                    : certstore.cleanupCrls(caIdent, caInfo.getNumCrls());
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
            X509CRL crl = doGenerateCrl(deltaCrl, thisUpdate, nextUpdate, event, msgId);
            successful = true;
            return crl;
        } finally {
            finish(event, successful);
        }
    }

    private X509CRL doGenerateCrl(final boolean deltaCrl, final Date thisUpdate,
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

        CrlControl crlControl = crlSigner.getCrlControl();
        boolean successful = false;

        try {
            ConcurrentContentSigner tmpCrlSigner = crlSigner.getSigner();
            CrlControl control = crlSigner.getCrlControl();

            boolean directCrl;
            X500Name crlIssuer;
            if (tmpCrlSigner == null) {
                directCrl = true;
                crlIssuer = caInfo.getPublicCaInfo().getX500Subject();
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
                    if (revInfo.getId() > maxId) {
                        maxId = revInfo.getId();
                    }

                    CrlReason reason = revInfo.getReason();
                    if (crlControl.isExcludeReason() && reason != CrlReason.REMOVE_FROM_CRL) {
                        reason = CrlReason.UNSPECIFIED;
                    }

                    Date revocationTime = revInfo.getRevocationTime();
                    Date invalidityTime = revInfo.getInvalidityTime();

                    switch (crlControl.getInvalidityDateMode()) {
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
                                + crlControl.getInvalidityDateMode());
                    }

                    BigInteger serial = revInfo.getSerial();
                    LOG.debug("added cert ca={} serial={} to CRL", caIdent, serial);

                    if (directCrl || !isFirstCrlEntry) {
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

                    Extension ext = createCertificateIssuerExtension(
                            caInfo.getPublicCaInfo().getX500Subject());
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
                        ? caInfo.getPublicCaInfo().getSubjectKeyIdentifer()
                        : crlSigner.getSubjectKeyIdentifier();
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
                List<String> deltaCrlUris = getCaInfo().getPublicCaInfo().getDeltaCrlUris();
                if (control.getDeltaCrlIntervals() > 0 && CollectionUtil.isNonEmpty(deltaCrlUris)) {
                    CRLDistPoint cdp = CaUtil.createCrlDistributionPoints(deltaCrlUris,
                            caInfo.getPublicCaInfo().getX500Subject(), crlIssuer);
                    crlBuilder.addExtension(Extension.freshestCRL, false, cdp);
                }
            } catch (CertIOException ex) {
                LogUtil.error(LOG, ex, "crlBuilder.addExtension");
                throw new OperationException(ErrorCode.INVALID_EXTENSION, ex);
            }

            addXipkiCertset(crlBuilder, deltaCrl, control, notExpireAt, onlyCaCerts, onlyUserCerts);

            ConcurrentContentSigner concurrentSigner = (tmpCrlSigner == null)
                    ? caInfo.getSigner(null) : tmpCrlSigner;

            X509CRLHolder crlHolder;
            try {
                crlHolder = concurrentSigner.build(crlBuilder);
            } catch (NoIdleSignerException ex) {
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, "NoIdleSignerException: "
                        + ex.getMessage());
            }

            try {
                X509CRL crl = X509Util.toX509Crl(crlHolder.toASN1Structure());
                caInfo.getCaEntry().setNextCrlNumber(crlNumber.longValue() + 1);
                caManager.commitNextCrlNo(caIdent, caInfo.getCaEntry().getNextCrlNumber());
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
                if (sid.getId() > maxId) {
                    maxId = sid.getId();
                }

                ASN1EncodableVector vec = new ASN1EncodableVector();
                vec.add(new ASN1Integer(sid.getSerial()));

                Integer profileId = null;

                if (control.isXipkiCertsetCertIncluded()) {
                    X509CertificateInfo certInfo;
                    try {
                        certInfo = certstore.getCertificateInfoForId(caIdent, caCert,
                                sid.getId(), caIdNameMap);
                    } catch (CertificateException ex) {
                        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                                "CertificateException: " + ex.getMessage());
                    }

                    Certificate cert = Certificate.getInstance(certInfo.getCert().getEncodedCert());
                    vec.add(new DERTaggedObject(true, 0, cert));

                    if (control.isXipkiCertsetProfilenameIncluded()) {
                        profileId = certInfo.getProfile().getId();
                    }
                } else if (control.isXipkiCertsetProfilenameIncluded()) {
                    profileId = certstore.getCertProfileForId(caIdent, sid.getId());
                }

                if (profileId != null) {
                    String profileName = caIdNameMap.getCertprofileName(profileId);
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
        return doPublishCertificate(certInfo) == 0;
    }

    /**
     *
     * @param certInfo certificate to be published.
     * @return 0 for published successfully, 1 if could not be published to CA certstore and
     *     any publishers, 2 if could be published to CA certstore but not to all publishers.
     */
    private int doPublishCertificate(final X509CertificateInfo certInfo) {
        ParamUtil.requireNonNull("certInfo", certInfo);
        if (certInfo.isAlreadyIssued()) {
            return 0;
        }

        if (!certstore.addCertificate(certInfo)) {
            return 1;
        }

        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
            if (!publisher.isAsyn()) {
                boolean successful;
                try {
                    successful = publisher.certificateAdded(certInfo);
                } catch (RuntimeException ex) {
                    successful = false;
                    LogUtil.warn(LOG, ex, "could not publish certificate to the publisher "
                            + publisher.getIdent());
                }

                if (successful) {
                    continue;
                }
            } // end if

            Long certId = certInfo.getCert().getCertId();
            try {
                certstore.addToPublishQueue(publisher.getIdent(), certId.longValue(), caIdent);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not add entry to PublishQueue");
                return 2;
            }
        } // end for

        return 0;
    } // method doPublishCertificate

    public boolean republishCertificates(final List<String> publisherNames, final int numThreads) {
        List<IdentifiedX509CertPublisher> publishers;
        if (publisherNames == null) {
            publishers = getPublishers();
        } else {
            publishers = new ArrayList<>(publisherNames.size());

            for (String publisherName : publisherNames) {
                IdentifiedX509CertPublisher publisher = null;
                for (IdentifiedX509CertPublisher p : getPublishers()) {
                    if (p.getIdent().getName().equals(publisherName)) {
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

        CaStatus status = caInfo.getStatus();

        caInfo.setStatus(CaStatus.INACTIVE);

        boolean onlyRevokedCerts = true;
        for (IdentifiedX509CertPublisher publisher : publishers) {
            if (publisher.publishsGoodCert()) {
                onlyRevokedCerts = false;
            }

            NameId publisherIdent = publisher.getIdent();
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
                            publisher.getIdent());
                    return false;
                }
            }

            if (caInfo.getRevocationInfo() != null) {
                for (IdentifiedX509CertPublisher publisher : publishers) {
                    boolean successful = publisher.caRevoked(caCert, caInfo.getRevocationInfo());
                    if (!successful) {
                        LOG.error("republishing CA revocation to publisher {} failed",
                                publisher.getIdent());
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
            NameId publisherIdent = caIdNameMap.getPublisher(publisherName);
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
        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
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
                certIds = certstore.getPublishQueueEntries(caIdent, publisher.getIdent(),
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
                    certstore.removeFromPublishQueue(publisher.getIdent(), certId);
                } catch (OperationException ex) {
                    LogUtil.warn(LOG, ex, "could not remove republished cert id=" + certId
                            + " and publisher=" + publisher.getIdent());
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

        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
            try {
                publisher.crlAdded(caCert, crl);
            } catch (RuntimeException ex) {
                LogUtil.error(LOG, ex, "could not publish CRL to the publisher "
                        + publisher.getIdent());
            }
        } // end for

        return true;
    } // method publishCrl

    public X509CertWithRevocationInfo revokeCertificate(final BigInteger serialNumber,
            final CrlReason reason, final Date invalidityTime, final String msgId)
            throws OperationException {
        if (caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber)) {
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
                    + tmpReason.getDescription());
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
            X509CertWithRevocationInfo ret = doRevokeCertificate(serialNumber, reason,
                    invalidityTime, false, event);
            successful = (ret != null);
            return ret;
        } finally {
            finish(event, successful);
        }
    } // method revokeCertificate

    public X509CertWithDbId unrevokeCertificate(final BigInteger serialNumber, final String msgId)
            throws OperationException {
        if (caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber)) {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "insufficient permission unrevoke CA certificate");
        }

        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_unrevoke_CERT, msgId);
        boolean successful = true;
        try {
            X509CertWithDbId ret = doUnrevokeCertificate(serialNumber, false, event);
            successful = true;
            return ret;
        } finally {
            finish(event, successful);
        }
    } // method unrevokeCertificate

    public X509CertWithDbId removeCertificate(final BigInteger serialNumber, String msgId)
            throws OperationException {
        if (caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber)) {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "insufficient permission remove CA certificate");
        }

        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_remove_cert, msgId);
        boolean successful = true;
        try {
            X509CertWithDbId ret = doRemoveCertificate(serialNumber, event);
            successful = (ret != null);
            return ret;
        } finally {
            finish(event, successful);
        }
    } // method removeCertificate

    private X509CertWithDbId doRemoveCertificate(final BigInteger serialNumber,
            final AuditEvent event)
            throws OperationException {
        event.addEventData(CaAuditConstants.NAME_serial, LogUtil.formatCsn(serialNumber));
        X509CertWithRevocationInfo certWithRevInfo =
                certstore.getCertWithRevocationInfo(caIdent, serialNumber, caIdNameMap);
        if (certWithRevInfo == null) {
            return null;
        }

        boolean successful = true;
        X509CertWithDbId certToRemove = certWithRevInfo.getCert();
        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
            boolean singleSuccessful;
            try {
                singleSuccessful = publisher.certificateRemoved(caCert, certToRemove);
            } catch (RuntimeException ex) {
                singleSuccessful = false;
                LogUtil.warn(LOG, ex, "could not remove certificate to the publisher "
                        + publisher.getIdent());
            }

            if (singleSuccessful) {
                continue;
            }

            successful = false;
            X509Certificate cert = certToRemove.getCert();
            if (LOG.isErrorEnabled()) {
                LOG.error("removing certificate issuer='{}', serial={}, subject='{}' from publisher"
                    + " {} failed.", X509Util.getRfc4519Name(cert.getIssuerX500Principal()),
                    LogUtil.formatCsn(cert.getSerialNumber()),
                    X509Util.getRfc4519Name(cert.getSubjectX500Principal()), publisher.getIdent());
            }
        } // end for

        if (!successful) {
            return null;
        }

        certstore.removeCertificate(caIdent, serialNumber);
        return certToRemove;
    } // method doRemoveCertificate

    private X509CertWithRevocationInfo doRevokeCertificate(final BigInteger serialNumber,
            final CrlReason reason, final Date invalidityTime, final boolean force,
            final AuditEvent event) throws OperationException {
        String hexSerial = LogUtil.formatCsn(serialNumber);
        event.addEventData(CaAuditConstants.NAME_serial, hexSerial);
        event.addEventData(CaAuditConstants.NAME_reason, reason.getDescription());
        if (invalidityTime != null) {
            event.addEventData(CaAuditConstants.NAME_invalidityTime,
                    DateUtil.toUtcTimeyyyyMMddhhmmss(invalidityTime));
        }

        LOG.info(
            "     START revokeCertificate: ca={}, serialNumber={}, reason={}, invalidityTime={}",
            caIdent, hexSerial, reason.getDescription(), invalidityTime);

        X509CertWithRevocationInfo revokedCert = null;

        CertRevocationInfo revInfo = new CertRevocationInfo(reason, new Date(), invalidityTime);
        revokedCert = certstore.revokeCertificate(caIdent, serialNumber, revInfo,
                force, shouldPublishToDeltaCrlCache(), caIdNameMap);
        if (revokedCert == null) {
            return null;
        }

        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
            if (!publisher.isAsyn()) {
                boolean successful;
                try {
                    successful = publisher.certificateRevoked(caCert, revokedCert.getCert(),
                            revokedCert.getCertprofile(), revokedCert.getRevInfo());
                } catch (RuntimeException ex) {
                    successful = false;
                    LogUtil.error(LOG, ex,
                            "could not publish revocation of certificate to the publisher "
                            + publisher.getIdent());
                }

                if (successful) {
                    continue;
                }
            } // end if

            Long certId = revokedCert.getCert().getCertId();
            try {
                certstore.addToPublishQueue(publisher.getIdent(), certId.longValue(), caIdent);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not add entry to PublishQueue");
            }
        } // end for

        if (LOG.isInfoEnabled()) {
            LOG.info("SUCCESSFUL revokeCertificate: ca={}, serialNumber={}, reason={},"
                + " invalidityTime={}, revocationResult=REVOKED",
                caIdent, hexSerial, reason.getDescription(), invalidityTime);
        }

        return revokedCert;
    } // method doRevokeCertificate

    private X509CertWithRevocationInfo revokeSuspendedCert(final BigInteger serialNumber,
            final CrlReason reason, final String msgId)
            throws OperationException {
        AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_revoke_suspendedCert, msgId);

        boolean successful = false;
        try {
            X509CertWithRevocationInfo ret = doRevokeSuspendedCert(serialNumber, reason, event);
            successful = (ret != null);
            return ret;
        } finally {
            finish(event, successful);
        }
    }

    private X509CertWithRevocationInfo doRevokeSuspendedCert(final BigInteger serialNumber,
            final CrlReason reason, final AuditEvent event)
            throws OperationException {
        String hexSerial = LogUtil.formatCsn(serialNumber);

        event.addEventData(CaAuditConstants.NAME_serial, hexSerial);
        event.addEventData(CaAuditConstants.NAME_reason, reason.getDescription());

        if (LOG.isInfoEnabled()) {
            LOG.info("     START revokeSuspendedCert: ca={}, serialNumber={}, reason={}",
                caIdent, hexSerial, reason.getDescription());
        }

        X509CertWithRevocationInfo revokedCert = certstore.revokeSuspendedCert(caIdent,
                serialNumber, reason, shouldPublishToDeltaCrlCache(), caIdNameMap);
        if (revokedCert == null) {
            return null;
        }

        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
            if (!publisher.isAsyn()) {
                boolean successful;
                try {
                    successful = publisher.certificateRevoked(caCert, revokedCert.getCert(),
                            revokedCert.getCertprofile(), revokedCert.getRevInfo());
                } catch (RuntimeException ex) {
                    successful = false;
                    LogUtil.error(LOG, ex,
                            "could not publish revocation of certificate to the publisher "
                            + publisher.getIdent());
                }

                if (successful) {
                    continue;
                }
            } // end if

            Long certId = revokedCert.getCert().getCertId();
            try {
                certstore.addToPublishQueue(publisher.getIdent(), certId.longValue(), caIdent);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not add entry to PublishQueue");
            }
        } // end for

        if (LOG.isInfoEnabled()) {
            LOG.info("SUCCESSFUL revokeSuspendedCert: ca={}, serialNumber={}, reason={}",
                caIdent, hexSerial, reason.getDescription());
        }

        return revokedCert;
    } // method doRevokeSuspendedCert

    private X509CertWithDbId doUnrevokeCertificate(final BigInteger serialNumber,
            final boolean force, final AuditEvent event) throws OperationException {
        String hexSerial = LogUtil.formatCsn(serialNumber);
        event.addEventData(CaAuditConstants.NAME_serial, hexSerial);

        LOG.info("     START unrevokeCertificate: ca={}, serialNumber={}", caIdent, hexSerial);

        X509CertWithDbId unrevokedCert = certstore.unrevokeCertificate(caIdent,
                serialNumber, force, shouldPublishToDeltaCrlCache(), caIdNameMap);
        if (unrevokedCert == null) {
            return null;
        }

        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
            if (!publisher.isAsyn()) {
                boolean successful;
                try {
                    successful = publisher.certificateUnrevoked(caCert, unrevokedCert);
                } catch (RuntimeException ex) {
                    successful = false;
                    LogUtil.error(LOG, ex,
                            "could not publish unrevocation of certificate to the publisher "
                            + publisher.getIdent());
                }

                if (successful) {
                    continue;
                }
            } // end if

            Long certId = unrevokedCert.getCertId();
            try {
                certstore.addToPublishQueue(publisher.getIdent(), certId.longValue(), caIdent);
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

        CrlControl control = crlSigner.getCrlControl();
        if (control.getUpdateMode() == UpdateMode.onDemand) {
            return false;
        }

        int deltaCrlInterval = control.getDeltaCrlIntervals();
        return deltaCrlInterval != 0 && deltaCrlInterval < control.getFullCrlIntervals();
    } // method shouldPublishToDeltaCrlCache

    public void revokeCa(final CertRevocationInfo revocationInfo, final String msgId)
            throws OperationException {
        ParamUtil.requireNonNull("revocationInfo", revocationInfo);
        caInfo.setRevocationInfo(revocationInfo);

        if (caInfo.isSelfSigned()) {
            AuditEvent event = newPerfAuditEvent(CaAuditConstants.TYPE_revoke_cert, msgId);
            boolean successful = true;
            try {
                X509CertWithRevocationInfo ret = doRevokeCertificate(caInfo.getSerialNumber(),
                        revocationInfo.getReason(), revocationInfo.getInvalidityTime(), true,
                        event);
                successful = (ret != null);
            } finally {
                finish(event, successful);
            }
        }

        boolean failed = false;
        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
            NameId ident = publisher.getIdent();
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
                doUnrevokeCertificate(caInfo.getSerialNumber(), true, event);
                successful = true;
            } finally {
                finish(event, successful);
            }
        }

        boolean failed = false;
        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
            NameId ident = publisher.getIdent();
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

    private List<IdentifiedX509CertPublisher> getPublishers() {
        return caManager.getIdentifiedPublishersForCa(caIdent.getName());
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
            final NameId certprofilIdent = gct.certprofile.getIdent();
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
                    X509CertWithDbId cert = certInfo.getCert();
                    LOG.info(
                        "{} generateCertificate: CA={}, profile={}, subject='{}', serialNumber={}",
                        prefix, caIdent, certprofilIdent, cert.getSubject(),
                        LogUtil.formatCsn(cert.getCert().getSerialNumber()));
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
                    + " certificates", exception.getIndex());
            // delete generated certificates
            for (X509CertificateInfo m : certInfos) {
                BigInteger serial = m.getCert().getCert().getSerialNumber();
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
            X509CertificateInfo ret = doGenerateCertificate(gct, requestor,
                    keyUpdate, reqType, transactionId, event);
            successful = (ret != null);
            return ret;
        } finally {
            finish(event, successful);
        }
    }

    private X509CertificateInfo doGenerateCertificate(final GrantedCertTemplate gct,
            final RequestorInfo requestor, final boolean keyUpdate, final RequestType reqType,
            final byte[] transactionId, final AuditEvent event)
            throws OperationException {
        ParamUtil.requireNonNull("gct", gct);

        event.addEventData(CaAuditConstants.NAME_reqSubject,
                X509Util.getRfc4519Name(gct.requestedSubject));
        event.addEventData(CaAuditConstants.NAME_certprofile, gct.certprofile.getIdent().getName());
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
                    caInfo.getPublicCaInfo().getX500Subject(), caInfo.nextSerial(),
                    gct.grantedNotBefore, gct.grantedNotAfter, gct.grantedSubject,
                    gct.grantedPublicKey);

            X509CertificateInfo ret;

            try {
                X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
                X509Certificate crlSignerCert = (crlSigner == null) ? null : crlSigner.getCert();

                ExtensionValues extensionTuples = certprofile.getExtensions(
                        gct.requestedSubject, gct.grantedSubject, gct.extensions,
                        gct.grantedPublicKey, caInfo.getPublicCaInfo(), crlSignerCert,
                        gct.grantedNotBefore, gct.grantedNotAfter);
                if (extensionTuples != null) {
                    for (ASN1ObjectIdentifier extensionType : extensionTuples.getExtensionTypes()) {
                        ExtensionValue extValue = extensionTuples.getExtensionValue(extensionType);
                        certBuilder.addExtension(extensionType, extValue.isCritical(),
                                extValue.getValue());
                    }
                }

                X509CertificateHolder certHolder;
                try {
                    certHolder = gct.signer.build(certBuilder);
                } catch (NoIdleSignerException ex) {
                    throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
                }

                Certificate bcCert = certHolder.toASN1Structure();
                byte[] encodedCert = bcCert.getEncoded();
                int maxCertSize = gct.certprofile.getMaxCertSize();
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
                    throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                            "should not happen, could not parse generated certificate");
                }

                if (!verifySignature(cert)) {
                    throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                            "could not verify the signature of generated certificate");
                }

                X509CertWithDbId certWithMeta = new X509CertWithDbId(cert, encodedCert);
                ret = new X509CertificateInfo(certWithMeta, caIdent, caCert,
                        gct.grantedPublicKeyData, gct.certprofile.getIdent(), requestor.getIdent());
                if (requestor instanceof ByUserRequestorInfo) {
                    ret.setUser((((ByUserRequestorInfo) requestor).getUserId()));
                }
                ret.setReqType(reqType);
                ret.setTransactionId(transactionId);
                ret.setRequestedSubject(gct.requestedSubject);

                if (doPublishCertificate(ret) == 1) {
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
    } // method doGenerateCertificate

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
                + gct.certprofile.getIdent()
                + " already issued, and could not create new unique serial number");
        }

        gct.setGrantedSubject(subject);
    }

    private GrantedCertTemplate createGrantedCertTemplate(final CertTemplateData certTemplate,
            final RequestorInfo requestor, final boolean keyUpdate)
            throws OperationException {
        ParamUtil.requireNonNull("certTemplate", certTemplate);
        if (caInfo.getRevocationInfo() != null) {
            throw new OperationException(ErrorCode.NOT_PERMITTED, "CA is revoked");
        }

        IdentifiedX509Certprofile certprofile = getX509Certprofile(
                certTemplate.getCertprofileName());

        if (certprofile == null) {
            throw new OperationException(ErrorCode.UNKNOWN_CERT_PROFILE,
                    "unknown cert profile " + certTemplate.getCertprofileName());
        }

        ConcurrentContentSigner signer = caInfo.getSigner(certprofile.getSignatureAlgorithms());
        if (signer == null) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "CA does not support any signature algorithm restricted by the cert profile");
        }

        final NameId certprofileIdent = certprofile.getIdent();
        if (certprofile.getVersion() != X509CertVersion.v3) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "unknown cert version " + certprofile.getVersion());
        }

        if (certprofile.isOnlyForRa()) {
            if (requestor == null || !requestor.isRa()) {
                throw new OperationException(ErrorCode.NOT_PERMITTED,
                        "profile " + certprofileIdent + " not applied to non-RA");
            }
        }

        X500Name requestedSubject = removeEmptyRdns(certTemplate.getSubject());

        if (!certprofile.isSerialNumberInReqPermitted()) {
            RDN[] rdns = requestedSubject.getRDNs(ObjectIdentifiers.DN_SN);
            if (rdns != null && rdns.length > 0) {
                throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                        "subjectDN SerialNumber in request is not permitted");
            }
        }

        Date now = new Date();
        Date reqNotBefore ;
        if (certTemplate.getNotBefore() != null && certTemplate.getNotBefore().after(now)) {
            reqNotBefore = certTemplate.getNotBefore();
        } else {
            reqNotBefore = now;
        }
        Date grantedNotBefore = certprofile.getNotBefore(reqNotBefore);
        // notBefore in the past is not permitted
        if (grantedNotBefore.before(now)) {
            grantedNotBefore = now;
        }

        if (certprofile.hasMidnightNotBefore()) {
            grantedNotBefore = setToMidnight(grantedNotBefore, certprofile.getTimezone());
        }

        if (grantedNotBefore.before(caInfo.getNotBefore())) {
            grantedNotBefore = caInfo.getNotBefore();
            if (certprofile.hasMidnightNotBefore()) {
                grantedNotBefore = setToMidnight(grantedNotBefore, certprofile.getTimezone());
            }
        }

        long time = caInfo.getNoNewCertificateAfter();
        if (grantedNotBefore.getTime() > time) {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "CA is not permitted to issue certifate after " + new Date(time));
        }

        SubjectPublicKeyInfo grantedPublicKeyInfo;
        try {
            grantedPublicKeyInfo = X509Util.toRfc3279Style(certTemplate.getPublicKeyInfo());
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
        if (certprofile.getSpecialCertprofileBehavior()
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

        X500Name grantedSubject = subjectInfo.getGrantedSubject();

        // make sure that empty subject is not permitted
        ASN1ObjectIdentifier[] attrTypes = grantedSubject.getAttributeTypes();
        if (attrTypes == null || attrTypes.length == 0) {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                    "empty subject is not permitted");
        }

        // make sure that the grantedSubject does not equal the CA's subject
        if (X509Util.canonicalizName(grantedSubject).equals(
                caInfo.getPublicCaInfo().getC14nSubject())) {
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

        if (subjectInfo.getWarning() != null) {
            msgBuilder.append(", ").append(subjectInfo.getWarning());
        }

        CertValidity validity = certprofile.getValidity();

        if (validity == null) {
            validity = caInfo.getMaxValidity();
        } else if (validity.compareTo(caInfo.getMaxValidity()) > 0) {
            validity = caInfo.getMaxValidity();
        }

        Date maxNotAfter = validity.add(grantedNotBefore);
        if (maxNotAfter.getTime() > MAX_CERT_TIME_MS) {
            maxNotAfter = new Date(MAX_CERT_TIME_MS);
        }

        // CHECKSTYLE:SKIP
        Date origMaxNotAfter = maxNotAfter;

        if (certprofile.getSpecialCertprofileBehavior()
                == SpecialX509CertprofileBehavior.gematik_gSMC_K) {
            String str = certprofile.getParameter(
                    SpecialX509CertprofileBehavior.PARAMETER_MAXLIFTIME);
            long maxLifetimeInDays = Long.parseLong(str);
            Date maxLifetime = new Date(gsmckFirstNotBefore.getTime()
                    + maxLifetimeInDays * DAY_IN_MS - MS_PER_SECOND);
            if (maxNotAfter.after(maxLifetime)) {
                maxNotAfter = maxLifetime;
            }
        }

        Date grantedNotAfter = certTemplate.getNotAfter();
        if (grantedNotAfter != null) {
            if (grantedNotAfter.after(maxNotAfter)) {
                grantedNotAfter = maxNotAfter;
                msgBuilder.append(", notAfter modified");
            }
        } else {
            grantedNotAfter = maxNotAfter;
        }

        if (grantedNotAfter.after(caInfo.getNotAfter())) {
            ValidityMode mode = caInfo.getValidityMode();
            if (mode == ValidityMode.CUTOFF) {
                grantedNotAfter = caInfo.getNotAfter();
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
            Calendar cal = Calendar.getInstance(certprofile.getTimezone());
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
        GrantedCertTemplate gct = new GrantedCertTemplate(certTemplate.getExtensions(), certprofile,
                grantedNotBefore, grantedNotAfter, requestedSubject, grantedPublicKeyInfo,
                fpPublicKey, subjectPublicKeyData, signer, warning);
        gct.setGrantedSubject(grantedSubject);
        return gct;

    } // method createGrantedCertTemplate

    public IdentifiedX509Certprofile getX509Certprofile(final String certprofileName) {
        if (certprofileName == null) {
            return null;
        }

        Set<String> profileNames = caManager.getCertprofilesForCa(caIdent.getName());
        return (profileNames == null || !profileNames.contains(certprofileName))
                ? null : caManager.getIdentifiedCertprofile(certprofileName);
    } // method getX509Certprofile

    public boolean supportsCertProfile(final String certprofileName) {
        ParamUtil.requireNonNull("certprofileLocalName", certprofileName);
        Set<String> profileNames = caManager.getCertprofilesForCa(caIdent.getName());
        return profileNames.contains(certprofileName.toUpperCase());
    }

    public CmpRequestorInfo getRequestor(final X500Name requestorSender) {
        if (requestorSender == null) {
            return null;
        }

        Set<CaHasRequestorEntry> requestorEntries = caManager.getRequestorsForCa(
                caIdent.getName());
        if (CollectionUtil.isEmpty(requestorEntries)) {
            return null;
        }

        for (CaHasRequestorEntry m : requestorEntries) {
            CmpRequestorEntryWrapper entry = caManager.getCmpRequestorWrapper(
                    m.getRequestorIdent().getName());
            if (entry.getCert().getSubjectAsX500Name().equals(requestorSender)) {
                return new CmpRequestorInfo(m, entry.getCert());
            }
        }

        return null;
    } // method getRequestor

    public CmpRequestorInfo getRequestor(final X509Certificate requestorCert) {
        if (requestorCert == null) {
            return null;
        }

        Set<CaHasRequestorEntry> requestorEntries =
                caManager.getRequestorsForCa(caIdent.getName());
        if (CollectionUtil.isEmpty(requestorEntries)) {
            return null;
        }

        for (CaHasRequestorEntry m : requestorEntries) {
            CmpRequestorEntryWrapper entry = caManager.getCmpRequestorWrapper(
                    m.getRequestorIdent().getName());
            if (entry.getCert().getCert().equals(requestorCert)) {
                return new CmpRequestorInfo(m, entry.getCert());
            }
        }

        return null;
    }

    public CaManagerImpl getCaManager() {
        return caManager;
    }

    private Date getCrlNextUpdate(final Date thisUpdate) {
        ParamUtil.requireNonNull("thisUpdate", thisUpdate);
        CrlControl control = getCrlSigner().getCrlControl();
        if (control.getUpdateMode() != UpdateMode.interval) {
            return null;
        }

        int intervalsTillNextCrl = 0;
        for (int i = 1;; i++) {
            if (i % control.getFullCrlIntervals() == 0) {
                intervalsTillNextCrl = i;
                break;
            } else if (!control.isExtendedNextUpdate() && control.getDeltaCrlIntervals() > 0) {
                if (i % control.getDeltaCrlIntervals() == 0) {
                    intervalsTillNextCrl = i;
                    break;
                }
            }
        }

        Date nextUpdate;
        if (control.getIntervalMinutes() != null) {
            int minutesTillNextUpdate = intervalsTillNextCrl * control.getIntervalMinutes()
                    + control.getOverlapMinutes();
            nextUpdate = new Date(MS_PER_SECOND * (thisUpdate.getTime() / MS_PER_SECOND / 60
                    + minutesTillNextUpdate) * 60);
        } else {
            Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            cal.setTime(thisUpdate);
            cal.add(Calendar.DAY_OF_YEAR, intervalsTillNextCrl);
            cal.set(Calendar.HOUR_OF_DAY, control.getIntervalDayTime().getHour());
            cal.set(Calendar.MINUTE, control.getIntervalDayTime().getMinute());
            cal.add(Calendar.MINUTE, control.getOverlapMinutes());
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
            int num = doRemoveExpirtedCerts(expiredAtTime, event, msgId);
            LOG.info("removed {} expired certificates of CA {}", num, caIdent);
            successful = true;
            return num;
        } finally {
            finish(event, successful);
        }
    }

    private int doRemoveExpirtedCerts(final Date expiredAtTime, final AuditEvent event,
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
                if ((caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serial))) {
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
            int num = doRevokeSuspendedCerts(event, msgId);
            LOG.info("revoked {} suspended certificates of CA {}", num, caIdent);
            successful = true;
            return num;
        } finally {
            finish(event, successful);
        }
    }

    private int doRevokeSuspendedCerts(final AuditEvent event, final String msgId)
            throws OperationException {
        if (!masterMode) {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "CA could not remove expired certificates in slave mode");
        }

        final int numEntries = 100;

        CertValidity val = caInfo.getRevokeSuspendedCertsControl().getUnchangedSince();
        long ms;
        switch (val.getUnit()) {
        case DAY:
            ms = val.getValidity() * DAY_IN_MS;
            break;
        case HOUR:
            ms = val.getValidity() * DAY_IN_MS / 24;
            break;
        case YEAR:
            ms = val.getValidity() * 365 * DAY_IN_MS;
            break;
        default:
            throw new RuntimeException("should not reach here, unknown Validity Unit "
                + val.getUnit());
        }
        final long latestLastUpdatedAt = (System.currentTimeMillis() - ms) / 1000; // seconds
        final CrlReason reason = caInfo.getRevokeSuspendedCertsControl().getTargetReason();

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
        if (crlSigner != null && crlSigner.getSigner() != null) {
            boolean crlSignerHealthy = crlSigner.getSigner().isHealthy();
            healthy &= crlSignerHealthy;

            HealthCheckResult crlSignerHealth = new HealthCheckResult("CRLSigner");
            crlSignerHealth.setHealthy(crlSignerHealthy);
            result.addChildCheck(crlSignerHealth);
        }

        for (IdentifiedX509CertPublisher publisher : getPublishers()) {
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

    private AuditService getAuditService() {
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
        event.addEventData(CaAuditConstants.NAME_CA, caIdent.getName());
        event.addEventType(eventType);
        event.addEventData(CaAuditConstants.NAME_mid, msgId);
        return event;
    }

    private boolean verifySignature(final X509Certificate cert) {
        ParamUtil.requireNonNull("cert", cert);
        PublicKey caPublicKey = caCert.getCert().getPublicKey();
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
        String crlSignerName = caInfo.getCrlSignerName();
        X509CrlSignerEntryWrapper crlSigner = (crlSignerName == null) ? null
                : caManager.getCrlSignerWrapper(crlSignerName);
        return crlSigner;
    }

    public NameId getCaIdent() {
        return caIdent;
    }

    public String getHexSha1OfCert() {
        return caInfo.getCaEntry().getHexSha1OfCert();
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

        ScheduledThreadPoolExecutor executor = caManager.getScheduledThreadPoolExecutor();
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
        getAuditService().logEvent(event);
    }

}
