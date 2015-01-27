/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.server.impl;

import java.io.ByteArrayInputStream;
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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.SimpleTimeZone;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
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
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.audit.api.AuditStatus;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.BadFormatException;
import org.xipki.ca.api.CertProfileException;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestorInfo;
import org.xipki.ca.api.X509CertWithId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.ca.api.profile.x509.SpecialX509CertProfileBehavior;
import org.xipki.ca.api.profile.x509.X509CertVersion;
import org.xipki.ca.api.publisher.X509CertificateInfo;
import org.xipki.ca.server.impl.store.CertificateStore;
import org.xipki.ca.server.impl.store.X509CertWithRevocationInfo;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CAMgmtException;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.CRLControl;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.CRLControl.HourMinute;
import org.xipki.ca.server.mgmt.api.CRLControl.UpdateMode;
import org.xipki.common.CRLReason;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.CustomObjectIdentifiers;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.KeyUsage;
import org.xipki.common.LogUtil;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

class X509CA
{

    private class ScheduledNextSerialCommitService implements Runnable
    {
        private boolean inProcess = false;
        @Override
        public void run()
        {
            if(inProcess)
            {
                return;
            }

            inProcess = true;
            try
            {
                try
                {
                    caInfo.commitNextSerial();
                } catch (Throwable t)
                {
                    final String message = "Could not commit the next_serial";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                    }
                    LOG.debug(message, t);
                }

                try
                {
                    caInfo.commitNextCrlNo();
                } catch (Throwable t)
                {
                    final String message = "Could not commit the next_crlno";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                    }
                    LOG.debug(message, t);
                }
            } finally
            {
                inProcess = false;
            }

        }
    }

    private class ScheduledExpiredCertsRemover implements Runnable
    {
        private boolean inProcess = false;
        @Override
        public void run()
        {
            if(inProcess)
            {
                return;
            }

            inProcess = true;
            boolean allCertsRemoved = true;
            long startTime = System.currentTimeMillis();
            RemoveExpiredCertsInfo task = null;
            try
            {
                task = removeExpiredCertsQueue.poll();
                if(task == null)
                {
                    return;
                }

                String caName = caInfo.getName();

                final int numEntries = 100;

                X509CertWithId caCert = caInfo.getCertificate();
                long expiredAt = task.getExpiredAt();

                List<BigInteger> serials;

                do
                {
                    serials = certstore.getExpiredCertSerials(caCert, expiredAt, numEntries,
                            task.getCertProfile(), task.getUserLike());

                    for(BigInteger serial : serials)
                    {
                        if((caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serial)) == false)
                        {
                            boolean removed = false;
                            try
                            {
                                removed = do_removeCertificate(serial) != null;
                            }catch(Throwable t)
                            {
                                final String message = "Could not remove expired certificate";
                                if(LOG.isErrorEnabled())
                                {
                                    LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                                }
                                removed = false;
                            } finally
                            {
                                AuditLoggingService audit = getAuditLoggingService();
                                if(audit != null);
                                {
                                    AuditEvent auditEvent = newAuditEvent();
                                    if(removed)
                                    {
                                        auditEvent.setLevel(AuditLevel.INFO);
                                        auditEvent.setStatus(AuditStatus.OK);
                                    }
                                    else
                                    {
                                        auditEvent.setLevel(AuditLevel.ERROR);
                                        auditEvent.setStatus(AuditStatus.FAILED);
                                    }
                                    auditEvent.addEventData(new AuditEventData("CA", caName));
                                    auditEvent.addEventData(new AuditEventData("serialNumber", serial.toString()));
                                    auditEvent.addEventData(new AuditEventData("eventType", "REMOVE_EXPIRED_CERT"));
                                    audit.logEvent(auditEvent);
                                }

                                if(removed == false)
                                {
                                    allCertsRemoved = false;
                                }
                            }
                        }
                    }
                }while(serials.size() >= numEntries && allCertsRemoved);

            } catch (Throwable t)
            {
                if(allCertsRemoved == false && task != null)
                {
                    removeExpiredCertsQueue.add(task);
                }

                final String message = "Could not remove expired certificates";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                }
                LOG.debug(message, t);
            } finally
            {
                AuditLoggingService audit = getAuditLoggingService();
                if(audit != null && task != null);
                {
                    long durationMillis = System.currentTimeMillis() - startTime;
                    AuditEvent auditEvent = newAuditEvent();
                    auditEvent.addEventData(new AuditEventData("duration", durationMillis));
                    auditEvent.addEventData(new AuditEventData("CA", caInfo.getName()));
                    auditEvent.addEventData(new AuditEventData("cerProfile", task.getCertProfile()));
                    auditEvent.addEventData(new AuditEventData("user", task.getUserLike()));
                    auditEvent.addEventData(new AuditEventData("expiredAt",
                            new Date(task.getExpiredAt() * MS_PER_SECOND).toString()));
                    auditEvent.addEventData(new AuditEventData("eventType", "REMOVE_EXPIRED_CERTS"));

                    if(allCertsRemoved)
                    {
                        auditEvent.setLevel(AuditLevel.INFO);
                        auditEvent.setStatus(AuditStatus.OK);
                    }
                    else
                    {
                        auditEvent.setLevel(AuditLevel.ERROR);
                        auditEvent.setStatus(AuditStatus.FAILED);
                    }
                    audit.logEvent(auditEvent);
                }

                inProcess = false;
            }

        }
    }

    private class ScheduledCRLGenerationService implements Runnable
    {
        @Override
        public void run()
        {
            X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
            if(crlSigner == null || crlSigner.getCRLControl().getUpdateMode() != UpdateMode.interval)
            {
                return;
            }

            if(crlGenInProcess.get())
            {
                return;
            }

            crlGenInProcess.set(true);

            try
            {
                final long SIGN_WINDOW_MIN = 20;

                Date thisUpdate = new Date();
                long minSinceCrlBaseTime = (thisUpdate.getTime() - caInfo.getCrlBaseTime().getTime())
                        / MS_PER_SECOND / SECOND_PER_MIN;

                CRLControl control = getCrlSigner().getCRLControl();
                int interval;

                if(control.getIntervalMinutes() != null)
                {
                    long intervalMin = control.getIntervalMinutes();
                    interval = (int) (minSinceCrlBaseTime / intervalMin);

                    long baseTimeInMin = interval * intervalMin;
                    if(minSinceCrlBaseTime - baseTimeInMin > SIGN_WINDOW_MIN)
                    {
                        // only generate CRL within the time window
                        return;
                    }
                } else
                {
                    HourMinute hm = control.getIntervalDayTime();
                    Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                    c.setTime(thisUpdate);
                    int minute = c.get(Calendar.HOUR_OF_DAY) * 60 + c.get(Calendar.MINUTE);
                    int scheduledMinute = hm.getHour() * 60 + hm.getMinute();
                    if(minute < scheduledMinute || minute - scheduledMinute > SIGN_WINDOW_MIN)
                    {
                        return;
                    }
                    interval = (int) (minSinceCrlBaseTime % MIN_PER_DAY);
                }

                boolean deltaCrl;
                if(interval % control.getFullCRLIntervals() == 0)
                {
                    deltaCrl = false;
                }
                else if(control.getDeltaCRLIntervals() > 0 && interval % control.getDeltaCRLIntervals() == 0)
                {
                    deltaCrl = true;
                } else
                {
                    return;
                }

                if(deltaCrl)
                {
                    if(certstore.hasCRL(caInfo.getCertificate()) == false)
                    {
                        // DeltaCRL will be generated only if fullCRL exists
                        return;
                    }
                }

                long nowInSecond = thisUpdate.getTime() / MS_PER_SECOND;
                long thisUpdateOfCurrentCRL = certstore.getThisUpdateOfCurrentCRL(caInfo.getCertificate());
                if(nowInSecond - thisUpdateOfCurrentCRL <= (SIGN_WINDOW_MIN + 5) * SECOND_PER_MIN)
                {
                    // CRL was just generated within 15 minutes
                    return;
                }

                // find out the next interval for fullCRL and deltaCRL
                int nextFullCRLInterval = 0;
                int nextDeltaCRLInterval = 0;

                for(int i = interval + 1; ; i++)
                {
                    if(i % control.getFullCRLIntervals() == 0)
                    {
                        nextFullCRLInterval = i;
                        break;
                    }

                    if(nextDeltaCRLInterval != 0 &&
                            control.getDeltaCRLIntervals() != 0 &&
                            i % control.getDeltaCRLIntervals() == 0)
                    {
                        nextDeltaCRLInterval = i;
                    }
                }

                int intervalOfNextUpdate;
                if(deltaCrl)
                {
                    intervalOfNextUpdate = nextDeltaCRLInterval == 0 ?
                            nextFullCRLInterval : Math.min(nextFullCRLInterval, nextDeltaCRLInterval);
                }
                else
                {
                    if(nextDeltaCRLInterval == 0)
                    {
                        intervalOfNextUpdate = nextFullCRLInterval;
                    }
                    else
                    {
                        intervalOfNextUpdate = control.isExtendedNextUpdate() ?
                                nextFullCRLInterval : Math.min(nextFullCRLInterval, nextDeltaCRLInterval);
                    }
                }

                Date nextUpdate;
                if(control.getIntervalMinutes() != null)
                {
                    int minutesTillNextUpdate = (intervalOfNextUpdate - interval) * control.getIntervalMinutes()
                            + control.getOverlapMinutes();
                    nextUpdate = new Date(MS_PER_SECOND * (nowInSecond + minutesTillNextUpdate * 60));
                }
                else
                {
                    HourMinute hm = control.getIntervalDayTime();
                    Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                    c.setTime(new Date(nowInSecond * MS_PER_SECOND));
                    c.add(Calendar.DAY_OF_YEAR, (intervalOfNextUpdate - interval));
                    c.set(Calendar.HOUR_OF_DAY, hm.getHour());
                    c.set(Calendar.MINUTE, hm.getMinute());
                    c.add(Calendar.MINUTE, control.getOverlapMinutes());
                    c.set(Calendar.SECOND, 0);
                    c.set(Calendar.MILLISECOND, 0);
                    nextUpdate = c.getTime();
                }

                Date start = new Date();
                AuditEvent auditEvent = new AuditEvent(start);
                auditEvent.setApplicationName("CA");
                auditEvent.setName("PERF");
                auditEvent.addEventData(new AuditEventData("eventType", "CRL_GEN_INTERVAL"));

                try
                {
                    long maxIdOfDeltaCRLCache = certstore.getMaxIdOfDeltaCRLCache(caInfo.getCertificate());

                    generateCRL(deltaCrl, thisUpdate, nextUpdate, auditEvent);
                    auditEvent.setStatus(AuditStatus.SUCCESSFUL);
                    auditEvent.setLevel(AuditLevel.INFO);

                    try
                    {
                        certstore.clearDeltaCRLCache(caInfo.getCertificate(), maxIdOfDeltaCRLCache);
                    } catch (Throwable t)
                    {
                        final String message = "CRL_GEN_INTERVAL: could not clear DeltaCRLCache of CA " + caInfo.getName();
                        if(LOG.isErrorEnabled())
                        {
                            LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                        }
                        LOG.debug(message, t);
                    }
                }catch(Throwable t)
                {
                    auditEvent.setStatus(AuditStatus.ERROR);
                    auditEvent.setLevel(AuditLevel.ERROR);
                    final String message = "CRL_GEN_INTERVAL: Error";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                    }
                    LOG.debug(message, t);
                }finally
                {
                    auditEvent.addEventData(new AuditEventData("duration", System.currentTimeMillis() - start.getTime()));
                }

                if(serviceRegister != null)
                {
                    serviceRegister.getAuditLoggingService().logEvent(auditEvent);
                }
                LOG.info("CRL_GEN_INTERVAL: {}", auditEvent.getStatus().name());
            } catch (Throwable t)
            {
                LOG.error("CRL_GEN_INTERVAL: fatal error", t);
            } finally
            {
                crlGenInProcess.set(false);
            }
        }
    }

    private static final long MS_PER_SECOND = 1000L;
    private static final int SECOND_PER_MIN = 60;
    private static final int MIN_PER_DAY = 24 * 60;
    private static final long DAY = MS_PER_SECOND * SECOND_PER_MIN * MIN_PER_DAY;

    private static Logger LOG = LoggerFactory.getLogger(X509CA.class);

    private final CertificateFactory cf;

    private final X509CAInfo caInfo;
    private final CertificateStore certstore;
    private final boolean masterMode;

    private final CAManagerImpl caManager;
    private Boolean tryXipkiNSStoVerify;
    private AtomicBoolean crlGenInProcess = new AtomicBoolean(false);

    private final ConcurrentSkipListMap<String, List<String>> pendingSubjectMap =
            new ConcurrentSkipListMap<>();
    private final ConcurrentSkipListMap<String, List<String>> pendingKeyMap =
            new ConcurrentSkipListMap<>();
    private final ConcurrentLinkedDeque<RemoveExpiredCertsInfo> removeExpiredCertsQueue =
            new ConcurrentLinkedDeque<>();

    private final AtomicInteger numActiveRevocations = new AtomicInteger(0);
    private AuditLoggingServiceRegister serviceRegister;

    public X509CA(
            CAManagerImpl caManager,
            X509CAInfo caInfo,
            CertificateStore certstore,
            SecurityFactory securityFactory,
            boolean masterMode)
    throws OperationException
    {
        ParamChecker.assertNotNull("caManager", caManager);
        ParamChecker.assertNotNull("caInfo", caInfo);
        ParamChecker.assertNotNull("certstore", certstore);

        this.caManager = caManager;
        this.caInfo = caInfo;
        this.certstore = certstore;
        this.masterMode = masterMode;

        if(caInfo.isSignerRequired())
        {
            try
            {
                caInfo.initSigner(securityFactory);
            } catch (SignerException e)
            {
                final String message = "security.createSigner caSigner (ca=" + caInfo.getName() + ")";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);

                throw new OperationException(ErrorCode.System_Failure, "SigenrException: " + e.getMessage());
            }
        }

        X509CertWithId caCert = caInfo.getCertificate();

        X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
        if(crlSigner != null)
        {
            // CA signs the CRL
            if(caManager.getCrlSignerWrapper(caInfo.getCrlSignerName()) == null)
            {
                if(SecurityUtil.hasKeyusage(caInfo.getCertificate().getCert(), KeyUsage.cRLSign) == false)
                {
                    final String msg = "CRL signer does not have keyusage cRLSign";
                    LOG.error(msg);
                    throw new OperationException(ErrorCode.System_Failure, msg);
                }
            }
        }

        this.cf = new CertificateFactory();

        if(caInfo.useRandomSerialNumber() == false)
        {
            ScheduledNextSerialCommitService nextSerialCommitService = new ScheduledNextSerialCommitService();
            caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
                    nextSerialCommitService, 1, 1, TimeUnit.MINUTES); // commit the next_serial every 1 minute
        }

        if(masterMode == false)
        {
            return;
        }

        for(IdentifiedX509CertPublisher publisher : getPublishers())
        {
            publisher.issuerAdded(caCert);
        }

        // CRL generation services
        ScheduledCRLGenerationService crlGenerationService = new ScheduledCRLGenerationService();
        caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(crlGenerationService,
                1, 1, TimeUnit.MINUTES);

        ScheduledExpiredCertsRemover expiredCertsRemover = new ScheduledExpiredCertsRemover();
        caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(expiredCertsRemover,
                10, 10, TimeUnit.MINUTES);
    }

    public X509CAInfo getCAInfo()
    {
        return caInfo;
    }

    public CertificateList getCurrentCRL()
    throws OperationException
    {
        return getCRL(null);
    }

    /**
     *
     * @param crlNumber
     * @return
     * @throws OperationException
     */
    public CertificateList getCRL(BigInteger crlNumber)
    throws OperationException
    {
        LOG.info("START getCurrentCRL: ca={}, crlNumber={}", caInfo.getName(), crlNumber);
        boolean successfull = false;

        try
        {
            byte[] encodedCrl = certstore.getEncodedCRL(caInfo.getCertificate(), crlNumber);
            if(encodedCrl == null)
            {
                return null;
            }

            try
            {
                CertificateList crl = CertificateList.getInstance(encodedCrl);
                successfull = true;

                LOG.info("SUCCESSFULL getCurrentCRL: ca={}, thisUpdate={}", caInfo.getName(),
                        crl.getThisUpdate().getTime());

                return crl;
            } catch (RuntimeException e)
            {
                throw new OperationException(ErrorCode.System_Failure,
                        e.getClass().getName() + ": " + e.getMessage());
            }
        }finally
        {
            if(successfull == false)
            {
                LOG.info("FAILED getCurrentCRL: ca={}", caInfo.getName());
            }
        }
    }

    private void cleanupCRLs()
    throws OperationException
    {
        int numCrls = caInfo.getNumCrls();
        LOG.info("START cleanupCRLs: ca={}, numCrls={}", caInfo.getName(), numCrls);

        boolean successfull = false;

        try
        {
            int numOfRemovedCRLs;
            if(numCrls > 0)
            {
                numOfRemovedCRLs = certstore.cleanupCRLs(caInfo.getCertificate(), caInfo.getNumCrls());
            }
            else
            {
                numOfRemovedCRLs = 0;
            }
            successfull = true;
            LOG.info("SUCCESSFULL cleanupCRLs: ca={}, numOfRemovedCRLs={}", caInfo.getName(),
                    numOfRemovedCRLs);
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure,
                    e.getClass().getName() + ": " + e.getMessage());
        }
        finally
        {
            if(successfull == false)
            {
                LOG.info("FAILED cleanupCRLs: ca={}", caInfo.getName());
            }
        }
    }

    public X509CRL generateCRLonDemand(AuditEvent auditEvent)
    throws OperationException
    {
        X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
        if(crlSigner == null)
        {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "CA cannot generate CRL");
        }

        if(crlGenInProcess.get())
        {
            throw new OperationException(ErrorCode.System_Unavailable,
                    "TRY_LATER");
        }

        crlGenInProcess.set(true);
        try
        {
            Date thisUpdate = new Date();
            Date nextUpdate = getCRLNextUpdate(thisUpdate);
            if(nextUpdate != null && nextUpdate.after(thisUpdate) == false)
            {
                nextUpdate = null;
            }

            long maxIdOfDeltaCRLCache = certstore.getMaxIdOfDeltaCRLCache(caInfo.getCertificate());
            X509CRL crl = generateCRL(false, thisUpdate, nextUpdate, auditEvent);

            if(crl != null)
            {
                try
                {
                    certstore.clearDeltaCRLCache(caInfo.getCertificate(), maxIdOfDeltaCRLCache);
                } catch (Throwable t)
                {
                    final String message = "Could not clear DeltaCRLCache of CA " + caInfo.getName();
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                    }
                    LOG.debug(message, t);
                }
            }

            return crl;
        }finally
        {
            crlGenInProcess.set(false);
        }
    }

    private X509CRL generateCRL(boolean deltaCRL, Date thisUpdate, Date nextUpdate, AuditEvent auditEvent)
    throws OperationException
    {
        X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
        if(crlSigner == null)
        {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "CRL generation is not allowed");
        }

        LOG.info("START generateCRL: ca={}, deltaCRL={}, nextUpdate={}",
                new Object[]{caInfo.getName(), deltaCRL, nextUpdate});

        if(nextUpdate != null)
        {
            if(nextUpdate.getTime() - thisUpdate.getTime() < 10 * 60 * MS_PER_SECOND) // less than 10 minutes
            throw new OperationException(ErrorCode.CRL_FAILURE, "nextUpdate and thisUpdate are too close");
        }

        CRLControl crlControl = crlSigner.getCRLControl();
        boolean successfull = false;

        try
        {
            ConcurrentContentSigner _crlSigner = crlSigner.getSigner();

            CRLControl control = crlSigner.getCRLControl();

            boolean directCRL = _crlSigner == null;
            X500Name crlIssuer = directCRL ? caInfo.getPublicCAInfo().getX500Subject() :
                X500Name.getInstance(_crlSigner.getCertificate().getSubjectX500Principal().getEncoded());

            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crlIssuer, thisUpdate);
            if(nextUpdate != null)
            {
                crlBuilder.setNextUpdate(nextUpdate);
                if(auditEvent != null)
                {
                    auditEvent.addEventData(new AuditEventData("nextUpdate", nextUpdate));
                }
            }
            else
            {
                if(auditEvent != null)
                {
                    auditEvent.addEventData(new AuditEventData("nextUpdate", "NULL"));
                }
            }

            BigInteger startSerial = BigInteger.ONE;
            final int numEntries = 100;

            X509CertWithId caCert = caInfo.getCertificate();
            List<CertRevocationInfoWithSerial> revInfos;
            boolean isFirstCRLEntry = true;

            Date notExpireAt;
            if(control.isIncludeExpiredCerts())
            {
                notExpireAt = new Date(0);
            }
            else
            {
                // 10 minutes buffer
                notExpireAt = new Date(thisUpdate.getTime() - 600L * MS_PER_SECOND);
            }

            do
            {
                if(deltaCRL)
                {
                    revInfos = certstore.getCertificatesForDeltaCRL(caCert, startSerial, numEntries,
                            control.isOnlyContainsCACerts(), control.isOnlyContainsUserCerts());
                }
                else
                {
                    revInfos = certstore.getRevokedCertificates(caCert, notExpireAt, startSerial, numEntries,
                            control.isOnlyContainsCACerts(), control.isOnlyContainsUserCerts());
                }

                if(auditEvent != null)
                {
                    auditEvent.addEventData(new AuditEventData("crlType", deltaCRL ? "DELTA_CRL" : "FULL_CRL"));
                }

                BigInteger maxSerial = BigInteger.ONE;
                for(CertRevocationInfoWithSerial revInfo : revInfos)
                {
                    BigInteger serial = revInfo.getSerial();
                    if(serial.compareTo(maxSerial) > 0)
                    {
                        maxSerial = serial;
                    }

                    CRLReason reason = revInfo.getReason();
                    Date revocationTime = revInfo.getRevocationTime();
                    Date invalidityTime = revInfo.getInvalidityTime();
                    if(invalidityTime != null && invalidityTime.equals(revocationTime))
                    {
                        invalidityTime = null;
                    }

                    if(directCRL || isFirstCRLEntry == false)
                    {
                        if(invalidityTime != null)
                        {
                            crlBuilder.addCRLEntry(revInfo.getSerial(), revocationTime,
                                    reason.getCode(), invalidityTime);
                        }
                        else
                        {
                            crlBuilder.addCRLEntry(revInfo.getSerial(), revocationTime,
                                    reason.getCode());
                        }
                    }
                    else
                    {
                        List<Extension> extensions = new ArrayList<>(3);
                        if(reason != CRLReason.UNSPECIFIED)
                        {
                            Extension ext = createReasonExtension(reason.getCode());
                            extensions.add(ext);
                        }
                        if(invalidityTime != null)
                        {
                            Extension ext = createInvalidityDateExtension(invalidityTime);
                            extensions.add(ext);
                        }

                        Extension ext = createCertificateIssuerExtension(caInfo.getPublicCAInfo().getX500Subject());
                        extensions.add(ext);

                        Extensions asn1Extensions = new Extensions(extensions.toArray(new Extension[0]));
                        crlBuilder.addCRLEntry(revInfo.getSerial(), revocationTime, asn1Extensions);
                        isFirstCRLEntry = false;
                    }
                }

                startSerial = maxSerial.add(BigInteger.ONE);

            }while(revInfos.size() >= numEntries);

            BigInteger crlNumber = caInfo.nextCRLNumber();
            if(auditEvent != null)
            {
                auditEvent.addEventData(new AuditEventData("crlNumber", crlNumber));
            }

            try
            {
                // AuthorityKeyIdentifier
                byte[] akiValues = directCRL ?
                        caInfo.getPublicCAInfo().getSubjectKeyIdentifer() :
                        crlSigner.getSubjectKeyIdentifier();
                AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(akiValues);
                crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);

                // add extension CRL Number
                crlBuilder.addExtension(Extension.cRLNumber, false, new ASN1Integer(crlNumber));

                // IssuingDistributionPoint
                boolean onlyUserCerts = crlControl.isOnlyContainsUserCerts();
                if(onlyUserCerts == false)
                {
                    if(certstore.containsCACertificates(caCert) == false)
                    {
                        onlyUserCerts = true;
                    }
                }

                boolean onlyCACerts = crlControl.isOnlyContainsCACerts();
                if(onlyCACerts == false)
                {
                    if(certstore.containsUserCertificates(caCert) == false)
                    {
                        onlyCACerts = true;
                    }
                }

                if(onlyUserCerts && onlyCACerts)
                {
                    throw new RuntimeException("should not reach here");
                }

                IssuingDistributionPoint idp = new IssuingDistributionPoint(
                        (DistributionPointName) null, // distributionPoint,
                        onlyUserCerts, // onlyContainsUserCerts,
                        onlyCACerts, // onlyContainsCACerts,
                        (ReasonFlags) null, // onlySomeReasons,
                        directCRL == false, // indirectCRL,
                        false // onlyContainsAttributeCerts
                        );

                crlBuilder.addExtension(Extension.issuingDistributionPoint, true, idp);
            } catch (CertIOException e)
            {
                final String message = "crlBuilder.addExtension";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
                throw new OperationException(ErrorCode.INVALID_EXTENSION, e.getMessage());
            }

            startSerial = BigInteger.ONE;
            if(deltaCRL == false && control.isEmbedsCerts()) // XiPKI extension
            {
                ASN1EncodableVector vector = new ASN1EncodableVector();

                List<BigInteger> serials;

                do
                {
                    serials = certstore.getCertSerials(caCert, notExpireAt, startSerial, numEntries, false,
                            control.isOnlyContainsCACerts(), control.isOnlyContainsUserCerts());

                    BigInteger maxSerial = BigInteger.ONE;
                    for(BigInteger serial : serials)
                    {
                        if(serial.compareTo(maxSerial) > 0)
                        {
                            maxSerial = serial;
                        }

                        X509CertificateInfo certInfo;
                        try
                        {
                            certInfo = certstore.getCertificateInfoForSerial(caCert, serial);
                        } catch (CertificateException e)
                        {
                            throw new OperationException(ErrorCode.System_Failure,
                                    "CertificateException: " + e.getMessage());
                        }

                        Certificate cert = Certificate.getInstance(certInfo.getCert().getEncodedCert());

                        ASN1EncodableVector v = new ASN1EncodableVector();
                        v.add(cert);
                        String profileName = certInfo.getProfileName();
                        if(profileName != null && profileName.isEmpty() == false)
                        {
                            v.add(new DERUTF8String(certInfo.getProfileName()));
                        }
                        ASN1Sequence certWithInfo = new DERSequence(v);

                        vector.add(certWithInfo);
                    }

                    startSerial = maxSerial.add(BigInteger.ONE);
                }while(serials.size() >= numEntries);

                try
                {
                    crlBuilder.addExtension(
                            CustomObjectIdentifiers.id_ext_crl_certset, false, new DERSet(vector));
                } catch (CertIOException e)
                {
                    throw new OperationException(ErrorCode.INVALID_EXTENSION,
                            "CertIOException: " + e.getMessage());
                }
            }

            ConcurrentContentSigner concurrentSigner = (_crlSigner == null) ? caInfo.getSigner() : _crlSigner;
            ContentSigner contentSigner;
            try
            {
                contentSigner = concurrentSigner.borrowContentSigner();
            } catch (NoIdleSignerException e)
            {
                throw new OperationException(ErrorCode.System_Failure, "NoIdleSignerException: " + e.getMessage());
            }

            X509CRLHolder crlHolder;
            try
            {
                crlHolder = crlBuilder.build(contentSigner);
            }finally
            {
                concurrentSigner.returnContentSigner(contentSigner);
            }

            try
            {
                X509CRL crl = new X509CRLObject(crlHolder.toASN1Structure());
                publishCRL(crl);

                successfull = true;
                LOG.info("SUCCESSFULL generateCRL: ca={}, crlNumber={}, thisUpdate={}",
                        new Object[]{caInfo.getName(), crlNumber, crl.getThisUpdate()});

                // clean up the CRL
                if(deltaCRL == false)
                {
                    try
                    {
                        cleanupCRLs();
                    }catch(Throwable t)
                    {
                        LOG.warn("Could not cleanup CRLs.{}: {}", t.getClass().getName(), t.getMessage());
                    }
                }

                return crl;
            } catch (CRLException e)
            {
                throw new OperationException(ErrorCode.CRL_FAILURE, "CRLException: " + e.getMessage());
            }
        }finally
        {
            if(successfull == false)
            {
                LOG.info("FAILED generateCRL: ca={}", caInfo.getName());
            }
        }
    }

    private static Extension createReasonExtension(int reasonCode)
    {
        org.bouncycastle.asn1.x509.CRLReason crlReason =
                org.bouncycastle.asn1.x509.CRLReason.lookup(reasonCode);

        try
        {
            return new Extension(Extension.reasonCode, false, crlReason.getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e.getMessage(), e);
        }
    }

    private static Extension createInvalidityDateExtension(Date invalidityDate)
    {
        try
        {
            ASN1GeneralizedTime asnTime = new ASN1GeneralizedTime(invalidityDate);
            return new Extension(Extension.invalidityDate, false, asnTime.getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e.getMessage(), e);
        }
    }

    /**
     * added by lijun liao add the support of
     * @param certificateIssuer
     * @return
     */
    private static Extension createCertificateIssuerExtension(X500Name certificateIssuer)
    {
        try
        {
            GeneralName generalName = new GeneralName(certificateIssuer);
            return new Extension(Extension.certificateIssuer, true,
                    new GeneralNames(generalName).getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e.getMessage(), e);
        }
    }

    public X509CertificateInfo generateCertificate(
            boolean requestedByRA,
            RequestorInfo requestor,
            String certProfileName,
            String user,
            X500Name subject,
            SubjectPublicKeyInfo publicKeyInfo,
            Date notBefore,
            Date notAfter,
            Extensions extensions)
    throws OperationException
    {
        final String subjectText = SecurityUtil.getRFC4519Name(subject);
        LOG.info("START generateCertificate: CA={}, profile={}, subject='{}'",
                new Object[]{caInfo.getName(), certProfileName, subjectText});

        boolean successfull = false;

        try
        {
            try
            {
                X509CertificateInfo ret = intern_generateCertificate(
                        requestedByRA, requestor,
                        certProfileName, user,
                        subject, publicKeyInfo,
                        notBefore, notAfter, extensions, false);
                successfull = true;

                String prefix = ret.isAlreadyIssued() ? "RETURN_OLD_CERT" : "SUCCESSFULL";
                LOG.info("{} generateCertificate: CA={}, profile={},"
                        + " subject='{}', serialNumber={}",
                        new Object[]{prefix, caInfo.getName(), certProfileName,
                            ret.getCert().getSubject(), ret.getCert().getCert().getSerialNumber()});
                return ret;
            }catch(RuntimeException e)
            {
                final String message = "RuntimeException in generateCertificate()";
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
                throw new OperationException(ErrorCode.System_Failure, "RuntimeException:  " + e.getMessage());
            }
        }finally
        {
            if(successfull == false)
            {
                LOG.warn("FAILED generateCertificate: CA={}, profile={}, subject='{}'",
                        new Object[]{caInfo.getName(), certProfileName, subjectText});
            }
        }
    }

    public X509CertificateInfo regenerateCertificate(
            boolean requestedByRA,
            RequestorInfo requestor,
            String certProfileName,
            String user,
            X500Name subject,
            SubjectPublicKeyInfo publicKeyInfo,
            Date notBefore,
            Date notAfter,
            Extensions extensions)
    throws OperationException
    {
        final String subjectText = SecurityUtil.getRFC4519Name(subject);
        LOG.info("START regenerateCertificate: CA={}, profile={}, subject='{}'",
                new Object[]{caInfo.getName(), certProfileName, subjectText});

        boolean successfull = false;

        try
        {
            X509CertificateInfo ret = intern_generateCertificate(
                    requestedByRA, requestor, certProfileName, user,
                    subject, publicKeyInfo,
                    notBefore, notAfter, extensions, false);
            successfull = true;
            LOG.info("SUCCESSFULL generateCertificate: CA={}, profile={},"
                    + " subject='{}', serialNumber={}",
                    new Object[]{caInfo.getName(), certProfileName,
                        ret.getCert().getSubject(), ret.getCert().getCert().getSerialNumber()});

            return ret;
        }catch(RuntimeException e)
        {
            final String message = "RuntimeException in regenerateCertificate()";
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.System_Failure, "RuntimeException:  " + e.getMessage());
        } finally
        {
            if(successfull == false)
            {
                LOG.warn("FAILED regenerateCertificate: CA={}, profile={}, subject='{}'",
                        new Object[]{caInfo.getName(), certProfileName, subjectText});
            }
        }
    }

    public boolean publishCertificate(X509CertificateInfo certInfo)
    {
        return intern_publishCertificate(certInfo) == 0;
    }

    /**
     *
     * @param certInfo
     * @return 0 for published successfully, 1 if could not be published to CA certstore and any publishers,
     *  2 if could be published to CA certstore but not to all publishers.
     */
    private int intern_publishCertificate(X509CertificateInfo certInfo)
    {
        if(certInfo.isAlreadyIssued())
        {
            return 0;
        }

        if(certstore.addCertificate(certInfo) == false)
        {
            return 1;
        }

        for(IdentifiedX509CertPublisher publisher : getPublishers())
        {
            if(publisher.isAsyn() == false)
            {
                boolean successfull;
                try
                {
                    successfull = publisher.certificateAdded(certInfo);
                }
                catch (RuntimeException e)
                {
                    successfull = false;
                    final String message = "Error while publish certificate to the publisher " + publisher.getName();
                    if(LOG.isWarnEnabled())
                    {
                        LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                }

                if(successfull)
                {
                    continue;
                }
            }

            Integer certId = certInfo.getCert().getCertId();
            try
            {
                certstore.addToPublishQueue(publisher.getName(), certId.intValue(), caInfo.getCertificate());
            } catch(Throwable t)
            {
                final String message = "Error while add entry to PublishQueue";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                }
                LOG.debug(message, t);
                return 2;
            }
        }

        return 0;
    }

    public boolean republishCertificates(List<String> publisherNames)
    {
        List<IdentifiedX509CertPublisher> publishers;
        if(publisherNames == null)
        {
            publishers = getPublishers();
        }
        else
        {
            publishers = new ArrayList<>(publisherNames.size());

            for(String publisherName : publisherNames)
            {
                IdentifiedX509CertPublisher publisher = null;
                for(IdentifiedX509CertPublisher p : getPublishers())
                {
                    if(p.getName().equals(publisherName))
                    {
                        publisher = p;
                        break;
                    }
                }

                if(publisher == null)
                {
                    throw new IllegalArgumentException(
                            "Could not find publisher " + publisherName + " for CA " + caInfo.getName());
                }
                publishers.add(publisher);
            }
        }

        if(publishers.isEmpty())
        {
            return true;
        }

        CAStatus status = caInfo.getStatus();

        caInfo.setStatus(CAStatus.INACTIVE);

        // wait till no certificate request in process
        while(pendingSubjectMap.isEmpty() == false || numActiveRevocations.get() > 0)
        {
            LOG.info("Certificate requests are still in process, wait 1 second");
            try
            {
                Thread.sleep(MS_PER_SECOND);
            }catch(InterruptedException e)
            {
            }
        }

        boolean allPublishersOnlyForRevokedCerts = true;
        for(IdentifiedX509CertPublisher publisher : publishers)
        {
            if(publisher.publishsGoodCert())
            {
                allPublishersOnlyForRevokedCerts = false;
            }

            String name = publisher.getName();
            try
            {
                LOG.info("Clearing PublishQueue for publisher {}", name);
                certstore.clearPublishQueue(this.caInfo.getCertificate(), name);
                LOG.info(" Cleared PublishQueue for publisher {}", name);
            } catch (SQLException | OperationException e)
            {
                final String message = "Exception while clearing PublishQueue for publisher";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
            }
        }

        try
        {
            List<BigInteger> serials;
            X509CertWithId caCert = caInfo.getCertificate();

            Date notExpiredAt = null;

            BigInteger startSerial = BigInteger.ONE;
            int numEntries = 100;

            boolean onlyRevokedCerts = false;

            int sum = 0;
            do
            {
                try
                {
                    serials = certstore.getCertSerials(caCert, notExpiredAt, startSerial, numEntries, onlyRevokedCerts,
                            false, false);
                } catch (OperationException e)
                {
                    final String message = "Exception";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                    return false;
                }

                // Even if only revoked certificates will be published, good certificates will be republished
                // at the first round. This is required to publish CA information if there is no revoked certs
                if(allPublishersOnlyForRevokedCerts)
                {
                    onlyRevokedCerts = true;
                }

                BigInteger maxSerial = BigInteger.ONE;
                for(BigInteger serial : serials)
                {
                    if(serial.compareTo(maxSerial) > 0)
                    {
                        maxSerial = serial;
                    }

                    X509CertificateInfo certInfo;

                    try
                    {
                        certInfo = certstore.getCertificateInfoForSerial(caCert, serial);
                    } catch (OperationException | CertificateException e)
                    {
                        final String message = "Exception";
                        if(LOG.isErrorEnabled())
                        {
                            LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                        }
                        LOG.debug(message, e);
                        return false;
                    }

                    for(IdentifiedX509CertPublisher publisher : publishers)
                    {
                        boolean successfull = publisher.certificateAdded(certInfo);
                        if(successfull == false)
                        {
                            LOG.error("Republish certificate serial={} to publisher {} failed", serial, publisher.getName());
                            return false;
                        }
                    }
                }

                startSerial = maxSerial.add(BigInteger.ONE);

                sum += serials.size();
                System.out.println("CA " + caInfo.getName() + " republished " + sum + " certificates");
            } while(serials.size() >= numEntries);

            if(caInfo.getRevocationInfo() != null)
            {
                for(IdentifiedX509CertPublisher publisher : publishers)
                {
                    boolean successfull = publisher.caRevoked(caInfo.getCertificate(), caInfo.getRevocationInfo());
                    if(successfull == false)
                    {
                        LOG.error("Republish CA revocation to publisher {} failed", publisher.getName());
                        return false;
                    }
                }
            }

            return true;
        } finally
        {
            caInfo.setStatus(status);
        }
    }

    public boolean clearPublishQueue(List<String> publisherNames)
    throws CAMgmtException
    {
        if(publisherNames == null)
        {
            try
            {
                certstore.clearPublishQueue(caInfo.getCertificate(), null);
                return true;
            } catch (SQLException | OperationException e)
            {
                throw new CAMgmtException(e.getMessage(), e);
            }
        }

        for(String publisherName : publisherNames)
        {
            try
            {
                certstore.clearPublishQueue(caInfo.getCertificate(), publisherName);
            } catch (SQLException | OperationException e)
            {
                throw new CAMgmtException(e.getMessage(), e);
            }
        }

        return true;
    }

    public boolean publishCertsInQueue()
    {
        boolean allSuccessfull = true;
        for(IdentifiedX509CertPublisher publisher : getPublishers())
        {
            if(publishCertsInQueue(publisher) == false)
            {
                allSuccessfull = false;
            }
        }

        return allSuccessfull;
    }

    private boolean publishCertsInQueue(IdentifiedX509CertPublisher publisher)
    {
        X509CertWithId caCert = caInfo.getCertificate();

        final int numEntries = 500;

        while(true)
        {
            List<Integer> certIds;
            try
            {
                certIds = certstore.getPublishQueueEntries(caCert, publisher.getName(), numEntries);
            } catch (OperationException e)
            {
                final String message = "Exception";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
                return false;
            }

            if(certIds == null || certIds.isEmpty())
            {
                break;
            }

            for(Integer certId : certIds)
            {
                X509CertificateInfo certInfo;

                try
                {
                    certInfo = certstore.getCertificateInfoForId(caCert, certId);
                } catch (OperationException | CertificateException e)
                {
                    final String message = "Exception";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                    return false;
                }

                boolean successfull = publisher.certificateAdded(certInfo);
                if(successfull)
                {
                    try
                    {
                        certstore.removeFromPublishQueue(publisher.getName(), certId);
                    } catch (OperationException e)
                    {
                        final String message = "SQLException while removing republished cert id=" + certId +
                                " and publisher=" + publisher.getName();
                        if(LOG.isWarnEnabled())
                        {
                            LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                        }
                        LOG.debug(message, e);
                        continue;
                    }
                }
                else
                {
                    LOG.error("Republish certificate id={} failed", certId);
                    return false;
                }
            }
        }

        return true;
    }

    private boolean publishCRL(X509CRL crl)
    {
        X509CertWithId caCert = caInfo.getCertificate();
        if(certstore.addCRL(caCert, crl) == false)
        {
            return false;
        }

        for(IdentifiedX509CertPublisher publisher : getPublishers())
        {
            try
            {
                publisher.crlAdded(caCert, crl);
            }
            catch (RuntimeException e)
            {
                final String message = "Error while publish CRL to the publisher " + publisher.getName();
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
            }
        }

        return true;
    }

    public X509CertWithRevocationInfo revokeCertificate(BigInteger serialNumber,
            CRLReason reason, Date invalidityTime)
    throws OperationException
    {
        if(caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber))
        {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "Not allow to revoke CA certificate");
        }

        if(reason == null)
        {
            reason = CRLReason.UNSPECIFIED;
        }

        switch(reason)
        {
            case CA_COMPROMISE:
            case AA_COMPROMISE:
            case REMOVE_FROM_CRL:
                throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                        "Not allow to revoke certificate with reason " + reason.getDescription());
            case UNSPECIFIED:
            case KEY_COMPROMISE:
            case AFFILIATION_CHANGED:
            case SUPERSEDED:
            case CESSATION_OF_OPERATION:
            case CERTIFICATE_HOLD:
            case PRIVILEGE_WITHDRAWN:
                break;
        }
        return do_revokeCertificate(serialNumber, reason, invalidityTime, false);
    }

    public X509CertWithId unrevokeCertificate(BigInteger serialNumber)
    throws OperationException
    {
        if(caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber))
        {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "Not allow to unrevoke CA certificate");
        }

        return do_unrevokeCertificate(serialNumber, false);
    }

    public X509CertWithId removeCertificate(BigInteger serialNumber)
    throws OperationException
    {
        if(caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber))
        {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "Not allow to remove CA certificate");
        }

        return do_removeCertificate(serialNumber);
    }

    private X509CertWithId do_removeCertificate(BigInteger serialNumber)
    throws OperationException
    {
        X509CertWithRevocationInfo certWithRevInfo =
                certstore.getCertWithRevocationInfo(caInfo.getCertificate(), serialNumber);
        if(certWithRevInfo == null)
        {
            return null;
        }

        boolean successful = true;
        X509CertWithId certToRemove = certWithRevInfo.getCert();
        for(IdentifiedX509CertPublisher publisher : getPublishers())
        {
            boolean singleSuccessful;
            try
            {
                singleSuccessful = publisher.certificateRemoved(caInfo.getCertificate(), certToRemove);
            }
            catch (RuntimeException e)
            {
                singleSuccessful = false;
                final String message = "Error while remove certificate to the publisher " + publisher.getName();
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
            }

            if(singleSuccessful == false)
            {
                successful = false;
                X509Certificate c = certToRemove.getCert();
                LOG.error("Removing certificate issuer='{}', serial={}, subject='{}' from publisher {} failed.",
                        new Object[]
                        {
                                SecurityUtil.getRFC4519Name(c.getIssuerX500Principal()),
                                c.getSerialNumber(),
                                SecurityUtil.getRFC4519Name(c.getSubjectX500Principal()),
                                publisher.getName()});
            }
        }

        if(successful == false)
        {
            return null;
        }

        certstore.removeCertificate(caInfo.getCertificate(), serialNumber);
        return certToRemove;
    }

    private X509CertWithRevocationInfo do_revokeCertificate(BigInteger serialNumber,
            CRLReason reason, Date invalidityTime, boolean force)
    throws OperationException
    {
        LOG.info("START revokeCertificate: ca={}, serialNumber={}, reason={}, invalidityTime={}",
                new Object[]{caInfo.getName(), serialNumber, reason.getDescription(), invalidityTime});

        numActiveRevocations.addAndGet(1);
        X509CertWithRevocationInfo revokedCert = null;

        try
        {
            CertRevocationInfo revInfo = new CertRevocationInfo(reason, new Date(), invalidityTime);
            revokedCert = certstore.revokeCertificate(
                    caInfo.getCertificate(),
                    serialNumber, revInfo, force, shouldPublishToDeltaCRLCache());
            if(revokedCert == null)
            {
                return null;
            }

            for(IdentifiedX509CertPublisher publisher : getPublishers())
            {
                if(publisher.isAsyn() == false)
                {
                    boolean successfull;
                    try
                    {
                        successfull = publisher.certificateRevoked(caInfo.getCertificate(),
                                revokedCert.getCert(), revokedCert.getCertProfile(), revokedCert.getRevInfo());
                    }
                    catch (RuntimeException e)
                    {
                        successfull = false;
                        final String message = "Error while publish revocation of certificate to the publisher " +
                                publisher.getName();
                        if(LOG.isErrorEnabled())
                        {
                            LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                        }
                        LOG.debug(message, e);
                    }

                    if(successfull)
                    {
                        continue;
                    }
                }

                Integer certId = revokedCert.getCert().getCertId();
                try
                {
                    certstore.addToPublishQueue(publisher.getName(), certId.intValue(), caInfo.getCertificate());
                }catch(Throwable t)
                {
                    final String message = "Error while add entry to PublishQueue";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                    }
                    LOG.debug(message, t);
                }
            }
        } finally
        {
            numActiveRevocations.addAndGet(-1);
        }

        String resultText = revokedCert == null ? "CERT_NOT_EXIST" : "REVOKED";
        LOG.info("SUCCESSFULL revokeCertificate: ca={}, serialNumber={}, reason={},"
                + " invalidityTime={}, revocationResult={}",
                new Object[]{caInfo.getName(), serialNumber, reason.getDescription(),
                        invalidityTime, resultText});

        return revokedCert;
    }

    private X509CertWithId do_unrevokeCertificate(BigInteger serialNumber, boolean force)
    throws OperationException
    {
        LOG.info("START unrevokeCertificate: ca={}, serialNumber={}", caInfo.getName(), serialNumber);

        numActiveRevocations.addAndGet(1);
        X509CertWithId unrevokedCert = null;

        try
        {
            unrevokedCert = certstore.unrevokeCertificate(
                    caInfo.getCertificate(), serialNumber, force, shouldPublishToDeltaCRLCache());
            if(unrevokedCert == null)
            {
                return null;
            }

            for(IdentifiedX509CertPublisher publisher : getPublishers())
            {
                if(publisher.isAsyn() == false)
                {
                    boolean successfull;
                    try
                    {
                        successfull = publisher.certificateUnrevoked(caInfo.getCertificate(), unrevokedCert);
                    }
                    catch (RuntimeException e)
                    {
                        successfull = false;
                        final String message = "Error while publish unrevocation of certificate to the publisher " +
                                publisher.getName();
                        if(LOG.isErrorEnabled())
                        {
                            LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                        }
                        LOG.debug(message, e);
                    }

                    if(successfull)
                    {
                        continue;
                    }
                }

                Integer certId = unrevokedCert.getCertId();
                try
                {
                    certstore.addToPublishQueue(publisher.getName(), certId.intValue(), caInfo.getCertificate());
                }catch(Throwable t)
                {
                    final String message = "Error while add entry to PublishQueue";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                    }
                    LOG.debug(message, t);
                }
            }
        } finally
        {
            numActiveRevocations.addAndGet(-1);
        }

        String resultText = unrevokedCert == null ? "CERT_NOT_EXIST" : "UNREVOKED";
        LOG.info("SUCCESSFULL unrevokeCertificate: ca={}, serialNumber={}, revocationResult={}",
                new Object[]{caInfo.getName(), serialNumber, resultText});

        return unrevokedCert;
    }

    private boolean shouldPublishToDeltaCRLCache()
    {
        X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
        if(crlSigner == null)
        {
            return false;
        }

        CRLControl control = crlSigner.getCRLControl();
        if(control.getUpdateMode() == UpdateMode.onDemand)
        {
            return false;
        }

        int deltaCRLInterval = control.getDeltaCRLIntervals();
        if(deltaCRLInterval == 0 || deltaCRLInterval >= control.getFullCRLIntervals())
        {
            return false;
        }

        return true;
    }

    public void revoke(CertRevocationInfo revocationInfo)
    throws OperationException
    {
        ParamChecker.assertNotNull("revocationInfo", revocationInfo);

        caInfo.setRevocationInfo(revocationInfo);
        if(caInfo.isSelfSigned())
        {
            do_revokeCertificate(caInfo.getSerialNumber(), revocationInfo.getReason(),
                revocationInfo.getInvalidityTime(), true);
        }

        for(IdentifiedX509CertPublisher publisher : getPublishers())
        {
            try
            {
                boolean successfull = publisher.caRevoked(caInfo.getCertificate(), revocationInfo);
                if(successfull == false)
                {
                    throw new OperationException(ErrorCode.System_Failure, "Publishing CA revocation failed");
                }
            }
            catch (RuntimeException e)
            {
                String message = "Error while publish revocation of CA to the publisher " + publisher.getName();
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
                throw new OperationException(ErrorCode.System_Failure, message);
            }
        }
    }

    public void unrevoke()
    throws OperationException
    {
        caInfo.setRevocationInfo(null);
        if(caInfo.isSelfSigned())
        {
            do_unrevokeCertificate(caInfo.getSerialNumber(), true);
        }

        for(IdentifiedX509CertPublisher publisher : getPublishers())
        {
            try
            {
                boolean successfull = publisher.caUnrevoked(caInfo.getCertificate());
                if(successfull == false)
                {
                    throw new OperationException(ErrorCode.System_Failure, "Publishing CA revocation failed");
                }
            }
            catch (RuntimeException e)
            {
                String message = "Error while publish revocation of CA to the publisher " + publisher.getName();
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
                throw new OperationException(ErrorCode.System_Failure, message);
            }
        }
    }

    private List<IdentifiedX509CertPublisher> getPublishers()
    {
        return caManager.getIdentifiedPublishersForCa(caInfo.getName());
    }

    private X509CertificateInfo intern_generateCertificate(
            boolean requestedByRA,
            RequestorInfo requestor,
            String certProfileName,
            String user,
            X500Name requestedSubject,
            SubjectPublicKeyInfo publicKeyInfo,
            Date notBefore,
            Date notAfter,
            org.bouncycastle.asn1.x509.Extensions extensions,
            boolean keyUpdate)
    throws OperationException
    {
        ConcurrentContentSigner signer = caInfo.getSigner();
        if(signer == null)
        {
            throw new OperationException(ErrorCode.System_Failure, "Signer of the CA is not initialized");
        }

        if(caInfo.getRevocationInfo() != null)
        {
            throw new OperationException(ErrorCode.NOT_PERMITTED, "CA is revoked");
        }

        IdentifiedX509CertProfile certProfile;
        try
        {
            certProfile = getX509CertProfile(certProfileName);
        } catch (CertProfileException e)
        {
            throw new OperationException(ErrorCode.System_Failure, "invalid configuration of cert profile " + certProfileName);
        }

        if(certProfile == null)
        {
            throw new OperationException(ErrorCode.UNKNOWN_CERT_PROFILE, "unknown cert profile " + certProfileName);
        }

        if(certProfile.getVersion() != X509CertVersion.V3)
        {
            throw new OperationException(ErrorCode.System_Failure, "unknown cert version " + certProfile);
        }

        if(certProfile.isOnlyForRA() && requestedByRA == false)
        {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "Profile " + certProfileName + " not applied to non-RA");
        }

        Set<ASN1ObjectIdentifier> permittedSigAlgs = certProfile.getSignatureAlgorithms();
        if(permittedSigAlgs != null && permittedSigAlgs.isEmpty() == false)
        {
            ASN1ObjectIdentifier sigAlgId = signer.getAlgorithmIdentifier().getAlgorithm();
            if(permittedSigAlgs.contains(sigAlgId) == false)
            {
                throw new OperationException(ErrorCode.System_Failure,
                        "Signature algorithm  " + sigAlgId.getId() + " is not permitted");
            }
        }

        requestedSubject = removeEmptyRDNs(requestedSubject);

        if(certProfile.isSerialNumberInReqPermitted() == false)
        {
            RDN[] rdns = requestedSubject.getRDNs(ObjectIdentifiers.DN_SN);
            if(rdns != null && rdns.length > 0)
            {
                throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                        "SubjectDN SerialNumber in request is not permitted");
            }
        }

        notBefore = certProfile.getNotBefore(notBefore);
        if(notBefore == null)
        {
            notBefore = new Date();
        }

        if(certProfile.hasMidnightNotBefore())
        {
            notBefore = setToMidnight(notBefore, certProfile.getTimezone());
        }

        if(notBefore.before(caInfo.getNotBefore()))
        {
            notBefore = caInfo.getNotBefore();
            if(certProfile.hasMidnightNotBefore())
            {
                notBefore = setToMidnight(new Date(notBefore.getTime() + DAY), certProfile.getTimezone());
            }
        }

        long t = caInfo.getNoNewCertificateAfter();
        if(notBefore.getTime() > t)
        {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "CA is not permitted to issue certifate after " + new Date(t));
        }

        try
        {
            publicKeyInfo = SecurityUtil.toRfc3279Style(publicKeyInfo);
        } catch (InvalidKeySpecException e)
        {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                    "invalid SubjectPublicKeyInfo");
        }

        // public key
        try
        {
            publicKeyInfo = certProfile.checkPublicKey(publicKeyInfo);
        } catch (BadCertTemplateException e)
        {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        }

        Date gSMC_KFirstNotBefore = null;
        if(certProfile.getSpecialCertProfileBehavior() == SpecialX509CertProfileBehavior.gematik_gSMC_K)
        {
            gSMC_KFirstNotBefore = notBefore;

            RDN[] cnRDNs = requestedSubject.getRDNs(ObjectIdentifiers.DN_CN);
            if(cnRDNs != null && cnRDNs.length > 0)
            {
                String requestedCN = SecurityUtil.rdnValueToString(cnRDNs[0].getFirst().getValue());
                Long gsmckFirstNotBeforeInSecond = certstore.getNotBeforeOfFirstCertStartsWithCN(
                        requestedCN, certProfileName);
                if(gsmckFirstNotBeforeInSecond != null)
                {
                    gSMC_KFirstNotBefore = new Date(gsmckFirstNotBeforeInSecond * MS_PER_SECOND);
                }

                // append the commonName with '-' + yyyyMMdd
                SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMdd");
                dateF.setTimeZone(new SimpleTimeZone(0,"Z"));
                String yyyyMMdd = dateF.format(gSMC_KFirstNotBefore);
                String suffix = "-" + yyyyMMdd;

                // append the -yyyyMMdd to the commonName
                RDN[] rdns = requestedSubject.getRDNs();
                for(int i = 0; i < rdns.length; i++)
                {
                    if(ObjectIdentifiers.DN_CN.equals(rdns[i].getFirst().getType()))
                    {
                        rdns[i] = new RDN(ObjectIdentifiers.DN_CN, new DERUTF8String(requestedCN + suffix));
                    }
                }
                requestedSubject = new X500Name(rdns);
            }
        }

        // subject
        SubjectInfo subjectInfo;
        try
        {
            subjectInfo = certProfile.getSubject(requestedSubject);
        }catch(CertProfileException e)
        {
            throw new OperationException(ErrorCode.System_Failure, "exception in cert profile " + certProfileName);
        } catch (BadCertTemplateException e)
        {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        }

        X500Name grantedSubject = subjectInfo.getGrantedSubject();

        // make sure that the grantedSubject does not equal the CA's subject
        if(grantedSubject.equals(caInfo.getPublicCAInfo().getX500Subject()))
        {
            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                    "Certificate with the same subject as CA is not allowed");
        }

        DuplicationMode keyMode = caInfo.getDuplicateKeyMode();
        if(keyMode == DuplicationMode.PERMITTED && certProfile.isDuplicateKeyPermitted() == false)
        {
            keyMode = DuplicationMode.FORBIDDEN_WITHIN_PROFILE;
        }

        DuplicationMode subjectMode = caInfo.getDuplicateSubjectMode();
        if(subjectMode == DuplicationMode.PERMITTED && certProfile.isDuplicateSubjectPermitted() == false)
        {
            subjectMode = DuplicationMode.FORBIDDEN_WITHIN_PROFILE;
        }

        String sha1FpSubject = SecurityUtil.sha1sum_canonicalized_name(grantedSubject);
        String grandtedSubjectText = SecurityUtil.getRFC4519Name(grantedSubject);

        byte[] subjectPublicKeyData =  publicKeyInfo.getPublicKeyData().getBytes();
        String sha1FpPublicKey = SecurityUtil.sha1sum(subjectPublicKeyData);

        if(keyUpdate)
        {
            CertStatus certStatus = certstore.getCertStatusForSubject(caInfo.getCertificate(), grantedSubject);
            if(certStatus == CertStatus.Revoked)
            {
                throw new OperationException(ErrorCode.CERT_REVOKED);
            }
            else if(certStatus == CertStatus.Unknown)
            {
                throw new OperationException(ErrorCode.UNKNOWN_CERT);
            }
        }
        else
        {
            // try to get certificate with the same subject, key and certificate profile
            SubjectKeyProfileBundle triple = certstore.getLatestCert(caInfo.getCertificate(),
                    sha1FpSubject, sha1FpPublicKey, certProfileName);

            if(triple != null)
            {
                /*
                 * If there exists a certificate whose public key, subject and profile match the request,
                 * returns the certificate if it is not revoked, otherwise OperationException with
                 * ErrorCode CERT_REVOKED will be thrown
                 */
                if(triple.isRevoked())
                {
                    throw new OperationException(ErrorCode.CERT_REVOKED);
                }
                else
                {
                    X509CertWithId issuedCert = certstore.getCertForId(triple.getCertId());
                    if(issuedCert == null)
                    {
                        throw new OperationException(ErrorCode.System_Failure,
                            "Find no certificate in table RAWCERT for CERT_ID " + triple.getCertId());
                    }
                    else
                    {
                        X509CertificateInfo certInfo;
                        try
                        {
                            certInfo = new X509CertificateInfo(issuedCert,
                                    caInfo.getCertificate(), subjectPublicKeyData, certProfileName);
                        } catch (CertificateEncodingException e)
                        {
                            throw new OperationException(ErrorCode.System_Failure,
                                    "could not construct CertificateInfo: " + e.getMessage());
                        }
                        certInfo.setAlreadyIssued(true);
                        return certInfo;
                    }
                }
            }

            if(keyMode != DuplicationMode.PERMITTED)
            {
                if(keyMode == DuplicationMode.FORBIDDEN)
                {
                    if(certstore.isCertForKeyIssued(caInfo.getCertificate(), sha1FpPublicKey))
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given public key already issued");
                    }
                }
                else if(keyMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
                {
                    if(certstore.isCertForKeyIssued(caInfo.getCertificate(), sha1FpPublicKey, certProfileName))
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given public key and profile " + certProfileName + " already issued");
                    }
                }
                else
                {
                    throw new RuntimeException("should not reach here");
                }
            }

            if(subjectMode != DuplicationMode.PERMITTED)
            {
                final boolean incSerial = certProfile.incSerialNumberIfSubjectExists();
                final boolean certIssued;
                if(subjectMode == DuplicationMode.FORBIDDEN)
                {
                    certIssued = certstore.isCertForSubjectIssued(caInfo.getCertificate(), sha1FpSubject);
                    if(certIssued && incSerial == false)
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given subject " + grandtedSubjectText + " already issued");
                    }
                }
                else if(subjectMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
                {
                    certIssued = certstore.isCertForSubjectIssued(caInfo.getCertificate(), sha1FpSubject, certProfileName);
                    if(certIssued && incSerial == false)
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given subject " + grandtedSubjectText +
                                " and profile " + certProfileName + " already issued");
                    }
                }
                else
                {
                    throw new RuntimeException("should not reach here");
                }

                if(certIssued)
                {
                    String latestSN;
                    try
                    {
                        Object[] objs = incSerialNumber(certProfile, grantedSubject, null);
                        latestSN = certstore.getLatestSN((X500Name) objs[0]);
                    }catch(BadFormatException e)
                    {
                        throw new OperationException(ErrorCode.System_Failure, "BadFormatException: " + e.getMessage());
                    }

                    boolean foundUniqueSubject = false;
                    // maximal 100 tries
                    for(int i = 0; i < 100; i++)
                    {
                        try
                        {
                            Object[] objs = incSerialNumber(certProfile, grantedSubject, latestSN);
                            grantedSubject = (X500Name) objs[0];
                            latestSN = (String) objs[1];
                        }catch (BadFormatException e)
                        {
                            throw new OperationException(ErrorCode.System_Failure, "BadFormatException: " + e.getMessage());
                        }

                        foundUniqueSubject = (certstore.certIssuedForSubject(caInfo.getCertificate(),
                                    SecurityUtil.sha1sum_canonicalized_name(grantedSubject)) == false);
                        if(foundUniqueSubject)
                        {
                            break;
                        }
                    }

                    if(foundUniqueSubject == false)
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given subject " + grandtedSubjectText +
                                " and profile " + certProfileName +
                                " already issued, and could not create new unique serial number");
                    }
                }
            }
        }

        try
        {
            if(subjectMode == DuplicationMode.FORBIDDEN || subjectMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
            {
                synchronized (pendingSubjectMap)
                {
                    // check request with the same subject is still in process
                    if(subjectMode == DuplicationMode.FORBIDDEN)
                    {
                        if(pendingSubjectMap.containsKey(sha1FpSubject))
                        {
                            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                    "Certificate for the given subject " + grandtedSubjectText + " already in process");
                        }
                    }
                    else if(subjectMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
                    {
                        if(pendingSubjectMap.containsKey(sha1FpSubject) &&
                                pendingSubjectMap.get(sha1FpSubject).contains(certProfileName))
                        {
                            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                    "Certificate for the given subject " + grandtedSubjectText +
                                    " and profile " + certProfileName + " already in process");
                        }
                    }

                    List<String> profiles = pendingSubjectMap.get(sha1FpSubject);
                    if(profiles == null)
                    {
                        profiles = new LinkedList<>();
                        pendingSubjectMap.put(sha1FpSubject, profiles);
                    }
                    profiles.add(certProfileName);
                }
            }

            if(keyMode == DuplicationMode.FORBIDDEN || keyMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
            {
                synchronized (pendingSubjectMap)
                {
                    // check request with the same subject is still in process
                    if(keyMode == DuplicationMode.FORBIDDEN)
                    {
                        if(pendingKeyMap.containsKey(sha1FpPublicKey))
                        {
                            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                    "Certificate for the given public key already in process");
                        }
                    }
                    else if(keyMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
                    {
                        if(pendingKeyMap.containsKey(sha1FpPublicKey) &&
                                pendingKeyMap.get(sha1FpPublicKey).contains(certProfileName))
                        {
                            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                    "Certificate for the given public key" +
                                    " and profile " + certProfileName + " already in process");
                        }
                    }

                    List<String> profiles = pendingKeyMap.get(sha1FpSubject);
                    if(profiles == null)
                    {
                        profiles = new LinkedList<>();
                        pendingKeyMap.put(sha1FpPublicKey, profiles);
                    }
                    profiles.add(certProfileName);
                }
            }

            StringBuilder msgBuilder = new StringBuilder();

            if(subjectInfo.getWarning() != null)
            {
                msgBuilder.append(", ").append(subjectInfo.getWarning());
            }

            CertValidity validity = certProfile.getValidity();

            if(validity == null)
            {
                validity = caInfo.getMaxValidity();
            }
            else if(validity.compareTo(caInfo.getMaxValidity()) > 0)
            {
                validity = caInfo.getMaxValidity();
            }

            Date maxNotAfter = validity.add(notBefore);
            Date origMaxNotAfter = maxNotAfter;

            if(certProfile.getSpecialCertProfileBehavior() == SpecialX509CertProfileBehavior.gematik_gSMC_K)
            {
                String s = certProfile.getParameter(SpecialX509CertProfileBehavior.PARAMETER_MAXLIFTIME);
                long maxLifetimeInDays = Long.parseLong(s);
                Date maxLifetime = new Date(gSMC_KFirstNotBefore.getTime() + maxLifetimeInDays * DAY - MS_PER_SECOND);
                if(maxNotAfter.after(maxLifetime))
                {
                    maxNotAfter = maxLifetime;
                }
            }

            if(notAfter != null)
            {
                if(notAfter.after(maxNotAfter))
                {
                    notAfter = maxNotAfter;
                    msgBuilder.append(", NotAfter modified");
                }
            }
            else
            {
                notAfter = maxNotAfter;
            }

            if(notAfter.after(caInfo.getNotAfter()))
            {
                ValidityMode mode = caInfo.getValidityMode();
                if(mode == ValidityMode.CUTOFF)
                {
                    notAfter = caInfo.getNotAfter();
                }
                else if(mode == ValidityMode.STRICT)
                {
                    throw new OperationException(ErrorCode.NOT_PERMITTED,
                            "notAfter outside of CA's validity is not permitted");
                }
                else if(mode == ValidityMode.LAX)
                {
                    // permitted
                }
                else
                {
                    throw new RuntimeException("should not reach here");
                }
            }

            if(certProfile.hasMidnightNotBefore() && maxNotAfter.equals(origMaxNotAfter) == false)
            {
                Calendar c = Calendar.getInstance(certProfile.getTimezone());
                c.setTime(new Date(notAfter.getTime() - DAY));
                c.set(Calendar.HOUR_OF_DAY, 23);
                c.set(Calendar.MINUTE, 59);
                c.set(Calendar.SECOND, 59);
                c.set(Calendar.MILLISECOND, 0);
                notAfter = c.getTime();
            }

            try
            {
                RdnUpperBounds.checkUpperBounds(grantedSubject);
            } catch (BadCertTemplateException e)
            {
                throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
            }

            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    caInfo.getPublicCAInfo().getX500Subject(),
                    caInfo.nextSerial(),
                    notBefore,
                    notAfter,
                    grantedSubject,
                    publicKeyInfo);

            X509CertificateInfo ret;

            try
            {
                X509CrlSignerEntryWrapper crlSigner = getCrlSigner();
                X509Certificate crlSignerCert = crlSigner == null ? null : crlSigner.getCert();

                ExtensionValues extensionTuples = certProfile.getExtensions(requestedSubject, extensions,
                        publicKeyInfo, caInfo.getPublicCAInfo(), crlSignerCert);
                if(extensionTuples != null)
                {
                    for(ASN1ObjectIdentifier extensionType : extensionTuples.getExtensionTypes())
                    {
                        ExtensionValue extValue = extensionTuples.getExtensionValue(extensionType);
                        certBuilder.addExtension(extensionType, extValue.isCritical(), extValue.getValue());
                    }
                }

                ContentSigner contentSigner;
                try
                {
                    contentSigner = signer.borrowContentSigner();
                } catch (NoIdleSignerException e)
                {
                    throw new OperationException(ErrorCode.System_Failure, "NoIdleSignerException: " + e.getMessage());
                }

                Certificate bcCert;
                try
                {
                    bcCert = certBuilder.build(contentSigner).toASN1Structure();
                }finally
                {
                    signer.returnContentSigner(contentSigner);
                }

                byte[] encodedCert = bcCert.getEncoded();

                X509Certificate cert = (X509Certificate) cf.engineGenerateCertificate(
                        new ByteArrayInputStream(encodedCert));
                if(verifySignature(cert) == false)
                {
                    throw new OperationException(ErrorCode.System_Failure,
                            "Could not verify the signature of generated certificate");
                }

                X509CertWithId certWithMeta = new X509CertWithId(cert, encodedCert);

                ret = new X509CertificateInfo(certWithMeta, caInfo.getCertificate(),
                        subjectPublicKeyData, certProfileName);
                ret.setUser(user);
                ret.setRequestor(requestor);

                if(intern_publishCertificate(ret) == 1)
                {
                    throw new OperationException(ErrorCode.System_Failure, "could not save certificate");
                }
            } catch (BadCertTemplateException e)
            {
                throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
            } catch (Throwable t2)
            {
                final String message = "Could not generate certificate";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), t2.getClass().getName(), t2.getMessage());
                }
                LOG.debug(message, t2);

                throw new OperationException(ErrorCode.System_Failure, t2.getClass().getName() + ": " + t2.getMessage());
            }

            if(msgBuilder.length() > 2)
            {
                ret.setWarningMessage(msgBuilder.substring(2));
            }

            return ret;
        }finally
        {
            synchronized (pendingSubjectMap)
            {
                List<String> profiles = pendingSubjectMap.remove(sha1FpSubject);
                if(profiles != null)
                {
                    profiles.remove(certProfileName);
                    if(profiles.isEmpty() == false)
                    {
                        pendingSubjectMap.put(sha1FpSubject, profiles);
                    }
                }

                profiles = pendingKeyMap.remove(sha1FpSubject);
                if(profiles != null)
                {
                    profiles.remove(certProfileName);
                    if(profiles.isEmpty() == false)
                    {
                        pendingKeyMap.put(sha1FpSubject, profiles);
                    }
                }
            }
        }
    }

    // remove the RDNs with empty content
    private static X500Name removeEmptyRDNs(X500Name name)
    {
        RDN[] rdns = name.getRDNs();
        List<RDN> l = new ArrayList<RDN>(rdns.length);
        boolean changed = false;
        for(RDN rdn : rdns)
        {
            String textValue = SecurityUtil.rdnValueToString(rdn.getFirst().getValue());
            if(textValue == null || textValue.isEmpty())
            {
                changed = true;
            }
            else
            {
                l.add(rdn);
            }
        }

        if(changed)
        {
            return new X500Name(l.toArray(new RDN[0]));
        }
        else
        {
            return name;
        }
    }

    public IdentifiedX509CertProfile getX509CertProfile(String certProfileName)
    throws CertProfileException
    {
        if(certProfileName == null)
        {
            return null;
        }

        Set<String> profileNames = caManager.getCertProfilesForCA(caInfo.getName());
        if(profileNames == null || profileNames.contains(certProfileName) == false)
        {
            return null;
        }

        return caManager.getIdentifiedCertProfile(certProfileName);
    }

    public CmpRequestorInfo getRequestor(X500Name requestorSender)
    {
        if(requestorSender == null)
        {
            return null;
        }

        Set<CAHasRequestorEntry> requestorEntries = caManager.getCmpRequestorsForCA(caInfo.getName());
        if(requestorEntries == null || requestorEntries.isEmpty())
        {
            return null;
        }

        for(CAHasRequestorEntry m : requestorEntries)
        {
            CmpRequestorEntryWrapper entry = caManager.getCmpRequestorWrapper(m.getRequestorName());
            if(entry.getCert().getSubjectAsX500Name().equals(requestorSender))
            {
                return new CmpRequestorInfo(m, entry.getCert());
            }
        }

        return null;
    }

    public CAManagerImpl getCAManager()
    {
        return caManager;
    }

    public RemoveExpiredCertsInfo removeExpiredCerts(String certProfile, String userLike, Long overlapSeconds)
    throws OperationException
    {
        if(masterMode == false)
        {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "CA cannot remove expired certificates at slave mode");
        }

        if(userLike != null)
        {
            if(userLike.indexOf(' ') != -1 || userLike.indexOf('\t') != -1 ||
                    userLike.indexOf('\r') != -1|| userLike.indexOf('\n') != -1)
            {
                throw new OperationException(ErrorCode.BAD_REQUEST, "invalid userLike '" + userLike + "'");
            }

            if(userLike.indexOf('*') != -1)
            {
                userLike = userLike.replace('*', '%');
            }
        }

        RemoveExpiredCertsInfo info = new RemoveExpiredCertsInfo();
        info.setUserLike(userLike);
        info.setCertProfile(certProfile);

        if(overlapSeconds == null || overlapSeconds < 0)
        {
            overlapSeconds = 24L * 60 * 60;
        }
        info.setOverlap(overlapSeconds);

        long now = System.currentTimeMillis();
        // remove the following DEBUG CODE
        // now += DAY * 10 * 365;

        long expiredAt = now / MS_PER_SECOND - overlapSeconds;
        info.setExpiredAt(expiredAt);

        int numOfCerts = certstore.getNumOfExpiredCerts(caInfo.getCertificate(), expiredAt,
                certProfile, userLike);
        info.setNumOfCerts(numOfCerts);

        if(numOfCerts > 0)
        {
            removeExpiredCertsQueue.add(info);
        }

        return info;
    }

    private Date getCRLNextUpdate(Date thisUpdate)
    {
        CRLControl control = getCrlSigner().getCRLControl();
        if(control.getUpdateMode() != UpdateMode.interval)
        {
            return null;
        }

        int intervalsTillNextCRL = 0;
        for(int i = 1; ; i++)
        {
            if(i % control.getFullCRLIntervals() == 0)
            {
                intervalsTillNextCRL = i;
                break;
            }
            else if(control.isExtendedNextUpdate() == false && control.getDeltaCRLIntervals() > 0)
            {
                if(i% control.getDeltaCRLIntervals() == 0)
                {
                    intervalsTillNextCRL = i;
                    break;
                }
            }
        }

        Date nextUpdate;
        if(control.getIntervalMinutes() != null)
        {
            int minutesTillNextUpdate = intervalsTillNextCRL * control.getIntervalMinutes()
                    + control.getOverlapMinutes();
            nextUpdate = new Date(MS_PER_SECOND * (thisUpdate.getTime() / MS_PER_SECOND / 60  + minutesTillNextUpdate) * 60);
        }
        else
        {
            Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            c.setTime(thisUpdate);
            c.add(Calendar.DAY_OF_YEAR, intervalsTillNextCRL);
            c.set(Calendar.HOUR_OF_DAY, control.getIntervalDayTime().getHour());
            c.set(Calendar.MINUTE, control.getIntervalDayTime().getMinute());
            c.add(Calendar.MINUTE, control.getOverlapMinutes());
            c.set(Calendar.SECOND, 0);
            c.set(Calendar.MILLISECOND, 0);
            nextUpdate = c.getTime();
        }

        return nextUpdate;
    }

    public HealthCheckResult healthCheck()
    {
        HealthCheckResult result = new HealthCheckResult("X509CA");

        boolean healthy = true;

        ConcurrentContentSigner signer = caInfo.getSigner();
        if(signer != null)
        {
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
        if(crlSigner != null && crlSigner.getSigner() != null)
        {
            boolean crlSignerHealthy = crlSigner.getSigner().isHealthy();
            healthy &= crlSignerHealthy;

            HealthCheckResult crlSignerHealth = new HealthCheckResult("CRLSigner");
            crlSignerHealth.setHealthy(crlSignerHealthy);
            result.addChildCheck(crlSignerHealth);
        }

        for(IdentifiedX509CertPublisher publisher : getPublishers())
        {
            boolean ph = publisher.isHealthy();
            healthy &= ph;

            HealthCheckResult publisherHealth = new HealthCheckResult("Publisher");
            publisherHealth.setHealthy(publisher.isHealthy());
            result.addChildCheck(publisherHealth);
        }

        result.setHealthy(healthy);

        return result;
    }

    public void setAuditServiceRegister(AuditLoggingServiceRegister serviceRegister)
    {
        this.serviceRegister = serviceRegister;
    }

    private AuditLoggingService getAuditLoggingService()
    {
        return serviceRegister == null ? null : serviceRegister.getAuditLoggingService();
    }

    private AuditEvent newAuditEvent()
    {
        AuditEvent ae = new AuditEvent(new Date());
        ae.setApplicationName("CA");
        ae.setName("SYSTEM");
        return ae;
    }

    private static Object[] incSerialNumber(IdentifiedX509CertProfile profile, X500Name origName, String latestSN)
    throws BadFormatException
    {
        RDN[] rdns = origName.getRDNs();

        int commonNameIndex = -1;
        int serialNumberIndex = -1;
        for(int i = 0; i < rdns.length; i++)
        {
            RDN rdn = rdns[i];
            ASN1ObjectIdentifier type = rdn.getFirst().getType();
            if(ObjectIdentifiers.DN_CN.equals(type))
            {
                commonNameIndex = i;
            }
            else if(ObjectIdentifiers.DN_SERIALNUMBER.equals(type))
            {
                serialNumberIndex = i;
            }
        }

        String newSerialNumber = profile.incSerialNumber(latestSN);
        RDN serialNumberRdn = new RDN(ObjectIdentifiers.DN_SERIALNUMBER, new DERPrintableString(newSerialNumber));

        X500Name newName;
        if(serialNumberIndex != -1)
        {
            rdns[serialNumberIndex] = serialNumberRdn;
            newName = new X500Name(rdns);
        }
        else
        {
            List<RDN> newRdns = new ArrayList<>(rdns.length + 1);

            if(commonNameIndex == -1)
            {
                newRdns.add(serialNumberRdn);
            }

            for(int i = 0; i < rdns.length; i++)
            {
                newRdns.add(rdns[i]);
                if(i == commonNameIndex)
                {
                    newRdns.add(serialNumberRdn);
                }
            }

            newName = new X500Name(newRdns.toArray(new RDN[0]));
        }

        return new Object[]{newName, newSerialNumber};
    }

    private boolean verifySignature(X509Certificate cert)
    {
        PublicKey caPublicKey = caInfo.getCertificate().getCert().getPublicKey();
        try
        {
            final String provider = "XipkiNSS";

            if(tryXipkiNSStoVerify == null)
            {
                // Not for ECDSA
                if(caPublicKey instanceof ECPublicKey)
                {
                    tryXipkiNSStoVerify = Boolean.FALSE;
                }
                else
                {
                    if(Security.getProvider(provider) == null)
                    {
                        LOG.info("Security provider {} is not registered", provider);
                        tryXipkiNSStoVerify = Boolean.FALSE;
                    }
                    else
                    {
                        byte[] tbs = cert.getTBSCertificate();
                        byte[] signatureValue = cert.getSignature();
                        String sigAlgName = cert.getSigAlgName();
                        try
                        {
                            Signature verifier = Signature.getInstance(sigAlgName, provider);
                            verifier.initVerify(caPublicKey);
                            verifier.update(tbs);
                            boolean sigValid = verifier.verify(signatureValue);

                            LOG.info("Use {} to verify {} signature", provider, sigAlgName);
                            tryXipkiNSStoVerify = Boolean.TRUE;
                            return sigValid;
                        }catch(Exception e)
                        {
                            LOG.info("Cannot use {} to verify {} signature", provider, sigAlgName);
                            tryXipkiNSStoVerify = Boolean.FALSE;
                        }
                    }
                }
            }

            if(tryXipkiNSStoVerify)
            {
                byte[] tbs = cert.getTBSCertificate();
                byte[] signatureValue = cert.getSignature();
                String sigAlgName = cert.getSigAlgName();
                Signature verifier = Signature.getInstance(sigAlgName, provider);
                verifier.initVerify(caPublicKey);
                verifier.update(tbs);
                return verifier.verify(signatureValue);
            }
            else
            {
                cert.verify(caPublicKey);
                return true;
            }
        } catch (SignatureException | InvalidKeyException | CertificateException |
                NoSuchAlgorithmException | NoSuchProviderException e)
        {
            LOG.debug("{} while verifying signature: {}", e.getClass().getName(), e.getMessage());
            return false;
        }
    }

    private static Date setToMidnight(Date date, TimeZone timezone)
    {
        Calendar c = Calendar.getInstance(timezone);
        c.setTime(date);
        c.set(Calendar.HOUR_OF_DAY, 0);
        c.set(Calendar.MINUTE, 0);
        c.set(Calendar.SECOND, 0);
        c.set(Calendar.MILLISECOND, 0);
        return c.getTime();
    }

    private X509CrlSignerEntryWrapper getCrlSigner()
    {
        String crlSignerName = caInfo.getCrlSignerName();
        X509CrlSignerEntryWrapper crlSigner = crlSignerName == null ?
                null : caManager.getCrlSignerWrapper(crlSignerName);
        return crlSigner;
    }
}
