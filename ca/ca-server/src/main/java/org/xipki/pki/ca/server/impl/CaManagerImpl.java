/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.audit.api.AuditEvent;
import org.xipki.commons.audit.api.AuditEventData;
import org.xipki.commons.audit.api.AuditLevel;
import org.xipki.commons.audit.api.AuditService;
import org.xipki.commons.audit.api.AuditServiceRegister;
import org.xipki.commons.audit.api.AuditStatus;
import org.xipki.commons.audit.api.PciAuditEvent;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.datasource.api.DataSourceFactory;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.CrlReason;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.util.AlgorithmUtil;
import org.xipki.pki.ca.api.CertPublisherException;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.api.DfltEnvParameterResolver;
import org.xipki.pki.ca.api.EnvParameterResolver;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.api.X509Cert;
import org.xipki.pki.ca.api.X509CertWithDbId;
import org.xipki.pki.ca.api.publisher.X509CertificateInfo;
import org.xipki.pki.ca.server.impl.X509SelfSignedCertBuilder.GenerateSelfSignedResult;
import org.xipki.pki.ca.server.impl.cmp.CmpRequestorEntryWrapper;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderEntryWrapper;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderManager;
import org.xipki.pki.ca.server.impl.cmp.X509CaCmpResponder;
import org.xipki.pki.ca.server.impl.scep.Scep;
import org.xipki.pki.ca.server.impl.scep.ScepManager;
import org.xipki.pki.ca.server.impl.store.CertificateStore;
import org.xipki.pki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CaManager;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.CaSystemStatus;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeScepEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControl;
import org.xipki.pki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.pki.ca.server.mgmt.api.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.UserEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CaUris;
import org.xipki.pki.ca.server.mgmt.api.X509ChangeCrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CrlSignerEntry;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaManagerImpl implements CaManager, CmpResponderManager, ScepManager {

    private class ScheduledPublishQueueCleaner implements Runnable {

        private boolean inProcess;

        @Override
        public void run() {
            if (inProcess || !caSystemSetuped) {
                return;
            }

            inProcess = true;
            try {
                LOG.debug("publishing certificates in PUBLISHQUEUE");
                for (String name : x509cas.keySet()) {
                    X509Ca ca = x509cas.get(name);
                    boolean b = ca.publishCertsInQueue();
                    if (b) {
                        LOG.debug(" published certificates of CA '{}' in PUBLISHQUEUE", name);
                    } else {
                        LOG.error("publishing certificates of CA '{}' in PUBLISHQUEUE failed",
                                name);
                    }
                }
            } catch (Throwable th) {
            } finally {
                inProcess = false;
            }
        } // method run

    } // class ScheduledPublishQueueCleaner

    private class ScheduledDeleteCertsInProcessService implements Runnable {

        private boolean inProcess;

        @Override
        public void run() {
            if (inProcess) {
                return;
            }

            inProcess = true;
            try {
                try {
                    // older than 10 minutes
                    certstore.deleteCertsInProcessOlderThan(
                            new Date(System.currentTimeMillis() - 10 * 60 * 1000L));
                } catch (Throwable th) {
                    final String message =
                            "could not call certstore.deleteCertsInProcessOlderThan";
                    if (LOG.isErrorEnabled()) {
                        LOG.error(LogUtil.buildExceptionLogFormat(message),
                                th.getClass().getName(), th.getMessage());
                    }
                    LOG.debug(message, th);
                }
            } finally {
                inProcess = false;
            }
        } // method run

    } // class ScheduledDeleteCertsInProcessService

    private class ScheduledCARestarter implements Runnable {

        private boolean inProcess;

        @Override
        public void run() {
            if (inProcess) {
                return;
            }

            inProcess = true;
            try {
                SystemEvent event = queryExecutor.getSystemEvent(EVENT_CACHAGNE);
                long caChangedTime = (event == null)
                        ? 0
                        : event.getEventTime();

                if (LOG.isDebugEnabled()) {
                    LOG.debug(
                        "check the restart CA system event: CA changed at={}, lastStartTime={}",
                        new Date(caChangedTime * 1000L), lastStartTime);
                }

                if (caChangedTime > lastStartTime.getTime() / 1000L) {
                    LOG.info("received event to restart CA");
                    restartCaSystem();
                } else {
                    LOG.debug("received no event to restart CA");
                }
            } catch (Throwable th) {
                LOG.error("ScheduledCArestarter: " + th.getMessage(), th);
            } finally {
                inProcess = false;
            }
        } // method run

    } // class ScheduledCARestarter

    private static final Logger LOG = LoggerFactory.getLogger(CaManagerImpl.class);

    private static final String EVENT_LOCK = "LOCK";

    private static final String EVENT_CACHAGNE = "CA_CHANGE";

    private final String lockInstanceId;

    private Map<String, CmpResponderEntry> responderDbEntries = new ConcurrentHashMap<>();

    private Map<String, CmpResponderEntryWrapper> responders = new ConcurrentHashMap<>();

    private boolean caLockedByMe;

    private boolean masterMode;

    private Map<String, DataSourceWrapper> datasources;

    private final Map<String, X509CaInfo> caInfos = new ConcurrentHashMap<>();

    private final Map<String, IdentifiedX509Certprofile> certprofiles = new ConcurrentHashMap<>();

    private final Map<String, CertprofileEntry> certprofileDbEntries = new ConcurrentHashMap<>();

    private final Map<String, IdentifiedX509CertPublisher> publishers = new ConcurrentHashMap<>();

    private final Map<String, PublisherEntry> publisherDbEntries = new ConcurrentHashMap<>();

    private final Map<String, CmpControl> cmpControls = new ConcurrentHashMap<>();

    private final Map<String, CmpControlEntry> cmpControlDbEntries = new ConcurrentHashMap<>();

    private final Map<String, CmpRequestorEntryWrapper> requestors = new ConcurrentHashMap<>();

    private final Map<String, CmpRequestorEntry> requestorDbEntries = new ConcurrentHashMap<>();

    private final Map<String, X509CrlSignerEntryWrapper> crlSigners = new ConcurrentHashMap<>();

    private final Map<String, X509CrlSignerEntry> crlSignerDbEntries = new ConcurrentHashMap<>();

    private final Map<String, Scep> sceps = new ConcurrentHashMap<>();

    private final Map<String, ScepEntry> scepDbEntries = new ConcurrentHashMap<>();

    private final Map<String, Map<String, String>> caHasProfiles = new ConcurrentHashMap<>();

    private final Map<String, Set<String>> caHasPublishers = new ConcurrentHashMap<>();

    private final Map<String, Set<CaHasRequestorEntry>> caHasRequestors
            = new ConcurrentHashMap<>();

    private final Map<String, String> caAliases = new ConcurrentHashMap<>();

    private final DfltEnvParameterResolver envParameterResolver = new DfltEnvParameterResolver();

    private ScheduledThreadPoolExecutor persistentScheduledThreadPoolExecutor;

    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    private final Map<String, X509CaCmpResponder> x509Responders = new ConcurrentHashMap<>();

    private final Map<String, X509Ca> x509cas = new ConcurrentHashMap<>();

    private String caConfFile;

    private boolean caSystemSetuped;

    private boolean responderInitialized;

    private boolean requestorsInitialized;

    private boolean caAliasesInitialized;

    private boolean certprofilesInitialized;

    private boolean publishersInitialized;

    private boolean crlSignersInitialized;

    private boolean cmpControlInitialized;

    private boolean casInitialized;

    private boolean environmentParametersInitialized;

    private boolean scepsInitialized;

    private Date lastStartTime;

    private AuditServiceRegister auditServiceRegister;

    private DataSourceWrapper datasource;

    private CertificateStore certstore;

    private SecurityFactory securityFactory;

    private DataSourceFactory datasourceFactory;

    private CaManagerQueryExecutor queryExecutor;

    private boolean initializing;

    public CaManagerImpl()
    throws InvalidConfException {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        String calockId = null;
        File caLockFile = new File("calock");
        if (caLockFile.exists()) {
            try {
                calockId = new String(IoUtil.read(caLockFile));
            } catch (IOException ex) {
            }
        }

        if (calockId == null) {
            calockId = UUID.randomUUID().toString();
            try {
                IoUtil.save(caLockFile, calockId.getBytes());
            } catch (IOException ex) {
            }
        }

        String hostAddress = null;
        try {
            hostAddress = IoUtil.getHostAddress();
        } catch (SocketException ex) {
        }

        this.lockInstanceId = (hostAddress == null)
                ? calockId
                : hostAddress + "/" + calockId;
    } // constructor

    public SecurityFactory getSecurityFactory() {
        return securityFactory;
    }

    public void setSecurityFactory(
            final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

    public DataSourceFactory getDataSourceFactory() {
        return datasourceFactory;
    }

    public void setDataSourceFactory(
            final DataSourceFactory datasourceFactory) {
        this.datasourceFactory = datasourceFactory;
    }

    private void init()
    throws CaMgmtException {
        if (securityFactory == null) {
            throw new IllegalStateException("securityFactory is not set");
        }
        if (datasourceFactory == null) {
            throw new IllegalStateException("datasourceFactory is not set");
        }
        if (caConfFile == null) {
            throw new IllegalStateException("caConfFile is not set");
        }

        Properties caConfProps = new Properties();
        try {
            caConfProps.load(new FileInputStream(IoUtil.expandFilepath(caConfFile)));
        } catch (IOException ex) {
            throw new CaMgmtException("IOException while parsing ca configuration" + caConfFile,
                    ex);
        }

        String caModeStr = caConfProps.getProperty("ca.mode");
        if (caModeStr != null) {
            if ("slave".equalsIgnoreCase(caModeStr)) {
                masterMode = false;
            } else if ("master".equalsIgnoreCase(caModeStr)) {
                masterMode = true;
            } else {
                throw new CaMgmtException("invalid ca.mode '" + caModeStr + "'");
            }
        } else {
            masterMode = true;
        }

        if (this.datasources == null) {
            this.datasources = new ConcurrentHashMap<>();
            for (Object objKey : caConfProps.keySet()) {
                String key = (String) objKey;
                if (!StringUtil.startsWithIgnoreCase(key, "datasource.")) {
                    continue;
                }

                String datasourceFile = caConfProps.getProperty(key);
                try {
                    String datasourceName = key.substring("datasource.".length());
                    DataSourceWrapper datasource = datasourceFactory.createDataSourceForFile(
                            datasourceName, datasourceFile, securityFactory.getPasswordResolver());

                    Connection conn = datasource.getConnection();
                    datasource.returnConnection(conn);

                    this.datasources.put(datasourceName, datasource);
                } catch (DataAccessException | PasswordResolverException | IOException
                        | RuntimeException ex) {
                    throw new CaMgmtException(ex.getClass().getName()
                            + " while parsing datasoure " + datasourceFile, ex);
                }
            }

            this.datasource = this.datasources.get("ca");
        }

        if (this.datasource == null) {
            throw new CaMgmtException("no datasource configured with name 'ca'");
        }

        this.queryExecutor = new CaManagerQueryExecutor(this.datasource);

        if (masterMode) {
            boolean lockedSuccessful;
            try {
                lockedSuccessful = lockCa(true);
            } catch (DataAccessException ex) {
                throw new CaMgmtException("DataAccessException while locking CA", ex);
            }

            if (!lockedSuccessful) {
                final String msg =
                    "could not lock the CA database. In general this indicates that another"
                    + " CA software in active mode is accessing the database or the last"
                    + " shutdown of CA software in active mode is abnormal.";
                throw new CaMgmtException(msg);
            }
        }

        try {
            this.certstore = new CertificateStore(datasource);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }

        initDataObjects();
    } // method init

    @Override
    public CaSystemStatus getCaSystemStatus() {
        if (caSystemSetuped) {
            return masterMode
                    ? CaSystemStatus.STARTED_AS_MASTER
                    : CaSystemStatus.STARTED_AS_SLAVE;
        } else if (initializing) {
            return CaSystemStatus.INITIALIZING;
        } else if (!caLockedByMe) {
            return CaSystemStatus.LOCK_FAILED;
        } else {
            return CaSystemStatus.ERROR;
        }
    }

    private boolean lockCa(
            final boolean forceRelock)
    throws DataAccessException, CaMgmtException {
        SystemEvent lockInfo = queryExecutor.getSystemEvent(EVENT_LOCK);

        if (lockInfo != null) {
            String lockedBy = lockInfo.getOwner();
            Date lockedAt = new Date(lockInfo.getEventTime() * 1000L);

            if (!this.lockInstanceId.equals(lockedBy)) {
                LOG.error("could not lock CA, it has been locked by {} since {}", lockedBy,
                        lockedAt);
                return false;
            }

            if (!forceRelock) {
                return true;
            } else {
                LOG.info("CA has been locked by me since {}, relock it", lockedAt);
            }
        }

        SystemEvent newLockInfo = new SystemEvent(EVENT_LOCK, lockInstanceId,
                System.currentTimeMillis() / 1000L);
        return queryExecutor.changeSystemEvent(newLockInfo);
    } // method lockCa

    @Override
    public boolean unlockCa() {
        if (!masterMode) {
            LOG.error("could not unlock CA in slave mode");
            return false;
        }

        caLockedByMe = false;

        boolean successful = false;
        try {
            queryExecutor.unlockCa();
            successful = true;
        } catch (DataAccessException | CaMgmtException ex) {
            final String message = "error in unlockCA()";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
        }

        if (successful) {
            LOG.info("unlocked CA");
        } else {
            LOG.error("unlocking CA failed");
        }
        auditLogPciEvent(successful, "UNLOCK");
        return successful;
    } // method unlockCa

    private void reset() {
        caSystemSetuped = false;
        responderInitialized = false;
        requestorsInitialized = false;
        caAliasesInitialized = false;
        certprofilesInitialized = false;
        publishersInitialized = false;
        crlSignersInitialized = false;
        cmpControlInitialized = false;
        casInitialized = false;
        environmentParametersInitialized = false;
        scepsInitialized = false;

        shutdownScheduledThreadPoolExecutor();
    } // method reset

    private void initDataObjects()
    throws CaMgmtException {
        initEnvironemtParamters();
        initCaAliases();
        initCertprofiles();
        initPublishers();
        initCmpControls();
        initRequestors();
        initResponders();
        initCrlSigners();
        initCas();
        initSceps();
        markLastSeqValues();
    } // method initDataObjects

    @Override
    public boolean restartCaSystem() {
        reset();
        boolean caSystemStarted = doStartCaSystem();

        if (!caSystemStarted) {
            String msg = "could not restart CA system";
            LOG.error(msg);
        }

        auditLogPciEvent(caSystemStarted, "CA_CHANGE");
        return caSystemStarted;
    } // method restartCaSystem

    @Override
    public boolean notifyCaChange()
    throws CaMgmtException {
        try {
            SystemEvent systemEvent = new SystemEvent(EVENT_CACHAGNE, lockInstanceId,
                    System.currentTimeMillis() / 1000L);
            queryExecutor.changeSystemEvent(systemEvent);
            LOG.info("notified the change of CA system");
            return true;
        } catch (CaMgmtException ex) {
            final String message = "error while notifying Slave CAs to restart";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            return false;
        }
    } // method notifyCaChange

    public void startCaSystem() {
        boolean caSystemStarted = false;
        try {
            caSystemStarted = doStartCaSystem();
        } catch (Throwable th) {
            final String message = "do_startCaSystem()";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), th.getClass().getName(),
                        th.getMessage());
            }
            LOG.debug(message, th);
            LOG.error(message);
        }

        if (!caSystemStarted) {
            String msg = "could not start CA system";
            LOG.error(msg);
        }

        auditLogPciEvent(caSystemStarted, "START");
    } // method startCaSystem

    private boolean doStartCaSystem() {
        if (caSystemSetuped) {
            return true;
        }

        initializing = true;
        shutdownScheduledThreadPoolExecutor();

        try {
            LOG.info("starting CA system");
            try {
                init();
            } catch (Exception ex) {
                final String message = "do_startCaSystem().init()";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
                return false;
            }

            this.lastStartTime = new Date();

            x509cas.clear();
            x509Responders.clear();

            scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(10);
            scheduledThreadPoolExecutor.setRemoveOnCancelPolicy(true);

            // Add the CAs to the store
            for (String caName : caInfos.keySet()) {
                if (!startCa(caName)) {
                    return false;
                }
            }

            caSystemSetuped = true;
            StringBuilder sb = new StringBuilder();
            sb.append("started CA system");
            Set<String> names = new HashSet<>(getCaNames());

            if (names.size() > 0) {
                sb.append(" with following CAs: ");
                Set<String> caAliasNames = getCaAliasNames();
                for (String aliasName : caAliasNames) {
                    String name = getCaNameForAlias(aliasName);
                    names.remove(name);
                    sb.append(name).append(" (alias ").append(aliasName).append(")").append(", ");
                }

                for (String name : names) {
                    sb.append(name).append(", ");
                }

                int len = sb.length();
                sb.delete(len - 2, len);

                scheduledThreadPoolExecutor.scheduleAtFixedRate(new ScheduledPublishQueueCleaner(),
                        120, 120, TimeUnit.SECONDS);
                scheduledThreadPoolExecutor.scheduleAtFixedRate(
                        new ScheduledDeleteCertsInProcessService(),
                        120, 120, TimeUnit.SECONDS);
            } else {
                sb.append(": no CA is configured");
            }
            LOG.info("{}", sb);
        } finally {
            initializing = false;
            if (!masterMode && persistentScheduledThreadPoolExecutor == null) {
                persistentScheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
                persistentScheduledThreadPoolExecutor.setRemoveOnCancelPolicy(true);
                ScheduledCARestarter caRestarter = new ScheduledCARestarter();
                persistentScheduledThreadPoolExecutor.scheduleAtFixedRate(caRestarter, 300, 300,
                        TimeUnit.SECONDS);
            }
        }

        return true;
    } // method doStartCaSystem

    private boolean startCa(
            final String caName) {
        X509CaInfo caEntry = caInfos.get(caName);
        boolean signerRequired = caEntry.isSignerRequired();

        X509CrlSignerEntryWrapper crlSignerEntry = null;
        String crlSignerName = caEntry.getCrlSignerName();
        // CRL will be generated only in master mode
        if (signerRequired && masterMode && crlSignerName != null) {
            crlSignerEntry = crlSigners.get(crlSignerName);
            try {
                crlSignerEntry.getDbEntry().setConfFaulty(true);
                crlSignerEntry.initSigner(securityFactory);
                crlSignerEntry.getDbEntry().setConfFaulty(false);
            } catch (SignerException | OperationException | InvalidConfException ex) {
                final String message = "X09CrlSignerEntryWrapper.initSigner (name="
                        + crlSignerName + ")";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
                return false;
            }
        }

        X509Ca ca;
        try {
            ca = new X509Ca(this, caEntry, certstore, securityFactory, masterMode);
            if (auditServiceRegister != null) {
                ca.setAuditServiceRegister(auditServiceRegister);
            }
        } catch (OperationException ex) {
            final String message = "X509CA.<init> (ca=" + caName + ")";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            return false;
        }

        x509cas.put(caName, ca);

        X509CaCmpResponder caResponder = new X509CaCmpResponder(this, caName);
        x509Responders.put(caName, caResponder);

        // referesh the SCEP
        if (sceps.containsKey(caName)) {
            try {
                sceps.get(caName).refreshCa();
            } catch (CaMgmtException ex) {
                final String message = "X509CA.SCEP (ca=" + caName + ")";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
                return false;
            }
        }
        return true;
    } // method startCa

    public void shutdown() {
        LOG.info("stopping CA system");
        shutdownScheduledThreadPoolExecutor();

        if (persistentScheduledThreadPoolExecutor != null) {
            persistentScheduledThreadPoolExecutor.shutdown();
            while (!persistentScheduledThreadPoolExecutor.isTerminated()) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ex) {
                }
            }
            persistentScheduledThreadPoolExecutor = null;
        }

        for (String caName : x509cas.keySet()) {
            X509Ca ca = x509cas.get(caName);
            try {
                ca.getCaInfo().commitNextSerial();
            } catch (Throwable th) {
                LOG.info("Exception while calling CAInfo.commitNextSerial for CA '{}': {}",
                        caName, th.getMessage());
            }

            try {
                ca.shutdown();
            } catch (Throwable th) {
                LOG.info("Exception while calling ca.shutdown() for CA '{}': {}",
                        caName, th.getMessage());
            }
        }

        if (caLockedByMe) {
            unlockCa();
        }

        File caLockFile = new File("calock");
        if (caLockFile.exists()) {
            caLockFile.delete();
        }

        for (String dsName :datasources.keySet()) {
            DataSourceWrapper ds = datasources.get(dsName);
            try {
                ds.shutdown();
            } catch (Exception ex) {
                final String message = "could not shutdown datasource " + dsName;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
            }
        }

        LOG.info("stopped CA system");
        auditLogPciEvent(true, "SHUTDOWN");
    } // method shutdown

    @Override
    public X509CaCmpResponder getX509CaCmpResponder(
            final String name) {
        ParamUtil.requireNonBlank("name", name);
        return x509Responders.get(name.toUpperCase());
    }

    public ScheduledThreadPoolExecutor getScheduledThreadPoolExecutor() {
        return scheduledThreadPoolExecutor;
    }

    @Override
    public Set<String> getCertprofileNames() {
        return certprofileDbEntries.keySet();
    }

    @Override
    public Set<String> getPublisherNames() {
        return publisherDbEntries.keySet();
    }

    @Override
    public Set<String> getCmpRequestorNames() {
        return requestorDbEntries.keySet();
    }

    @Override
    public Set<String> getCmpResponderNames() {
        return responderDbEntries.keySet();
    }

    @Override
    public Set<String> getCrlSignerNames() {
        return crlSigners.keySet();
    }

    @Override
    public Set<String> getCmpControlNames() {
        return cmpControlDbEntries.keySet();
    }

    @Override
    public Set<String> getCaNames() {
        return caInfos.keySet();
    }

    private void initRequestors()
    throws CaMgmtException {
        if (requestorsInitialized) {
            return;
        }

        requestorDbEntries.clear();
        requestors.clear();
        List<String> names = queryExecutor.getNamesFromTable("REQUESTOR");
        for (String name : names) {
            CmpRequestorEntry requestorDbEntry = queryExecutor.createRequestor(name);
            if (requestorDbEntry == null) {
                continue;
            }

            requestorDbEntries.put(name, requestorDbEntry);
            CmpRequestorEntryWrapper requestor = new CmpRequestorEntryWrapper();
            requestor.setDbEntry(requestorDbEntry);
            requestors.put(name, requestor);
        }
        requestorsInitialized = true;
    } // method initRequestors

    private void initResponders()
    throws CaMgmtException {
        if (responderInitialized) {
            return;
        }

        responderDbEntries.clear();
        responders.clear();

        List<String> names = queryExecutor.getNamesFromTable("RESPONDER");
        for (String name : names) {
            CmpResponderEntry dbEntry = queryExecutor.createResponder(name);
            if (dbEntry == null) {
                continue;
            }

            dbEntry.setConfFaulty(true);
            responderDbEntries.put(name, dbEntry);

            CmpResponderEntryWrapper responder = createCmpResponder(dbEntry);
            if (responder != null) {
                dbEntry.setConfFaulty(false);
                responders.put(name, responder);
            }
        }
        responderInitialized = true;
    } // method initResponders

    private void initEnvironemtParamters()
    throws CaMgmtException {
        if (environmentParametersInitialized) {
            return;
        }

        Map<String, String> map = queryExecutor.createEnvParameters();
        envParameterResolver.clear();
        for (String name : map.keySet()) {
            envParameterResolver.addEnvParam(name, map.get(name));
        }

        environmentParametersInitialized = true;
    } // method initEnvironemtParamters

    private void initCaAliases()
    throws CaMgmtException {
        if (caAliasesInitialized) {
            return;
        }

        Map<String, String> map = queryExecutor.createCaAliases();
        caAliases.clear();
        for (String aliasName : map.keySet()) {
            caAliases.put(aliasName, map.get(aliasName));
        }

        caAliasesInitialized = true;
    } // method initCaAliases

    private void initCertprofiles()
    throws CaMgmtException {
        if (certprofilesInitialized) {
            return;
        }

        for (String name : certprofiles.keySet()) {
            shutdownCertprofile(certprofiles.get(name));
        }
        certprofileDbEntries.clear();
        certprofiles.clear();

        List<String> names = queryExecutor.getNamesFromTable("PROFILE");
        for (String name : names) {
            CertprofileEntry dbEntry = queryExecutor.createCertprofile(name);
            if (dbEntry == null) {
                LOG.error("could not initialize CertificateEntry '{}'", name);
                continue;
            }

            dbEntry.setFaulty(true);
            certprofileDbEntries.put(name, dbEntry);

            IdentifiedX509Certprofile profile = createCertprofile(dbEntry);
            if (profile != null) {
                dbEntry.setFaulty(false);
                certprofiles.put(name, profile);
            }
        }

        certprofilesInitialized = true;
    } // method initCertprofiles

    private void initPublishers()
    throws CaMgmtException {
        if (publishersInitialized) {
            return;
        }

        for (String name : publishers.keySet()) {
            shutdownPublisher(publishers.get(name));
        }
        publishers.clear();
        publisherDbEntries.clear();

        List<String> names = queryExecutor.getNamesFromTable("PUBLISHER");
        for (String name : names) {
            PublisherEntry dbEntry = queryExecutor.createPublisher(name);
            if (dbEntry == null) {
                continue;
            }

            dbEntry.setFaulty(true);
            publisherDbEntries.put(name, dbEntry);

            IdentifiedX509CertPublisher publisher = createPublisher(dbEntry);
            if (publisher != null) {
                dbEntry.setFaulty(false);
                publishers.put(name, publisher);
            }
        }

        publishersInitialized = true;
    } // method initPublishers

    private void initCrlSigners()
    throws CaMgmtException {
        if (crlSignersInitialized) {
            return;
        }
        crlSigners.clear();
        crlSignerDbEntries.clear();

        List<String> names = queryExecutor.getNamesFromTable("CRLSIGNER");
        for (String name : names) {
            X509CrlSignerEntry dbEntry = queryExecutor.createCrlSigner(name);
            if (dbEntry == null) {
                continue;
            }

            crlSignerDbEntries.put(name, dbEntry);
            X509CrlSignerEntryWrapper crlSigner = createX509CrlSigner(dbEntry);
            crlSigners.put(name, crlSigner);
        }

        crlSignersInitialized = true;
    } // method initCrlSigners

    private void initCmpControls()
    throws CaMgmtException {
        if (cmpControlInitialized) {
            return;
        }

        cmpControls.clear();
        cmpControlDbEntries.clear();

        List<String> names = queryExecutor.getNamesFromTable("CMPCONTROL");
        for (String name : names) {
            CmpControlEntry cmpControlDb = queryExecutor.createCmpControl(name);
            if (cmpControlDb == null) {
                continue;
            }

            cmpControlDb.setFaulty(true);
            cmpControlDbEntries.put(name, cmpControlDb);

            CmpControl cmpControl;
            try {
                cmpControl = new CmpControl(cmpControlDb);
                cmpControlDb.setFaulty(false);
                cmpControls.put(name, cmpControl);
            } catch (InvalidConfException ex) {
                final String message = "could not initialize CMP control " + name
                        + ", ignore it";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
            }
        }

        cmpControlInitialized = true;
    } // method initCmpControls

    private void initSceps()
    throws CaMgmtException {
        if (scepsInitialized) {
            return;
        }

        sceps.clear();
        scepDbEntries.clear();

        List<String> names = queryExecutor.getNamesFromTable("SCEP", "CA_NAME");
        for (String name : names) {
            ScepEntry scepDb = queryExecutor.getScep(name);
            if (scepDb == null) {
                continue;
            }

            scepDb.setConfFaulty(true);
            scepDbEntries.put(name, scepDb);

            try {
                Scep scep = new Scep(scepDb, this);
                scepDb.setConfFaulty(false);
                sceps.put(name, scep);
            } catch (CaMgmtException ex) {
                final String message = "could not initialize SCEP entry " + name
                        + ", ignore it";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
            }
        }
        scepsInitialized = true;
    } // method initSceps

    private void initCas()
    throws CaMgmtException {
        if (casInitialized) {
            return;
        }

        caInfos.clear();
        caHasRequestors.clear();
        caHasPublishers.clear();
        caHasProfiles.clear();

        List<String> names = queryExecutor.getNamesFromTable("CA");
        for (String name : names) {
            createCa(name);
        }
        casInitialized = true;
    } // method initCas

    private boolean createCa(
            final String name)
    throws CaMgmtException {
        caInfos.remove(name);
        caHasProfiles.remove(name);
        caHasPublishers.remove(name);
        caHasRequestors.remove(name);
        X509Ca oldCa = x509cas.remove(name);
        x509Responders.remove(name);
        if (oldCa != null) {
            oldCa.shutdown();
        }

        X509CaInfo ca = queryExecutor.createCaInfo(name, masterMode, certstore);
        try {
            ca.markMaxSerial();
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
        caInfos.put(name, ca);

        Set<CaHasRequestorEntry> caHasRequestorList = queryExecutor.createCaHasRequestors(name);
        caHasRequestors.put(name, caHasRequestorList);

        Map<String, String> profileNames = queryExecutor.createCaHasProfiles(name);
        caHasProfiles.put(name, profileNames);

        Set<String> publisherNames = queryExecutor.createCaHasPublishers(name);
        caHasPublishers.put(name, publisherNames);

        return true;
    } // method createCa

    private void markLastSeqValues()
    throws CaMgmtException {
        try {
            // sequence DCC_ID
            long maxId = datasource.getMax(null, "DELTACRL_CACHE", "ID");
            datasource.setLastUsedSeqValue("DCC_ID", maxId);

            // sequence CID
            maxId = datasource.getMax(null, "CERT", "ID");
            datasource.setLastUsedSeqValue("CID", maxId);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method markLastSeqValues

    @Override
    public boolean addCa(
            final CaEntry caEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("caEntry", caEntry);
        asssertMasterMode();
        String name = caEntry.getName();

        if (caInfos.containsKey(name)) {
            throw new CaMgmtException("CA named " + name + " exists");
        }

        if (caEntry instanceof X509CaEntry) {
            X509CaEntry xEntry = (X509CaEntry) caEntry;

            ConcurrentContentSigner signer;
            try {
                List<String[]> signerConfs = splitCaSignerConfs(xEntry.getSignerConf());
                for (String[] m : signerConfs) {
                    String signerConf = m[1];
                    signer = securityFactory.createSigner(
                            xEntry.getSignerType(), signerConf, xEntry.getCertificate());
                    if (xEntry.getCertificate() == null) {
                        if (signer.getCertificate() == null) {
                            throw new CaMgmtException(
                                    "CA signer without certificate is not allowed");
                        }
                        xEntry.setCertificate(signer.getCertificate());
                    }
                }
            } catch (SignerException ex) {
                throw new CaMgmtException(
                        "could not create signer for new CA " + name + ": " + ex.getMessage(), ex);
            }
        }

        queryExecutor.addCa(caEntry);
        createCa(name);
        startCa(name);
        return true;
    } // method addCa

    @Override
    public X509CaEntry getCa(
            final String name) {
        ParamUtil.requireNonBlank("name", name);
        X509CaInfo caInfo = caInfos.get(name.toUpperCase());
        return (caInfo == null)
                ? null
                : caInfo.getCaEntry();
    }

    @Override
    public boolean changeCa(
            final ChangeCaEntry entry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("entry", entry);
        asssertMasterMode();
        String name = entry.getName();

        boolean changed = queryExecutor.changeCa(entry, securityFactory);
        if (!changed) {
            LOG.info("no change of CA '{}' is processed", name);
        } else {
            createCa(name);
            startCa(name);
        }

        return changed;
    } // method changeCa

    @Override
    public boolean removeCertprofileFromCa(
            final String profileLocalname,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("profileLocalname", profileLocalname);
        String tmpCaName = ParamUtil.requireNonBlank("caName", caName).toUpperCase();
        asssertMasterMode();
        boolean b = queryExecutor.removeCertprofileFromCa(profileLocalname, tmpCaName);
        if (!b) {
            return false;
        }

        if (caHasProfiles.containsKey(tmpCaName)) {
            Map<String, String> map = caHasProfiles.get(tmpCaName);
            if (map != null) {
                map.remove(profileLocalname);
            }
        }
        return true;
    } // method removeCertprofileFromCa

    @Override
    public boolean addCertprofileToCa(
            final String profileName,
            final String profileLocalname,
            final String caName)
    throws CaMgmtException {
        String localProfileName = ParamUtil.requireNonBlank("profileName", profileName);
        String tmpCaName = ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();

        String localProfileLocalname = profileLocalname;

        if (StringUtil.isBlank(localProfileLocalname)) {
            localProfileLocalname = localProfileName;
        }
        tmpCaName = tmpCaName.toUpperCase();

        Map<String, String> map = caHasProfiles.get(tmpCaName);
        if (map == null) {
            map = new HashMap<>();
            caHasProfiles.put(tmpCaName, map);
        } else {
            if (map.containsKey(localProfileLocalname)) {
                return false;
            }
        }

        if (!certprofiles.containsKey(localProfileName)) {
            throw new CaMgmtException("certprofile '" + localProfileName + "' is faulty");
        }

        queryExecutor.addCertprofileToCa(localProfileName, localProfileLocalname, tmpCaName);
        map.put(localProfileLocalname, localProfileName);
        return true;
    } // method addCertprofileToCa

    @Override
    public boolean removePublisherFromCa(
            final String publisherName,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("publisherName", publisherName);
        String tmpCaName = ParamUtil.requireNonBlank("caName", caName).toUpperCase();
        asssertMasterMode();
        boolean b = queryExecutor.removePublisherFromCa(publisherName, tmpCaName);
        if (!b) {
            return false;
        }

        Set<String> publisherNames = caHasPublishers.get(tmpCaName);
        if (publisherNames != null) {
            publisherNames.remove(publisherName);
        }
        return true;
    } // method removePublisherFromCa

    @Override
    public boolean addPublisherToCa(
            final String publisherName,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("publisherName", publisherName);
        String tmpCaName = ParamUtil.requireNonBlank("caName", caName).toUpperCase();
        asssertMasterMode();
        Set<String> publisherNames = caHasPublishers.get(tmpCaName);
        if (publisherNames == null) {
            publisherNames = new HashSet<>();
            caHasPublishers.put(tmpCaName, publisherNames);
        } else {
            if (publisherNames.contains(publisherName)) {
                return false;
            }
        }

        IdentifiedX509CertPublisher publisher = publishers.get(publisherName);
        if (publisher == null) {
            throw new CaMgmtException("publisher '" + publisherName + "' is faulty");
        }

        queryExecutor.addPublisherToCa(publisherName, tmpCaName);
        publisherNames.add(publisherName);
        caHasPublishers.get(tmpCaName).add(publisherName);

        publisher.issuerAdded(caInfos.get(tmpCaName).getCertificate());
        return true;
    } // method addPublisherToCa

    @Override
    public Map<String, String> getCertprofilesForCa(
            final String caName) {
        ParamUtil.requireNonBlank("caName", caName);
        return caHasProfiles.get(caName.toUpperCase());
    }

    @Override
    public Set<CaHasRequestorEntry> getCmpRequestorsForCa(
            final String caName) {
        ParamUtil.requireNonBlank("caName", caName);
        return caHasRequestors.get(caName.toUpperCase());
    }

    @Override
    public CmpRequestorEntry getCmpRequestor(
            final String name) {
        ParamUtil.requireNonBlank("name", name);
        return requestorDbEntries.get(name);
    }

    public CmpRequestorEntryWrapper getCmpRequestorWrapper(
            final String name) {
        ParamUtil.requireNonBlank("name", name);
        return requestors.get(name);
    }

    @Override
    public boolean addCmpRequestor(
            final CmpRequestorEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getName();
        if (requestorDbEntries.containsKey(name)) {
            return false;
        }

        CmpRequestorEntryWrapper requestor = new CmpRequestorEntryWrapper();
        requestor.setDbEntry(dbEntry);

        queryExecutor.addCmpRequestor(dbEntry);

        requestorDbEntries.put(name, dbEntry);
        requestors.put(name, requestor);

        try {
            certstore.addRequestorName(name);
        } catch (OperationException ex) {
            final String message = "exception while publishing requestor name to certStore";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            throw new CaMgmtException(message + ": " + ex.getErrorCode() + ", " + ex.getMessage());
        }

        return true;
    } // method addCmpRequestor

    @Override
    public boolean removeCmpRequestor(
            final String requestorName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("requestorName", requestorName);
        asssertMasterMode();
        for (String caName : caHasRequestors.keySet()) {
            removeCmpRequestorFromCa(requestorName, caName);
        }

        boolean b = queryExecutor.deleteRowWithName(requestorName, "REQUESTOR");
        if (!b) {
            return false;
        }

        requestorDbEntries.remove(requestorName);
        requestors.remove(requestorName);
        LOG.info("removed requestor '{}'", requestorName);
        return true;
    } // method removeCmpRequestor

    @Override
    public boolean changeCmpRequestor(
            final String name,
            final String base64Cert)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        if (base64Cert == null) {
            return false;
        }

        CmpRequestorEntryWrapper requestor = queryExecutor.changeCmpRequestor(name, base64Cert);
        if (requestor == null) {
            return false;
        }

        requestorDbEntries.remove(name);
        requestors.remove(name);

        requestorDbEntries.put(name, requestor.getDbEntry());
        requestors.put(name, requestor);
        return true;
    } // method changeCmpRequestor

    @Override
    public boolean removeCmpRequestorFromCa(
            final String requestorName,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("requestorName", requestorName);
        String tmpCaName = ParamUtil.requireNonBlank("caName", caName).toUpperCase();
        asssertMasterMode();

        boolean b = queryExecutor.removeCmpRequestorFromCa(requestorName, tmpCaName);
        if (b && caHasRequestors.containsKey(tmpCaName)) {
            Set<CaHasRequestorEntry> entries = caHasRequestors.get(tmpCaName);
            CaHasRequestorEntry entry = null;
            for (CaHasRequestorEntry m : entries) {
                if (m.getRequestorName().equals(requestorName)) {
                    entry = m;
                }
            }
            entries.remove(entry);
        }
        return b;
    } // method removeCmpRequestorFromCa

    @Override
    public boolean addCmpRequestorToCa(
            final CaHasRequestorEntry requestor,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonNull("requestor", requestor);
        String tmpCaName = ParamUtil.requireNonBlank("caName", caName).toUpperCase();
        asssertMasterMode();
        String requestorName = requestor.getRequestorName();
        Set<CaHasRequestorEntry> cmpRequestors = caHasRequestors.get(tmpCaName);
        if (cmpRequestors == null) {
            cmpRequestors = new HashSet<>();
            caHasRequestors.put(tmpCaName, cmpRequestors);
        } else {
            boolean foundEntry = false;
            for (CaHasRequestorEntry entry : cmpRequestors) {
                if (entry.getRequestorName().equals(requestorName)) {
                    foundEntry = true;
                    break;
                }
            }

            // already added
            if (foundEntry) {
                return false;
            }
        }

        cmpRequestors.add(requestor);
        queryExecutor.addCmpRequestorToCa(requestor, tmpCaName);
        caHasRequestors.get(tmpCaName).add(requestor);
        return true;
    } // method addCmpRequestorToCa

    @Override
    public CertprofileEntry getCertprofile(
            final String profileName) {
        return certprofileDbEntries.get(profileName);
    }

    @Override
    public boolean removeCertprofile(
            final String profileName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("profileName", profileName);
        asssertMasterMode();
        for (String caName : caHasProfiles.keySet()) {
            removeCertprofileFromCa(profileName, caName);
        }

        boolean b = queryExecutor.deleteRowWithName(profileName, "PROFILE");
        if (!b) {
            return false;
        }

        LOG.info("removed profile '{}'", profileName);
        certprofileDbEntries.remove(profileName);
        IdentifiedX509Certprofile profile = certprofiles.remove(profileName);
        shutdownCertprofile(profile);
        return true;
    } // method removeCertprofile

    @Override
    public boolean changeCertprofile(
            final String name,
            final String type,
            final String conf)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        if (type == null && conf == null) {
            return false;
        }

        asssertMasterMode();
        IdentifiedX509Certprofile profile = queryExecutor.changeCertprofile(
                name, type, conf, this);
        if (profile == null) {
            return false;
        }

        certprofileDbEntries.remove(name);
        IdentifiedX509Certprofile oldProfile = certprofiles.remove(name);
        certprofileDbEntries.put(name, profile.getDbEntry());
        certprofiles.put(name, profile);

        if (oldProfile != null) {
            shutdownCertprofile(oldProfile);
        }

        return true;
    } // method changeCertprofile

    @Override
    public boolean addCertprofile(
            final CertprofileEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getName();
        if (certprofileDbEntries.containsKey(name)) {
            return false;
        }

        dbEntry.setFaulty(true);
        IdentifiedX509Certprofile profile = createCertprofile(dbEntry);
        if (profile == null) {
            return false;
        }

        dbEntry.setFaulty(false);
        certprofiles.put(name, profile);

        queryExecutor.addCertprofile(dbEntry);
        certprofileDbEntries.put(name, dbEntry);

        try {
            certstore.addCertprofileName(name);
        } catch (OperationException ex) {
            final String message = "exception while publishing certprofile name to certStore";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
        }

        return true;
    } // method addCertprofile

    @Override
    public boolean addCmpResponder(
            final CmpResponderEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getName();
        if (crlSigners.containsKey(name)) {
            return false;
        }

        CmpResponderEntryWrapper responder = createCmpResponder(dbEntry);
        queryExecutor.addCmpResponder(dbEntry);
        responders.put(name, responder);
        responderDbEntries.put(name, dbEntry);
        return true;
    } // method addCmpResponder

    @Override
    public boolean removeCmpResponder(
            final String name)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        boolean b = queryExecutor.deleteRowWithName(name, "RESPONDER");
        if (!b) {
            return false;
        }
        for (String caName : caInfos.keySet()) {
            X509CaInfo caInfo = caInfos.get(caName);
            if (name.equals(caInfo.getResponderName())) {
                caInfo.setResponderName(null);
            }
        }

        responderDbEntries.remove(name);
        responders.remove(name);
        LOG.info("removed Responder '{}'", name);
        return true;
    } // method removeCmpResponder

    @Override
    public boolean changeCmpResponder(
            final String name,
            final String type,
            final String conf,
            final String base64Cert)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        if (type == null && conf == null && base64Cert == null) {
            return false;
        }

        CmpResponderEntryWrapper newResponder = queryExecutor.changeCmpResponder(
                name, type, conf, base64Cert, this);
        if (newResponder == null) {
            return false;
        }

        responders.remove(name);
        responderDbEntries.remove(name);
        responderDbEntries.put(name, newResponder.getDbEntry());
        responders.put(name, newResponder);
        return true;
    } // method changeCmpResponder

    @Override
    public CmpResponderEntry getCmpResponder(
            final String name) {
        return responderDbEntries.get(name);
    }

    public CmpResponderEntryWrapper getCmpResponderWrapper(
            final String name) {
        return responders.get(name);
    }

    @Override
    public boolean addCrlSigner(
            final X509CrlSignerEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getName();
        if (crlSigners.containsKey(name)) {
            return false;
        }

        X509CrlSignerEntryWrapper crlSigner = createX509CrlSigner(dbEntry);
        X509CrlSignerEntry tmpDbEntry = crlSigner.getDbEntry();
        queryExecutor.addCrlSigner(tmpDbEntry);
        crlSigners.put(name, crlSigner);
        crlSignerDbEntries.put(name, tmpDbEntry);
        return true;
    } // method addCrlSigner

    @Override
    public boolean removeCrlSigner(
            final String name)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        boolean b = queryExecutor.deleteRowWithName(name, "CRLSIGNER");
        if (!b) {
            return false;
        }
        for (String caName : caInfos.keySet()) {
            X509CaInfo caInfo = caInfos.get(caName);
            if (name.equals(caInfo.getCrlSignerName())) {
                caInfo.setCrlSignerName(null);
            }
        }

        crlSigners.remove(name);
        crlSignerDbEntries.remove(name);
        LOG.info("removed CRLSigner '{}'", name);
        return true;
    } // method removeCrlSigner

    @Override
    public boolean changeCrlSigner(
            final X509ChangeCrlSignerEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();

        String name = dbEntry.getName();
        String signerType = dbEntry.getSignerType();
        String signerConf = dbEntry.getSignerConf();
        String signerCert = dbEntry.getBase64Cert();
        String crlControl = dbEntry.getCrlControl();

        X509CrlSignerEntryWrapper crlSigner = queryExecutor.changeCrlSigner(
                name, signerType, signerConf, signerCert, crlControl, this);
        if (crlSigner == null) {
            return false;
        }

        crlSigners.remove(name);
        crlSignerDbEntries.remove(name);
        crlSignerDbEntries.put(name, crlSigner.getDbEntry());
        crlSigners.put(name, crlSigner);
        return true;
    } // method changeCrlSigner

    @Override
    public X509CrlSignerEntry getCrlSigner(
            final String name) {
        ParamUtil.requireNonBlank("name", name);
        return crlSignerDbEntries.get(name);
    }

    public X509CrlSignerEntryWrapper getCrlSignerWrapper(
            final String name) {
        return crlSigners.get(name);
    }

    @Override
    public boolean addPublisher(
            final PublisherEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getName();
        if (publisherDbEntries.containsKey(name)) {
            return false;
        }

        dbEntry.setFaulty(true);
        IdentifiedX509CertPublisher publisher = createPublisher(dbEntry);
        if (publisher == null) {
            return false;
        }

        dbEntry.setFaulty(false);

        queryExecutor.addPublisher(dbEntry);
        publisherDbEntries.put(name, dbEntry);
        publishers.put(name, publisher);

        try {
            certstore.addPublisherName(name);
        } catch (OperationException ex) {
            final String message = "exception while publishing publisher nameto certStore";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
        }

        return true;
    } // method addPublisher

    @Override
    public List<PublisherEntry> getPublishersForCa(
            final String caName) {
        ParamUtil.requireNonBlank("caName", caName);
        Set<String> publisherNames = caHasPublishers.get(caName.toUpperCase());
        if (publisherNames == null) {
            return Collections.emptyList();
        }

        List<PublisherEntry> ret = new ArrayList<>(publisherNames.size());
        for (String publisherName : publisherNames) {
            ret.add(publisherDbEntries.get(publisherName));
        }

        return ret;
    } // method getPublishersForCa

    @Override
    public PublisherEntry getPublisher(
            final String name) {
        ParamUtil.requireNonBlank("name", name);
        return publisherDbEntries.get(name);
    }

    @Override
    public boolean removePublisher(
            final String name)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        for (String caName : caHasPublishers.keySet()) {
            removePublisherFromCa(name, caName);
        }

        boolean b = queryExecutor.deleteRowWithName(name, "PUBLISHER");
        if (!b) {
            return false;
        }

        LOG.info("removed publisher '{}'", name);
        publisherDbEntries.remove(name);
        IdentifiedX509CertPublisher publisher = publishers.remove(name);
        shutdownPublisher(publisher);
        return true;
    } // method removePublisher

    @Override
    public boolean changePublisher(
            final String name,
            final String type,
            final String conf)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        if (type == null && conf == null) {
            return false;
        }

        IdentifiedX509CertPublisher publisher = queryExecutor.changePublisher(name, type,
                conf, this);
        if (publisher == null) {
            return false;
        }

        IdentifiedX509CertPublisher oldPublisher = publishers.remove(name);
        if (publisher != null) {
            shutdownPublisher(oldPublisher);
        }

        publisherDbEntries.put(name, publisher.getDbEntry());
        publishers.put(name, publisher);

        return true;
    } // method changePublisher

    @Override
    public CmpControlEntry getCmpControl(
            final String name) {
        ParamUtil.requireNonBlank("name", name);
        return cmpControlDbEntries.get(name);
    }

    public CmpControl getCmpControlObject(
            final String name) {
        ParamUtil.requireNonBlank("name", name);
        return cmpControls.get(name);
    }

    @Override
    public boolean addCmpControl(
            final CmpControlEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();
        final String name = dbEntry.getName();
        if (cmpControlDbEntries.containsKey(name)) {
            return false;
        }

        CmpControl cmpControl;
        try {
            cmpControl = new CmpControl(dbEntry);
        } catch (InvalidConfException ex) {
            final String message = "exception while adding CMP requestor to certStore";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            return false;
        }

        CmpControlEntry tmpDbEntry = cmpControl.getDbEntry();

        queryExecutor.addCmpControl(tmpDbEntry);

        cmpControls.put(name, cmpControl);
        cmpControlDbEntries.put(name, tmpDbEntry);
        return true;
    } // method addCmpControl

    @Override
    public boolean removeCmpControl(
            final String name)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        boolean b = queryExecutor.deleteRowWithName(name, "CMPCONTROL");
        if (!b) {
            return false;
        }

        for (String caName : caInfos.keySet()) {
            X509CaInfo caInfo = caInfos.get(caName);
            if (name.equals(caInfo.getCmpControlName())) {
                caInfo.setCmpControlName(null);
            }
        }

        cmpControlDbEntries.remove(name);
        cmpControls.remove(name);
        LOG.info("removed CMPControl '{}'", name);
        return true;
    } // method removeCmpControl

    @Override
    public boolean changeCmpControl(
            final String name,
            final String conf)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonBlank("conf", conf);
        asssertMasterMode();

        CmpControl newCmpControl = queryExecutor.changeCmpControl(name, conf);
        if (newCmpControl == null) {
            return false;
        }

        cmpControlDbEntries.put(name, newCmpControl.getDbEntry());
        cmpControls.put(name, newCmpControl);
        return true;
    } // method changeCmpControl

    public EnvParameterResolver getEnvParameterResolver() {
        return envParameterResolver;
    }

    @Override
    public Set<String> getEnvParamNames() {
        return envParameterResolver.getAllParameterNames();
    }

    @Override
    public String getEnvParam(
            final String name) {
        ParamUtil.requireNonBlank("name", name);
        return envParameterResolver.getEnvParam(name);
    }

    @Override
    public boolean addEnvParam(
            final String name,
            final String value)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonBlank("value", value);
        asssertMasterMode();
        if (envParameterResolver.getEnvParam(name) != null) {
            return false;
        }
        queryExecutor.addEnvParam(name, value);
        envParameterResolver.addEnvParam(name, value);
        return true;
    }

    @Override
    public boolean removeEnvParam(
            final String name)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        boolean b = queryExecutor.deleteRowWithName(name, "ENVIRONMENT");
        if (!b) {
            return false;
        }

        LOG.info("removed environment param '{}'", name);
        envParameterResolver.removeEnvParam(name);
        return true;
    }

    @Override
    public boolean changeEnvParam(
            final String name,
            final String value)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonNull("value", value);
        asssertMasterMode();
        assertNotNULL("value", value);

        if (envParameterResolver.getEnvParam(name) == null) {
            throw new CaMgmtException("could not find environment paramter " + name);
        }

        boolean changed = queryExecutor.changeEnvParam(name, value);
        if (!changed) {
            return false;
        }

        envParameterResolver.addEnvParam(name, value);
        return true;
    } // method changeEnvParam

    public String getCaConfFile() {
        return caConfFile;
    }

    public void setCaConfFile(
            final String caConfFile) {
        this.caConfFile = caConfFile;
    }

    @Override
    public boolean addCaAlias(
            final String aliasName,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("aliasName", aliasName);
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();
        String tmpCaName = caName.toUpperCase();
        if (caAliases.get(aliasName) != null) {
            return false;
        }

        queryExecutor.addCaAlias(aliasName, tmpCaName);
        caAliases.put(aliasName, tmpCaName);
        return true;
    } // method addCaAlias

    @Override
    public boolean removeCaAlias(
            final String name)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        boolean b = queryExecutor.removeCaAlias(name);
        if (!b) {
            return false;
        }

        caAliases.remove(name);
        return true;
    }

    @Override
    public String getCaNameForAlias(
            final String aliasName) {
        ParamUtil.requireNonBlank("aliasName", aliasName);
        return caAliases.get(aliasName);
    }

    @Override
    public Set<String> getAliasesForCa(
            final String caName) {
        ParamUtil.requireNonBlank("caName", caName);
        String tmpCaName = caName.toUpperCase();

        Set<String> aliases = new HashSet<>();
        for (String alias : caAliases.keySet()) {
            String thisCaName = caAliases.get(alias);
            if (thisCaName.equals(tmpCaName)) {
                aliases.add(alias);
            }
        }

        return aliases;
    } // method getAliasesForCa

    @Override
    public Set<String> getCaAliasNames() {
        return caAliases.keySet();
    }

    @Override
    public boolean removeCa(
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();
        String tmpCaName = caName.toUpperCase();

        boolean b = queryExecutor.removeCa(tmpCaName);
        if (!b) {
            return false;
        }

        CaMgmtException exception = null;

        X509CaInfo caInfo = caInfos.get(tmpCaName);
        if (caInfo != null && caInfo.getCaEntry().getNextSerial() > 0) {
            // drop the serial number sequence
            final String sequenceName = caInfo.getCaEntry().getSerialSeqName();
            try {
                datasource.dropSequence(sequenceName);
            } catch (DataAccessException ex) {
                final String message = "error in dropSequence " + sequenceName;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
                if (exception == null) {
                    exception = new CaMgmtException(ex.getMessage(), ex);
                }
            }
        }

        LOG.info("removed CA '{}'", tmpCaName);
        caInfos.remove(tmpCaName);
        caHasProfiles.remove(tmpCaName);
        caHasPublishers.remove(tmpCaName);
        caHasRequestors.remove(tmpCaName);
        X509Ca ca = x509cas.remove(tmpCaName);
        x509Responders.remove(tmpCaName);
        if (ca != null) {
            ca.shutdown();
        }

        if (exception != null) {
            throw exception;
        }
        return true;
    } // method removeCa

    @Override
    public boolean publishRootCa(
            final String caName,
            final String certprofile)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonBlank("certprofile", certprofile);
        asssertMasterMode();
        String tmpCaName = caName.toUpperCase();
        X509Ca ca = x509cas.get(tmpCaName);
        if (ca == null) {
            throw new CaMgmtException("could not find CA named " + tmpCaName);
        }

        X509Cert certInfo = ca.getCaInfo().getCertificate();

        X509CertWithDbId certInfoWithId = new X509CertWithDbId(certInfo.getCert());
        if (!certInfo.getCert().getSubjectX500Principal().equals(
                certInfo.getCert().getIssuerX500Principal())) {
            throw new CaMgmtException("CA named " + tmpCaName + " is not a self-signed CA");
        }

        byte[] encodedSubjectPublicKey = certInfo.getCert().getPublicKey().getEncoded();
        X509CertificateInfo ci;
        try {
            ci = new X509CertificateInfo(
                    certInfoWithId, certInfoWithId, encodedSubjectPublicKey,
                    (certprofile == null)
                        ? "UNKNOWN"
                        : certprofile);
            ci.setReqType(RequestType.CA);
        } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
        ca.publishCertificate(ci);
        return true;
    } // method publishRootCa

    @Override
    public boolean republishCertificates(
            final String caName,
            final List<String> publisherNames)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonEmpty("publisherNames", publisherNames);
        asssertMasterMode();

        String tmpCaName = caName;
        Set<String> caNames;
        if (tmpCaName == null) {
            caNames = x509cas.keySet();
        } else {
            tmpCaName = tmpCaName.toUpperCase();
            caNames = new HashSet<>();
            caNames.add(tmpCaName);
        }

        for (String name : caNames) {
            X509Ca ca = x509cas.get(name);
            if (ca == null) {
                throw new CaMgmtException("could not find CA named " + name);
            }

            boolean successful = ca.republishCertificates(publisherNames);
            if (!successful) {
                throw new CaMgmtException("republishing certificates of CA " + name + " failed");
            }
        }

        return true;
    } // method republishCertificates

    @Override
    public boolean revokeCa(
            final String caName,
            final CertRevocationInfo revocationInfo)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("revocationInfo", revocationInfo);
        asssertMasterMode();

        String tmpCaName = caName.toUpperCase();
        if (!x509cas.containsKey(tmpCaName)) {
            return false;
        }

        LOG.info("revoking CA '{}'", tmpCaName);
        X509Ca ca = x509cas.get(tmpCaName);

        CertRevocationInfo currentRevInfo = ca.getCaInfo().getRevocationInfo();
        if (currentRevInfo != null) {
            CrlReason currentReason = currentRevInfo.getReason();
            if (currentReason != CrlReason.CERTIFICATE_HOLD) {
                throw new CaMgmtException("CA " + tmpCaName + " has been revoked with reason "
                        + currentReason.name());
            }
        }

        boolean b = queryExecutor.revokeCa(tmpCaName, revocationInfo);
        if (!b) {
            return false;
        }

        try {
            ca.revoke(revocationInfo);
        } catch (OperationException ex) {
            throw new CaMgmtException("error while revoking CA " + ex.getMessage(), ex);
        }
        LOG.info("revoked CA '{}'", tmpCaName);
        auditLogPciEvent(true, "REVOKE CA " + tmpCaName);
        return true;
    } // method revokeCa

    @Override
    public boolean unrevokeCa(
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();
        String lcoalCaName = caName.toUpperCase();
        if (!x509cas.containsKey(lcoalCaName)) {
            throw new CaMgmtException("could not find CA named " + lcoalCaName);
        }

        LOG.info("unrevoking of CA '{}'", lcoalCaName);

        boolean b = queryExecutor.unrevokeCa(lcoalCaName);
        if (!b) {
            return false;
        }

        X509Ca ca = x509cas.get(lcoalCaName);
        try {
            ca.unrevoke();
        } catch (OperationException ex) {
            throw new CaMgmtException("error while unrevoking of CA " + ex.getMessage(), ex);
        }
        LOG.info("unrevoked CA '{}'", lcoalCaName);

        auditLogPciEvent(true, "UNREVOKE CA " + lcoalCaName);
        return true;
    } // method unrevokeCa

    public void setAuditServiceRegister(
            final AuditServiceRegister serviceRegister) {
        this.auditServiceRegister = serviceRegister;

        for (String name : publishers.keySet()) {
            IdentifiedX509CertPublisher publisherEntry = publishers.get(name);
            publisherEntry.setAuditServiceRegister(auditServiceRegister);
        }

        for (String name : x509cas.keySet()) {
            X509Ca ca = x509cas.get(name);
            ca.setAuditServiceRegister(serviceRegister);
        }
    } // method setAuditServiceRegister

    private void auditLogPciEvent(
            final boolean successful,
            final String eventType) {
        AuditService auditService = (auditServiceRegister == null)
                ? null
                : auditServiceRegister.getAuditService();
        if (auditService == null) {
            return;
        }

        PciAuditEvent auditEvent = new PciAuditEvent(new Date());
        auditEvent.setUserId("CA-SYSTEM");
        auditEvent.setEventType(eventType);
        auditEvent.setAffectedResource("CORE");
        if (successful) {
            auditEvent.setStatus(AuditStatus.SUCCESSFUL.name());
            auditEvent.setLevel(AuditLevel.INFO);
        } else {
            auditEvent.setStatus(AuditStatus.FAILED.name());
            auditEvent.setLevel(AuditLevel.ERROR);
        }
        auditService.logEvent(auditEvent);
    } // method auditLogPciEvent

    @Override
    public boolean clearPublishQueue(
            final String caName,
            final List<String> publisherNames)
    throws CaMgmtException {
        asssertMasterMode();

        if (caName == null) {
            try {
                certstore.clearPublishQueue((X509CertWithDbId) null, (String) null);
                return true;
            } catch (OperationException ex) {
                throw new CaMgmtException(ex.getMessage(), ex);
            }
        }

        String tmpCaName = caName.toUpperCase();
        X509Ca ca = x509cas.get(tmpCaName);
        if (ca == null) {
            throw new CaMgmtException("could not find CA named " + tmpCaName);
        }
        return ca.clearPublishQueue(publisherNames);
    } // method clearPublishQueue

    private void shutdownScheduledThreadPoolExecutor() {
        if (scheduledThreadPoolExecutor == null) {
            return;
        }

        scheduledThreadPoolExecutor.shutdown();
        while (!scheduledThreadPoolExecutor.isTerminated()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) {
            }
        }
        scheduledThreadPoolExecutor = null;
    } // method shutdownScheduledThreadPoolExecutor

    @Override
    public boolean revokeCertificate(
            final String caName,
            final BigInteger serialNumber,
            final CrlReason reason,
            final Date invalidityTime)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("serialNumber", serialNumber);
        X509Ca ca = getX509Ca(caName);
        try {
            return ca.revokeCertificate(serialNumber, reason, invalidityTime) != null;
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method revokeCertificate

    @Override
    public boolean unrevokeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("serialNumber", serialNumber);
        X509Ca ca = getX509Ca(caName);
        try {
            return ca.unrevokeCertificate(serialNumber) != null;
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method unrevokeCertificate

    @Override
    public boolean removeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("serialNumber", serialNumber);
        asssertMasterMode();
        X509Ca ca = getX509Ca(caName);
        if (ca == null) {
            return false;
        }

        try {
            return ca.removeCertificate(serialNumber) != null;
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method removeCertificate

    @Override
    public X509Certificate generateCertificate(
            final String caName,
            final String profileName,
            final String user,
            final byte[] encodedPkcs10Request)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonBlank("profileName", profileName);
        ParamUtil.requireNonNull("encodedPkcs10Request", encodedPkcs10Request);

        X509Ca ca = getX509Ca(caName);
        CertificationRequest p10cr;
        try {
            p10cr = CertificationRequest.getInstance(encodedPkcs10Request);
        } catch (Exception ex) {
            throw new CaMgmtException("invalid PKCS#10 request. ERROR: " + ex.getMessage());
        }

        if (!securityFactory.verifyPopo(p10cr)) {
            throw new CaMgmtException("could not validate POP for the pkcs#10 requst");
        }

        CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();
        Extensions extensions = null;
        ASN1Set attrs = certTemp.getAttributes();
        for (int i = 0; i < attrs.size(); i++) {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
                extensions = Extensions.getInstance(attr.getAttributeValues()[0]);
            }
        }

        X500Name subject = certTemp.getSubject();
        SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

        CertTemplateData certTemplateData = new CertTemplateData(subject, publicKeyInfo,
                (Date) null, (Date) null, extensions, profileName);

        X509CertificateInfo certInfo;
        try {
            certInfo = ca.generateCertificate(certTemplateData, false, null, user, RequestType.CA,
                    (byte[]) null);
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }

        return certInfo.getCert().getCert();
    } // method generateCertificate

    public X509Ca getX509Ca(
            final String name)
    throws CaMgmtException {
        X509Ca ca = x509cas.get(name.toUpperCase());
        if (ca == null) {
            throw new CaMgmtException("unknown CA " + name);
        }
        return ca;
    }

    public IdentifiedX509Certprofile getIdentifiedCertprofile(
            final String profileName) {
        return certprofiles.get(profileName);
    }

    public List<IdentifiedX509CertPublisher> getIdentifiedPublishersForCa(
            final String caName) {
        ParamUtil.requireNonBlank("caName", caName);
        String tmpCaName = caName.toUpperCase();
        List<IdentifiedX509CertPublisher> ret = new LinkedList<>();
        Set<String> publisherNames = caHasPublishers.get(tmpCaName);
        if (publisherNames == null) {
            return ret;
        }

        for (String publisherName : publisherNames) {
            IdentifiedX509CertPublisher publisher = publishers.get(publisherName);
            ret.add(publisher);
        }
        return ret;
    } // method getIdentifiedPublishersForCa

    @Override
    public X509Certificate generateRootCa(
            final X509CaEntry caEntry,
            final String certprofileName,
            final byte[] p10Req)
    throws CaMgmtException {
        ParamUtil.requireNonNull("caEntry", caEntry);
        ParamUtil.requireNonBlank("certprofileName", certprofileName);
        ParamUtil.requireNonNull("p10Req", p10Req);
        String name = caEntry.getName();
        long nextSerial = caEntry.getNextSerial();
        int numCrls = caEntry.getNumCrls();
        int expirationPeriod = caEntry.getExpirationPeriod();
        int nextCrlNumber = caEntry.getNextCrlNumber();
        CaStatus status = caEntry.getStatus();
        List<String> crlUris = caEntry.getCrlUris();
        List<String> deltaCrlUris = caEntry.getDeltaCrlUris();
        List<String> ocspUris = caEntry.getOcspUris();
        List<String> cacertUris = caEntry.getCacertUris();
        String signerType = caEntry.getSignerType();
        String tSignerConf = caEntry.getSignerConf();

        asssertMasterMode();
        if (nextSerial < 0) {
            System.err.println("invalid serial number: " + nextSerial);
            return null;
        }

        if (numCrls < 0) {
            System.err.println("invalid numCrls: " + numCrls);
            return null;
        }

        if (expirationPeriod < 0) {
            System.err.println("invalid expirationPeriod: " + expirationPeriod);
            return null;
        }

        CertificationRequest p10Request;
        if (p10Req == null) {
            System.err.println("p10Req is null");
            return null;
        }

        try {
            p10Request = CertificationRequest.getInstance(p10Req);
        } catch (Exception ex) {
            System.err.println("invalid p10Req");
            return null;
        }

        IdentifiedX509Certprofile certprofile = getIdentifiedCertprofile(certprofileName);
        if (certprofile == null) {
            throw new CaMgmtException("unknown cert profile " + certprofileName);
        }

        long serialOfThisCert;
        if (nextSerial > 0) {
            serialOfThisCert = nextSerial;
            nextSerial++;
        } else {
            serialOfThisCert =
                    RandomSerialNumberGenerator.getInstance().nextSerialNumber().longValue();
        }

        GenerateSelfSignedResult result;
        try {
            result = X509SelfSignedCertBuilder.generateSelfSigned(securityFactory,
                    signerType, tSignerConf,
                    certprofile, p10Request, serialOfThisCert,
                    cacertUris, ocspUris, crlUris, deltaCrlUris);
        } catch (OperationException | InvalidConfException ex) {
            throw new CaMgmtException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }

        String signerConf = result.getSignerConf();
        X509Certificate caCert = result.getCert();

        if ("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType)) {
            try {
                signerConf = canonicalizeSignerConf(signerType, signerConf,
                        new X509Certificate[]{caCert}, securityFactory);
            } catch (Exception ex) {
                throw new CaMgmtException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
            }
        }

        X509CaUris caUris = new X509CaUris(cacertUris, ocspUris, crlUris, deltaCrlUris);

        X509CaEntry entry = new X509CaEntry(name, nextSerial, nextCrlNumber,
                signerType, signerConf,
                caUris, numCrls, expirationPeriod);
        entry.setCertificate(caCert);
        entry.setCmpControlName(caEntry.getCmpControlName());
        entry.setCrlSignerName(caEntry.getCrlSignerName());
        entry.setDuplicateKeyPermitted(caEntry.isDuplicateKeyPermitted());
        entry.setDuplicateSubjectPermitted(caEntry.isDuplicateSubjectPermitted());
        entry.setExtraControl(caEntry.getExtraControl());
        entry.setMaxValidity(caEntry.getMaxValidity());
        entry.setKeepExpiredCertInDays(caEntry.getKeepExpiredCertInDays());
        entry.setPermissions(caEntry.getPermissions());
        entry.setResponderName(caEntry.getResponderName());
        entry.setStatus(status);
        entry.setValidityMode(caEntry.getValidityMode());

        addCa(entry);
        return caCert;
    } // method generateRootCa

    private void asssertMasterMode()
    throws CaMgmtException {
        if (!masterMode) {
            throw new CaMgmtException("operation not allowed in slave mode");
        }
    }

    void shutdownCertprofile(
            final IdentifiedX509Certprofile profile) {
        if (profile == null) {
            return;
        }

        try {
            profile.shutdown();
        } catch (Exception ex) {
            final String message = "could not shutdown Certprofile " + profile.getName();
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
        }
    } // method shutdownCertprofile

    void shutdownPublisher(
            final IdentifiedX509CertPublisher publisher) {
        if (publisher == null) {
            return;
        }

        try {
            publisher.shutdown();
        } catch (Exception ex) {
            final String message = "could not shutdown CertPublisher " + publisher.getName();
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
        }
    } // method shutdownPublisher

    CmpResponderEntryWrapper createCmpResponder(
            final CmpResponderEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        CmpResponderEntryWrapper ret = new CmpResponderEntryWrapper();
        ret.setDbEntry(dbEntry);
        try {
            ret.initSigner(securityFactory);
        } catch (SignerException ex) {
            final String message = "createCmpResponder";
            LOG.debug(message, ex);
            throw new CaMgmtException(ex.getMessage());
        }
        return ret;
    } // method createCmpResponder

    X509CrlSignerEntryWrapper createX509CrlSigner(
            final X509CrlSignerEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        X509CrlSignerEntryWrapper signer = new X509CrlSignerEntryWrapper();
        try {
            signer.setDbEntry(dbEntry);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException("ConfigurationException: " + ex.getMessage());
        }
        try {
            signer.initSigner(securityFactory);
        } catch (SignerException | OperationException | InvalidConfException ex) {
            final String message = "exception while creating CRL signer " + dbEntry.getName();
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);

            if (ex instanceof OperationException) {
                throw new CaMgmtException(message + ": "
                        + ((OperationException) ex).getErrorCode() + ", " + ex.getMessage());
            } else {
                throw new CaMgmtException(message + ": " + ex.getMessage());
            }
        }

        return signer;
    } // method createX509CrlSigner

    IdentifiedX509Certprofile createCertprofile(
            final CertprofileEntry dbEntry) {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        try {
            String realType = getRealCertprofileType(dbEntry.getType());
            IdentifiedX509Certprofile ret = new IdentifiedX509Certprofile(dbEntry, realType);
            ret.setEnvParameterResolver(envParameterResolver);
            ret.validate();
            return ret;
        } catch (CertprofileException ex) {
            final String message = "could not initialize Certprofile " + dbEntry.getName()
                + ", ignore it";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            return null;
        }
    } // method createCertprofile

    IdentifiedX509CertPublisher createPublisher(
            final PublisherEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        String name = dbEntry.getName();
        String type = dbEntry.getType();

        String realType = getRealPublisherType(type);
        IdentifiedX509CertPublisher ret;
        try {
            ret = new IdentifiedX509CertPublisher(dbEntry, realType);
            ret.initialize(securityFactory.getPasswordResolver(), datasources);
            return ret;
        } catch (CertPublisherException | RuntimeException ex) {
            final String message = "invalid configuration for the certPublisher " + name;
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message),
                        ex.getClass().getName(), ex.getMessage());
            }
            LOG.debug(message, ex);
            return null;
        }
    } // method createPublisher

    private String getRealCertprofileType(
            final String certprofileType) {
        return getRealType(envParameterResolver.getParameterValue("certprofileType.map"),
                certprofileType);
    }

    private String getRealPublisherType(
            final String publisherType) {
        return getRealType(envParameterResolver.getParameterValue("publisherType.map"),
                publisherType);
    }

    @Override
    public boolean addUser(
            final AddUserEntry userEntry)
    throws CaMgmtException {
        return queryExecutor.addUser(userEntry);
    }

    @Override
    public boolean changeUser(
            final String username,
            final String password,
            final String cnRegex)
    throws CaMgmtException {
        return queryExecutor.changeUser(username, password, cnRegex);
    }

    @Override
    public boolean removeUser(
            final String username)
    throws CaMgmtException {
        return queryExecutor.removeUser(username);
    }

    @Override
    public UserEntry getUser(
            final String username)
    throws CaMgmtException {
        return queryExecutor.getUser(username);
    }

    @Override
    public X509CRL generateCrlOnDemand(
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);

        AuditEvent auditEvent = new AuditEvent(new Date());
        auditEvent.addEventData(new AuditEventData("eventType", "CAMGMT_CRL_GEN_ONDEMAND"));
        X509Ca ca = getX509Ca(caName);
        try {
            return ca.generateCrlOnDemand(auditEvent);
        } catch (OperationException ex) {
            auditEvent.setStatus(AuditStatus.FAILED);
            auditEvent.addEventData(new AuditEventData("message", ex.getErrorCode().name()));
            throw new CaMgmtException(ex.getMessage(), ex);
        } finally {
            if (auditServiceRegister != null && auditServiceRegister.getAuditService() != null) {
                auditServiceRegister.getAuditService().logEvent(auditEvent);
            }
        }
    } // method generateCrlOnDemand

    @Override
    public X509CRL getCrl(
            final String caName,
            final BigInteger crlNumber)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);

        AuditEvent auditEvent = new AuditEvent(new Date());
        auditEvent.addEventData(new AuditEventData("eventType", "CRL_DOWNLOAD_WITH_SN"));
        auditEvent.addEventData(new AuditEventData("crlNumber", crlNumber.toString()));
        X509Ca ca = getX509Ca(caName);
        try {
            CertificateList crl = ca.getCrl(crlNumber);
            if (crl == null) {
                auditEvent.addEventData(new AuditEventData("message", "found no CRL"));
                return null;
            }
            return new X509CRLObject(crl);
        } catch (OperationException ex) {
            auditEvent.setStatus(AuditStatus.FAILED);
            auditEvent.addEventData(new AuditEventData("message", ex.getErrorCode().name()));
            throw new CaMgmtException(ex.getMessage(), ex);
        } catch (CRLException ex) {
            auditEvent.setStatus(AuditStatus.FAILED);
            auditEvent.addEventData(new AuditEventData("message", "CRLException"));
            throw new CaMgmtException(ex.getMessage(), ex);
        } finally {
            if (auditServiceRegister != null && auditServiceRegister.getAuditService() != null) {
                auditServiceRegister.getAuditService().logEvent(auditEvent);
            }
        }
    } // method getCrl

    @Override
    public X509CRL getCurrentCrl(
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);

        AuditEvent auditEvent = new AuditEvent(new Date());
        auditEvent.addEventData(new AuditEventData("eventType", "CAMGMT_CRL_DOWNLOAD"));
        X509Ca ca = getX509Ca(caName);
        try {
            CertificateList crl = ca.getCurrentCrl();
            if (crl == null) {
                auditEvent.addEventData(new AuditEventData("message", "found no CRL"));
                return null;
            }
            return new X509CRLObject(crl);
        } catch (OperationException ex) {
            auditEvent.setStatus(AuditStatus.FAILED);
            auditEvent.addEventData(new AuditEventData("message", ex.getErrorCode().name()));
            throw new CaMgmtException(ex.getMessage(), ex);
        } catch (CRLException ex) {
            auditEvent.setStatus(AuditStatus.FAILED);
            auditEvent.addEventData(new AuditEventData("message", "CRLException"));
            throw new CaMgmtException(ex.getMessage(), ex);
        } finally {
            if (auditServiceRegister != null && auditServiceRegister.getAuditService() != null) {
                auditServiceRegister.getAuditService().logEvent(auditEvent);
            }
        }
    } // method getCurrentCrl

    @Override
    public boolean addScep(
            final ScepEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();

        Scep scep = new Scep(dbEntry, this);
        boolean b = queryExecutor.addScep(dbEntry);
        if (b) {
            final String caName = dbEntry.getCaName();
            scep.refreshCa();
            scepDbEntries.put(caName, dbEntry);
            sceps.put(caName, scep);
        }
        return b;
    } // method addScep

    @Override
    public boolean removeScep(
            final String name)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();

        String tmpName = name.toUpperCase();
        boolean b = queryExecutor.removeScep(tmpName);
        if (b) {
            scepDbEntries.remove(tmpName);
            sceps.remove(tmpName);
        }
        return b;
    } // method removeScep

    public boolean changeScep(
            final ChangeScepEntry scepEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("scepEntry", scepEntry);
        asssertMasterMode();

        String caName = scepEntry.getCaName();
        String type = scepEntry.getResponderType();
        String conf = scepEntry.getResponderConf();
        String base64Cert = scepEntry.getBase64Cert();
        String control = scepEntry.getControl();
        if (type == null && conf == null && base64Cert == null && control == null) {
            return false;
        }

        Scep scep = queryExecutor.changeScep(caName, type, conf, base64Cert, control, this);
        if (scep == null) {
            return false;
        }
        scep.refreshCa();

        sceps.remove(caName);
        scepDbEntries.remove(caName);
        scepDbEntries.put(caName, scep.getDbEntry());
        sceps.put(caName, scep);
        return true;
    } // method changeScep

    @Override
    public ScepEntry getScepEntry(
            final String caName) {
        return (scepDbEntries == null)
                ? null
                : scepDbEntries.get(caName.toUpperCase());
    }

    @Override
    public Scep getScep(
            final String caName) {
        return (sceps == null)
                ? null
                : sceps.get(caName.toUpperCase());
    }

    @Override
    public Set<String> getScepNames() {
        return (scepDbEntries == null)
                ? null
                : Collections.unmodifiableSet(scepDbEntries.keySet());
    }

    private static void assertNotNULL(
            final String parameterName,
            final String parameterValue) {
        if (CaManager.NULL.equalsIgnoreCase(parameterValue)) {
            throw new IllegalArgumentException(parameterName + " must not be " + CaManager.NULL);
        }
    }

    private static String canonicalizeSignerConf(
            final String keystoreType,
            final String signerConf,
            final X509Certificate[] certChain,
            final SecurityFactory securityFactory)
    throws Exception {
        if (!signerConf.contains("file:") && !signerConf.contains("base64:")) {
            return signerConf;
        }

        ConfPairs pairs = new ConfPairs(signerConf);
        String keystoreConf = pairs.getValue("keystore");
        String passwordHint = pairs.getValue("password");
        String keyLabel = pairs.getValue("key-label");

        byte[] keystoreBytes;
        if (StringUtil.startsWithIgnoreCase(keystoreConf, "file:")) {
            String keystoreFile = keystoreConf.substring("file:".length());
            keystoreBytes = IoUtil.read(keystoreFile);
        } else if (StringUtil.startsWithIgnoreCase(keystoreConf, "base64:")) {
            keystoreBytes = Base64.decode(keystoreConf.substring("base64:".length()));
        } else {
            return signerConf;
        }

        keystoreBytes = securityFactory.extractMinimalKeyStore(keystoreType,
                keystoreBytes, keyLabel,
                securityFactory.getPasswordResolver().resolvePassword(passwordHint), certChain);

        pairs.putPair("keystore", "base64:" + Base64.toBase64String(keystoreBytes));
        return pairs.getEncoded();
    } // method canonicalizeSignerConf

    private static String getRealType(
            final String typeMap,
            final String type) {
        if (typeMap == null) {
            return null;
        }

        String tmpTypeMap = typeMap.trim();
        if (StringUtil.isBlank(tmpTypeMap)) {
            return null;
        }

        ConfPairs pairs;
        try {
            pairs = new ConfPairs(tmpTypeMap);
        } catch (IllegalArgumentException ex) {
            LOG.error("CA environment {}: '{}' is not valid CMP UTF-8 pairs", tmpTypeMap, type);
            return null;
        }
        return pairs.getValue(type);
    } // method getRealType

    static List<String[]> splitCaSignerConfs(
            final String conf)
    throws SignerException {
        ConfPairs pairs = new ConfPairs(conf);
        String str = pairs.getValue("algo");
        List<String> list = StringUtil.split(str, ":");
        if (list == null) {
            throw new SignerException("no algo is defined in CA signerConf");
        }

        List<String[]> signerConfs = new ArrayList<>(list.size());
        for (String n : list) {
            String c14nAlgo;
            try {
                c14nAlgo = AlgorithmUtil.canonicalizeSignatureAlgo(n);
            } catch (NoSuchAlgorithmException ex) {
                throw new SignerException(ex.getMessage(), ex);
            }
            pairs.putPair("algo", c14nAlgo);
            signerConfs.add(new String[]{c14nAlgo, pairs.getEncoded()});
        }

        return signerConfs;
    } // method splitCaSignerConfs

}
