/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.pki.ca.server.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
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
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditService;
import org.xipki.audit.api.AuditServiceRegister;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.PCIAuditEvent;
import org.xipki.common.ConfPairs;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.password.api.PasswordResolver;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.pki.ca.api.CertPublisherException;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.api.DfltEnvParameterResolver;
import org.xipki.pki.ca.api.EnvParameterResolver;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.api.X509Cert;
import org.xipki.pki.ca.api.X509CertWithDBCertId;
import org.xipki.pki.ca.api.publisher.X509CertificateInfo;
import org.xipki.pki.ca.server.impl.X509SelfSignedCertBuilder.GenerateSelfSignedResult;
import org.xipki.pki.ca.server.impl.cmp.CmpRequestorEntryWrapper;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderEntryWrapper;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderManager;
import org.xipki.pki.ca.server.impl.cmp.X509CACmpResponder;
import org.xipki.pki.ca.server.impl.scep.Scep;
import org.xipki.pki.ca.server.impl.scep.ScepManager;
import org.xipki.pki.ca.server.impl.store.CertificateStore;
import org.xipki.pki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CAEntry;
import org.xipki.pki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CAManager;
import org.xipki.pki.ca.server.mgmt.api.CAMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CAStatus;
import org.xipki.pki.ca.server.mgmt.api.CASystemStatus;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeCAEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeScepEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControl;
import org.xipki.pki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.pki.ca.server.mgmt.api.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.UserEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.pki.ca.server.mgmt.api.X509ChangeCrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CrlSignerEntry;
import org.xipki.security.api.CRLReason;
import org.xipki.security.api.CertRevocationInfo;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.util.AlgorithmUtil;
import org.xipki.security.api.util.SecurityUtil;

/**
 * @author Lijun Liao
 */

public class CAManagerImpl
implements CAManager, CmpResponderManager, ScepManager {

    private class ScheduledPublishQueueCleaner implements Runnable {
        private boolean inProcess = false;

        @Override
        public void run() {
            if (inProcess || !caSystemSetuped) {
                return;
            }

            inProcess = true;
            try {
                LOG.debug("publishing certificates in PUBLISHQUEUE");
                for (String name : x509cas.keySet()) {
                    X509CA ca = x509cas.get(name);
                    boolean b = ca.publishCertsInQueue();
                    if (b) {
                        LOG.debug(" published certificates of CA '{}' in PUBLISHQUEUE", name);
                    } else {
                        LOG.error("publishing certificates of CA '{}' in PUBLISHQUEUE failed",
                                name);
                    }
                }
            } catch (Throwable t) {
            } finally {
                inProcess = false;
            }
        }
    }

    private class ScheduledDeleteCertsInProcessService implements Runnable {
        private boolean inProcess = false;
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
                } catch (Throwable t) {
                    final String message =
                            "could not call certstore.deleteCertsInProcessOlderThan";
                    if (LOG.isErrorEnabled()) {
                        LOG.error(LogUtil.buildExceptionLogFormat(message),
                                t.getClass().getName(), t.getMessage());
                    }
                    LOG.debug(message, t);
                }
            } finally {
                inProcess = false;
            }

        }
    }

    private class ScheduledCARestarter implements Runnable {
        private boolean inProcess = false;

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
            } catch (Throwable t) {
                LOG.error("ScheduledCArestarter: " + t.getMessage(), t);
            } finally {
                inProcess = false;
            }
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(CAManagerImpl.class);

    private static final String EVENT_LOCK = "LOCK";

    private static final String EVENT_CACHAGNE = "CA_CHANGE";

    private final String lockInstanceId;

    private Map<String, CmpResponderEntry> responderDbEntries = new ConcurrentHashMap<>();

    private Map<String, CmpResponderEntryWrapper> responders = new ConcurrentHashMap<>();

    private boolean caLockedByMe = false;

    private boolean masterMode = false;

    private Map<String, DataSourceWrapper> dataSources = null;

    private final Map<String, X509CAInfo> caInfos = new ConcurrentHashMap<>();

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

    private final Map<String, Map<String, String>> ca_has_profiles = new ConcurrentHashMap<>();

    private final Map<String, Set<String>> ca_has_publishers = new ConcurrentHashMap<>();

    private final Map<String, Set<CAHasRequestorEntry>> ca_has_requestors
            = new ConcurrentHashMap<>();

    private final Map<String, String> caAliases = new ConcurrentHashMap<>();

    private final DfltEnvParameterResolver envParameterResolver = new DfltEnvParameterResolver();

    private ScheduledThreadPoolExecutor persistentScheduledThreadPoolExecutor;

    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    private final Map<String, X509CACmpResponder> x509Responders = new ConcurrentHashMap<>();

    private final Map<String, X509CA> x509cas = new ConcurrentHashMap<>();

    private String caConfFile;

    private boolean caSystemSetuped = false;

    private boolean responderInitialized = false;

    private boolean requestorsInitialized = false;

    private boolean caAliasesInitialized = false;

    private boolean certprofilesInitialized = false;

    private boolean publishersInitialized = false;

    private boolean crlSignersInitialized = false;

    private boolean cmpControlInitialized = false;

    private boolean cAsInitialized = false;

    private boolean environmentParametersInitialized = false;

    private boolean scepsInitialized = false;

    private Date lastStartTime;

    private AuditServiceRegister auditServiceRegister;

    private DataSourceWrapper dataSource;

    private CertificateStore certstore;

    private SecurityFactory securityFactory;

    private DataSourceFactory dataSourceFactory;

    private CAManagerQueryExecutor queryExecutor;

    public CAManagerImpl()
    throws InvalidConfException {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        String calockId = null;
        File caLockFile = new File("calock");
        if (caLockFile.exists()) {
            try {
                calockId = new String(IoUtil.read(caLockFile));
            } catch (IOException e) {
            }
        }

        if (calockId == null) {
            calockId = UUID.randomUUID().toString();
            try {
                IoUtil.save(caLockFile, calockId.getBytes());
            } catch (IOException e) {
            }
        }

        String hostAddress = null;
        try {
            hostAddress = IoUtil.getHostAddress();
        } catch (SocketException e) {
        }

        this.lockInstanceId = (hostAddress == null)
                ? calockId
                : hostAddress + "/" + calockId;
    }

    public SecurityFactory getSecurityFactory() {
        return securityFactory;
    }

    public void setSecurityFactory(
            final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

    public DataSourceFactory getDataSourceFactory() {
        return dataSourceFactory;
    }

    public void setDataSourceFactory(
            final DataSourceFactory dataSourceFactory) {
        this.dataSourceFactory = dataSourceFactory;
    }

    private void init()
    throws CAMgmtException {
        if (securityFactory == null) {
            throw new IllegalStateException("securityFactory is not set");
        }
        if (dataSourceFactory == null) {
            throw new IllegalStateException("dataSourceFactory is not set");
        }
        if (caConfFile == null) {
            throw new IllegalStateException("caConfFile is not set");
        }

        Properties caConfProps = new Properties();
        try {
            caConfProps.load(new FileInputStream(IoUtil.expandFilepath(caConfFile)));
        } catch (IOException e) {
            throw new CAMgmtException("IOException while parsing ca configuration" + caConfFile, e);
        }

        String caModeStr = caConfProps.getProperty("ca.mode");
        if (caModeStr != null) {
            if (caModeStr.equalsIgnoreCase("slave")) {
                masterMode = false;
            } else if (caModeStr.equalsIgnoreCase("master")) {
                masterMode = true;
            } else {
                throw new CAMgmtException("invalid ca.mode '" + caModeStr + "'");
            }
        } else {
            masterMode = true;
        }

        if (this.dataSources == null) {
            this.dataSources = new ConcurrentHashMap<>();
            for (Object objKey : caConfProps.keySet()) {
                String key = (String) objKey;
                if (!StringUtil.startsWithIgnoreCase(key, "datasource.")) {
                    continue;
                }

                String datasourceFile = caConfProps.getProperty(key);
                try {
                    String datasourceName = key.substring("datasource.".length());
                    DataSourceWrapper datasource = dataSourceFactory.createDataSourceForFile(
                            datasourceName, datasourceFile, securityFactory.getPasswordResolver());

                    Connection conn = datasource.getConnection();
                    datasource.returnConnection(conn);

                    this.dataSources.put(datasourceName, datasource);
                } catch (DataAccessException | PasswordResolverException | IOException
                        | RuntimeException e) {
                    throw new CAMgmtException(e.getClass().getName()
                            + " while parsing datasoure " + datasourceFile, e);
                }
            }

            this.dataSource = this.dataSources.get("ca");
        }

        if (this.dataSource == null) {
            throw new CAMgmtException("no datasource configured with name 'ca'");
        }

        this.queryExecutor = new CAManagerQueryExecutor(this.dataSource);

        if (masterMode) {
            boolean lockedSuccessful;
            try {
                lockedSuccessful = lockCA(true);
            } catch (DataAccessException e) {
                throw new CAMgmtException("DataAccessException while locking CA", e);
            }

            if (!lockedSuccessful) {
                final String msg =
                    "could not lock the CA database. In general this indicates that another"
                    + " CA software in active mode is accessing the database or the last"
                    + " shutdown of CA software in active mode is abnormal.";
                throw new CAMgmtException(msg);
            }
        }

        try {
            this.certstore = new CertificateStore(dataSource);
        } catch (DataAccessException e) {
            throw new CAMgmtException(e.getMessage(), e);
        }

        initDataObjects();
    }

    @Override
    public CASystemStatus getCASystemStatus() {
        if (caSystemSetuped) {
            return masterMode
                    ? CASystemStatus.STARTED_AS_MASTER
                    : CASystemStatus.STARTED_AS_SLAVE;
        } else if (initializing) {
            return CASystemStatus.INITIALIZING;
        } else if (!caLockedByMe) {
            return CASystemStatus.LOCK_FAILED;
        } else {
            return CASystemStatus.ERROR;
        }
    }

    private boolean lockCA(
            final boolean forceRelock)
    throws DataAccessException, CAMgmtException {
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
    }

    @Override
    public boolean unlockCA() {
        if (!masterMode) {
            LOG.error("could not unlock CA in slave mode");
            return false;
        }

        caLockedByMe = false;

        boolean successful = false;
        try {
            queryExecutor.unlockCA();
            successful = true;
        } catch (DataAccessException | CAMgmtException e) {
            final String message = "error in unlockCA()";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }

        if (successful) {
            LOG.info("unlocked CA");
        } else {
            LOG.error("unlocking CA failed");
        }
        auditLogPCIEvent(successful, "UNLOCK");
        return successful;
    }

    private void reset() {
        caSystemSetuped = false;
        responderInitialized = false;
        requestorsInitialized = false;
        caAliasesInitialized = false;
        certprofilesInitialized = false;
        publishersInitialized = false;
        crlSignersInitialized = false;
        cmpControlInitialized = false;
        cAsInitialized = false;
        environmentParametersInitialized = false;
        scepsInitialized = false;

        shutdownScheduledThreadPoolExecutor();
    }

    private void initDataObjects()
    throws CAMgmtException {
        initEnvironemtParamters();
        initCaAliases();
        initCertprofiles();
        initPublishers();
        initCmpControls();
        initRequestors();
        initResponders();
        initCrlSigners();
        initCAs();
        initSceps();
        markLastSeqValues();
    }

    @Override
    public boolean restartCaSystem() {
        reset();
        boolean caSystemStarted = do_startCaSystem();

        if (!caSystemStarted) {
            String msg = "could not restart CA system";
            LOG.error(msg);
        }

        auditLogPCIEvent(caSystemStarted, "CA_CHANGE");
        return caSystemStarted;
    }

    @Override
    public boolean notifyCAChange()
    throws CAMgmtException {
        try {
            SystemEvent systemEvent = new SystemEvent(EVENT_CACHAGNE, lockInstanceId,
                    System.currentTimeMillis() / 1000L);
            queryExecutor.changeSystemEvent(systemEvent);
            LOG.info("notified the change of CA system");
            return true;
        } catch (CAMgmtException e) {
            final String message = "error while notifying Slave CAs to restart";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            return false;
        }
    }

    public void startCaSystem() {
        boolean caSystemStarted = false;
        try {
            caSystemStarted = do_startCaSystem();
        } catch (Throwable t) {
            final String message = "do_startCaSystem()";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                        t.getMessage());
            }
            LOG.debug(message, t);
            LOG.error(message);
        }

        if (!caSystemStarted) {
            String msg = "could not start CA system";
            LOG.error(msg);
        }

        auditLogPCIEvent(caSystemStarted, "START");
    }

    private boolean initializing = false;
    private boolean do_startCaSystem() {
        if (caSystemSetuped) {
            return true;
        }

        initializing = true;
        shutdownScheduledThreadPoolExecutor();

        try {
            LOG.info("starting CA system");
            try {
                init();
            } catch (Exception e) {
                final String message = "do_startCaSystem().init()";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);
                return false;
            }

            this.lastStartTime = new Date();

            x509cas.clear();
            x509Responders.clear();

            scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(10);
            scheduledThreadPoolExecutor.setRemoveOnCancelPolicy(true);

            // Add the CAs to the store
            for (String caName : caInfos.keySet()) {
                if (!startCA(caName)) {
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
    }

    private boolean startCA(
            final String caName) {
        X509CAInfo caEntry = caInfos.get(caName);
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
            } catch (SignerException | OperationException | InvalidConfException e) {
                final String message = "X09CrlSignerEntryWrapper.initSigner (name="
                        + crlSignerName + ")";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);
                return false;
            }
        }

        X509CA ca;
        try {
            ca = new X509CA(this, caEntry, certstore, securityFactory, masterMode);
            if (auditServiceRegister != null) {
                ca.setAuditServiceRegister(auditServiceRegister);
            }
        } catch (OperationException e) {
            final String message = "X509CA.<init> (ca=" + caName + ")";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            return false;
        }

        x509cas.put(caName, ca);

        X509CACmpResponder caResponder = new X509CACmpResponder(this, caName);
        x509Responders.put(caName, caResponder);

        // referesh the SCEP
        if (sceps.containsKey(caName)) {
            try {
                sceps.get(caName).refreshCA();
            } catch (CAMgmtException e) {
                final String message = "X509CA.SCEP (ca=" + caName + ")";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);
                return false;
            }
        }
        return true;
    }

    public void shutdown() {
        LOG.info("stopping CA system");
        shutdownScheduledThreadPoolExecutor();

        if (persistentScheduledThreadPoolExecutor != null) {
            persistentScheduledThreadPoolExecutor.shutdown();
            while (!persistentScheduledThreadPoolExecutor.isTerminated()) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                }
            }
            persistentScheduledThreadPoolExecutor = null;
        }

        for (String caName : x509cas.keySet()) {
            X509CA ca = x509cas.get(caName);
            try {
                ca.getCAInfo().commitNextSerial();
            } catch (Throwable t) {
                LOG.info("Exception while calling CAInfo.commitNextSerial for CA '{}': {}",
                        caName, t.getMessage());
            }
        }

        if (caLockedByMe) {
            unlockCA();
        }

        File caLockFile = new File("calock");
        if (caLockFile.exists()) {
            caLockFile.delete();
        }

        for (String dsName :dataSources.keySet()) {
            DataSourceWrapper ds = dataSources.get(dsName);
            try {
                ds.shutdown();
            } catch (Exception e) {
                final String message = "could not shutdown datasource " + dsName;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);
            }
        }

        LOG.info("stopped CA system");
        auditLogPCIEvent(true, "SHUTDOWN");
    }

    @Override
    public X509CACmpResponder getX509CACmpResponder(
            final String name) {
        ParamUtil.assertNotBlank("name", name);
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
    throws CAMgmtException {
        if (requestorsInitialized) {
            return;
        }

        requestorDbEntries.clear();
        requestors.clear();
        List<String> names = queryExecutor.getNamesFromTable("REQUESTOR");

        if (CollectionUtil.isNotEmpty(names)) {
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
        }

        requestorsInitialized = true;
    }

    private void initResponders()
    throws CAMgmtException {
        if (responderInitialized) {
            return;
        }

        responderDbEntries.clear();
        responders.clear();

        List<String> names = queryExecutor.getNamesFromTable("RESPONDER");

        if (CollectionUtil.isNotEmpty(names)) {
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
        }

        responderInitialized = true;
    }

    private void initEnvironemtParamters()
    throws CAMgmtException {
        if (environmentParametersInitialized) {
            return;
        }

        Map<String, String> map = queryExecutor.createEnvParameters();
        envParameterResolver.clear();
        for (String name : map.keySet()) {
            envParameterResolver.addEnvParam(name, map.get(name));
        }

        environmentParametersInitialized = true;
    }

    private void initCaAliases()
    throws CAMgmtException {
        if (caAliasesInitialized) {
            return;
        }

        Map<String, String> map = queryExecutor.createCaAliases();
        caAliases.clear();
        for (String aliasName : map.keySet()) {
            caAliases.put(aliasName, map.get(aliasName));
        }

        caAliasesInitialized = true;
    }

    private void initCertprofiles()
    throws CAMgmtException {
        if (certprofilesInitialized) {
            return;
        }

        for (String name : certprofiles.keySet()) {
            shutdownCertprofile(certprofiles.get(name));
        }
        certprofileDbEntries.clear();
        certprofiles.clear();

        List<String> names = queryExecutor.getNamesFromTable("PROFILE");

        if (CollectionUtil.isNotEmpty(names)) {
            for (String name : names) {
                CertprofileEntry dbEntry = queryExecutor.createCertprofile(name);
                if (dbEntry != null) {
                    dbEntry.setFaulty(true);
                    certprofileDbEntries.put(name, dbEntry);
                }

                IdentifiedX509Certprofile profile = createCertprofile(dbEntry);
                if (profile != null) {
                    dbEntry.setFaulty(false);
                    certprofiles.put(name, profile);
                }
            }
        }

        certprofilesInitialized = true;
    }

    private void initPublishers()
    throws CAMgmtException {
        if (publishersInitialized) {
            return;
        }

        for (String name : publishers.keySet()) {
            shutdownPublisher(publishers.get(name));
        }
        publishers.clear();
        publisherDbEntries.clear();

        List<String> names = queryExecutor.getNamesFromTable("PUBLISHER");

        if (CollectionUtil.isNotEmpty(names)) {
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
        }

        publishersInitialized = true;
    }

    private void initCrlSigners()
    throws CAMgmtException {
        if (crlSignersInitialized) {
            return;
        }
        crlSigners.clear();
        crlSignerDbEntries.clear();

        List<String> names = queryExecutor.getNamesFromTable("CRLSIGNER");

        if (CollectionUtil.isNotEmpty(names)) {
            for (String name : names) {
                X509CrlSignerEntry dbEntry = queryExecutor.createCrlSigner(name);
                if (dbEntry == null) {
                    continue;
                }

                crlSignerDbEntries.put(name, dbEntry);
                X509CrlSignerEntryWrapper crlSigner = createX509CrlSigner(dbEntry);
                crlSigners.put(name, crlSigner);
            }
        }

        crlSignersInitialized = true;
    }

    private void initCmpControls()
    throws CAMgmtException {
        if (cmpControlInitialized) {
            return;
        }

        cmpControls.clear();
        cmpControlDbEntries.clear();

        List<String> names = queryExecutor.getNamesFromTable("CMPCONTROL");

        if (CollectionUtil.isNotEmpty(names)) {
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
                } catch (InvalidConfException e) {
                    final String message = "could not initialize CMP control " + name
                            + ", ignore it";
                    if (LOG.isErrorEnabled()) {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                                e.getMessage());
                    }
                    LOG.debug(message, e);
                }
            }
        }

        cmpControlInitialized = true;
    }

    private void initSceps()
    throws CAMgmtException {
        if (scepsInitialized) {
            return;
        }

        sceps.clear();
        scepDbEntries.clear();

        List<String> names = queryExecutor.getNamesFromTable("SCEP", "CA_NAME");

        if (CollectionUtil.isNotEmpty(names)) {
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
                } catch (CAMgmtException e) {
                    final String message = "could not initialize SCEP entry " + name
                            + ", ignore it";
                    if (LOG.isErrorEnabled()) {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                                e.getMessage());
                    }
                    LOG.debug(message, e);
                }
            }
        }

        scepsInitialized = true;
    }

    private void initCAs()
    throws CAMgmtException {
        if (cAsInitialized) {
            return;
        }

        caInfos.clear();
        ca_has_requestors.clear();
        ca_has_publishers.clear();
        ca_has_profiles.clear();

        List<String> names = queryExecutor.getNamesFromTable("CA");
        if (CollectionUtil.isNotEmpty(names)) {
            for (String name : names) {
                createCA(name);
            }
        }

        cAsInitialized = true;
    }

    private boolean createCA(
            final String name)
    throws CAMgmtException {
        caInfos.remove(name);
        ca_has_profiles.remove(name);
        ca_has_publishers.remove(name);
        ca_has_requestors.remove(name);
        X509CA oldCa = x509cas.remove(name);
        x509Responders.remove(name);
        if (oldCa != null) {
            oldCa.shutdown();
        }

        X509CAInfo ca = queryExecutor.createCAInfo(name, masterMode, certstore);
        try {
            ca.markMaxSerial();
        } catch (OperationException e) {
            throw new CAMgmtException(e.getMessage(), e);
        }
        caInfos.put(name, ca);

        Set<CAHasRequestorEntry> caHasRequestors = queryExecutor.createCAhasRequestors(name);
        ca_has_requestors.put(name, caHasRequestors);

        Map<String, String> profileNames = queryExecutor.createCAhasProfiles(name);
        ca_has_profiles.put(name, profileNames);

        Set<String> publisherNames = queryExecutor.createCAhasPublishers(name);
        ca_has_publishers.put(name, publisherNames);

        return true;
    }

    private void markLastSeqValues()
    throws CAMgmtException {
        try {
            // sequence DCC_ID
            long maxId = dataSource.getMax(null, "DELTACRL_CACHE", "ID");
            dataSource.setLastUsedSeqValue("DCC_ID", maxId);

            // sequence CID
            maxId = dataSource.getMax(null, "CERT", "ID");
            dataSource.setLastUsedSeqValue("CID", maxId);
        } catch (DataAccessException e) {
            throw new CAMgmtException(e.getMessage(), e);
        }
    }

    @Override
    public boolean addCA(
            final CAEntry caEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("caEntry", caEntry);
        asssertMasterMode();
        String name = caEntry.getName();

        if (caInfos.containsKey(name)) {
            throw new CAMgmtException("CA named " + name + " exists");
        }

        if (caEntry instanceof X509CAEntry) {
            X509CAEntry xEntry = (X509CAEntry) caEntry;

            ConcurrentContentSigner signer;
            try {
                List<String[]> signerConfs = splitCASignerConfs(xEntry.getSignerConf());
                for (String[] m : signerConfs) {
                    String signerConf = m[1];
                    signer = securityFactory.createSigner(
                            xEntry.getSignerType(), signerConf, xEntry.getCertificate());
                    if (xEntry.getCertificate() == null) {
                        xEntry.setCertificate(signer.getCertificate());
                    }
                }
            } catch (SignerException e) {
                throw new CAMgmtException(
                        "could not create signer for new CA " + name + ": " + e.getMessage(), e);
            }
        }

        queryExecutor.addCA(caEntry);
        createCA(name);
        startCA(name);
        return true;
    }

    @Override
    public X509CAEntry getCA(
            final String name) {
        ParamUtil.assertNotBlank("name", name);
        X509CAInfo caInfo = caInfos.get(name.toUpperCase());
        return (caInfo == null)
                ? null
                : caInfo.getCaEntry();
    }

    @Override
    public boolean changeCA(
            final ChangeCAEntry entry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("entry", entry);
        asssertMasterMode();
        String name = entry.getName();

        boolean changed = queryExecutor.changeCA(entry, securityFactory);
        if (!changed) {
            LOG.info("no change of CA '{}' is processed", name);
        } else {
            createCA(name);
            startCA(name);
        }

        return changed;
    }

    @Override
    public boolean removeCertprofileFromCA(
            final String profileLocalname,
            String caName)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("profileLocalname", profileLocalname);
        ParamUtil.assertNotBlank("caName", caName);
        asssertMasterMode();
        caName = caName.toUpperCase();
        boolean b = queryExecutor.removeCertprofileFromCA(profileLocalname, caName);
        if (!b) {
            return false;
        }

        if (ca_has_profiles.containsKey(caName)) {
            Map<String, String> map = ca_has_profiles.get(caName);
            if (map != null) {
                map.remove(profileLocalname);
            }
        }
        return true;
    }

    @Override
    public boolean addCertprofileToCA(
            final String profileName,
            String profileLocalname,
            String caName)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("profileName", profileName);
        ParamUtil.assertNotBlank("caName", caName);
        asssertMasterMode();
        if (StringUtil.isBlank(profileLocalname)) {
            profileLocalname = profileName;
        }
        caName = caName.toUpperCase();

        Map<String, String> map = ca_has_profiles.get(caName);
        if (map == null) {
            map = new HashMap<>();
            ca_has_profiles.put(caName, map);
        } else {
            if (map.containsKey(profileLocalname)) {
                return false;
            }
        }

        if (!certprofiles.containsKey(profileName)) {
            throw new CAMgmtException("certprofile '" + profileName + "' is faulty");
        }

        queryExecutor.addCertprofileToCA(profileName, profileLocalname, caName);
        map.put(profileLocalname, profileName);
        return true;
    }

    @Override
    public boolean removePublisherFromCA(
            final String publisherName,
            String caName)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("publisherName", publisherName);
        ParamUtil.assertNotBlank("caName", caName);
        asssertMasterMode();
        caName = caName.toUpperCase();
        boolean b = queryExecutor.removePublisherFromCA(publisherName, caName);
        if (!b) {
            return false;
        }

        Set<String> publisherNames = ca_has_publishers.get(caName);
        if (publisherNames != null) {
            publisherNames.remove(publisherName);
        }
        return true;
    }

    @Override
    public boolean addPublisherToCA(
            final String publisherName,
            String caName)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("publisherName", publisherName);
        ParamUtil.assertNotBlank("caName", caName);
        asssertMasterMode();
        caName = caName.toUpperCase();
        Set<String> publisherNames = ca_has_publishers.get(caName);
        if (publisherNames == null) {
            publisherNames = new HashSet<>();
            ca_has_publishers.put(caName, publisherNames);
        } else {
            if (publisherNames.contains(publisherName)) {
                return false;
            }
        }

        IdentifiedX509CertPublisher publisher = publishers.get(publisherName);
        if (publisher == null) {
            throw new CAMgmtException("publisher '" + publisherName + "' is faulty");
        }

        queryExecutor.addPublisherToCA(publisherName, caName);
        publisherNames.add(publisherName);
        ca_has_publishers.get(caName).add(publisherName);

        publisher.issuerAdded(caInfos.get(caName).getCertificate());
        return true;
    }

    @Override
    public Map<String, String> getCertprofilesForCA(
            final String caName) {
        ParamUtil.assertNotBlank("caName", caName);
        return ca_has_profiles.get(caName.toUpperCase());
    }

    @Override
    public Set<CAHasRequestorEntry> getCmpRequestorsForCA(
            final String caName) {
        ParamUtil.assertNotBlank("caName", caName);
        return ca_has_requestors.get(caName.toUpperCase());
    }

    @Override
    public CmpRequestorEntry getCmpRequestor(
            final String name) {
        ParamUtil.assertNotBlank("name", name);
        return requestorDbEntries.get(name);
    }

    public CmpRequestorEntryWrapper getCmpRequestorWrapper(
            final String name) {
        ParamUtil.assertNotBlank("name", name);
        return requestors.get(name);
    }

    @Override
    public boolean addCmpRequestor(
            final CmpRequestorEntry dbEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
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
        } catch (OperationException e) {
            final String message = "exception while publishing requestor name to certStore";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            throw new CAMgmtException(message + ": " + e.getErrorCode() + ", " + e.getMessage());
        }

        return true;
    }

    @Override
    public boolean removeCmpRequestor(
            final String requestorName)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("requestorName", requestorName);
        asssertMasterMode();
        for (String caName : ca_has_requestors.keySet()) {
            removeCmpRequestorFromCA(requestorName, caName);
        }

        boolean b = queryExecutor.deleteRowWithName(requestorName, "REQUESTOR");
        if (!b) {
            return false;
        }

        requestorDbEntries.remove(requestorName);
        requestors.remove(requestorName);
        LOG.info("removed requestor '{}'", requestorName);
        return true;
    }

    @Override
    public boolean changeCmpRequestor(
            final String name,
            final String base64Cert)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
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
    }

    @Override
    public boolean removeCmpRequestorFromCA(
            final String requestorName,
            String caName)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("requestorName", requestorName);
        ParamUtil.assertNotBlank("caName", caName);
        asssertMasterMode();
        caName = caName.toUpperCase();
        boolean b = queryExecutor.removeCmpRequestorFromCA(requestorName, caName);
        if (b && ca_has_requestors.containsKey(caName)) {
            Set<CAHasRequestorEntry> entries = ca_has_requestors.get(caName);
            CAHasRequestorEntry entry = null;
            for (CAHasRequestorEntry m : entries) {
                if (m.getRequestorName().equals(requestorName)) {
                    entry = m;
                }
            }
            entries.remove(entry);
        }
        return b;
    }

    @Override
    public boolean addCmpRequestorToCA(
            final CAHasRequestorEntry requestor,
            String caName)
    throws CAMgmtException {
        ParamUtil.assertNotNull("requestor", requestor);
        ParamUtil.assertNotBlank("caName", caName);
        asssertMasterMode();
        caName = caName.toUpperCase();
        String requestorName = requestor.getRequestorName();
        Set<CAHasRequestorEntry> cmpRequestors = ca_has_requestors.get(caName);
        if (cmpRequestors == null) {
            cmpRequestors = new HashSet<>();
            ca_has_requestors.put(caName, cmpRequestors);
        } else {
            boolean foundEntry = false;
            for (CAHasRequestorEntry entry : cmpRequestors) {
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
        queryExecutor.addCmpRequestorToCA(requestor, caName);
        ca_has_requestors.get(caName).add(requestor);
        return true;
    }

    @Override
    public CertprofileEntry getCertprofile(
            final String profileName) {
        return certprofileDbEntries.get(profileName);
    }

    @Override
    public boolean removeCertprofile(
            final String profileName)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("profileName", profileName);
        asssertMasterMode();
        for (String caName : ca_has_profiles.keySet()) {
            removeCertprofileFromCA(profileName, caName);
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
    }

    @Override
    public boolean changeCertprofile(
            final String name,
            final String type,
            final String conf)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
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
    }

    @Override
    public boolean addCertprofile(
            final CertprofileEntry dbEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
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
        } catch (OperationException e) {
            final String message = "exception while publishing certprofile name to certStore";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }

        return true;
    }

    @Override
    public boolean addCmpResponder(
            final CmpResponderEntry dbEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getName();
        if (crlSigners.containsKey(name)) {
            return false;
        }

        CmpResponderEntryWrapper _responder = createCmpResponder(dbEntry);
        queryExecutor.addCmpResponder(dbEntry);
        responders.put(name, _responder);
        responderDbEntries.put(name, dbEntry);
        return true;
    }

    @Override
    public boolean removeCmpResponder(
            final String name)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
        asssertMasterMode();
        boolean b = queryExecutor.deleteRowWithName(name, "RESPONDER");
        if (!b) {
            return false;
        }
        for (String caName : caInfos.keySet()) {
            X509CAInfo caInfo = caInfos.get(caName);
            if (name.equals(caInfo.getResponderName())) {
                caInfo.setResponderName(null);
            }
        }

        responderDbEntries.remove(name);
        responders.remove(name);
        LOG.info("removed Responder '{}'", name);
        return true;
    }

    @Override
    public boolean changeCmpResponder(
            final String name,
            final String type,
            final String conf,
            final String base64Cert)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
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
    }

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
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getName();
        if (crlSigners.containsKey(name)) {
            return false;
        }

        X509CrlSignerEntryWrapper crlSigner = createX509CrlSigner(dbEntry);
        X509CrlSignerEntry _dbEntry = crlSigner.getDbEntry();
        queryExecutor.addCrlSigner(_dbEntry);
        crlSigners.put(name, crlSigner);
        crlSignerDbEntries.put(name, _dbEntry);
        return true;
    }

    @Override
    public boolean removeCrlSigner(
            final String name)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
        asssertMasterMode();
        boolean b = queryExecutor.deleteRowWithName(name, "CRLSIGNER");
        if (!b) {
            return false;
        }
        for (String caName : caInfos.keySet()) {
            X509CAInfo caInfo = caInfos.get(caName);
            if (name.equals(caInfo.getCrlSignerName())) {
                caInfo.setCrlSignerName(null);
            }
        }

        crlSigners.remove(name);
        crlSignerDbEntries.remove(name);
        LOG.info("removed CRLSigner '{}'", name);
        return true;
    }

    @Override
    public boolean changeCrlSigner(
            final X509ChangeCrlSignerEntry dbEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
        asssertMasterMode();

        String name = dbEntry.getName();
        String signer_type = dbEntry.getSignerType();
        String signer_conf = dbEntry.getSignerConf();
        String signer_cert = dbEntry.getBase64Cert();
        String crlControl = dbEntry.getCrlControl();

        X509CrlSignerEntryWrapper crlSigner = queryExecutor.changeCrlSigner(
                name, signer_type, signer_conf, signer_cert, crlControl, this);
        if (crlSigner == null) {
            return false;
        }

        crlSigners.remove(name);
        crlSignerDbEntries.remove(name);
        crlSignerDbEntries.put(name, crlSigner.getDbEntry());
        crlSigners.put(name, crlSigner);
        return true;
    }

    @Override
    public X509CrlSignerEntry getCrlSigner(
            final String name) {
        ParamUtil.assertNotBlank("name", name);
        return crlSignerDbEntries.get(name);
    }

    public X509CrlSignerEntryWrapper getCrlSignerWrapper(
            final String name) {
        return crlSigners.get(name);
    }

    @Override
    public boolean addPublisher(
            final PublisherEntry dbEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
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
        } catch (OperationException e) {
            final String message = "exception while publishing publisher nameto certStore";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }

        return true;
    }

    @Override
    public List<PublisherEntry> getPublishersForCA(
            final String caName) {
        ParamUtil.assertNotBlank("caName", caName);
        Set<String> publisherNames = ca_has_publishers.get(caName.toUpperCase());
        if (publisherNames == null) {
            return Collections.emptyList();
        }

        List<PublisherEntry> ret = new ArrayList<>(publisherNames.size());
        for (String publisherName : publisherNames) {
            ret.add(publisherDbEntries.get(publisherName));
        }

        return ret;
    }

    @Override
    public PublisherEntry getPublisher(
            final String name) {
        ParamUtil.assertNotBlank("name", name);
        return publisherDbEntries.get(name);
    }

    @Override
    public boolean removePublisher(
            final String name)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
        asssertMasterMode();
        for (String caName : ca_has_publishers.keySet()) {
            removePublisherFromCA(name, caName);
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
    }

    @Override
    public boolean changePublisher(
            final String name,
            final String type,
            final String conf)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
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
    }

    @Override
    public CmpControlEntry getCmpControl(
            final String name) {
        ParamUtil.assertNotBlank("name", name);
        return cmpControlDbEntries.get(name);
    }

    public CmpControl getCmpControlObject(
            final String name) {
        ParamUtil.assertNotBlank("name", name);
        return cmpControls.get(name);
    }

    @Override
    public boolean addCmpControl(
            final CmpControlEntry dbEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
        asssertMasterMode();
        final String name = dbEntry.getName();
        if (cmpControlDbEntries.containsKey(name)) {
            return false;
        }

        CmpControl cmpControl;
        try {
            cmpControl = new CmpControl(dbEntry);
        } catch (InvalidConfException e) {
            final String message = "exception while adding CMP requestor to certStore";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            return false;
        }

        CmpControlEntry _dbEntry = cmpControl.getDbEntry();

        queryExecutor.addCmpControl(_dbEntry);

        cmpControls.put(name, cmpControl);
        cmpControlDbEntries.put(name, _dbEntry);
        return true;
    }

    @Override
    public boolean removeCmpControl(
            final String name)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
        asssertMasterMode();
        boolean b = queryExecutor.deleteRowWithName(name, "CMPCONTROL");
        if (!b) {
            return false;
        }

        for (String caName : caInfos.keySet()) {
            X509CAInfo caInfo = caInfos.get(caName);
            if (name.equals(caInfo.getCmpControlName())) {
                caInfo.setCmpControlName(null);
            }
        }

        cmpControlDbEntries.remove(name);
        cmpControls.remove(name);
        LOG.info("removed CMPControl '{}'", name);
        return true;
    }

    @Override
    public boolean changeCmpControl(
            final String name,
            final String conf)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
        ParamUtil.assertNotBlank("conf", conf);
        asssertMasterMode();

        CmpControl newCmpControl = queryExecutor.changeCmpControl(name, conf);
        if (newCmpControl == null) {
            return false;
        }

        cmpControlDbEntries.put(name, newCmpControl.getDbEntry());
        cmpControls.put(name, newCmpControl);
        return true;
    }

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
        ParamUtil.assertNotBlank("name", name);
        return envParameterResolver.getEnvParam(name);
    }

    @Override
    public boolean addEnvParam(
            final String name,
            final String value)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
        ParamUtil.assertNotBlank("value", value);
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
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
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
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
        ParamUtil.assertNotNull("value", value);
        asssertMasterMode();
        assertNotNULL("value", value);

        if (envParameterResolver.getEnvParam(name) == null) {
            throw new CAMgmtException("could not find environment paramter " + name);
        }

        boolean changed = queryExecutor.changeEnvParam(name, value);
        if (!changed) {
            return false;
        }

        envParameterResolver.addEnvParam(name, value);
        return true;
    }

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
            String caName)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("aliasName", aliasName);
        ParamUtil.assertNotBlank("caName", caName);
        asssertMasterMode();
        caName = caName.toUpperCase();
        if (caAliases.get(aliasName) != null) {
            return false;
        }

        queryExecutor.addCaAlias(aliasName, caName);
        caAliases.put(aliasName, caName);
        return true;
    }

    @Override
    public boolean removeCaAlias(
            final String name)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
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
        ParamUtil.assertNotBlank("aliasName", aliasName);
        return caAliases.get(aliasName);
    }

    @Override
    public Set<String> getAliasesForCA(
            String caName) {
        ParamUtil.assertNotBlank("caName", caName);
        caName = caName.toUpperCase();

        Set<String> aliases = new HashSet<>();
        for (String alias : caAliases.keySet()) {
            String thisCaName = caAliases.get(alias);
            if (thisCaName.equals(caName)) {
                aliases.add(alias);
            }
        }

        return aliases;
    }

    @Override
    public Set<String> getCaAliasNames() {
        return caAliases.keySet();
    }

    @Override
    public boolean removeCA(
            String name)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
        asssertMasterMode();
        name = name.toUpperCase();

        boolean b = queryExecutor.removeCA(name);
        if (!b) {
            return false;
        }

        CAMgmtException exception = null;

        X509CAInfo caInfo = caInfos.get(name);
        if (caInfo != null && caInfo.getCaEntry().getNextSerial() > 0) {
            // drop the serial number sequence
            final String sequenceName = caInfo.getCaEntry().getSerialSeqName();
            try {
                dataSource.dropSequence(sequenceName);
            } catch (DataAccessException e) {
                final String message = "error in dropSequence " + sequenceName;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);
                if (exception == null) {
                    exception = new CAMgmtException(e.getMessage(), e);
                }
            }
        }

        LOG.info("removed CA '{}'", name);
        caInfos.remove(name);
        ca_has_profiles.remove(name);
        ca_has_publishers.remove(name);
        ca_has_requestors.remove(name);
        X509CA ca = x509cas.remove(name);
        x509Responders.remove(name);
        if (ca != null) {
            ca.shutdown();
        }

        if (exception != null) {
            throw exception;
        }
        return true;
    }

    @Override
    public boolean publishRootCA(
            String caName,
            final String certprofile)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("caName", caName);
        ParamUtil.assertNotBlank("certprofile", certprofile);
        asssertMasterMode();
        caName = caName.toUpperCase();
        X509CA ca = x509cas.get(caName);
        if (ca == null) {
            throw new CAMgmtException("could not find CA named " + caName);
        }

        X509Cert certInfo = ca.getCAInfo().getCertificate();

        X509CertWithDBCertId certInfoWithId = new X509CertWithDBCertId(certInfo.getCert());
        if (!certInfo.getCert().getSubjectX500Principal().equals(
                certInfo.getCert().getIssuerX500Principal())) {
            throw new CAMgmtException("CA named " + caName + " is not a self-signed CA");
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
        } catch (CertificateEncodingException e) {
            throw new CAMgmtException(e.getMessage(), e);
        }
        ca.publishCertificate(ci);
        return true;
    }

    @Override
    public boolean republishCertificates(
            String caName,
            final List<String> publisherNames)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("caName", caName);
        ParamUtil.assertNotEmpty("publisherNames", publisherNames);
        asssertMasterMode();

        Set<String> caNames;
        if (caName == null) {
            caNames = x509cas.keySet();
        } else {
            caName = caName.toUpperCase();
            caNames = new HashSet<>();
            caNames.add(caName);
        }

        for (String name : caNames) {
            X509CA ca = x509cas.get(name);
            if (ca == null) {
                throw new CAMgmtException("could not find CA named " + name);
            }

            boolean successful = ca.republishCertificates(publisherNames);
            if (!successful) {
                throw new CAMgmtException("republishing certificates of CA " + name + " failed");
            }
        }

        return true;
    }

    @Override
    public boolean revokeCa(
            String name,
            final CertRevocationInfo revocationInfo)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("caName", name);
        ParamUtil.assertNotNull("revocationInfo", revocationInfo);
        asssertMasterMode();
        ParamUtil.assertNotBlank("caName", name);
        ParamUtil.assertNotNull("revocationInfo", revocationInfo);

        name = name.toUpperCase();
        if (!x509cas.containsKey(name)) {
            return false;
        }

        LOG.info("revoking CA '{}'", name);
        X509CA ca = x509cas.get(name);

        CertRevocationInfo currentRevInfo = ca.getCAInfo().getRevocationInfo();
        if (currentRevInfo != null) {
            CRLReason currentReason = currentRevInfo.getReason();
            if (currentReason != CRLReason.CERTIFICATE_HOLD) {
                throw new CAMgmtException("CA " + name + " has been revoked with reason "
                        + currentReason.name());
            }
        }

        boolean b = queryExecutor.revokeCa(name, revocationInfo);
        if (!b) {
            return false;
        }

        try {
            ca.revoke(revocationInfo);
        } catch (OperationException e) {
            throw new CAMgmtException("error while revoking CA " + e.getMessage(), e);
        }
        LOG.info("revoked CA '{}'", name);
        auditLogPCIEvent(true, "REVOKE CA " + name);
        return true;
    }

    @Override
    public boolean unrevokeCa(
            String name)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("caName", name);
        asssertMasterMode();
        name = name.toUpperCase();
        if (!x509cas.containsKey(name)) {
            throw new CAMgmtException("could not find CA named " + name);
        }

        LOG.info("unrevoking of CA '{}'", name);

        boolean b = queryExecutor.unrevokeCa(name);
        if (!b) {
            return false;
        }

        X509CA ca = x509cas.get(name);
        try {
            ca.unrevoke();
        } catch (OperationException e) {
            throw new CAMgmtException("error while unrevoking of CA " + e.getMessage(), e);
        }
        LOG.info("unrevoked CA '{}'", name);

        auditLogPCIEvent(true, "UNREVOKE CA " + name);
        return true;
    }

    public void setAuditServiceRegister(
            final AuditServiceRegister serviceRegister) {
        this.auditServiceRegister = serviceRegister;

        for (String name : publishers.keySet()) {
            IdentifiedX509CertPublisher publisherEntry = publishers.get(name);
            publisherEntry.setAuditServiceRegister(auditServiceRegister);
        }

        for (String name : x509cas.keySet()) {
            X509CA ca = x509cas.get(name);
            ca.setAuditServiceRegister(serviceRegister);
        }
    }

    private void auditLogPCIEvent(
            final boolean successful,
            final String eventType) {
        AuditService auditService = (auditServiceRegister == null)
                ? null
                : auditServiceRegister.getAuditService();
        if (auditService == null) {
            return;
        }

        PCIAuditEvent auditEvent = new PCIAuditEvent(new Date());
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
    }

    @Override
    public boolean clearPublishQueue(
            String caName,
            final List<String> publisherNames)
    throws CAMgmtException {
        asssertMasterMode();

        if (caName == null) {
            try {
                certstore.clearPublishQueue((X509CertWithDBCertId) null, (String) null);
                return true;
            } catch (OperationException e) {
                throw new CAMgmtException(e.getMessage(), e);
            }
        }

        caName = caName.toUpperCase();
        X509CA ca = x509cas.get(caName);
        if (ca == null) {
            throw new CAMgmtException("could not find CA named " + caName);
        }
        return ca.clearPublishQueue(publisherNames);
    }

    private void shutdownScheduledThreadPoolExecutor() {
        if (scheduledThreadPoolExecutor == null) {
            return;
        }

        scheduledThreadPoolExecutor.shutdown();
        while (!scheduledThreadPoolExecutor.isTerminated()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
            }
        }
        scheduledThreadPoolExecutor = null;
    }

    @Override
    public boolean revokeCertificate(
            final String caName,
            final BigInteger serialNumber,
            final CRLReason reason,
            final Date invalidityTime)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("caName", caName);
        ParamUtil.assertNotNull("serialNumber", serialNumber);
        X509CA ca = getX509CA(caName);
        try {
            return ca.revokeCertificate(serialNumber, reason, invalidityTime) != null;
        } catch (OperationException e) {
            throw new CAMgmtException(e.getMessage(), e);
        }
    }

    @Override
    public boolean unrevokeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("caName", caName);
        ParamUtil.assertNotNull("serialNumber", serialNumber);
        X509CA ca = getX509CA(caName);
        try {
            return ca.unrevokeCertificate(serialNumber) != null;
        } catch (OperationException e) {
            throw new CAMgmtException(e.getMessage(), e);
        }
    }

    @Override
    public boolean removeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("caName", caName);
        ParamUtil.assertNotNull("serialNumber", serialNumber);
        asssertMasterMode();
        X509CA ca = getX509CA(caName);
        if (ca == null) {
            return false;
        }

        try {
            return ca.removeCertificate(serialNumber) != null;
        } catch (OperationException e) {
            throw new CAMgmtException(e.getMessage(), e);
        }
    }

    @Override
    public X509Certificate generateCertificate(
            final String caName,
            final String profileName,
            final String user,
            final byte[] encodedPkcs10Request)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("caName", caName);
        ParamUtil.assertNotBlank("profileName", profileName);
        ParamUtil.assertNotNull("encodedPkcs10Request", encodedPkcs10Request);

        X509CA ca = getX509CA(caName);
        CertificationRequest p10cr;
        try {
            p10cr = CertificationRequest.getInstance(encodedPkcs10Request);
        } catch (Exception e) {
            throw new CAMgmtException("invalid PKCS#10 request. ERROR: " + e.getMessage());
        }

        if (!securityFactory.verifyPOPO(p10cr)) {
            throw new CAMgmtException("could not validate POP for the pkcs#10 requst");
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

        X509CertificateInfo certInfo;
        try {
            certInfo = ca.generateCertificate(false, null, profileName, user, subject,
                    publicKeyInfo, extensions, RequestType.CA, null);
        } catch (OperationException e) {
            throw new CAMgmtException(e.getMessage(), e);
        }

        return certInfo.getCert().getCert();
    }

    public X509CA getX509CA(
            final String name)
    throws CAMgmtException {
        X509CA ca = x509cas.get(name.toUpperCase());
        if (ca == null) {
            throw new CAMgmtException("unknown CA " + name);
        }
        return ca;
    }

    public IdentifiedX509Certprofile getIdentifiedCertprofile(
            final String profileName) {
        return certprofiles.get(profileName);
    }

    public List<IdentifiedX509CertPublisher> getIdentifiedPublishersForCa(
            String caName) {
        ParamUtil.assertNotBlank("caName", caName);
        caName = caName.toUpperCase();
        List<IdentifiedX509CertPublisher> ret = new LinkedList<>();
        Set<String> publisherNames = ca_has_publishers.get(caName);
        if (publisherNames == null) {
            return ret;
        }

        for (String publisherName : publisherNames) {
            IdentifiedX509CertPublisher publisher = publishers.get(publisherName);
            ret.add(publisher);
        }
        return ret;
    }

    @Override
    public X509Certificate generateRootCA(
            final X509CAEntry caEntry,
            final String certprofileName,
            final byte[] p10Req)
    throws CAMgmtException {
        ParamUtil.assertNotNull("caEntry", caEntry);
        ParamUtil.assertNotBlank("certprofileName", certprofileName);
        ParamUtil.assertNotNull("p10Req", p10Req);
        String name = caEntry.getName();
        long nextSerial = caEntry.getNextSerial();
        int numCrls = caEntry.getNumCrls();
        int expirationPeriod = caEntry.getExpirationPeriod();
        int nextCrlNumber = caEntry.getNextCRLNumber();
        CAStatus status = caEntry.getStatus();
        List<String> crl_uris = caEntry.getCrlUris();
        List<String> delta_crl_uris = caEntry.getDeltaCrlUris();
        List<String> ocsp_uris = caEntry.getOcspUris();
        List<String> cacert_uris = caEntry.getCacertUris();
        String signer_type = caEntry.getSignerType();
        String signer_conf = caEntry.getSignerConf();

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
        } catch (Exception e) {
            System.err.println("invalid p10Req");
            return null;
        }

        IdentifiedX509Certprofile certprofile = getIdentifiedCertprofile(certprofileName);
        if (certprofile == null) {
            throw new CAMgmtException("unknown cert profile " + certprofileName);
        }

        long serialOfThisCert;
        if (nextSerial > 0) {
            serialOfThisCert = nextSerial;
            nextSerial++;
        } else {
            serialOfThisCert =
                    RandomSerialNumberGenerator.getInstance().getSerialNumber().longValue();
        }

        GenerateSelfSignedResult result;
        try {
            result = X509SelfSignedCertBuilder.generateSelfSigned(securityFactory,
                    signer_type, signer_conf,
                    certprofile, p10Request, serialOfThisCert,
                    cacert_uris, ocsp_uris, crl_uris, delta_crl_uris);
        } catch (OperationException | InvalidConfException e) {
            throw new CAMgmtException(e.getClass().getName() + ": " + e.getMessage(), e);
        }

        String signerConf = result.getSignerConf();
        X509Certificate caCert = result.getCert();

        if ("PKCS12".equalsIgnoreCase(signer_type) || "JKS".equalsIgnoreCase(signer_type)) {
            try {
                signerConf = canonicalizeSignerConf(signer_type, signerConf,
                        securityFactory.getPasswordResolver(),
                        new X509Certificate[]{caCert});
            } catch (Exception e) {
                throw new CAMgmtException(e.getClass().getName() + ": " + e.getMessage(), e);
            }
        }

        X509CAEntry entry = new X509CAEntry(name, nextSerial, nextCrlNumber,
                signer_type, signerConf,
                cacert_uris, ocsp_uris, crl_uris, delta_crl_uris,
                numCrls, expirationPeriod);
        entry.setCertificate(caCert);
        entry.setCmpControlName(caEntry.getCmpControlName());
        entry.setCrlSignerName(caEntry.getCrlSignerName());
        entry.setDuplicateKeyMode(caEntry.getDuplicateKeyMode());
        entry.setDuplicateSubjectMode(caEntry.getDuplicateSubjectMode());
        entry.setDuplicateCNMode(caEntry.getDuplicateCNMode());
        entry.setExtraControl(caEntry.getExtraControl());
        entry.setMaxValidity(caEntry.getMaxValidity());
        entry.setKeepExpiredCertInDays(caEntry.getKeepExpiredCertInDays());
        entry.setPermissions(caEntry.getPermissions());
        entry.setResponderName(caEntry.getResponderName());
        entry.setStatus(status);
        entry.setValidityMode(caEntry.getValidityMode());

        addCA(entry);
        return caCert;
    }

    private void asssertMasterMode()
    throws CAMgmtException {
        if (!masterMode) {
            throw new CAMgmtException("operation not allowed in slave mode");
        }
    }

    private static void assertNotNULL(
            final String parameterName,
            final String parameterValue) {
        if (CAManager.NULL.equalsIgnoreCase(parameterValue)) {
            throw new IllegalArgumentException(parameterName + " could not be " + CAManager.NULL);
        }
    }

    private static String canonicalizeSignerConf(
            final String keystoreType,
            final String signerConf,
            final PasswordResolver passwordResolver,
            final X509Certificate[] certChain)
    throws Exception {
        if (!signerConf.contains("file:") && !signerConf.contains("base64:")) {
            return signerConf;
        }

        ConfPairs pairs = new ConfPairs(signerConf);
        String keystoreConf = pairs.getValue("keystore");
        String passwordHint = pairs.getValue("password");
        String keyLabel     = pairs.getValue("key-label");

        byte[] keystoreBytes;
        if (StringUtil.startsWithIgnoreCase(keystoreConf, "file:")) {
            String keystoreFile = keystoreConf.substring("file:".length());
            keystoreBytes = IoUtil.read(keystoreFile);
        } else if (StringUtil.startsWithIgnoreCase(keystoreConf, "base64:")) {
            keystoreBytes = Base64.decode(keystoreConf.substring("base64:".length()));
        } else {
            return signerConf;
        }

        keystoreBytes = SecurityUtil.extractMinimalKeyStore(keystoreType,
                keystoreBytes, keyLabel,
                passwordResolver.resolvePassword(passwordHint), certChain);

        pairs.putPair("keystore", "base64:" + Base64.toBase64String(keystoreBytes));
        return pairs.getEncoded();
    }

    void shutdownCertprofile(
            final IdentifiedX509Certprofile profile) {
        if (profile == null) {
            return;
        }

        try {
            profile.shutdown();
        } catch (Exception e) {
            final String message = "could not shutdown Certprofile " + profile.getName();
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    void shutdownPublisher(
            final IdentifiedX509CertPublisher publisher) {
        if (publisher == null) {
            return;
        }

        try {
            publisher.shutdown();
        } catch (Exception e) {
            final String message = "could not shutdown CertPublisher " + publisher.getName();
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    CmpResponderEntryWrapper createCmpResponder(
            final CmpResponderEntry dbEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
        CmpResponderEntryWrapper ret = new CmpResponderEntryWrapper();
        ret.setDbEntry(dbEntry);
        try {
            ret.initSigner(securityFactory);
        } catch (SignerException e) {
            final String message = "createCmpResponder";
            LOG.debug(message, e);
            throw new CAMgmtException(e.getMessage());
        }
        return ret;
    }

    X509CrlSignerEntryWrapper createX509CrlSigner(
            final X509CrlSignerEntry dbEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
        X509CrlSignerEntryWrapper signer = new X509CrlSignerEntryWrapper();
        try {
            signer.setDbEntry(dbEntry);
        } catch (InvalidConfException e) {
            throw new CAMgmtException("ConfigurationException: " + e.getMessage());
        }
        try {
            signer.initSigner(securityFactory);
        } catch (SignerException | OperationException | InvalidConfException e) {
            final String message = "exception while creating CRL signer " + dbEntry.getName();
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);

            if (e instanceof OperationException) {
                throw new CAMgmtException(message + ": "
                        + ((OperationException) e).getErrorCode() + ", " + e.getMessage());
            } else {
                throw new CAMgmtException(message + ": " + e.getMessage());
            }
        }

        return signer;
    }

    IdentifiedX509Certprofile createCertprofile(
            final CertprofileEntry dbEntry) {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
        try {
            String realType = getRealCertprofileType(dbEntry.getType());
            IdentifiedX509Certprofile ret = new IdentifiedX509Certprofile(dbEntry, realType);
            ret.setEnvParameterResolver(envParameterResolver);
            ret.validate();
            return ret;
        } catch (CertprofileException e) {
            final String message = "could not initialize Certprofile " + dbEntry.getName()
                + ", ignore it";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            return null;
        }
    }

    IdentifiedX509CertPublisher createPublisher(
            final PublisherEntry dbEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
        String name = dbEntry.getName();
        String type = dbEntry.getType();

        String realType = getRealPublisherType(type);
        IdentifiedX509CertPublisher ret;
        try {
            ret = new IdentifiedX509CertPublisher(dbEntry, realType);
            ret.initialize(securityFactory.getPasswordResolver(), dataSources);
            return ret;
        } catch (CertPublisherException | RuntimeException e) {
            final String message = "invalid configuration for the certPublisher " + name;
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message),
                        e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            return null;
        }
    }

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

    private static String getRealType(
            String typeMap,
            final String type) {
        if (typeMap == null) {
            return null;
        }

        typeMap = typeMap.trim();
        if (StringUtil.isBlank(typeMap)) {
            return null;
        }

        ConfPairs pairs;
        try {
            pairs = new ConfPairs(typeMap);
        } catch (IllegalArgumentException e) {
            LOG.error("CA environment {}: '{}' is not valid CMP UTF-8 pairs", typeMap, type);
            return null;
        }
        return pairs.getValue(type);
    }

    static List<String[]> splitCASignerConfs(
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
            } catch (NoSuchAlgorithmException e) {
                throw new SignerException(e.getMessage(), e);
            }
            pairs.putPair("algo", c14nAlgo);
            signerConfs.add(new String[]{c14nAlgo, pairs.getEncoded()});
        }

        return signerConfs;
    }

    @Override
    public boolean addUser(
            final AddUserEntry userEntry)
    throws CAMgmtException {
        return queryExecutor.addUser(userEntry);
    }

    @Override
    public boolean changeUser(
            final String username,
            final String password,
            final String cnRegex)
    throws CAMgmtException {
        return queryExecutor.changeUser(username, password, cnRegex);
    }

    @Override
    public boolean removeUser(
            final String username)
    throws CAMgmtException {
        return queryExecutor.removeUser(username);
    }

    @Override
    public UserEntry getUser(
            final String username)
    throws CAMgmtException {
        return queryExecutor.getUser(username);
    }

    @Override
    public boolean addScep(
            final ScepEntry dbEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("dbEntry", dbEntry);
        asssertMasterMode();

        Scep scep = new Scep(dbEntry, this);
        boolean b = queryExecutor.addScep(dbEntry);
        if (b) {
            final String caName = dbEntry.getCaName();
            scep.refreshCA();
            scepDbEntries.put(caName, dbEntry);
            sceps.put(caName, scep);
        }
        return b;
    }

    @Override
    public boolean removeScep(
            String name)
    throws CAMgmtException {
        ParamUtil.assertNotBlank("name", name);
        asssertMasterMode();

        name = name.toUpperCase();
        boolean b = queryExecutor.removeScep(name);
        if (b) {
            scepDbEntries.remove(name);
            sceps.remove(name);
        }
        return b;
    }

    public boolean changeScep(
            final ChangeScepEntry scepEntry)
    throws CAMgmtException {
        ParamUtil.assertNotNull("scepEntry", scepEntry);
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
        scep.refreshCA();

        sceps.remove(caName);
        scepDbEntries.remove(caName);
        scepDbEntries.put(caName, scep.getDbEntry());
        sceps.put(caName, scep);
        return true;
    }

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

}
