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

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
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
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBException;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.audit.AuditEvent;
import org.xipki.commons.audit.AuditLevel;
import org.xipki.commons.audit.AuditServiceRegister;
import org.xipki.commons.audit.AuditStatus;
import org.xipki.commons.audit.PciAuditEvent;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.ObjectCreationException;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.DateUtil;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.datasource.DataSourceFactory;
import org.xipki.commons.datasource.DataSourceWrapper;
import org.xipki.commons.datasource.springframework.dao.DataAccessException;
import org.xipki.commons.password.PasswordResolverException;
import org.xipki.commons.security.CertRevocationInfo;
import org.xipki.commons.security.ConcurrentContentSigner;
import org.xipki.commons.security.CrlReason;
import org.xipki.commons.security.SecurityFactory;
import org.xipki.commons.security.SignerConf;
import org.xipki.commons.security.exception.XiSecurityException;
import org.xipki.pki.ca.api.DfltEnvParameterResolver;
import org.xipki.pki.ca.api.EnvParameterResolver;
import org.xipki.pki.ca.api.NameId;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.api.profile.CertValidity.Unit;
import org.xipki.pki.ca.api.profile.CertprofileException;
import org.xipki.pki.ca.api.profile.x509.X509Certprofile;
import org.xipki.pki.ca.api.profile.x509.X509CertprofileFactoryRegister;
import org.xipki.pki.ca.api.publisher.CertPublisherException;
import org.xipki.pki.ca.api.publisher.x509.X509CertPublisher;
import org.xipki.pki.ca.api.publisher.x509.X509CertPublisherFactoryRegister;
import org.xipki.pki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.pki.ca.server.impl.X509SelfSignedCertBuilder.GenerateSelfSignedResult;
import org.xipki.pki.ca.server.impl.cmp.CmpRequestorEntryWrapper;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderEntryWrapper;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderManager;
import org.xipki.pki.ca.server.impl.cmp.X509CaCmpResponder;
import org.xipki.pki.ca.server.impl.ocsp.OcspCertPublisher;
import org.xipki.pki.ca.server.impl.scep.Scep;
import org.xipki.pki.ca.server.impl.scep.ScepManager;
import org.xipki.pki.ca.server.impl.store.CertificateStore;
import org.xipki.pki.ca.server.impl.store.X509CertWithRevocationInfo;
import org.xipki.pki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CaManager;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.CaSystemStatus;
import org.xipki.pki.ca.server.mgmt.api.CertListInfo;
import org.xipki.pki.ca.server.mgmt.api.CertListOrderBy;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControl;
import org.xipki.pki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.pki.ca.server.mgmt.api.RequestorInfo;
import org.xipki.pki.ca.server.mgmt.api.UserEntry;
import org.xipki.pki.ca.server.mgmt.api.conf.CaConf;
import org.xipki.pki.ca.server.mgmt.api.conf.GenSelfIssued;
import org.xipki.pki.ca.server.mgmt.api.conf.SingleCaConf;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.CAConfType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.CaHasRequestorType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.CaType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.CmpcontrolType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.CrlsignerType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.FileOrBinaryType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.FileOrValueType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.NameValueType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.ProfileType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.PublisherType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.RequestorType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.ResponderType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.ScepType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.StringsType;
import org.xipki.pki.ca.server.mgmt.api.conf.jaxb.X509CaInfoType;
import org.xipki.pki.ca.server.mgmt.api.x509.CertWithStatusInfo;
import org.xipki.pki.ca.server.mgmt.api.x509.ChangeScepEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.RevokeSuspendedCertsControl;
import org.xipki.pki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaUris;
import org.xipki.pki.ca.server.mgmt.api.x509.X509ChangeCrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaManagerImpl implements CaManager, CmpResponderManager, ScepManager {

    private class CertsInQueuePublisher implements Runnable {

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
                    boolean bo = ca.publishCertsInQueue();
                    if (bo) {
                        LOG.info(" published certificates of CA {} in PUBLISHQUEUE", name);
                    } else {
                        LOG.error("publishing certificates of CA {} in PUBLISHQUEUE failed", name);
                    }
                }
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not publish CertsInQueue");
            } finally {
                inProcess = false;
            }
        } // method run

    } // class ScheduledPublishQueueCleaner

    private class UnreferencedRequstCleaner implements Runnable {

        private boolean inProcess;

        @Override
        public void run() {
            if (inProcess) {
                return;
            }

            inProcess = true;
            try {
                try {
                    certstore.deleteUnreferencedRequests();
                    LOG.info("deleted unreferenced requests");
                } catch (Throwable th) {
                    LogUtil.error(LOG, th, "could not delete unreferenced requests");
                }
            } finally {
                inProcess = false;
            }
        } // method run

    } // class ScheduledDeleteUnreferencedRequstervice

    private class CaRestarter implements Runnable {

        private boolean inProcess;

        @Override
        public void run() {
            if (inProcess) {
                return;
            }

            inProcess = true;
            try {
                SystemEvent event = queryExecutor.getSystemEvent(EVENT_CACHAGNE);
                long caChangedTime = (event == null) ? 0 : event.getEventTime();

                LOG.info("check the restart CA system event: changed at={}, lastStartTime={}",
                        new Date(caChangedTime * 1000L), lastStartTime);

                if (caChangedTime > lastStartTime.getTime() / 1000L) {
                    LOG.info("received event to restart CA");
                    restartCaSystem();
                } else {
                    LOG.debug("received no event to restart CA");
                }
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "ScheduledCaRestarter");
            } finally {
                inProcess = false;
            }
        } // method run

    } // class ScheduledCaRestarter

    public static final String ENV_EPOCH = "EPOCH";

    private static final Logger LOG = LoggerFactory.getLogger(CaManagerImpl.class);

    private static final String EVENT_LOCK = "LOCK";

    private static final String EVENT_CACHAGNE = "CA_CHANGE";

    private final String lockInstanceId;

    private final CaIdNameMap idNameMap = new CaIdNameMap();

    private ByCaRequestorInfo byCaRequestor;

    private NameId byUserRequestorId;

    private boolean caLockedByMe;

    private boolean masterMode;

    private Map<String, DataSourceWrapper> datasources;

    private final Map<String, X509CaInfo> caInfos = new ConcurrentHashMap<>();

    private Map<String, CmpResponderEntryWrapper> responders = new ConcurrentHashMap<>();

    private Map<String, CmpResponderEntry> responderDbEntries = new ConcurrentHashMap<>();

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

    private final Map<String, Set<String>> caHasProfiles = new ConcurrentHashMap<>();

    private final Map<String, Set<String>> caHasPublishers = new ConcurrentHashMap<>();

    private final Map<String, Set<CaHasRequestorEntry>> caHasRequestors
            = new ConcurrentHashMap<>();

    private final Map<String, Integer> caAliases = new ConcurrentHashMap<>();

    private final DfltEnvParameterResolver envParameterResolver = new DfltEnvParameterResolver();

    private ScheduledThreadPoolExecutor persistentScheduledThreadPoolExecutor;

    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    private final Map<String, X509CaCmpResponder> x509Responders = new ConcurrentHashMap<>();

    private final Map<String, X509Ca> x509cas = new ConcurrentHashMap<>();

    private final DataSourceFactory datasourceFactory;

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

    private X509CertprofileFactoryRegister x509CertProfileFactoryRegister;

    private X509CertPublisherFactoryRegister x509CertPublisherFactoryRegister;

    private DataSourceWrapper datasource;

    private CertificateStore certstore;

    private SecurityFactory securityFactory;

    private CaManagerQueryExecutor queryExecutor;

    private boolean initializing;

    public CaManagerImpl() throws InvalidConfException {
        this.datasourceFactory = new DataSourceFactory();
        String calockId = null;
        File caLockFile = new File("calock");
        if (caLockFile.exists()) {
            try {
                calockId = new String(IoUtil.read(caLockFile));
            } catch (IOException ex) {
                LOG.error("could not read {}: {}", caLockFile.getName(), ex.getMessage());
            }
        }

        if (calockId == null) {
            calockId = UUID.randomUUID().toString();
            try {
                IoUtil.save(caLockFile, calockId.getBytes());
            } catch (IOException ex) {
                LOG.error("could not save {}: {}", caLockFile.getName(), ex.getMessage());
            }
        }

        String hostAddress = null;
        try {
            hostAddress = IoUtil.getHostAddress();
        } catch (SocketException ex) {
            LOG.warn("could not get host address: {}", ex.getMessage());
        }

        this.lockInstanceId = (hostAddress == null) ? calockId : hostAddress + "/" + calockId;
    } // constructor

    public SecurityFactory getSecurityFactory() {
        return securityFactory;
    }

    public void setSecurityFactory(final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

    public DataSourceFactory getDataSourceFactory() {
        return datasourceFactory;
    }

    public boolean isMasterMode() {
        return masterMode;
    }

    private void init() throws CaMgmtException {
        if (securityFactory == null) {
            throw new IllegalStateException("securityFactory is not set");
        }
        if (datasourceFactory == null) {
            throw new IllegalStateException("datasourceFactory is not set");
        }
        if (x509CertProfileFactoryRegister == null) {
            throw new IllegalStateException("x509CertProfileFactoryRegister is not set");
        }
        if (x509CertPublisherFactoryRegister == null) {
            throw new IllegalStateException("x509CertPublisherFactoryRegister is not set");
        }
        if (caConfFile == null) {
            throw new IllegalStateException("caConfFile is not set");
        }

        Properties caConfProps = new Properties();
        try {
            caConfProps.load(new FileInputStream(IoUtil.expandFilepath(caConfFile)));
        } catch (IOException ex) {
            throw new CaMgmtException("could not parse CA configuration" + caConfFile, ex);
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

        int shardId;
        String shardIdStr = caConfProps.getProperty("ca.shardId");
        if (StringUtil.isBlank(shardIdStr)) {
            throw new CaMgmtException("ca.shardId is not set");
        }
        LOG.info("ca.shardId: {}", shardIdStr);

        try {
            shardId = Integer.parseInt(shardIdStr);
        } catch (NumberFormatException ex) {
            throw new CaMgmtException("invalid ca.shardId '" + shardIdStr + "'");
        }

        if (shardId < 0 || shardId > 127) {
            throw new CaMgmtException("ca.shardId is not in [0, 127]");
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
                            + " while parsing datasource " + datasourceFile, ex);
                }
            }

            this.datasource = this.datasources.get("ca");
        }

        if (this.datasource == null) {
            throw new CaMgmtException("no datasource named 'ca' configured");
        }

        this.queryExecutor = new CaManagerQueryExecutor(this.datasource);

        initEnvironmentParamters();
        String envEpoch = envParameterResolver.getEnvParam(ENV_EPOCH);

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

            if (envEpoch == null) {
                final long day = 24L * 60 * 60 * 1000;
                envEpoch = queryExecutor.setEpoch(new Date(System.currentTimeMillis() - day));
                LOG.info("set environment {} to {}", ENV_EPOCH, envEpoch);
            }

            queryExecutor.addRequestorIfNeeded(RequestorInfo.NAME_BY_CA);
            queryExecutor.addRequestorIfNeeded(RequestorInfo.NAME_BY_USER);
        } else {
            if (envEpoch == null) {
                throw new CaMgmtException(
                        "The CA system must be started first with ca.mode = master");
            }
        }

        LOG.info("use EPOCH: {}", envEpoch);
        long epoch = DateUtil.parseUtcTimeyyyyMMdd(envEpoch).getTime();

        UniqueIdGenerator idGen = new UniqueIdGenerator(epoch, shardId);

        try {
            this.certstore = new CertificateStore(datasource, idGen);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }

        initCaAliases();
        initCertprofiles();
        initPublishers();
        initCmpControls();
        initRequestors();
        initResponders();
        initCrlSigners();
        initCas();
        initSceps();
    } // method init

    @Override
    public CaSystemStatus getCaSystemStatus() {
        if (caSystemSetuped) {
            return masterMode ? CaSystemStatus.STARTED_AS_MASTER : CaSystemStatus.STARTED_AS_SLAVE;
        } else if (initializing) {
            return CaSystemStatus.INITIALIZING;
        } else if (!caLockedByMe) {
            return CaSystemStatus.LOCK_FAILED;
        } else {
            return CaSystemStatus.ERROR;
        }
    }

    private boolean lockCa(final boolean forceRelock) throws DataAccessException, CaMgmtException {
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
                LOG.info("CA has been locked by me since {}, re-lock it", lockedAt);
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
        } catch (CaMgmtException ex) {
            LogUtil.warn(LOG, ex, "error in unlockCa()");
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
    public boolean notifyCaChange() throws CaMgmtException {
        try {
            SystemEvent systemEvent = new SystemEvent(EVENT_CACHAGNE, lockInstanceId,
                    System.currentTimeMillis() / 1000L);
            queryExecutor.changeSystemEvent(systemEvent);
            LOG.info("notified the change of CA system");
            return true;
        } catch (CaMgmtException ex) {
            LogUtil.warn(LOG, ex, "could not notify slave CAs to restart");
            return false;
        }
    } // method notifyCaChange

    public void startCaSystem() {
        boolean caSystemStarted = false;
        try {
            caSystemStarted = doStartCaSystem();
        } catch (Throwable th) {
            LogUtil.error(LOG, th, "could not start CA system");
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
                LogUtil.error(LOG, ex);
                return false;
            }

            this.lastStartTime = new Date();

            x509cas.clear();
            x509Responders.clear();

            scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(10);
            scheduledThreadPoolExecutor.setRemoveOnCancelPolicy(true);

            List<String> startedCaNames = new LinkedList<>();
            List<String> failedCaNames = new LinkedList<>();

            // Add the CAs to the store
            for (String caName : caInfos.keySet()) {
                CaStatus status = caInfos.get(caName).getCaEntry().getStatus();
                if (CaStatus.ACTIVE != status) {
                    continue;
                }

                if (startCa(caName)) {
                    startedCaNames.add(caName);
                    LOG.info("started CA {}", caName);
                } else {
                    failedCaNames.add(caName);
                    LOG.error("could not start CA {}", caName);
                }
            }

            caSystemSetuped = true;
            StringBuilder sb = new StringBuilder();
            sb.append("started CA system");

            Set<String> caAliasNames = getCaAliasNames();
            Set<String> names = new HashSet<>(getCaNames());

            if (names.size() > 0) {
                sb.append(" with following CAs: ");
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

                scheduledThreadPoolExecutor.scheduleAtFixedRate(
                        new CertsInQueuePublisher(), 120, 120, TimeUnit.SECONDS);
                scheduledThreadPoolExecutor.scheduleAtFixedRate(
                        new UnreferencedRequstCleaner(), 60, 24 * 60 * 60, // 1 DAY
                        TimeUnit.SECONDS);
            } else {
                sb.append(": no CA is configured");
            }

            if (!failedCaNames.isEmpty()) {
                sb.append(", and following CAs could not be started: ");
                for (String aliasName : caAliasNames) {
                    String name = getCaNameForAlias(aliasName);
                    if (failedCaNames.remove(name)) {
                        sb.append(name).append(" (alias ").append(aliasName).append(")");
                        sb.append(", ");
                    }
                }

                for (String name : failedCaNames) {
                    sb.append(name).append(", ");
                }

                int len = sb.length();
                sb.delete(len - 2, len);
            }

            LOG.info("{}", sb);
        } finally {
            initializing = false;
            if (!masterMode && persistentScheduledThreadPoolExecutor == null) {
                persistentScheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
                persistentScheduledThreadPoolExecutor.setRemoveOnCancelPolicy(true);
                persistentScheduledThreadPoolExecutor.scheduleAtFixedRate(new CaRestarter(),
                        300, 300, TimeUnit.SECONDS);
            }
        }

        return true;
    } // method doStartCaSystem

    private boolean startCa(final String caName) {
        X509CaInfo caEntry = caInfos.get(caName);

        String extraControl = caEntry.getCaEntry().getExtraControl();
        if (StringUtil.isNotBlank(extraControl)) {
            ConfPairs cp = new ConfPairs(extraControl);
            String str = cp.getValue(RevokeSuspendedCertsControl.KEY_REVOCATION_ENABLED);
            boolean enabled = false;
            if (str != null) {
                enabled = Boolean.parseBoolean(str);
            }

            if (enabled) {
                str = cp.getValue(RevokeSuspendedCertsControl.KEY_REVOCATION_REASON);
                CrlReason reason = (str == null) ? CrlReason.CESSATION_OF_OPERATION
                        : CrlReason.forNameOrText(str);

                str = cp.getValue(RevokeSuspendedCertsControl.KEY_UNCHANGED_SINCE);
                CertValidity unchangedSince = (str == null) ? new CertValidity(15, Unit.DAY)
                        : CertValidity.getInstance(str);
                RevokeSuspendedCertsControl control = new RevokeSuspendedCertsControl(reason,
                        unchangedSince);
                caEntry.setRevokeSuspendedCertsControl(control);
            }
        }

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
            } catch (XiSecurityException | OperationException | InvalidConfException ex) {
                LogUtil.error(LOG, ex,
                        "X09CrlSignerEntryWrapper.initSigner (name=" + crlSignerName + ")");
                return false;
            }
        }

        X509Ca ca;
        try {
            ca = new X509Ca(this, caEntry, certstore);
            ca.setAuditServiceRegister(auditServiceRegister);
        } catch (OperationException ex) {
            LogUtil.error(LOG, ex, "X509CA.<init> (ca=" + caName + ")");
            return false;
        }

        x509cas.put(caName, ca);
        X509CaCmpResponder caResponder = new X509CaCmpResponder(this, caName);
        x509Responders.put(caName, caResponder);

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
                    LOG.error("interrupted: {}", ex.getMessage());
                }
            }
            persistentScheduledThreadPoolExecutor = null;
        }

        for (String caName : x509cas.keySet()) {
            X509Ca ca = x509cas.get(caName);
            try {
                ca.shutdown();
            } catch (Throwable th) {
                LOG.info("could not call ca.shutdown() for CA '{}': {}", caName, th.getMessage());
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
                LogUtil.warn(LOG, ex, "could not shutdown datasource " + dsName);
            }
        }

        LOG.info("stopped CA system");
        auditLogPciEvent(true, "SHUTDOWN");
    } // method shutdown

    @Override
    public X509CaCmpResponder getX509CaResponder(final String name) {
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
    public Set<String> getRequestorNames() {
        return requestorDbEntries.keySet();
    }

    @Override
    public Set<String> getResponderNames() {
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

    @Override
    public Set<String> getSuccessfulCaNames() {
        Set<String> ret = new HashSet<>();
        for (String name : x509cas.keySet()) {
            if (CaStatus.ACTIVE == caInfos.get(name).getStatus()) {
                ret.add(name);
            }
        }
        return ret;
    }

    @Override
    public Set<String> getFailedCaNames() {
        Set<String> ret = new HashSet<>();
        for (String name : caInfos.keySet()) {
            if (CaStatus.ACTIVE == caInfos.get(name).getStatus()
                    && !x509cas.containsKey(name)) {
                ret.add(name);
            }
        }
        return ret;
    }

    @Override
    public Set<String> getInactiveCaNames() {
        Set<String> ret = new HashSet<>();
        for (String name : caInfos.keySet()) {
            if (CaStatus.INACTIVE == caInfos.get(name).getStatus()) {
                ret.add(name);
            }
        }
        return ret;
    }

    private void initRequestors() throws CaMgmtException {
        if (requestorsInitialized) {
            return;
        }

        idNameMap.clearRequestor();
        requestorDbEntries.clear();
        requestors.clear();
        List<String> names = queryExecutor.getNamesFromTable("REQUESTOR");
        for (String name : names) {
            if (RequestorInfo.NAME_BY_CA.equals(name)) {
                Integer id = queryExecutor.getRequestorId(name);
                NameId ident = new NameId(id, name);
                byCaRequestor = new ByCaRequestorInfo(ident);
                idNameMap.addRequestor(ident);
            } else if (RequestorInfo.NAME_BY_USER.equals(name)) {
                Integer id = queryExecutor.getRequestorId(name);
                byUserRequestorId = new NameId(id, name);
                idNameMap.addRequestor(byUserRequestorId);
            } else {
                CmpRequestorEntry requestorDbEntry = queryExecutor.createRequestor(name);
                if (requestorDbEntry == null) {
                    continue;
                }

                idNameMap.addRequestor(requestorDbEntry.getIdent());
                requestorDbEntries.put(name, requestorDbEntry);
                CmpRequestorEntryWrapper requestor = new CmpRequestorEntryWrapper();
                requestor.setDbEntry(requestorDbEntry);
                requestors.put(name, requestor);
            }
        }
        requestorsInitialized = true;
    } // method initRequestors

    private void initResponders() throws CaMgmtException {
        if (responderInitialized) {
            return;
        }

        responderDbEntries.clear();
        responders.clear();

        List<String> names = queryExecutor.getNamesFromTable("RESPONDER");
        for (String name : names) {
            CmpResponderEntry dbEntry = queryExecutor.createResponder(name);
            if (dbEntry == null) {
                LOG.error("could not initialize Responder '{}'", name);
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

    private void initEnvironmentParamters() throws CaMgmtException {
        if (environmentParametersInitialized) {
            return;
        }

        Map<String, String> map = queryExecutor.createEnvParameters();
        envParameterResolver.clear();
        for (String name : map.keySet()) {
            envParameterResolver.addEnvParam(name, map.get(name));
        }

        environmentParametersInitialized = true;
    } // method initEnvironmentParamters

    private void initCaAliases() throws CaMgmtException {
        if (caAliasesInitialized) {
            return;
        }

        Map<String, Integer> map = queryExecutor.createCaAliases();
        caAliases.clear();
        for (String aliasName : map.keySet()) {
            caAliases.put(aliasName, map.get(aliasName));
        }

        caAliasesInitialized = true;
    } // method initCaAliases

    private void initCertprofiles() throws CaMgmtException {
        if (certprofilesInitialized) {
            return;
        }

        for (String name : certprofiles.keySet()) {
            shutdownCertprofile(certprofiles.get(name));
        }
        certprofileDbEntries.clear();
        idNameMap.clearCertprofile();
        certprofiles.clear();

        List<String> names = queryExecutor.getNamesFromTable("PROFILE");
        for (String name : names) {
            CertprofileEntry dbEntry = queryExecutor.createCertprofile(name);
            if (dbEntry == null) {
                LOG.error("could not initialize Certprofile '{}'", name);
                continue;
            }

            idNameMap.addCertprofile(dbEntry.getIdent());
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

    private void initPublishers() throws CaMgmtException {
        if (publishersInitialized) {
            return;
        }

        for (String name : publishers.keySet()) {
            shutdownPublisher(publishers.get(name));
        }
        publishers.clear();
        publisherDbEntries.clear();
        idNameMap.clearPublisher();

        List<String> names = queryExecutor.getNamesFromTable("PUBLISHER");
        for (String name : names) {
            PublisherEntry dbEntry = queryExecutor.createPublisher(name);
            if (dbEntry == null) {
                LOG.error("could not initialize publisher '{}'", name);
                continue;
            }

            idNameMap.addPublisher(dbEntry.getIdent());
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

    private void initCrlSigners() throws CaMgmtException {
        if (crlSignersInitialized) {
            return;
        }
        crlSigners.clear();
        crlSignerDbEntries.clear();

        List<String> names = queryExecutor.getNamesFromTable("CRLSIGNER");
        for (String name : names) {
            X509CrlSignerEntry dbEntry = queryExecutor.createCrlSigner(name);
            if (dbEntry == null) {
                LOG.error("could not initialize CRL signer '{}'", name);
                continue;
            }

            crlSignerDbEntries.put(name, dbEntry);
            X509CrlSignerEntryWrapper crlSigner = createX509CrlSigner(dbEntry);
            crlSigners.put(name, crlSigner);
        }

        crlSignersInitialized = true;
    } // method initCrlSigners

    private void initCmpControls() throws CaMgmtException {
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
                LogUtil.error(LOG, ex, "could not initialize CMP control " + name + ", ignore it");
            }
        }

        cmpControlInitialized = true;
    } // method initCmpControls

    private void initSceps() throws CaMgmtException {
        if (scepsInitialized) {
            return;
        }

        sceps.clear();
        scepDbEntries.clear();

        List<String> names = queryExecutor.getNamesFromTable("SCEP");
        for (String name : names) {
            ScepEntry scepDb = queryExecutor.getScep(name, idNameMap);
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
                LogUtil.error(LOG, ex, "could not initialize SCEP entry " + name + ", ignore it");
            }
        }
        scepsInitialized = true;
    } // method initSceps

    private void initCas() throws CaMgmtException {
        if (casInitialized) {
            return;
        }

        caInfos.clear();
        caHasRequestors.clear();
        caHasPublishers.clear();
        caHasProfiles.clear();
        idNameMap.clearCa();

        List<String> names = queryExecutor.getNamesFromTable("CA");
        for (String name : names) {
            createCa(name);
        }
        casInitialized = true;
    } // method initCas

    private boolean createCa(final String name) throws CaMgmtException {
        caInfos.remove(name);
        idNameMap.removeCa(name);
        caHasProfiles.remove(name);
        caHasPublishers.remove(name);
        caHasRequestors.remove(name);
        X509Ca oldCa = x509cas.remove(name);
        x509Responders.remove(name);
        if (oldCa != null) {
            oldCa.shutdown();
        }

        X509CaInfo ca = queryExecutor.createCaInfo(name, masterMode, certstore);
        caInfos.put(name, ca);
        idNameMap.addCa(ca.getIdent());
        Set<CaHasRequestorEntry> caHasRequestorList
                = queryExecutor.createCaHasRequestors(ca.getIdent());
        caHasRequestors.put(name, caHasRequestorList);

        Set<Integer> profileIds = queryExecutor.createCaHasProfiles(ca.getIdent());
        Set<String> profileNames = new HashSet<>();
        for (Integer id : profileIds) {
            profileNames.add(idNameMap.getCertprofileName(id));
        }
        caHasProfiles.put(name, profileNames);

        Set<Integer> publisherIds = queryExecutor.createCaHasPublishers(ca.getIdent());
        Set<String> publisherNames = new HashSet<>();
        for (Integer id : publisherIds) {
            publisherNames.add(idNameMap.getPublisherName(id));
        }
        caHasPublishers.put(name, publisherNames);

        return true;
    } // method createCa

    public void commitNextCrlNo(final NameId ca, final long nextCrlNo)
            throws OperationException {
        try {
            queryExecutor.commitNextCrlNoIfLess(ca, nextCrlNo);
        } catch (CaMgmtException ex) {
            if (ex.getCause() instanceof DataAccessException) {
                throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
            } else {
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
            }
        } catch (RuntimeException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    }

    public ByUserRequestorInfo createByUserRequestor(CaHasUserEntry caHasUser) {
        return new ByUserRequestorInfo(byUserRequestorId, caHasUser);
    }

    @Override
    public boolean addCa(final CaEntry caEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("caEntry", caEntry);
        asssertMasterMode();
        NameId ident = caEntry.getIdent();
        String name = ident.getName();

        if (caInfos.containsKey(name)) {
            throw new CaMgmtException("CA named " + name + " exists");
        }

        if (caEntry instanceof X509CaEntry) {
            try {
                X509CaEntry tmpCaEntry = (X509CaEntry) caEntry;
                List<String[]> signerConfs = CaEntry.splitCaSignerConfs(tmpCaEntry.getSignerConf());
                ConcurrentContentSigner signer;
                for (String[] m : signerConfs) {
                    SignerConf signerConf = new SignerConf(m[1]);
                    signer = securityFactory.createSigner(tmpCaEntry.getSignerType(), signerConf,
                            tmpCaEntry.getCertificate());
                    if (tmpCaEntry.getCertificate() == null) {
                        if (signer.getCertificate() == null) {
                            throw new CaMgmtException(
                                    "CA signer without certificate is not allowed");
                        }
                        tmpCaEntry.setCertificate(signer.getCertificate());
                    }
                }
            } catch (XiSecurityException | ObjectCreationException ex) {
                throw new CaMgmtException(
                        "could not create signer for new CA " + name + ": " + ex.getMessage(), ex);
            }
        }

        queryExecutor.addCa(caEntry);
        if (!createCa(name)) {
            LOG.error("could not create CA {}", name);
        } else {
            if (startCa(name)) {
                LOG.info("started CA {}", name);
            } else {
                LOG.error("could not start CA {}", name);
            }
        }

        return true;
    } // method addCa

    @Override
    public X509CaEntry getCa(final String name) {
        ParamUtil.requireNonBlank("name", name);
        X509CaInfo caInfo = caInfos.get(name.toUpperCase());
        return (caInfo == null) ? null : caInfo.getCaEntry();
    }

    @Override
    public boolean changeCa(final ChangeCaEntry entry) throws CaMgmtException {
        ParamUtil.requireNonNull("entry", entry);
        asssertMasterMode();
        String name = entry.getIdent().getName();
        NameId ident = idNameMap.getCa(name);
        if (ident == null) {
            throw new CaMgmtException("No CA named " + name + " does not exist");
        }
        entry.getIdent().setId(ident.getId());

        boolean changed = queryExecutor.changeCa(entry, securityFactory);
        if (!changed) {
            LOG.info("no change of CA '{}' is processed", name);
        } else {
            if (!createCa(name)) {
                LOG.error("could not create CA {}", name);
            } else {
                X509CaInfo caInfo = caInfos.get(name);
                if (CaStatus.ACTIVE != caInfo.getCaEntry().getStatus()) {
                    return changed;
                }

                if (startCa(name)) {
                    LOG.info("started CA {}", name);
                } else {
                    LOG.error("could not start CA {}", name);
                }
            }
        }

        return changed;
    } // method changeCa

    @Override
    public boolean removeCertprofileFromCa(String profileName, String caName)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("profileName", profileName);
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();

        profileName = profileName.toUpperCase();
        caName = caName.toUpperCase();
        boolean bo = queryExecutor.removeCertprofileFromCa(profileName, caName);
        if (!bo) {
            return false;
        }

        if (caHasProfiles.containsKey(caName)) {
            Set<String> set = caHasProfiles.get(caName);
            if (set != null) {
                set.remove(profileName);
            }
        }
        return true;
    } // method removeCertprofileFromCa

    @Override
    public boolean addCertprofileToCa(String profileName, String caName)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("profileName", profileName);
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();

        profileName = profileName.toUpperCase();
        caName = caName.toUpperCase();
        NameId ident = idNameMap.getCertprofile(profileName);
        if (ident == null) {
            LOG.warn("CertProfile {} does not exist", profileName);
            return false;
        }

        Set<String> set = caHasProfiles.get(caName);
        if (set == null) {
            set = new HashSet<>();
            caHasProfiles.put(caName, set);
        } else {
            if (set.contains(profileName)) {
                LOG.warn("CertProfile {} already associated with CA {}", profileName, caName);
                return false;
            }
        }

        if (!certprofiles.containsKey(profileName)) {
            throw new CaMgmtException("certprofile '" + profileName + "' is faulty");
        }

        queryExecutor.addCertprofileToCa(ident, idNameMap.getCa(caName));
        set.add(profileName);
        return true;
    } // method addCertprofileToCa

    @Override
    public boolean removePublisherFromCa(String publisherName, String caName)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("publisherName", publisherName);
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();

        publisherName = publisherName.toUpperCase();
        caName = caName.toUpperCase();

        if (!queryExecutor.removePublisherFromCa(publisherName, caName)) {
            return false;
        }

        Set<String> publisherNames = caHasPublishers.get(caName);
        if (publisherNames != null) {
            publisherNames.remove(publisherName);
        }
        return true;
    } // method removePublisherFromCa

    @Override
    public boolean addPublisherToCa(String publisherName, String caName)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("publisherName", publisherName);
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();

        publisherName = publisherName.toUpperCase();
        caName = caName.toUpperCase();
        NameId ident = idNameMap.getPublisher(publisherName);
        if (ident == null) {
            LOG.warn("Publisher {} does not exist", publisherName);
            return false;
        }

        Set<String> publisherNames = caHasPublishers.get(caName);
        if (publisherNames == null) {
            publisherNames = new HashSet<>();
            caHasPublishers.put(caName, publisherNames);
        } else {
            if (publisherNames.contains(publisherName)) {
                LOG.warn("CertProfile {} already associated with CA {}", publisherName, caName);
                return false;
            }
        }

        IdentifiedX509CertPublisher publisher = publishers.get(publisherName);
        if (publisher == null) {
            throw new CaMgmtException("publisher '" + publisherName + "' is faulty");
        }

        queryExecutor.addPublisherToCa(idNameMap.getPublisher(publisherName),
                idNameMap.getCa(caName));
        publisherNames.add(publisherName);
        caHasPublishers.get(caName).add(publisherName);

        publisher.caAdded(caInfos.get(caName).getCertificate());
        return true;
    } // method addPublisherToCa

    @Override
    public Set<String> getCertprofilesForCa(final String caName) {
        ParamUtil.requireNonBlank("caName", caName);
        return caHasProfiles.get(caName.toUpperCase());
    }

    @Override
    public Set<CaHasRequestorEntry> getRequestorsForCa(final String caName) {
        ParamUtil.requireNonBlank("caName", caName);
        return caHasRequestors.get(caName.toUpperCase());
    }

    @Override
    public CmpRequestorEntry getRequestor(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return requestorDbEntries.get(name.toUpperCase());
    }

    public CmpRequestorEntryWrapper getCmpRequestorWrapper(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return requestors.get(name.toUpperCase());
    }

    @Override
    public boolean addRequestor(final CmpRequestorEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getIdent().getName();
        if (requestorDbEntries.containsKey(name)) {
            return false;
        }

        CmpRequestorEntryWrapper requestor = new CmpRequestorEntryWrapper();
        requestor.setDbEntry(dbEntry);

        queryExecutor.addRequestor(dbEntry);
        idNameMap.addRequestor(dbEntry.getIdent());
        requestorDbEntries.put(name, dbEntry);
        requestors.put(name, requestor);

        return true;
    } // method addRequestor

    @Override
    public boolean removeRequestor(String requestorName) throws CaMgmtException {
        ParamUtil.requireNonBlank("requestorName", requestorName);
        asssertMasterMode();

        requestorName = requestorName.toUpperCase();
        for (String caName : caHasRequestors.keySet()) {
            removeRequestorFromCa(requestorName, caName);
        }

        boolean bo = queryExecutor.deleteRowWithName(requestorName, "REQUESTOR");
        if (!bo) {
            return false;
        }

        idNameMap.removeRequestor(requestorDbEntries.get(requestorName).getIdent().getId());
        requestorDbEntries.remove(requestorName);
        requestors.remove(requestorName);
        LOG.info("removed requestor '{}'", requestorName);
        return true;
    } // method removeRequestor

    @Override
    public boolean changeRequestor(String name, final String base64Cert)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();

        name = name.toUpperCase();
        if (base64Cert == null) {
            return false;
        }

        NameId ident = idNameMap.getRequestor(name);
        if (ident == null) {
            throw new CaMgmtException("Requestor named " + name + " does not exists");
        }

        CmpRequestorEntryWrapper requestor = queryExecutor.changeRequestor(ident, base64Cert);
        if (requestor == null) {
            return false;
        }

        requestorDbEntries.remove(name);
        requestors.remove(name);

        requestorDbEntries.put(name, requestor.getDbEntry());
        requestors.put(name, requestor);
        return true;
    } // method changeRequestor

    @Override
    public boolean removeRequestorFromCa(String requestorName, String caName)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("requestorName", requestorName);
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();

        requestorName = requestorName.toUpperCase();
        caName = caName.toUpperCase();
        if (requestorName.equals(RequestorInfo.NAME_BY_CA)
                || requestorName.equals(RequestorInfo.NAME_BY_USER)) {
            throw new CaMgmtException("removing requestor " + requestorName + " is not permitted");
        }

        boolean bo = queryExecutor.removeRequestorFromCa(requestorName, caName);
        if (bo && caHasRequestors.containsKey(caName)) {
            Set<CaHasRequestorEntry> entries = caHasRequestors.get(caName);
            CaHasRequestorEntry entry = null;
            for (CaHasRequestorEntry m : entries) {
                if (m.getRequestorIdent().getName().equals(requestorName)) {
                    entry = m;
                }
            }
            entries.remove(entry);
        }
        return bo;
    } // method removeRequestorFromCa

    @Override
    public boolean addRequestorToCa(final CaHasRequestorEntry requestor, String caName)
            throws CaMgmtException {
        ParamUtil.requireNonNull("requestor", requestor);
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();
        caName = caName.toUpperCase();

        NameId requestorIdent = requestor.getRequestorIdent();
        NameId ident = idNameMap.getRequestor(requestorIdent.getName());
        if (ident == null) {
            LOG.warn("Requestor {} does not exist", requestorIdent.getName());
            return false;
        }
        // Set the ID of requestor
        requestorIdent.setId(ident.getId());

        Set<CaHasRequestorEntry> cmpRequestors = caHasRequestors.get(caName);
        if (cmpRequestors == null) {
            cmpRequestors = new HashSet<>();
            caHasRequestors.put(caName, cmpRequestors);
        } else {
            for (CaHasRequestorEntry entry : cmpRequestors) {
                if (entry.getRequestorIdent().getName().equals(requestorIdent.getName())) {
                    LOG.warn("Requestor {} already associated with CA {}",
                            requestorIdent.getName(), caName);
                    // already added
                    return false;
                }
            }
        }

        cmpRequestors.add(requestor);
        queryExecutor.addRequestorToCa(requestor, idNameMap.getCa(caName));
        caHasRequestors.get(caName).add(requestor);
        return true;
    } // method addRequestorToCa

    @Override
    public boolean removeUserFromCa(final String userName, final String caName)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("userName", userName);
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();

        return queryExecutor.removeUserFromCa(userName.toUpperCase(), caName.toUpperCase());
    }

    @Override
    public boolean addUserToCa(final CaHasUserEntry user, final String caName)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();

        X509Ca ca = getX509Ca(caName.toUpperCase());
        return queryExecutor.addUserToCa(user, ca.getCaIdent());
    }

    @Override
    public Map<String, CaHasUserEntry> getCaHasUsers(String user)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("user", user);
        return queryExecutor.getCaHasUsers(user, idNameMap);
    }

    @Override
    public CertprofileEntry getCertprofile(final String profileName) {
        ParamUtil.requireNonBlank("profileName", profileName);
        return certprofileDbEntries.get(profileName.toUpperCase());
    }

    @Override
    public boolean removeCertprofile(String profileName) throws CaMgmtException {
        ParamUtil.requireNonBlank("profileName", profileName);
        asssertMasterMode();

        profileName = profileName.toUpperCase();
        for (String caName : caHasProfiles.keySet()) {
            removeCertprofileFromCa(profileName, caName);
        }

        boolean bo = queryExecutor.deleteRowWithName(profileName, "PROFILE");
        if (!bo) {
            return false;
        }

        LOG.info("removed profile '{}'", profileName);
        idNameMap.removeCertprofile(certprofileDbEntries.get(profileName).getIdent().getId());
        certprofileDbEntries.remove(profileName);
        IdentifiedX509Certprofile profile = certprofiles.remove(profileName);
        shutdownCertprofile(profile);
        return true;
    } // method removeCertprofile

    @Override
    public boolean changeCertprofile(String name, final String type, final String conf)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        if (type == null && conf == null) {
            return false;
        }
        NameId ident = idNameMap.getCertprofile(name);
        if (ident == null) {
            throw new CaMgmtException("Certprofile " + name + " does not exist");
        }

        asssertMasterMode();
        name = name.toUpperCase();

        IdentifiedX509Certprofile profile = queryExecutor.changeCertprofile(
                ident, type, conf, this);
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
    public boolean addCertprofile(final CertprofileEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getIdent().getName();
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

        idNameMap.addCertprofile(dbEntry.getIdent());
        certprofileDbEntries.put(name, dbEntry);

        return true;
    } // method addCertprofile

    @Override
    public boolean addResponder(final CmpResponderEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getName();
        if (crlSigners.containsKey(name)) {
            return false;
        }

        CmpResponderEntryWrapper responder = createCmpResponder(dbEntry);
        queryExecutor.addResponder(dbEntry);
        responders.put(name, responder);
        responderDbEntries.put(name, dbEntry);
        return true;
    } // method addResponder

    @Override
    public boolean removeResponder(String name) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        name = name.toUpperCase();
        boolean bo = queryExecutor.deleteRowWithName(name, "RESPONDER");
        if (!bo) {
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
    } // method removeResponder

    @Override
    public boolean changeResponder(String name, final String type, final String conf,
            final String base64Cert) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        name = name.toUpperCase();
        if (type == null && conf == null && base64Cert == null) {
            return false;
        }

        CmpResponderEntryWrapper newResponder = queryExecutor.changeResponder(name, type, conf,
                base64Cert, this);
        if (newResponder == null) {
            return false;
        }

        responders.remove(name);
        responderDbEntries.remove(name);
        responderDbEntries.put(name, newResponder.getDbEntry());
        responders.put(name, newResponder);
        return true;
    } // method changeResponder

    @Override
    public CmpResponderEntry getResponder(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return responderDbEntries.get(name.toUpperCase());
    }

    public CmpResponderEntryWrapper getCmpResponderWrapper(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return responders.get(name.toUpperCase());
    }

    @Override
    public boolean addCrlSigner(final X509CrlSignerEntry dbEntry) throws CaMgmtException {
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
    public boolean removeCrlSigner(String name) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        name = name.toUpperCase();
        boolean bo = queryExecutor.deleteRowWithName(name, "CRLSIGNER");
        if (!bo) {
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
        LOG.info("removed CRL signer '{}'", name);
        return true;
    } // method removeCrlSigner

    @Override
    public boolean changeCrlSigner(final X509ChangeCrlSignerEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();

        String name = dbEntry.getName();
        String signerType = dbEntry.getSignerType();
        String signerConf = dbEntry.getSignerConf();
        String signerCert = dbEntry.getBase64Cert();
        String crlControl = dbEntry.getCrlControl();

        X509CrlSignerEntryWrapper crlSigner = queryExecutor.changeCrlSigner(name, signerType,
                signerConf, signerCert, crlControl, this);
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
    public X509CrlSignerEntry getCrlSigner(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return crlSignerDbEntries.get(name.toUpperCase());
    }

    public X509CrlSignerEntryWrapper getCrlSignerWrapper(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return crlSigners.get(name.toUpperCase());
    }

    @Override
    public boolean addPublisher(final PublisherEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();
        String name = dbEntry.getIdent().getName();
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

        idNameMap.addPublisher(dbEntry.getIdent());
        publisherDbEntries.put(name, dbEntry);
        publishers.put(name, publisher);

        return true;
    } // method addPublisher

    @Override
    public List<PublisherEntry> getPublishersForCa(String caName) {
        ParamUtil.requireNonBlank("caName", caName);
        caName = caName.toUpperCase();
        Set<String> publisherNames = caHasPublishers.get(caName);
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
    public PublisherEntry getPublisher(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return publisherDbEntries.get(name.toUpperCase());
    }

    @Override
    public boolean removePublisher(String name) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        name = name.toUpperCase();
        for (String caName : caHasPublishers.keySet()) {
            removePublisherFromCa(name, caName);
        }

        boolean bo = queryExecutor.deleteRowWithName(name, "PUBLISHER");
        if (!bo) {
            return false;
        }

        LOG.info("removed publisher '{}'", name);
        publisherDbEntries.remove(name);
        IdentifiedX509CertPublisher publisher = publishers.remove(name);
        shutdownPublisher(publisher);
        return true;
    } // method removePublisher

    @Override
    public boolean changePublisher(String name, final String type, final String conf)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        name = name.toUpperCase();
        if (type == null && conf == null) {
            return false;
        }

        IdentifiedX509CertPublisher publisher = queryExecutor.changePublisher(name, type,
                conf, this);
        if (publisher == null) {
            return false;
        }

        IdentifiedX509CertPublisher oldPublisher = publishers.remove(name);
        shutdownPublisher(oldPublisher);

        publisherDbEntries.put(name, publisher.getDbEntry());
        publishers.put(name, publisher);

        return true;
    } // method changePublisher

    @Override
    public CmpControlEntry getCmpControl(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return cmpControlDbEntries.get(name.toUpperCase());
    }

    public CmpControl getCmpControlObject(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return cmpControls.get(name.toUpperCase());
    }

    @Override
    public boolean addCmpControl(final CmpControlEntry dbEntry) throws CaMgmtException {
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
            LogUtil.error(LOG, ex, "could not add CMP control to certStore");
            return false;
        }

        CmpControlEntry tmpDbEntry = cmpControl.getDbEntry();
        queryExecutor.addCmpControl(tmpDbEntry);
        cmpControls.put(name, cmpControl);
        cmpControlDbEntries.put(name, tmpDbEntry);
        return true;
    } // method addCmpControl

    @Override
    public boolean removeCmpControl(String name) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        name = name.toUpperCase();
        boolean bo = queryExecutor.deleteRowWithName(name, "CMPCONTROL");
        if (!bo) {
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
    public boolean changeCmpControl(String name, final String conf) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonBlank("conf", conf);
        asssertMasterMode();
        name = name.toUpperCase();
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
    public String getEnvParam(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return envParameterResolver.getEnvParam(name);
    }

    @Override
    public boolean addEnvParam(final String name, final String value) throws CaMgmtException {
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
    public boolean removeEnvParam(final String name) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        boolean bo = queryExecutor.deleteRowWithName(name, "ENVIRONMENT");
        if (!bo) {
            return false;
        }

        LOG.info("removed environment param '{}'", name);
        envParameterResolver.removeEnvParam(name);
        return true;
    }

    @Override
    public boolean changeEnvParam(final String name, final String value) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonNull("value", value);
        asssertMasterMode();
        assertNotNull("value", value);

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

    public void setCaConfFile(final String caConfFile) {
        this.caConfFile = caConfFile;
    }

    @Override
    public boolean addCaAlias(String aliasName, String caName) throws CaMgmtException {
        ParamUtil.requireNonBlank("aliasName", aliasName);
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();
        aliasName = aliasName.toUpperCase();
        caName = caName.toUpperCase();

        X509Ca ca = x509cas.get(caName);
        if (ca == null) {
            return false;
        }

        String tmpAlias = aliasName.toUpperCase();
        if (caAliases.get(tmpAlias) != null) {
            return false;
        }

        queryExecutor.addCaAlias(tmpAlias, ca.getCaIdent());
        caAliases.put(tmpAlias, ca.getCaIdent().getId());
        return true;
    } // method addCaAlias

    @Override
    public boolean removeCaAlias(String name) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        name = name.toUpperCase();
        boolean bo = queryExecutor.removeCaAlias(name);
        if (!bo) {
            return false;
        }

        caAliases.remove(name);
        return true;
    }

    @Override
    public String getCaNameForAlias(String aliasName) {
        ParamUtil.requireNonBlank("aliasName", aliasName);
        aliasName = aliasName.toUpperCase();
        Integer caId = caAliases.get(aliasName);
        for (String name : x509cas.keySet()) {
            X509Ca ca = x509cas.get(name);
            if (ca.getCaIdent().getId() == caId) {
                return ca.getCaIdent().getName();
            }
        }
        return null;
    }

    @Override
    public Set<String> getAliasesForCa(String caName) {
        ParamUtil.requireNonBlank("caName", caName);
        caName = caName.toUpperCase();
        Set<String> aliases = new HashSet<>();
        X509Ca ca = x509cas.get(caName);
        if (ca == null) {
            return aliases;
        }

        NameId caIdent = ca.getCaIdent();

        for (String alias : caAliases.keySet()) {
            Integer thisCaId = caAliases.get(alias);
            if (thisCaId == caIdent.getId()) {
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
    public boolean removeCa(String caName) throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();
        caName = caName.toUpperCase();

        boolean bo = queryExecutor.removeCa(caName);
        if (!bo) {
            return false;
        }

        LOG.info("removed CA '{}'", caName);
        caInfos.remove(caName);
        idNameMap.removeCa(caName);
        idNameMap.removeCa(caName);
        caHasProfiles.remove(caName);
        caHasPublishers.remove(caName);
        caHasRequestors.remove(caName);
        X509Ca ca = x509cas.remove(caName);
        x509Responders.remove(caName);
        if (ca != null) {
            ca.shutdown();
        }
        return true;
    } // method removeCa

    @Override
    public boolean republishCertificates(String caName, final List<String> publisherNames,
            final int numThreads) throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireMin("numThreads", numThreads, 1);
        asssertMasterMode();
        caName = caName.toUpperCase();
        X509Ca ca = x509cas.get(caName);
        if (ca == null) {
            throw new CaMgmtException("could not find CA named " + caName);
        }

        List<String> upperPublisherNames = CollectionUtil.toUpperCaseList(publisherNames);
        boolean successful = ca.republishCertificates(upperPublisherNames, numThreads);
        if (!successful) {
            throw new CaMgmtException("republishing certificates of CA " + caName + " failed");
        }

        return true;
    } // method republishCertificates

    @Override
    public boolean revokeCa(String caName, final CertRevocationInfo revocationInfo)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("revocationInfo", revocationInfo);
        asssertMasterMode();

        caName = caName.toUpperCase();
        if (!x509cas.containsKey(caName)) {
            return false;
        }

        LOG.info("revoking CA '{}'", caName);
        X509Ca ca = x509cas.get(caName);

        CertRevocationInfo currentRevInfo = ca.getCaInfo().getRevocationInfo();
        if (currentRevInfo != null) {
            CrlReason currentReason = currentRevInfo.getReason();
            if (currentReason != CrlReason.CERTIFICATE_HOLD) {
                throw new CaMgmtException("CA " + caName + " has been revoked with reason "
                        + currentReason.name());
            }
        }

        boolean bo = queryExecutor.revokeCa(caName, revocationInfo);
        if (!bo) {
            return false;
        }

        try {
            ca.revokeCa(revocationInfo, CaAuditConstants.MSGID_CA_mgmt);
        } catch (OperationException ex) {
            throw new CaMgmtException("could not revoke CA " + ex.getMessage(), ex);
        }
        LOG.info("revoked CA '{}'", caName);
        auditLogPciEvent(true, "REVOKE CA " + caName);
        return true;
    } // method revokeCa

    @Override
    public boolean unrevokeCa(String caName) throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        asssertMasterMode();

        caName = caName.toUpperCase();
        if (!x509cas.containsKey(caName)) {
            throw new CaMgmtException("could not find CA named " + caName);
        }

        LOG.info("unrevoking of CA '{}'", caName);

        boolean bo = queryExecutor.unrevokeCa(caName);
        if (!bo) {
            return false;
        }

        X509Ca ca = x509cas.get(caName);
        try {
            ca.unrevokeCa(CaAuditConstants.MSGID_CA_mgmt);
        } catch (OperationException ex) {
            throw new CaMgmtException("could not unrevoke of CA " + ex.getMessage(), ex);
        }
        LOG.info("unrevoked CA '{}'", caName);

        auditLogPciEvent(true, "UNREVOKE CA " + caName);
        return true;
    } // method unrevokeCa

    public void setX509CertProfileFactoryRegister(
            final X509CertprofileFactoryRegister x509CertProfileFactoryRegister) {
        this.x509CertProfileFactoryRegister = x509CertProfileFactoryRegister;
    }

    public void setX509CertPublisherFactoryRegister(
            final X509CertPublisherFactoryRegister x509CertPublisherFactoryRegister) {
        this.x509CertPublisherFactoryRegister = x509CertPublisherFactoryRegister;
    }

    public void setAuditServiceRegister(final AuditServiceRegister serviceRegister) {
        this.auditServiceRegister = ParamUtil.requireNonNull("serviceRegister", serviceRegister);

        for (String name : publishers.keySet()) {
            IdentifiedX509CertPublisher publisherEntry = publishers.get(name);
            publisherEntry.setAuditServiceRegister(auditServiceRegister);
        }

        for (String name : x509cas.keySet()) {
            X509Ca ca = x509cas.get(name);
            ca.setAuditServiceRegister(serviceRegister);
        }
    }

    private void auditLogPciEvent(final boolean successful, final String eventType) {
        PciAuditEvent event = new PciAuditEvent(new Date());
        event.setUserId("CA-SYSTEM");
        event.setEventType(eventType);
        event.setAffectedResource("CORE");
        if (successful) {
            event.setStatus(AuditStatus.SUCCESSFUL.name());
            event.setLevel(AuditLevel.INFO);
        } else {
            event.setStatus(AuditStatus.FAILED.name());
            event.setLevel(AuditLevel.ERROR);
        }
        auditServiceRegister.getAuditService().logEvent(event);
    } // method auditLogPciEvent

    @Override
    public boolean clearPublishQueue(String caName, final List<String> publisherNames)
            throws CaMgmtException {
        asssertMasterMode();

        List<String> upperPublisherNames = CollectionUtil.toUpperCaseList(publisherNames);

        if (caName == null) {
            if (CollectionUtil.isNonEmpty(upperPublisherNames)) {
                throw new IllegalArgumentException("non-empty publisherNames is not allowed");
            }

            try {
                certstore.clearPublishQueue((NameId) null, (NameId) null);
                return true;
            } catch (OperationException ex) {
                throw new CaMgmtException(ex.getMessage(), ex);
            }
        }

        caName = caName.toUpperCase();
        X509Ca ca = x509cas.get(caName);
        if (ca == null) {
            throw new CaMgmtException("could not find CA named " + caName);
        }
        return ca.clearPublishQueue(upperPublisherNames);
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
                LOG.error("interrupted: {}", ex.getMessage());
            }
        }
        scheduledThreadPoolExecutor = null;
    } // method shutdownScheduledThreadPoolExecutor

    @Override
    public boolean revokeCertificate(String caName, final BigInteger serialNumber,
            final CrlReason reason, final Date invalidityTime) throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("serialNumber", serialNumber);
        asssertMasterMode();
        caName = caName.toUpperCase();
        X509Ca ca = getX509Ca(caName);
        try {
            return ca.revokeCertificate(serialNumber, reason, invalidityTime,
                    CaAuditConstants.MSGID_CA_mgmt) != null;
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method revokeCertificate

    @Override
    public boolean unrevokeCertificate(String caName, final BigInteger serialNumber)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("serialNumber", serialNumber);
        caName = caName.toUpperCase();
        X509Ca ca = getX509Ca(caName);
        try {
            return ca.unrevokeCertificate(serialNumber, CaAuditConstants.MSGID_CA_mgmt) != null;
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method unrevokeCertificate

    @Override
    public boolean removeCertificate(String caName, final BigInteger serialNumber)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("serialNumber", serialNumber);
        asssertMasterMode();
        caName = caName.toUpperCase();
        X509Ca ca = getX509Ca(caName);
        if (ca == null) {
            return false;
        }

        try {
            return ca.removeCertificate(serialNumber, CaAuditConstants.MSGID_CA_mgmt) != null;
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method removeCertificate

    @Override
    public X509Certificate generateCertificate(String caName, String profileName,
            final byte[] encodedCsr, Date notBefore, Date notAfter)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonBlank("profileName", profileName);
        ParamUtil.requireNonNull("encodedCsr", encodedCsr);

        caName = caName.toUpperCase();
        profileName = profileName.toUpperCase();

        AuditEvent event = new AuditEvent(new Date());
        event.setApplicationName(CaAuditConstants.APPNAME);
        event.setName(CaAuditConstants.NAME_PERF);
        event.addEventType("CAMGMT_CRL_GEN_ONDEMAND");

        X509Ca ca = getX509Ca(caName);
        CertificationRequest csr;
        try {
            csr = CertificationRequest.getInstance(encodedCsr);
        } catch (Exception ex) {
            throw new CaMgmtException("invalid CSR request. ERROR: " + ex.getMessage());
        }

        CmpControl cmpControl = getCmpControlObject(ca.getCaInfo().getCmpControlName());
        if (!securityFactory.verifyPopo(csr, cmpControl.getPopoAlgoValidator())) {
            throw new CaMgmtException("could not validate POP for the CSR");
        }

        CertificationRequestInfo certTemp = csr.getCertificationRequestInfo();
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
                notBefore, notAfter, extensions, profileName);

        X509CertificateInfo certInfo;
        try {
            certInfo = ca.generateCertificate(certTemplateData, byCaRequestor, RequestType.CA,
                    (byte[]) null, CaAuditConstants.MSGID_CA_mgmt);
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }

        if (ca.getCaInfo().isSaveRequest()) {
            try {
                long dbId = ca.addRequest(encodedCsr);
                ca.addRequestCert(dbId, certInfo.getCert().getCertId());
            } catch (OperationException ex) {
                LogUtil.warn(LOG, ex, "could not save request");
            }
        }

        return certInfo.getCert().getCert();
    } // method generateCertificate

    public X509Ca getX509Ca(String name) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        name = name.toUpperCase();
        X509Ca ca = x509cas.get(name);
        if (ca == null) {
            throw new CaMgmtException("unknown CA " + name);
        }
        return ca;
    }

    public X509Ca getX509Ca(final NameId ident) throws CaMgmtException {
        ParamUtil.requireNonNull("ident", ident);
        X509Ca ca = x509cas.get(ident.getName());
        if (ca == null) {
            throw new CaMgmtException("unknown CA " + ident);
        }
        return ca;
    }

    public IdentifiedX509Certprofile getIdentifiedCertprofile(final String profileName) {
        ParamUtil.requireNonBlank("profileName", profileName);
        return certprofiles.get(profileName.toUpperCase());
    }

    public List<IdentifiedX509CertPublisher> getIdentifiedPublishersForCa(String caName) {
        ParamUtil.requireNonBlank("caName", caName);
        caName = caName.toUpperCase();
        List<IdentifiedX509CertPublisher> ret = new LinkedList<>();
        Set<String> publisherNames = caHasPublishers.get(caName);
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
    public X509Certificate generateRootCa(final X509CaEntry caEntry, String certprofileName,
            final byte[] encodedCsr, final BigInteger serialNumber) throws CaMgmtException {
        ParamUtil.requireNonNull("caEntry", caEntry);
        ParamUtil.requireNonBlank("certprofileName", certprofileName);
        ParamUtil.requireNonNull("encodedCsr", encodedCsr);
        certprofileName = certprofileName.toUpperCase();

        int numCrls = caEntry.getNumCrls();
        List<String> crlUris = caEntry.getCrlUris();
        List<String> deltaCrlUris = caEntry.getDeltaCrlUris();
        List<String> ocspUris = caEntry.getOcspUris();
        List<String> cacertUris = caEntry.getCacertUris();
        String signerType = caEntry.getSignerType();

        asssertMasterMode();

        if (numCrls < 0) {
            System.err.println("invalid numCrls: " + numCrls);
            return null;
        }

        int expirationPeriod = caEntry.getExpirationPeriod();
        if (expirationPeriod < 0) {
            System.err.println("invalid expirationPeriod: " + expirationPeriod);
            return null;
        }

        CertificationRequest csr;
        try {
            csr = CertificationRequest.getInstance(encodedCsr);
        } catch (Exception ex) {
            System.err.println("invalid encodedCsr");
            return null;
        }

        IdentifiedX509Certprofile certprofile = getIdentifiedCertprofile(certprofileName);
        if (certprofile == null) {
            throw new CaMgmtException("unknown certprofile " + certprofileName);
        }

        BigInteger serialOfThisCert = (serialNumber != null) ? serialNumber
                : RandomSerialNumberGenerator.getInstance().nextSerialNumber(
                        caEntry.getSerialNoBitLen());

        GenerateSelfSignedResult result;
        try {
            result = X509SelfSignedCertBuilder.generateSelfSigned(securityFactory, signerType,
                    caEntry.getSignerConf(), certprofile, csr, serialOfThisCert, cacertUris,
                    ocspUris, crlUris, deltaCrlUris);
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

        String name = caEntry.getIdent().getName();
        long nextCrlNumber = caEntry.getNextCrlNumber();
        CaStatus status = caEntry.getStatus();

        X509CaEntry entry = new X509CaEntry(new NameId(null, name), caEntry.getSerialNoBitLen(),
                nextCrlNumber, signerType, signerConf, caUris, numCrls, expirationPeriod);
        entry.setCertificate(caCert);
        entry.setCmpControlName(caEntry.getCmpControlName());
        entry.setCrlSignerName(caEntry.getCrlSignerName());
        entry.setDuplicateKeyPermitted(caEntry.isDuplicateKeyPermitted());
        entry.setDuplicateSubjectPermitted(caEntry.isDuplicateSubjectPermitted());
        entry.setExtraControl(caEntry.getExtraControl());
        entry.setKeepExpiredCertInDays(caEntry.getKeepExpiredCertInDays());
        entry.setMaxValidity(caEntry.getMaxValidity());
        entry.setPermission(caEntry.getPermission());
        entry.setResponderName(caEntry.getResponderName());
        entry.setSaveRequest(caEntry.isSaveRequest());
        entry.setStatus(status);
        entry.setValidityMode(caEntry.getValidityMode());

        addCa(entry);
        return caCert;
    } // method generateRootCa

    private void asssertMasterMode() throws CaMgmtException {
        if (!masterMode) {
            throw new CaMgmtException("operation not allowed in slave mode");
        }
    }

    void shutdownCertprofile(final IdentifiedX509Certprofile profile) {
        if (profile == null) {
            return;
        }

        try {
            profile.shutdown();
        } catch (Exception ex) {
            LogUtil.warn(LOG, ex, "could not shutdown Certprofile " + profile.getIdent());
        }
    } // method shutdownCertprofile

    void shutdownPublisher(final IdentifiedX509CertPublisher publisher) {
        if (publisher == null) {
            return;
        }

        try {
            publisher.shutdown();
        } catch (Exception ex) {
            LogUtil.warn(LOG, ex,
                    "could not shutdown CertPublisher " + publisher.getIdent());
        }
    } // method shutdownPublisher

    CmpResponderEntryWrapper createCmpResponder(final CmpResponderEntry dbEntry)
            throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        CmpResponderEntryWrapper ret = new CmpResponderEntryWrapper();
        ret.setDbEntry(dbEntry);
        try {
            ret.initSigner(securityFactory);
        } catch (ObjectCreationException ex) {
            final String message = "createCmpResponder";
            LOG.debug(message, ex);
            throw new CaMgmtException(ex.getMessage());
        }
        return ret;
    } // method createCmpResponder

    X509CrlSignerEntryWrapper createX509CrlSigner(final X509CrlSignerEntry dbEntry)
            throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        X509CrlSignerEntryWrapper signer = new X509CrlSignerEntryWrapper();
        try {
            signer.setDbEntry(dbEntry);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException("InvalidConfException: " + ex.getMessage());
        }
        try {
            signer.initSigner(securityFactory);
        } catch (XiSecurityException | OperationException | InvalidConfException ex) {
            String message = "could not create CRL signer " + dbEntry.getName();
            LogUtil.error(LOG, ex, message);

            if (ex instanceof OperationException) {
                throw new CaMgmtException(message + ": "
                        + ((OperationException) ex).getErrorCode() + ", " + ex.getMessage());
            } else {
                throw new CaMgmtException(message + ": " + ex.getMessage());
            }
        }

        return signer;
    } // method createX509CrlSigner

    IdentifiedX509Certprofile createCertprofile(final CertprofileEntry dbEntry) {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        try {
            X509Certprofile profile = x509CertProfileFactoryRegister.newCertprofile(
                    dbEntry.getType());
            IdentifiedX509Certprofile ret = new IdentifiedX509Certprofile(dbEntry, profile);
            ret.setEnvParameterResolver(envParameterResolver);
            ret.validate();
            return ret;
        } catch (ObjectCreationException | CertprofileException ex) {
            LogUtil.error(LOG, ex, "could not initialize Certprofile "
                    + dbEntry.getIdent() + ", ignore it");
            return null;
        }
    } // method createCertprofile

    IdentifiedX509CertPublisher createPublisher(final PublisherEntry dbEntry)
            throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        String type = dbEntry.getType();

        X509CertPublisher publisher;
        IdentifiedX509CertPublisher ret;
        try {
            if ("OCSP".equalsIgnoreCase(type)) {
                publisher = new OcspCertPublisher();
            } else {
                publisher = x509CertPublisherFactoryRegister.newPublisher(type);
            }
            ret = new IdentifiedX509CertPublisher(dbEntry, publisher);
            ret.initialize(securityFactory.getPasswordResolver(), datasources);
            return ret;
        } catch (ObjectCreationException | CertPublisherException | RuntimeException ex) {
            LogUtil.error(LOG, ex, "invalid configuration for the publisher "
                    + dbEntry.getIdent());
            return null;
        }
    } // method createPublisher

    @Override
    public boolean addUser(final AddUserEntry userEntry) throws CaMgmtException {
        asssertMasterMode();
        return queryExecutor.addUser(userEntry);
    }

    @Override
    public boolean changeUser(final ChangeUserEntry userEntry)
            throws CaMgmtException {
        asssertMasterMode();
        return queryExecutor.changeUser(userEntry);
    }

    @Override
    public boolean removeUser(final String username) throws CaMgmtException {
        ParamUtil.requireNonBlank("username", username);
        asssertMasterMode();
        return queryExecutor.removeUser(username.toUpperCase());
    }

    @Override
    public UserEntry getUser(final String username) throws CaMgmtException {
        ParamUtil.requireNonBlank("username", username);
        return queryExecutor.getUser(username.toUpperCase());
    }

    CaIdNameMap getIdNameMap() {
        return idNameMap;
    }

    @Override
    public X509CRL generateCrlOnDemand(String caName) throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        caName = caName.toUpperCase();

        X509Ca ca = getX509Ca(caName);
        try {
            return ca.generateCrlOnDemand(CaAuditConstants.MSGID_CA_mgmt);
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method generateCrlOnDemand

    @Override
    public X509CRL getCrl(String caName, final BigInteger crlNumber) throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("crlNumber", crlNumber);
        caName = caName.toUpperCase();
        X509Ca ca = getX509Ca(caName);
        try {
            X509CRL crl = ca.getCrl(crlNumber);
            if (crl == null) {
                LOG.warn("found no CRL for CA {} and crlNumber {}", caName, crlNumber);
            }
            return crl;
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method getCrl

    @Override
    public X509CRL getCurrentCrl(String caName) throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        caName = caName.toUpperCase();
        X509Ca ca = getX509Ca(caName);
        try {
            X509CRL crl = ca.getCurrentCrl();
            if (crl == null) {
                LOG.warn("found no CRL for CA {}", caName);
            }
            return crl;
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method getCurrentCrl

    @Override
    public boolean addScep(final ScepEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        asssertMasterMode();

        NameId caIdent = idNameMap.getCa(dbEntry.getCaIdent().getName());
        if (caIdent == null) {
            LOG.warn("CA {} does not exist", dbEntry.getCaIdent().getName());
        }
        dbEntry.getCaIdent().setId(caIdent.getId());

        Scep scep = new Scep(dbEntry, this);
        boolean bo = queryExecutor.addScep(dbEntry);
        if (bo) {
            final String name = dbEntry.getName();
            scepDbEntries.put(name, dbEntry);
            sceps.put(name, scep);
        }
        return bo;
    } // method addScep

    @Override
    public boolean removeScep(String name) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        asssertMasterMode();
        name = name.toUpperCase();
        boolean bo = queryExecutor.removeScep(name);
        if (bo) {
            scepDbEntries.remove(name);
            sceps.remove(name);
        }
        return bo;
    } // method removeScep

    public boolean changeScep(final ChangeScepEntry scepEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("scepEntry", scepEntry);
        asssertMasterMode();

        String name = scepEntry.getName();
        Boolean active = scepEntry.isActive();
        String type = scepEntry.getResponderType();
        String conf = scepEntry.getResponderConf();
        String base64Cert = scepEntry.getBase64Cert();
        String control = scepEntry.getControl();
        if (type == null && conf == null && base64Cert == null && control == null) {
            return false;
        }

        Scep scep = queryExecutor.changeScep(name, scepEntry.getCaIdent(), active,
                type, conf, base64Cert, scepEntry.getCertProfiles(), control, this);
        if (scep == null) {
            return false;
        }

        sceps.remove(name);
        scepDbEntries.remove(name);
        scepDbEntries.put(name, scep.getDbEntry());
        sceps.put(name, scep);
        return true;
    } // method changeScep

    @Override
    public ScepEntry getScepEntry(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return (scepDbEntries == null) ? null : scepDbEntries.get(name.toUpperCase());
    }

    @Override
    public Scep getScep(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return (sceps == null) ? null : sceps.get(name.toUpperCase());
    }

    @Override
    public Set<String> getScepNames() {
        return (scepDbEntries == null) ? null : Collections.unmodifiableSet(scepDbEntries.keySet());
    }

    private static void assertNotNull(final String parameterName, final String parameterValue) {
        if (CaManager.NULL.equalsIgnoreCase(parameterValue)) {
            throw new IllegalArgumentException(parameterName + " must not be " + CaManager.NULL);
        }
    }

    private static String canonicalizeSignerConf(final String keystoreType, final String signerConf,
            final X509Certificate[] certChain, final SecurityFactory securityFactory)
            throws Exception {
        if (!signerConf.contains("file:") && !signerConf.contains("base64:")) {
            return signerConf;
        }

        ConfPairs pairs = new ConfPairs(signerConf);
        String keystoreConf = pairs.getValue("keystore");
        String passwordHint = pairs.getValue("password");
        String keyLabel = pairs.getValue("key-label");

        byte[] ksBytes;
        if (StringUtil.startsWithIgnoreCase(keystoreConf, "file:")) {
            String keystoreFile = keystoreConf.substring("file:".length());
            ksBytes = IoUtil.read(keystoreFile);
        } else if (StringUtil.startsWithIgnoreCase(keystoreConf, "base64:")) {
            ksBytes = Base64.decode(keystoreConf.substring("base64:".length()));
        } else {
            return signerConf;
        }

        ksBytes = securityFactory.extractMinimalKeyStore(keystoreType, ksBytes, keyLabel,
                securityFactory.getPasswordResolver().resolvePassword(passwordHint), certChain);
        pairs.putPair("keystore", "base64:" + Base64.toBase64String(ksBytes));
        return pairs.getEncoded();
    } // method canonicalizeSignerConf

    @Override
    public CertWithStatusInfo getCert(String caName, BigInteger serialNumber)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("serialNumber", serialNumber);
        caName = caName.toUpperCase();
        X509Ca ca = getX509Ca(caName);
        X509CertWithRevocationInfo certInfo;
        try {
            certInfo = ca.getCertWithRevocationInfo(serialNumber);
        } catch (CertificateException | OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
        return (certInfo != null) ? certInfo.toCertWithStatusInfo() : new CertWithStatusInfo();
    }

    @Override
    public byte[] getCertRequest(String caName, BigInteger serialNumber)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("serialNumber", serialNumber);
        caName = caName.toUpperCase();
        X509Ca ca = getX509Ca(caName);
        try {
            return ca.getCertRequest(serialNumber);
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    }

    @Override
    public List<CertListInfo> listCertificates(String caName, final X500Name subjectPattern,
            final Date validFrom, final Date validTo, final CertListOrderBy orderBy,
            final int numEntries) throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireRange("numEntries", numEntries, 1, 1000);
        caName = caName.toUpperCase();
        X509Ca ca = getX509Ca(caName);
        try {
            return ca.listCertificates(subjectPattern, validFrom, validTo, orderBy, numEntries);
        } catch (OperationException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean loadConf(CaConf conf) throws CaMgmtException {
        ParamUtil.requireNonNull("conf", conf);
        for (String name : conf.getCmpControlNames()) {
            CmpControlEntry entry = conf.getCmpControl(name);
            CmpControlEntry entryB = cmpControlDbEntries.get(name);
            if (entryB != null) {
                if (entry.equals(entryB)) {
                    LOG.info("ignore existed CMP control {}", name);
                } else {
                    String msg = "CMP control " + name + " existed, could not re-added it";
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            } else {
                if (addCmpControl(entry)) {
                    LOG.info("added CMP control {}", name);
                } else {
                    String msg = "could not add CMP control " + name;
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            }
        }

        for (String name : conf.getResponderNames()) {
            CmpResponderEntry entry = conf.getResponder(name);
            CmpResponderEntry entryB = responderDbEntries.get(name);
            if (entryB != null) {
                if (entry.equals(entryB)) {
                    LOG.info("ignore existed CMP responder {}", name);
                } else {
                    String msg = "CMP responder " + name + " existed, could not re-added it";
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            } else {
                if (addResponder(entry)) {
                    LOG.info("added CMP responder {}", name);
                } else {
                    String msg = "could not add CMP responder " + name;
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            }
        }

        for (String name : conf.getEnvironmentNames()) {
            String entry = conf.getEnvironment(name);
            String entryB = envParameterResolver.getEnvParam(name);
            if (entryB != null) {
                if (entry.equals(entryB)) {
                    LOG.info("ignore existed environment parameter {}", name);
                } else {
                    String msg = "environment parameter " + name
                            + " existed, could not re-added it";
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            } else {
                if (addEnvParam(name, entry)) {
                    LOG.info("could not add environment parameter {}", name);
                } else {
                    String msg = "could not add environment parameter " + name;
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            }
        }

        for (String name : conf.getCrlSignerNames()) {
            X509CrlSignerEntry entry = conf.getCrlSigner(name);
            X509CrlSignerEntry entryB = crlSignerDbEntries.get(name);
            if (entryB != null) {
                if (entry.equals(entryB)) {
                    LOG.info("ignore existed CRL signer {}", name);
                } else {
                    String msg = "CRL signer " + name + " existed, could not re-added it";
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            } else {
                if (addCrlSigner(entry)) {
                    LOG.info("added CRL signer {}", name);
                } else {
                    String msg = "could not add CRL signer " + name;
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            }
        }

        for (String name : conf.getCrlSignerNames()) {
            X509CrlSignerEntry entry = conf.getCrlSigner(name);
            X509CrlSignerEntry entryB = crlSignerDbEntries.get(name);
            if (entryB != null) {
                if (entry.equals(entryB)) {
                    LOG.info("ignore existed CRL signer {}", name);
                } else {
                    String msg = "CRL signer " + name + " existed, could not re-added it";
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            } else {
                if (addCrlSigner(entry)) {
                    LOG.info("added CRL signer {}", name);
                } else {
                    String msg = "could not add CRL signer " + name;
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            }
        }

        for (String name : conf.getRequestorNames()) {
            CmpRequestorEntry entry = conf.getRequestor(name);
            CmpRequestorEntry entryB = requestorDbEntries.get(name);
            if (entryB != null) {
                if (entry.equals(entryB)) {
                    LOG.info("ignore existed CMP requestor {}", name);
                    continue;
                } else {
                    String msg = "CMP requestor " + name + " existed, could not re-added it";
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            }

            if (addRequestor(entry)) {
                LOG.info("added CMP requestor {}", name);
            } else {
                String msg = "could not add CMP requestor " + name;
                LOG.error(msg);
                throw new CaMgmtException(msg);
            }
        }

        for (String name : conf.getPublisherNames()) {
            PublisherEntry entry = conf.getPublisher(name);
            PublisherEntry entryB = publisherDbEntries.get(name);
            if (entryB != null) {
                if (entry.equals(entryB)) {
                    LOG.info("ignore existed publisher {}", name);
                    continue;
                } else {
                    String msg = "publisher " + name + " existed, could not re-added it";
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            }

            if (addPublisher(entry)) {
                LOG.info("added publisher {}", name);
            } else {
                String msg = "could not add publisher " + name;
                LOG.error(msg);
                throw new CaMgmtException(msg);
            }
        }

        for (String name : conf.getCertProfileNames()) {
            CertprofileEntry entry = conf.getCertProfile(name);
            CertprofileEntry entryB = certprofileDbEntries.get(name);
            if (entryB != null) {
                if (entry.equals(entryB)) {
                    LOG.info("ignore existed certProfile {}", name);
                } else {
                    String msg = "certProfile " + name + " existed, could not re-added it";
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            } else {
                if (addCertprofile(entry)) {
                    LOG.info("added certProfile {}", name);
                } else {
                    String msg = "could not add certProfile " + name;
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            }
        }

        for (String name : conf.getCertProfileNames()) {
            CertprofileEntry entry = conf.getCertProfile(name);
            CertprofileEntry entryB = certprofileDbEntries.get(name);
            if (entryB != null) {
                if (entry.equals(entryB)) {
                    LOG.info("ignore existed certProfile {}", name);
                } else {
                    String msg = "certProfile " + name + " existed, could not re-added it";
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            } else {
                if (addCertprofile(entry)) {
                    LOG.info("added certProfile {}", name);
                } else {
                    String msg = "could not add certProfile " + name;
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            }
        }

        for (String caName : conf.getCaNames()) {
            SingleCaConf scc = conf.getCa(caName);
            GenSelfIssued genSelfIssued = scc.getGenSelfIssued();
            CaEntry caEntry = scc.getCaEntry();
            if (caEntry != null) {
                if (! (caEntry instanceof X509CaEntry)) {
                    throw new CaMgmtException("Unsupported CaEntry " + caName
                            + " (only X509CaEntry is supported");
                }

                X509CaEntry entry = (X509CaEntry) caEntry;
                if (caInfos.containsKey(caName)) {
                    CaEntry entryB = caInfos.get(caName).getCaEntry();
                    if (entry.getCertificate() == null && genSelfIssued != null) {
                        SignerConf signerConf = new SignerConf(entry.getSignerConf());
                        ConcurrentContentSigner signer;
                        try {
                            signer = securityFactory.createSigner(entry.getSignerType(), signerConf,
                                    (X509Certificate) null);
                        } catch (ObjectCreationException ex) {
                            throw new CaMgmtException("could not create signer for CA " + caName,
                                    ex);
                        }
                        entry.setCertificate(signer.getCertificate());
                    }

                    if (entry.equals(entryB, true)) {
                        LOG.info("ignore existed CA {}", caName);
                    } else {
                        String msg = "CA " + caName + " existed, could not re-added it";
                        LOG.error(msg);
                        throw new CaMgmtException(msg);
                    }
                } else {
                    if (genSelfIssued != null) {
                        X509Certificate cert = generateRootCa(entry, genSelfIssued.getProfile(),
                                genSelfIssued.getCsr(), genSelfIssued.getSerialNumber());
                        LOG.info("generated root CA {}", caName);
                        String fn = genSelfIssued.getCertFilename();
                        if (fn != null) {
                            try {
                                IoUtil.save(fn, cert.getEncoded());
                                LOG.info("saved generated certificate of root CA {} to {}",
                                        caName, fn);
                            } catch (CertificateEncodingException ex) {
                                LogUtil.error(LOG, ex,
                                        "could not encode certificate of CA " + caName);
                            } catch (IOException ex) {
                                LogUtil.error(LOG, ex, "error while saving certificate of root CA "
                                        + caName + " to " + fn);
                            }
                        }
                    } else  if (addCa(entry)) {
                        LOG.info("added CA {}", caName);
                    } else {
                        String msg = "could not add CA " + caName;
                        LOG.error(msg);
                        throw new CaMgmtException(msg);
                    }
                }
            }

            if (scc.getAliases() != null) {
                Set<String> aliasesB = getAliasesForCa(caName);
                for (String aliasName : scc.getAliases()) {
                    if (aliasesB != null && aliasesB.contains(aliasName)) {
                        LOG.info("ignored adding existing CA alias {} to CA {}", aliasName, caName);
                    } else {
                        if (addCaAlias(aliasName, caName)) {
                            LOG.info("associated alias {} to CA {}", aliasName, caName);
                        } else {
                            String msg = "could not associate alias " + aliasName + " to CA "
                                    + caName;
                            LOG.error(msg);
                            throw new CaMgmtException(msg);
                        }
                    }
                }
            }

            if (scc.getProfileNames() != null) {
                Set<String> profilesB = caHasProfiles.get(caName);
                for (String profileName : scc.getProfileNames()) {
                    if (profilesB != null && profilesB.contains(profileName)) {
                        LOG.info("ignored adding certprofile {} to CA {}", profileName, caName);
                    } else {
                        if (addCertprofileToCa(profileName, caName)) {
                            LOG.info("added certprofile {} to CA {}", profileName, caName);
                        } else {
                            String msg = "could not add certprofile " + profileName + " to CA "
                                    + caName;
                            LOG.error(msg);
                            throw new CaMgmtException(msg);
                        }
                    }
                }
            }

            if (scc.getPublisherNames() != null) {
                Set<String> publishersB = caHasPublishers.get(caName);
                for (String publisherName : scc.getPublisherNames()) {
                    if (publishersB != null && publishersB.contains(publisherName)) {
                        LOG.info("ignored adding publisher {} to CA {}", publisherName, caName);
                    } else {
                        if (addPublisherToCa(publisherName, caName)) {
                            LOG.info("added publisher {} to CA {}", publisherName, caName);
                        } else {
                            String msg = "could not add publisher " + publisherName + " to CA "
                                    + caName;
                            LOG.error(msg);
                            throw new CaMgmtException(msg);
                        }
                    }
                }
            }

            if (scc.getRequestors() != null) {
                Set<CaHasRequestorEntry> requestorsB = caHasRequestors.get(caName);

                for (CaHasRequestorEntry requestor : scc.getRequestors()) {
                    String requestorName = requestor.getRequestorIdent().getName();
                    CaHasRequestorEntry requestorB = null;
                    if (requestorsB != null) {
                        for (CaHasRequestorEntry m : requestorsB) {
                            if (m.getRequestorIdent().getName().equals(requestorName)) {
                                requestorB = m;
                                break;
                            }
                        }
                    }

                    if (requestorB != null) {
                        if (requestor.equals(requestorB)) {
                            LOG.info("ignored adding requestor {} to CA {}", requestorName, caName);
                        } else {
                            String msg = "could not add requestor " + requestorName + " to CA"
                                    + caName;
                            LOG.error(msg);
                            throw new CaMgmtException(msg);
                        }
                    } else {
                        if (addRequestorToCa(requestor, caName)) {
                            LOG.info("added publisher {} to CA {}", requestorName, caName);
                        } else {
                            String msg = "could not add publisher " + requestorName + " to CA "
                                    + caName;
                            LOG.error(msg);
                            throw new CaMgmtException(msg);
                        }
                    }
                }
            } // scc.getRequestors()
        } // cas

        for (String name : conf.getScepNames()) {
            ScepEntry entry = conf.getScep(name);
            ScepEntry entryB = scepDbEntries.get(name);
            if (entryB != null) {
                if (entry.equals(entryB)) {
                    LOG.error("ignore existed SCEP {}", name);
                    continue;
                } else {
                    String msg = "SCEP " + name + " existed, could not re-added it";
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            } else {
                if (addScep(entry)) {
                    LOG.info("added SCEP {}", name);
                } else {
                    String msg = "could not add SCEP " + name;
                    LOG.error(msg);
                    throw new CaMgmtException(msg);
                }
            }
        }

        return true;
    }

    @Override
    public boolean exportConf(@NonNull String zipFilename, @Nullable List<String> caNames)
            throws CaMgmtException, IOException {
        List<String> upperCaNames;
        if (caNames == null) {
            upperCaNames = null;
        } else {
            upperCaNames = new ArrayList<>(caNames.size());
            for (String name : caNames) {
                upperCaNames.add(name);
            }
        }

        File zipFile = new File(zipFilename);
        if (zipFile.exists()) {
            throw new IOException("File " + zipFilename + " exists.");
        }

        CAConfType root = new CAConfType();
        root.setVersion(1);

        ZipOutputStream zipStream = getZipOutputStream(zipFile);
        try {
            Set<String> includeCaNames = new HashSet<>();
            Set<String> includeCmpControlNames = new HashSet<>();
            Set<String> includeResponderNames = new HashSet<>();
            Set<String> includeRequestorNames = new HashSet<>();
            Set<String> includeProfileNames = new HashSet<>();
            Set<String> includePublisherNames = new HashSet<>();
            Set<String> includeCrlSignerNames = new HashSet<>();

            // cas
            if (CollectionUtil.isNonEmpty(x509cas)) {
                List<CaType> list = new LinkedList<>();

                for (String name : x509cas.keySet()) {
                    if (upperCaNames != null && !upperCaNames.contains(name)) {
                        continue;
                    }
                    includeCaNames.add(name);

                    CaType jaxb = new CaType();
                    jaxb.setName(name);

                    Set<String> strs = getAliasesForCa(name);
                    if (CollectionUtil.isNonEmpty(strs)) {
                        jaxb.setAliases(createStrings(strs));
                    }

                    strs = caHasProfiles.get(name);
                    if (CollectionUtil.isNonEmpty(strs)) {
                        includeProfileNames.addAll(strs);
                        jaxb.setProfiles(createStrings(strs));
                    }

                    strs = caHasPublishers.get(name);
                    if (CollectionUtil.isNonEmpty(strs)) {
                        includePublisherNames.addAll(strs);
                        jaxb.setPublishers(createStrings(strs));
                    }

                    Set<CaHasRequestorEntry> requestors = caHasRequestors.get(name);
                    if (CollectionUtil.isNonEmpty(requestors)) {
                        jaxb.setRequestors(new CaType.Requestors());

                        for (CaHasRequestorEntry m : requestors) {
                            String requestorName = m.getRequestorIdent().getName();
                            includeRequestorNames.add(requestorName);

                            CaHasRequestorType jaxb2 = new CaHasRequestorType();
                            jaxb2.setRequestorName(requestorName);
                            jaxb2.setRa(m.isRa());
                            jaxb2.setProfiles(createStrings(m.getProfiles()));
                            jaxb2.setPermission(m.getPermission());

                            jaxb.getRequestors().getRequestor().add(jaxb2);
                        }
                    }

                    X509CaEntry entry = x509cas.get(name).getCaInfo().getCaEntry();
                    X509CaInfoType ciJaxb = new X509CaInfoType();
                    ciJaxb.setCacertUris(createStrings(entry.getCacertUris()));
                    byte[] certBytes;
                    try {
                        certBytes = entry.getCertificate().getEncoded();
                    } catch (CertificateEncodingException ex) {
                        throw new CaMgmtException("could not encode CA certificate " + name);
                    }
                    ciJaxb.setCert(createFileOrBinary(zipStream, certBytes,
                            "files/ca-" + name + "-cert.der"));

                    if (entry.getCmpControlName() != null) {
                        includeCmpControlNames.add(entry.getCmpControlName());
                        ciJaxb.setCmpcontrolName(entry.getCmpControlName());
                    }

                    if (entry.getCrlSignerName() != null) {
                        includeCrlSignerNames.add(entry.getCrlSignerName());
                        ciJaxb.setCrlsignerName(entry.getCrlSignerName());
                    }

                    ciJaxb.setCrlUris(createStrings(entry.getCrlUris()));
                    ciJaxb.setDeltacrlUris(createStrings(entry.getDeltaCrlUris()));
                    ciJaxb.setDuplicateKey(entry.isDuplicateKeyPermitted());
                    ciJaxb.setDuplicateSubject(entry.isDuplicateSubjectPermitted());
                    ciJaxb.setExpirationPeriod(entry.getExpirationPeriod());
                    ciJaxb.setExtraControl(
                            createFileOrValue(zipStream, entry.getExtraControl(),
                                    "files/ca-" + name + "-extracontrol.conf"));
                    ciJaxb.setKeepExpiredCertDays(entry.getKeepExpiredCertInDays());
                    ciJaxb.setMaxValidity(entry.getMaxValidity().toString());
                    ciJaxb.setNextCrlNo(entry.getNextCrlNumber());
                    ciJaxb.setNumCrls(entry.getNumCrls());
                    ciJaxb.setOcspUris(createStrings(entry.getOcspUris()));
                    ciJaxb.setPermission(entry.getPermission());
                    if (entry.getResponderName() != null) {
                        includeResponderNames.add(entry.getResponderName());
                        ciJaxb.setResponderName(entry.getResponderName());
                    }
                    ciJaxb.setSaveReq(entry.isSaveRequest());
                    ciJaxb.setSignerConf(createFileOrValue(zipStream, entry.getSignerConf(),
                            "files/ca-" + name + "-signerconf.conf"));
                    ciJaxb.setSignerType(entry.getSignerType());
                    ciJaxb.setSnSize(entry.getSerialNoBitLen());
                    ciJaxb.setStatus(entry.getStatus().getStatus());
                    ciJaxb.setValidityMode(entry.getValidityMode().name());

                    jaxb.setCaInfo(new CaType.CaInfo());
                    jaxb.getCaInfo().setX509Ca(ciJaxb);

                    list.add(jaxb);
                }

                if (!list.isEmpty()) {
                    root.setCas(new CAConfType.Cas());
                    root.getCas().getCa().addAll(list);
                }
            }

            // cmp controls
            if (CollectionUtil.isNonEmpty(cmpControlDbEntries)) {
                List<CmpcontrolType> list = new LinkedList<>();

                for (String name : cmpControlDbEntries.keySet()) {
                    if (!includeCmpControlNames.contains(name)) {
                        continue;
                    }

                    CmpcontrolType jaxb = new CmpcontrolType();
                    CmpControlEntry entry = cmpControlDbEntries.get(name);
                    jaxb.setName(name);
                    jaxb.setConf(createFileOrValue(zipStream, entry.getConf(),
                            "files/cmpcontrol-" + name + ".conf"));
                    list.add(jaxb);
                }

                if (!list.isEmpty()) {
                    root.setCmpcontrols(new CAConfType.Cmpcontrols());
                    root.getCmpcontrols().getCmpcontrol().addAll(list);
                }
            }

            // responders
            if (CollectionUtil.isNonEmpty(responderDbEntries)) {
                List<ResponderType> list = new LinkedList<>();

                for (String name : responderDbEntries.keySet()) {
                    if (!includeResponderNames.contains(name)) {
                        continue;
                    }

                    CmpResponderEntry entry = responderDbEntries.get(name);
                    ResponderType jaxb = new ResponderType();
                    jaxb.setName(name);
                    jaxb.setType(entry.getType());
                    jaxb.setConf(createFileOrValue(zipStream, entry.getConf(),
                            "files/responder-" + name + ".conf"));
                    jaxb.setCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
                            "files/responder-" + name + ".der"));

                    list.add(jaxb);
                }

                if (!list.isEmpty()) {
                    root.setResponders(new CAConfType.Responders());
                    root.getResponders().getResponder().addAll(list);
                }
            }

            // environments
            Set<String> names = envParameterResolver.getAllParameterNames();
            if (CollectionUtil.isNonEmpty(names)) {
                List<NameValueType> list = new LinkedList<>();

                for (String name : names) {
                    if (ENV_EPOCH.equalsIgnoreCase(name)) {
                        continue;
                    }

                    NameValueType jaxb = new NameValueType();
                    jaxb.setName(name);
                    jaxb.setValue(envParameterResolver.getEnvParam(name));

                    list.add(jaxb);
                }

                if (!list.isEmpty()) {
                    root.setEnvironments(new CAConfType.Environments());
                    root.getEnvironments().getEnvironment().addAll(list);
                }
            }

            // crlsigners
            if (CollectionUtil.isNonEmpty(crlSignerDbEntries)) {
                List<CrlsignerType> list = new LinkedList<>();

                for (String name : crlSignerDbEntries.keySet()) {
                    if (!includeCrlSignerNames.contains(name)) {
                        continue;
                    }

                    X509CrlSignerEntry entry = crlSignerDbEntries.get(name);
                    CrlsignerType jaxb = new CrlsignerType();
                    jaxb.setName(name);
                    jaxb.setSignerType(entry.getType());
                    jaxb.setSignerConf(createFileOrValue(zipStream, entry.getConf(),
                            "files/crlsigner-" + name + ".conf"));
                    jaxb.setSignerCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
                            "files/crlsigner-" + name + ".der"));
                    jaxb.setCrlControl(entry.getCrlControl());

                    list.add(jaxb);
                }

                if (!list.isEmpty()) {
                    root.setCrlsigners(new CAConfType.Crlsigners());
                    root.getCrlsigners().getCrlsigner().addAll(list);
                }
            }

            // requestors
            if (CollectionUtil.isNonEmpty(requestorDbEntries)) {
                List<RequestorType> list = new LinkedList<>();
                for (String name : requestorDbEntries.keySet()) {
                    if (!includeRequestorNames.contains(name)) {
                        continue;
                    }

                    CmpRequestorEntry entry = requestorDbEntries.get(name);
                    RequestorType jaxb = new RequestorType();
                    jaxb.setName(name);
                    jaxb.setCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
                            "files/requestor-" + name + ".der"));

                    list.add(jaxb);
                }

                if (!list.isEmpty()) {
                    root.setRequestors(new CAConfType.Requestors());
                    root.getRequestors().getRequestor().addAll(list);
                }
            }

            // publishers
            if (CollectionUtil.isNonEmpty(publisherDbEntries)) {
                List<PublisherType> list = new LinkedList<>();
                for (String name : publisherDbEntries.keySet()) {
                    if (!includePublisherNames.contains(name)) {
                        continue;
                    }
                    PublisherEntry entry = publisherDbEntries.get(name);
                    PublisherType jaxb = new PublisherType();
                    jaxb.setName(name);
                    jaxb.setType(entry.getType());
                    jaxb.setConf(createFileOrValue(zipStream, entry.getConf(),
                            "files/publisher-" + name + ".conf"));
                    list.add(jaxb);
                }

                if (!list.isEmpty()) {
                    root.setPublishers(new CAConfType.Publishers());
                    root.getPublishers().getPublisher().addAll(list);
                }
            }

            // profiles
            if (CollectionUtil.isNonEmpty(certprofileDbEntries)) {
                List<ProfileType> list = new LinkedList<>();
                for (String name : certprofileDbEntries.keySet()) {
                    if (!includeProfileNames.contains(name)) {
                        continue;
                    }
                    CertprofileEntry entry = certprofileDbEntries.get(name);
                    ProfileType jaxb = new ProfileType();
                    jaxb.setName(name);
                    jaxb.setType(entry.getType());
                    jaxb.setConf(createFileOrValue(zipStream, entry.getConf(),
                            "files/certprofile-" + name + ".conf"));
                    list.add(jaxb);
                }

                if (!list.isEmpty()) {
                    root.setProfiles(new CAConfType.Profiles());
                    root.getProfiles().getProfile().addAll(list);
                }
            }

            // sceps
            if (CollectionUtil.isNonEmpty(scepDbEntries)) {
                List<ScepType> list = new LinkedList<>();
                for (String name : scepDbEntries.keySet()) {
                    if (!includeCaNames.contains(name)) {
                        continue;
                    }
                    ScepEntry entry = scepDbEntries.get(name);
                    ScepType jaxb = new ScepType();
                    jaxb.setCaName(name);
                    jaxb.setResponderType(entry.getResponderType());
                    jaxb.setResponderConf(createFileOrValue(zipStream, entry.getResponderConf(),
                            "files/scep-" + name + ".conf"));
                    jaxb.setResponderCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
                            "files/scep-" + name + ".der"));
                    jaxb.setControl(entry.getControl());

                    list.add(jaxb);
                }

                if (!list.isEmpty()) {
                    root.setSceps(new CAConfType.Sceps());
                    root.getSceps().getScep().addAll(list);
                }
            }

            // add the CAConf XML file
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            try {
                CaConf.marshal(root, bout);
            } catch (JAXBException | SAXException ex) {
                LogUtil.error(LOG, ex, "could not marshal CAConf");
                throw new CaMgmtException("could not marshal CAConf: " + ex.getMessage(), ex);
            } finally {
                bout.flush();
            }

            zipStream.putNextEntry(new ZipEntry("caconf.xml"));
            try {
                zipStream.write(bout.toByteArray());
            } finally {
                zipStream.closeEntry();
            }
        } finally {
            zipStream.close();
        }

        return true;
    }

    private static FileOrValueType createFileOrValue(final ZipOutputStream zipStream,
            final String content, final String fileName) throws IOException {
        if (StringUtil.isBlank(content)) {
            return null;
        }

        FileOrValueType ret = new FileOrValueType();
        if (content.length() < 256) {
            ret.setValue(content);
        } else {
            ret.setFile(fileName);
            ZipEntry certZipEntry = new ZipEntry(fileName);
            zipStream.putNextEntry(certZipEntry);
            try {
                zipStream.write(content.getBytes("UTF-8"));
            } finally {
                zipStream.closeEntry();
            }
        }
        return ret;
    }

    private static FileOrBinaryType createFileOrBase64Value(final ZipOutputStream zipStream,
            final String b64Content, final String fileName) throws IOException {
        if (StringUtil.isBlank(b64Content)) {
            return null;
        }

        return createFileOrBinary(zipStream, Base64.decode(b64Content), fileName);
    }

    private static FileOrBinaryType createFileOrBinary(final ZipOutputStream zipStream,
            final byte[] content, final String fileName) throws IOException {
        if (content == null || content.length == 0) {
            return null;
        }

        FileOrBinaryType ret = new FileOrBinaryType();
        if (content.length < 256) {
            ret.setBinary(content);
        } else {
            ret.setFile(fileName);
            ZipEntry certZipEntry = new ZipEntry(fileName);
            zipStream.putNextEntry(certZipEntry);
            try {
                zipStream.write(content);
            } finally {
                zipStream.closeEntry();
            }
        }
        return ret;
    }

    private static ZipOutputStream getZipOutputStream(final File zipFile)
            throws FileNotFoundException {
        ParamUtil.requireNonNull("zipFile", zipFile);

        BufferedOutputStream out = new BufferedOutputStream(
                new FileOutputStream(zipFile), 1048576); // 1M
        ZipOutputStream zipOutStream = new ZipOutputStream(out);
        zipOutStream.setLevel(Deflater.BEST_SPEED);
        return zipOutStream;
    }

    private static StringsType createStrings(Collection<String> strs) {
        if (CollectionUtil.isEmpty(strs)) {
            return null;
        }

        StringsType ret = new StringsType();
        for (String str : strs) {
            ret.getStr().add(str);
        }
        return ret;
    }

}
