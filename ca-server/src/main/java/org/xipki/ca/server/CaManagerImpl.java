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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.audit.Audits;
import org.xipki.audit.PciAuditEvent;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.api.mgmt.CaConf;
import org.xipki.ca.api.mgmt.CaConfType;
import org.xipki.ca.api.mgmt.CaConfType.NameTypeConf;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CaSystemStatus;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.api.mgmt.CertListOrderBy;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.MgmtEntry;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.CertprofileFactoryRegister;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertPublisherFactoryRegister;
import org.xipki.ca.server.CaManagerQueryExecutor.SystemEvent;
import org.xipki.ca.server.SelfSignedCertBuilder.GenerateSelfSignedResult;
import org.xipki.ca.server.cmp.CmpResponder;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceConf;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.CrlReason;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.DateUtil;
import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.StringUtil;
import org.xipki.util.http.SslContextConf;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

/**
 * Manages the CA system.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaManagerImpl implements CaManager, Closeable {

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

  } // class CertsInQueuePublisher

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

  } // class UnreferencedRequstCleaner

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

  } // class CaRestarter

  private static final Logger LOG = LoggerFactory.getLogger(CaManagerImpl.class);

  private static final String version;

  private static final String EVENT_LOCK = "LOCK";

  private static final String EVENT_CACHAGNE = "CA_CHANGE";

  private final String lockInstanceId;

  private final CaIdNameMap idNameMap = new CaIdNameMap();

  private RequestorInfo byCaRequestor;

  private NameId byUserRequestorId;

  private boolean caLockedByMe;

  private boolean masterMode;

  private Map<String, FileOrValue> datasourceNameConfFileMap;

  private final Map<String, CaInfo> caInfos = new ConcurrentHashMap<>();

  private Map<String, SignerEntryWrapper> signers = new ConcurrentHashMap<>();

  private Map<String, MgmtEntry.Signer> signerDbEntries = new ConcurrentHashMap<>();

  private final Map<String, IdentifiedCertprofile> certprofiles = new ConcurrentHashMap<>();

  private final Map<String, MgmtEntry.Certprofile> certprofileDbEntries = new ConcurrentHashMap<>();

  private final Map<String, IdentifiedCertPublisher> publishers = new ConcurrentHashMap<>();

  private final Map<String, MgmtEntry.Publisher> publisherDbEntries = new ConcurrentHashMap<>();

  private final Map<String, RequestorEntryWrapper> requestors = new ConcurrentHashMap<>();

  private final Map<String, MgmtEntry.Requestor> requestorDbEntries = new ConcurrentHashMap<>();

  private final Map<String, Set<String>> caHasProfiles = new ConcurrentHashMap<>();

  private final Map<String, Set<String>> caHasPublishers = new ConcurrentHashMap<>();

  private final Map<String, Set<MgmtEntry.CaHasRequestor>> caHasRequestors =
      new ConcurrentHashMap<>();

  private final Map<String, Integer> caAliases = new ConcurrentHashMap<>();

  private ScheduledThreadPoolExecutor persistentScheduledThreadPoolExecutor;

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  private final Map<String, CmpResponder> cmpResponders = new ConcurrentHashMap<>();

  private final Map<String, ScepResponder> scepResponders = new ConcurrentHashMap<>();

  private final Map<String, X509Ca> x509cas = new ConcurrentHashMap<>();

  private final DataSourceFactory datasourceFactory;

  private final RestResponder restResponder;

  private CtLogPublicKeyFinder ctLogPublicKeyFinder;

  private CaServerConf caServerConf;

  private boolean caSystemSetuped;

  private boolean signerInitialized;

  private boolean requestorsInitialized;

  private boolean caAliasesInitialized;

  private boolean certprofilesInitialized;

  private boolean publishersInitialized;

  private boolean casInitialized;

  private Date lastStartTime;

  private CertprofileFactoryRegister certprofileFactoryRegister;

  private CertPublisherFactoryRegister certPublisherFactoryRegister;

  private DataSourceWrapper datasource;

  private CertStore certstore;

  private SecurityFactory securityFactory;

  private CaManagerQueryExecutor queryExecutor;

  private boolean initializing;

  static {
    String ver;
    try {
      ver = new String(IoUtil.read(CaManagerImpl.class.getResourceAsStream("/version"))).trim();
    } catch (Exception ex) {
      ver = "UNKNOWN";
    }
    version = ver;
  }

  public CaManagerImpl() {
    LOG.info("XiPKI CA version {}", version);

    this.datasourceFactory = new DataSourceFactory();
    String calockId = null;
    File caLockFile = new File(IoUtil.expandFilepath("calock"));
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
        IoUtil.save(caLockFile, StringUtil.toUtf8Bytes(calockId));
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
    this.restResponder = new RestResponder(this);
  } // constructor

  public SecurityFactory getSecurityFactory() {
    return securityFactory;
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  public DataSourceFactory getDataSourceFactory() {
    return datasourceFactory;
  }

  public boolean isMasterMode() {
    return masterMode;
  }

  @Override
  public Set<String> getSupportedSignerTypes() {
    return securityFactory.getSupportedSignerTypes();
  }

  @Override
  public Set<String> getSupportedCertprofileTypes() {
    return certprofileFactoryRegister.getSupportedTypes();
  }

  @Override
  public Set<String> getSupportedPublisherTypes() {
    return certPublisherFactoryRegister.getSupportedTypes();
  }

  private void init() throws CaMgmtException {
    if (securityFactory == null) {
      throw new IllegalStateException("securityFactory is not set");
    }
    if (datasourceFactory == null) {
      throw new IllegalStateException("datasourceFactory is not set");
    }
    if (certprofileFactoryRegister == null) {
      throw new IllegalStateException("certprofileFactoryRegister is not set");
    }
    if (certPublisherFactoryRegister == null) {
      throw new IllegalStateException("certPublisherFactoryRegister is not set");
    }
    if (caServerConf == null) {
      throw new IllegalStateException("caServerConf is not set");
    }

    masterMode = caServerConf.isMaster();
    LOG.info("ca.masterMode: {}", masterMode);

    int shardId = caServerConf.getShardId();
    LOG.info("ca.shardId: {}", shardId);

    if (caServerConf.getCtLog() != null) {
      try {
        ctLogPublicKeyFinder = new CtLogPublicKeyFinder(caServerConf.getCtLog());
      } catch (Exception ex) {
        throw new CaMgmtException("could not load CtLogPublicKeyFinder: " + ex.getMessage(), ex);
      }
    }

    if (this.datasourceNameConfFileMap == null) {
      this.datasourceNameConfFileMap = new ConcurrentHashMap<>();
      List<DataSourceConf> datasourceList = caServerConf.getDatasources();
      for (DataSourceConf datasource : datasourceList) {
        this.datasourceNameConfFileMap.put(datasource.getName(), datasource.getConf());
      }

      FileOrValue caDatasourceConf = datasourceNameConfFileMap.remove("ca");
      if (caDatasourceConf == null) {
        throw new CaMgmtException("no datasource named 'ca' configured");
      }

      this.datasource = loadDatasource("ca", caDatasourceConf);
    }

    this.queryExecutor = new CaManagerQueryExecutor(this.datasource);

    if (masterMode) {
      lockCa(true);

      queryExecutor.addRequestorIfNeeded(RequestorInfo.NAME_BY_CA);
      queryExecutor.addRequestorIfNeeded(RequestorInfo.NAME_BY_USER);
    }

    final long epoch = DateUtil.parseUtcTimeyyyyMMdd("20100101").getTime();
    UniqueIdGenerator idGen = new UniqueIdGenerator(epoch, shardId);

    try {
      this.certstore = new CertStore(datasource, idGen);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }

    initCaAliases();
    initCertprofiles();
    initPublishers();
    initRequestors();
    initSigners();
    initCas();
  } // method init

  private DataSourceWrapper loadDatasource(String datasourceName, FileOrValue datasourceConf)
      throws CaMgmtException {
    try {
      DataSourceWrapper datasource = datasourceFactory.createDataSource(
          datasourceName, datasourceConf, securityFactory.getPasswordResolver());

      // test the datasource
      Connection conn = datasource.getConnection();
      datasource.returnConnection(conn);

      LOG.info("loaded datasource.{}", datasourceName);
      return datasource;
    } catch (DataAccessException | PasswordResolverException | IOException
        | RuntimeException ex) {
      throw new CaMgmtException(concat(ex.getClass().getName(),
        " while parsing datasource ", datasourceName, ": ", ex.getMessage()), ex);
    }
  } // method loadDatasource

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
  } // method getCaSystemStatus

  private void lockCa(boolean forceRelock) throws CaMgmtException {
    SystemEvent lockInfo = queryExecutor.getSystemEvent(EVENT_LOCK);

    if (lockInfo != null) {
      String lockedBy = lockInfo.getOwner();
      Date lockedAt = new Date(lockInfo.getEventTime() * 1000L);

      if (!this.lockInstanceId.equals(lockedBy)) {
        String msg = concat("could not lock CA, it has been locked by ", lockedBy, " since ",
            lockedAt.toString(),  ". In general this indicates that another"
            + " CA software in active mode is accessing the database or the last shutdown of CA"
            + " software in active mode is abnormal.");
        throw logAndCreateException(msg);
      }

      if (forceRelock) {
        LOG.info("CA has been locked by me since {}, re-lock it", lockedAt);
      }
    }

    SystemEvent newLockInfo = new SystemEvent(EVENT_LOCK, lockInstanceId,
        System.currentTimeMillis() / 1000L);
    queryExecutor.changeSystemEvent(newLockInfo);
    caLockedByMe = true;
  } // method lockCa

  @Override
  public void unlockCa() throws CaMgmtException {
    if (!masterMode) {
      throw logAndCreateException("could not unlock CA in slave mode");
    }

    boolean succ = false;
    try {
      queryExecutor.unlockCa();
      LOG.info("unlocked CA");
      succ = true;
    } finally {
      auditLogPciEvent(succ, "UNLOCK");
    }
  } // method unlockCa

  private void reset() {
    caSystemSetuped = false;
    signerInitialized = false;
    requestorsInitialized = false;
    caAliasesInitialized = false;
    certprofilesInitialized = false;
    publishersInitialized = false;
    casInitialized = false;
    ctLogPublicKeyFinder = null;

    shutdownScheduledThreadPoolExecutor();
  } // method reset

  @Override
  public void restartCa(String name) throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    assertMasterModeAndSetuped();

    NameId ident = idNameMap.getCa(name);
    if (ident == null) {
      throw new CaMgmtException("Unknown CA " + name);
    }

    if (createCa(name)) {
      CaInfo caInfo = caInfos.get(name);
      if (CaStatus.ACTIVE != caInfo.getCaEntry().getStatus()) {
        return;
      }

      if (startCa(name)) {
        LOG.info("started CA {}", name);
      } else {
        LOG.error("could not start CA {}", name);
      }
    } else {
      LOG.error("could not create CA {}", name);
    }
  } // method restartCa

  @Override
  public void restartCaSystem() throws CaMgmtException {
    reset();
    boolean caSystemStarted = startCaSystem0();
    auditLogPciEvent(caSystemStarted, "CA_CHANGE");

    if (!caSystemStarted) {
      throw logAndCreateException("could not restart CA system");
    }
  } // method restartCaSystem

  @Override
  public void notifyCaChange() throws CaMgmtException {
    try {
      SystemEvent systemEvent = new SystemEvent(EVENT_CACHAGNE, lockInstanceId,
          System.currentTimeMillis() / 1000L);
      queryExecutor.changeSystemEvent(systemEvent);
      LOG.info("notified the change of CA system");
    } catch (CaMgmtException ex) {
      LogUtil.warn(LOG, ex, "could not notify slave CAs to restart");
      throw ex;
    }
  } // method notifyCaChange

  public void startCaSystem() {
    boolean caSystemStarted = false;
    try {
      caSystemStarted = startCaSystem0();
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "could not start CA system");
    }

    if (!caSystemStarted) {
      LOG.error("could not start CA system");
    }

    auditLogPciEvent(caSystemStarted, "START");
  } // method startCaSystem

  private boolean startCaSystem0() {
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
      cmpResponders.clear();
      scepResponders.clear();

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
          if (name != null) {
            sb.append(name).append(" (alias ").append(aliasName).append("), ");
          }
        }

        for (String name : names) {
          sb.append(name).append(", ");
        }

        int len = sb.length();
        sb.delete(len - 2, len);

        scheduledThreadPoolExecutor.scheduleAtFixedRate(
            new CertsInQueuePublisher(), 120, 120, TimeUnit.SECONDS);
        scheduledThreadPoolExecutor.scheduleAtFixedRate(
            new UnreferencedRequstCleaner(), 60, 24L * 60 * 60, // 1 DAY
            TimeUnit.SECONDS);
      } else {
        sb.append(": no CA is configured");
      }

      if (!failedCaNames.isEmpty()) {
        sb.append(", and following CAs could not be started: ");
        for (String aliasName : caAliasNames) {
          String name = getCaNameForAlias(aliasName);
          if (failedCaNames.remove(name)) {
            sb.append(name).append(" (alias ").append(aliasName).append("), ");
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
  } // method startCaSystem0

  private boolean startCa(String caName) {
    CaInfo caEntry = caInfos.get(caName);

    CtlogControl ctlogControl = caEntry.getCaEntry().getCtlogControl();
    CtLogClient ctlogClient = null;
    if (ctlogControl != null && ctlogControl.isEnabled()) {
      String name = ctlogControl.getSslContextName();
      SslContextConf ctxConf;
      if (name == null) {
        ctxConf = null;
      } else {
        ctxConf = caServerConf.getSslContextConf(name);
        if (ctxConf == null) {
          LOG.error(concat("getSslContextConf (ca=", caName,
              "): found no SslContext named " + name));
          return false;
        } else {
          try {
            ctxConf.getSslContext();
          } catch (ObjectCreationException ex) {
            LOG.error(concat("startCa (ca=", caName,
                        "): could not initialize SslContext named " + name));
            return false;
          }
        }
      }
      ctlogClient = new CtLogClient(ctlogControl.getServers(), ctxConf);
    }

    X509Ca ca;
    try {
      ca = new X509Ca(this, caEntry, certstore, ctlogClient);
    } catch (OperationException ex) {
      LogUtil.error(LOG, ex, concat("X509CA.<init> (ca=", caName, ")"));
      return false;
    }

    x509cas.put(caName, ca);
    CmpResponder caResponder;
    try {
      caResponder = new CmpResponder(this, caName);
    } catch (NoSuchAlgorithmException ex) {
      LogUtil.error(LOG, ex, concat("CmpResponder.<init> (ca=", caName, ")"));
      return false;
    }

    cmpResponders.put(caName, caResponder);

    if (caEntry.getScepResponderName() != null) {
      try {
        scepResponders.put(caName, new ScepResponder(this, caEntry.getCaEntry()));
      } catch (CaMgmtException ex) {
        LogUtil.error(LOG, ex, concat("ScepResponder.<init> (ca=", caName, ")"));
        return false;
      }
    }
    return true;
  } // method startCa

  @Override
  public void close() {
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
        ca.close();
      } catch (Throwable th) {
        LogUtil.error(LOG, th, concat("could not call ca.close() for CA ", caName));
      }
    }

    if (caLockedByMe) {
      try {
        unlockCa();
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not unlock CA system");
      }
    }

    if (datasource != null) {
      try {
        datasource.close();
      } catch (Exception ex) {
        LogUtil.warn(LOG, ex, concat("could not close datasource ca"));
      }
    }

    if (publishers != null) {
      for (String name : publishers.keySet()) {
        IdentifiedCertPublisher publisher = publishers.get(name);
        shutdownPublisher(publisher);
      }
    }

    if (certprofiles != null) {
      for (String name : certprofiles.keySet()) {
        IdentifiedCertprofile certprofile = certprofiles.get(name);
        shutdownCertprofile(certprofile);
      }
    }

    File caLockFile = new File(IoUtil.expandFilepath("calock"));
    if (caLockFile.exists()) {
      caLockFile.delete();
    }

    auditLogPciEvent(true, "SHUTDOWN");
    LOG.info("stopped CA system");
  } // method close

  public CmpResponder getX509CaResponder(String name) {
    return cmpResponders.get(Args.toNonBlankLower(name, "name"));
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
  public Set<String> getSignerNames() {
    return signerDbEntries.keySet();
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
  } // method getSuccessfulCaNames

  @Override
  public Set<String> getFailedCaNames() {
    Set<String> ret = new HashSet<>();
    for (String name : caInfos.keySet()) {
      if (CaStatus.ACTIVE == caInfos.get(name).getStatus() && !x509cas.containsKey(name)) {
        ret.add(name);
      }
    }
    return ret;
  } // method getFailedCaNames

  @Override
  public Set<String> getInactiveCaNames() {
    Set<String> ret = new HashSet<>();
    for (String name : caInfos.keySet()) {
      if (CaStatus.INACTIVE == caInfos.get(name).getStatus()) {
        ret.add(name);
      }
    }
    return ret;
  } // method getInactiveCaNames

  private void initRequestors() throws CaMgmtException {
    if (requestorsInitialized) {
      return;
    }

    idNameMap.clearRequestor();
    requestorDbEntries.clear();
    requestors.clear();
    List<String> names = queryExecutor.namesFromTable("REQUESTOR");
    for (String name : names) {
      if (RequestorInfo.NAME_BY_CA.equals(name)) {
        Integer id = queryExecutor.getRequestorId(name);
        NameId ident = new NameId(id, name);
        byCaRequestor = new RequestorInfo.ByCaRequestorInfo(ident);
        idNameMap.addRequestor(ident);
      } else if (RequestorInfo.NAME_BY_USER.equals(name)) {
        Integer id = queryExecutor.getRequestorId(name);
        byUserRequestorId = new NameId(id, name);
        idNameMap.addRequestor(byUserRequestorId);
      } else {
        MgmtEntry.Requestor requestorDbEntry = queryExecutor.createRequestor(name);
        if (requestorDbEntry == null) {
          LOG.error("could not load requestor {}", name);
          continue;
        }

        idNameMap.addRequestor(requestorDbEntry.getIdent());
        requestorDbEntries.put(name, requestorDbEntry);
        RequestorEntryWrapper requestor = new RequestorEntryWrapper();
        requestor.setDbEntry(requestorDbEntry, securityFactory.getPasswordResolver());
        requestors.put(name, requestor);
      }

      LOG.info("loaded requestor {}", name);
    }
    requestorsInitialized = true;
  } // method initRequestors

  private void initSigners() throws CaMgmtException {
    if (signerInitialized) {
      return;
    }

    signerDbEntries.clear();
    signers.clear();

    List<String> names = queryExecutor.namesFromTable("SIGNER");
    for (String name : names) {
      MgmtEntry.Signer entry = queryExecutor.createSigner(name);
      if (entry == null) {
        LOG.error("could not initialize signer '{}'", name);
        continue;
      }

      entry.setConfFaulty(true);
      signerDbEntries.put(name, entry);

      SignerEntryWrapper signer = createSigner(entry);
      if (signer != null) {
        entry.setConfFaulty(false);
        signers.put(name, signer);
        LOG.info("loaded signer {}", name);
      } else {
        LOG.error("could not load signer {}", name);
      }
    }
    signerInitialized = true;
  } // method initSigners

  private void initCaAliases() throws CaMgmtException {
    if (caAliasesInitialized) {
      return;
    }

    Map<String, Integer> map = queryExecutor.createCaAliases();
    caAliases.clear();
    for (String aliasName : map.keySet()) {
      caAliases.put(aliasName, map.get(aliasName));
    }

    LOG.info("caAliases: {}", caAliases);
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

    List<String> names = queryExecutor.namesFromTable("PROFILE");
    for (String name : names) {
      MgmtEntry.Certprofile dbEntry = queryExecutor.createCertprofile(name);
      if (dbEntry == null) {
        LOG.error("could not initialize Certprofile '{}'", name);
        continue;
      }

      idNameMap.addCertprofile(dbEntry.getIdent());
      dbEntry.setFaulty(true);
      certprofileDbEntries.put(name, dbEntry);

      IdentifiedCertprofile profile = createCertprofile(dbEntry);
      if (profile != null) {
        dbEntry.setFaulty(false);
        certprofiles.put(name, profile);
        LOG.info("loaded certprofile {}", name);
      } else {
        LOG.error("could not load certprofile {}", name);
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

    List<String> names = queryExecutor.namesFromTable("PUBLISHER");
    for (String name : names) {
      MgmtEntry.Publisher dbEntry = queryExecutor.createPublisher(name);
      if (dbEntry == null) {
        LOG.error("could not initialize publisher '{}'", name);
        continue;
      }

      idNameMap.addPublisher(dbEntry.getIdent());
      dbEntry.setFaulty(true);
      publisherDbEntries.put(name, dbEntry);

      IdentifiedCertPublisher publisher = createPublisher(dbEntry);
      if (publisher != null) {
        dbEntry.setFaulty(false);
        publishers.put(name, publisher);
        LOG.info("loaded publisher {}", name);
      } else {
        LOG.error("could not load publisher {}", name);
      }
    }

    publishersInitialized = true;
  } // method initPublishers

  private void initCas() throws CaMgmtException {
    if (casInitialized) {
      return;
    }

    caInfos.clear();
    caHasRequestors.clear();
    caHasPublishers.clear();
    caHasProfiles.clear();
    idNameMap.clearCa();

    List<String> names = queryExecutor.namesFromTable("CA");
    for (String name : names) {
      createCa(name);
    }
    casInitialized = true;
  } // method initCas

  private boolean createCa(String name) throws CaMgmtException {
    caInfos.remove(name);
    idNameMap.removeCa(name);
    caHasProfiles.remove(name);
    caHasPublishers.remove(name);
    caHasRequestors.remove(name);
    X509Ca oldCa = x509cas.remove(name);
    cmpResponders.remove(name);
    scepResponders.remove(name);
    if (oldCa != null) {
      oldCa.close();
    }

    CaInfo ca = queryExecutor.createCaInfo(name, masterMode, certstore);
    LOG.info("created CA {}: {}", name, ca.toString(false));
    caInfos.put(name, ca);
    idNameMap.addCa(ca.getIdent());
    Set<MgmtEntry.CaHasRequestor> caReqEntries = queryExecutor.createCaHasRequestors(ca.getIdent());
    caHasRequestors.put(name, caReqEntries);
    if (LOG.isInfoEnabled()) {
      StringBuilder sb = new StringBuilder();
      for (MgmtEntry.CaHasRequestor entry : caReqEntries) {
        sb.append("\n    ").append(entry);
      }
      LOG.info("CA {} is associated requestors:{}", name, sb);
    }

    Set<Integer> profileIds = queryExecutor.createCaHasProfiles(ca.getIdent());
    Set<String> profileNames = new HashSet<>();
    for (Integer id : profileIds) {
      profileNames.add(idNameMap.getCertprofileName(id));
    }
    caHasProfiles.put(name, profileNames);
    LOG.info("CA {} is associated with profiles: {}", name, profileNames);

    Set<Integer> publisherIds = queryExecutor.createCaHasPublishers(ca.getIdent());
    Set<String> publisherNames = new HashSet<>();
    for (Integer id : publisherIds) {
      publisherNames.add(idNameMap.getPublisherName(id));
    }
    caHasPublishers.put(name, publisherNames);
    LOG.info("CA {} is associated with publishers: {}", name, publisherNames);

    return true;
  } // method createCa

  public void commitNextCrlNo(NameId ca, long nextCrlNo) throws OperationException {
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
  } // method commitNextCrlNo

  public RequestorInfo.ByUserRequestorInfo createByUserRequestor(MgmtEntry.CaHasUser caHasUser) {
    return new RequestorInfo.ByUserRequestorInfo(byUserRequestorId, caHasUser);
  }

  @Override
  public void addCa(MgmtEntry.Ca caEntry) throws CaMgmtException {
    Args.notNull(caEntry, "caEntry");
    assertMasterModeAndSetuped();
    NameId ident = caEntry.getIdent();
    String name = ident.getName();

    if (caInfos.containsKey(name)) {
      throw new CaMgmtException(concat("CA named ", name, " exists"));
    }

    String origSignerConf = caEntry.getSignerConf();
    String newSignerConf = canonicalizeSignerConf(caEntry.getSignerType(),
        origSignerConf, null, securityFactory);
    if (!origSignerConf.equals(newSignerConf)) {
      caEntry.setSignerConf(newSignerConf);
    }

    try {
      List<String[]> signerConfs = MgmtEntry.Ca.splitCaSignerConfs(caEntry.getSignerConf());
      ConcurrentContentSigner signer;
      for (String[] m : signerConfs) {
        SignerConf signerConf = new SignerConf(m[1]);
        signer = securityFactory.createSigner(caEntry.getSignerType(), signerConf,
            caEntry.getCert());
        if (caEntry.getCert() == null) {
          if (signer.getCertificate() == null) {
            throw new CaMgmtException("CA signer without certificate is not allowed");
          }
          caEntry.setCert(signer.getCertificate());
        }
      }
    } catch (XiSecurityException | ObjectCreationException ex) {
      throw new CaMgmtException(
        concat("could not create signer for new CA ", name, ": ", ex.getMessage()), ex);
    }

    queryExecutor.addCa(caEntry);
    if (createCa(name)) {
      if (startCa(name)) {
        LOG.info("started CA {}", name);
      } else {
        LOG.error("could not start CA {}", name);
      }
    } else {
      LOG.error("could not create CA {}", name);
    }
  } // method addCa

  @Override
  public MgmtEntry.Ca getCa(String name) {
    CaInfo caInfo = caInfos.get(Args.toNonBlankLower(name, "name"));
    return (caInfo == null) ? null : caInfo.getCaEntry();
  } // method getCa

  @Override
  public void changeCa(MgmtEntry.ChangeCa entry) throws CaMgmtException {
    Args.notNull(entry, "entry");
    assertMasterModeAndSetuped();
    String name = entry.getIdent().getName();
    NameId ident = idNameMap.getCa(name);
    if (ident == null) {
      throw new CaMgmtException("Unknown CA " + name);
    }

    entry.getIdent().setId(ident.getId());

    queryExecutor.changeCa(entry, caInfos.get(name).getCaEntry(), securityFactory);

    if (createCa(name)) {
      CaInfo caInfo = caInfos.get(name);
      if (CaStatus.ACTIVE != caInfo.getCaEntry().getStatus()) {
        return;
      }

      if (startCa(name)) {
        LOG.info("started CA {}", name);
      } else {
        LOG.error("could not start CA {}", name);
      }
    } else {
      LOG.error("could not create CA {}", name);
    }
  } // method changeCa

  @Override
  public void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    profileName = Args.toNonBlankLower(profileName, "profileName");
    caName = Args.toNonBlankLower(caName, "caName");
    assertMasterModeAndSetuped();

    queryExecutor.removeCertprofileFromCa(profileName, caName);

    if (caHasProfiles.containsKey(caName)) {
      Set<String> set = caHasProfiles.get(caName);
      if (set != null) {
        set.remove(profileName);
      }
    }
  } // method removeCertprofileFromCa

  @Override
  public void addCertprofileToCa(String profileName, String caName) throws CaMgmtException {
    profileName = Args.toNonBlankLower(profileName, "profileName");
    caName = Args.toNonBlankLower(caName, "caName");
    assertMasterModeAndSetuped();

    NameId ident = idNameMap.getCertprofile(profileName);
    if (ident == null) {
      throw logAndCreateException(concat("unknown Certprofile ", profileName));
    }

    NameId caIdent = idNameMap.getCa(caName);
    if (caIdent == null) {
      throw logAndCreateException(concat("unknown CA ", caName));
    }

    Set<String> set = caHasProfiles.get(caName);
    if (set == null) {
      set = new HashSet<>();
      caHasProfiles.put(caName, set);
    } else {
      if (set.contains(profileName)) {
        throw logAndCreateException(
            concat("Certprofile ", profileName, " already associated with CA ", caName));
      }
    }

    if (!certprofiles.containsKey(profileName)) {
      throw new CaMgmtException(concat("certprofile '", profileName, "' is faulty"));
    }

    queryExecutor.addCertprofileToCa(ident, caIdent);
    set.add(profileName);
  } // method addCertprofileToCa

  @Override
  public void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException {
    publisherName = Args.toNonBlankLower(publisherName, "publisherName");
    caName = Args.toNonBlankLower(caName, "caName");
    assertMasterModeAndSetuped();

    queryExecutor.removePublisherFromCa(publisherName, caName);

    Set<String> publisherNames = caHasPublishers.get(caName);
    if (publisherNames != null) {
      publisherNames.remove(publisherName);
    }
  } // method removePublisherFromCa

  @Override
  public void addPublisherToCa(String publisherName, String caName) throws CaMgmtException {
    publisherName = Args.toNonBlankLower(publisherName, "publisherName");
    caName = Args.toNonBlankLower(caName, "caName");
    assertMasterModeAndSetuped();

    NameId ident = idNameMap.getPublisher(publisherName);
    if (ident == null) {
      throw logAndCreateException(concat("unknown publisher ", publisherName));
    }

    NameId caIdent = idNameMap.getCa(caName);
    if (caIdent == null) {
      throw logAndCreateException(concat("unknown CA ", caName));
    }

    Set<String> publisherNames = caHasPublishers.get(caName);
    if (publisherNames == null) {
      publisherNames = new HashSet<>();
      caHasPublishers.put(caName, publisherNames);
    } else {
      if (publisherNames.contains(publisherName)) {
        String msg = concat("publisher ", publisherName, " already associated with CA ", caName);
        throw logAndCreateException(msg);
      }
    }

    IdentifiedCertPublisher publisher = publishers.get(publisherName);
    if (publisher == null) {
      throw new CaMgmtException(concat("publisher '", publisherName, "' is faulty"));
    }

    queryExecutor.addPublisherToCa(idNameMap.getPublisher(publisherName), caIdent);
    publisherNames.add(publisherName);
    caHasPublishers.get(caName).add(publisherName);

    publisher.caAdded(caInfos.get(caName).getCert());
  } // method addPublisherToCa

  @Override
  public Set<String> getCertprofilesForCa(String caName) {
    return caHasProfiles.get(caName = Args.toNonBlankLower(caName, "caName"));
  }

  @Override
  public Set<MgmtEntry.CaHasRequestor> getRequestorsForCa(String caName) {
    return caHasRequestors.get(caName = Args.toNonBlankLower(caName, "caName"));
  }

  @Override
  public MgmtEntry.Requestor getRequestor(String name) {
    return requestorDbEntries.get(Args.toNonBlankLower(name, "name"));
  }

  public RequestorEntryWrapper getRequestorWrapper(String name) {
    return requestors.get(Args.toNonBlankLower(name, "name"));
  }

  @Override
  public void addRequestor(MgmtEntry.Requestor requestorEntry) throws CaMgmtException {
    Args.notNull(requestorEntry, "requestorEntry");
    assertMasterModeAndSetuped();
    String name = requestorEntry.getIdent().getName();
    if (requestorDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Requestor named ", name, " exists"));
    }

    // encrypt the password
    PasswordResolver pwdResolver = securityFactory.getPasswordResolver();
    if (MgmtEntry.Requestor.TYPE_PBM.equalsIgnoreCase(requestorEntry.getType())) {
      String conf = requestorEntry.getConf();
      if (!StringUtil.startsWithIgnoreCase(conf, "PBE:")) {
        String encryptedPassword;
        try {
          encryptedPassword = pwdResolver.protectPassword("PBE", conf.toCharArray());
        } catch (PasswordResolverException ex) {
          throw new CaMgmtException("could not encrypt requestor " + name, ex);
        }
        requestorEntry = new MgmtEntry.Requestor(requestorEntry.getIdent(),
                            requestorEntry.getType(), encryptedPassword);
      }
    }

    RequestorEntryWrapper requestor = new RequestorEntryWrapper();
    requestor.setDbEntry(requestorEntry, pwdResolver);

    queryExecutor.addRequestor(requestorEntry);
    idNameMap.addRequestor(requestorEntry.getIdent());
    requestorDbEntries.put(name, requestorEntry);
    requestors.put(name, requestor);
  } // method addRequestor

  @Override
  public void removeRequestor(String name) throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    assertMasterModeAndSetuped();

    for (String caName : caHasRequestors.keySet()) {
      boolean removeMe = false;
      for (MgmtEntry.CaHasRequestor caHasRequestor : caHasRequestors.get(caName)) {
        if (caHasRequestor.getRequestorIdent().getName().equals(name)) {
          removeMe = true;
          break;
        }
      }

      if (removeMe) {
        removeRequestorFromCa(name, caName);
      }
    }

    if (!queryExecutor.deleteRowWithName(name, "REQUESTOR")) {
      throw new CaMgmtException("unknown requestor " + name);
    }

    idNameMap.removeRequestor(requestorDbEntries.get(name).getIdent().getId());
    requestorDbEntries.remove(name);
    requestors.remove(name);
    LOG.info("removed requestor '{}'", name);
  } // method removeRequestor

  @Override
  public void changeRequestor(String name, String type, String conf) throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    Args.notBlank(type, "type");
    Args.notBlank(conf, "conf");

    assertMasterModeAndSetuped();

    NameId ident = idNameMap.getRequestor(name);
    if (ident == null) {
      throw logAndCreateException(concat("unknown requestor ", name));
    }

    RequestorEntryWrapper requestor = queryExecutor.changeRequestor(ident, type, conf,
        securityFactory.getPasswordResolver());

    requestorDbEntries.remove(name);
    requestors.remove(name);

    requestorDbEntries.put(name, requestor.getDbEntry());
    requestors.put(name, requestor);
  } // method changeRequestor

  @Override
  public void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    requestorName = Args.toNonBlankLower(requestorName, "requestorName");
    caName = Args.toNonBlankLower(caName, "caName");
    assertMasterModeAndSetuped();

    if (requestorName.equals(RequestorInfo.NAME_BY_CA)
        || requestorName.equals(RequestorInfo.NAME_BY_USER)) {
      throw new CaMgmtException(concat("removing requestor ", requestorName, " is not permitted"));
    }

    queryExecutor.removeRequestorFromCa(requestorName, caName);
    if (caHasRequestors.containsKey(caName)) {
      Set<MgmtEntry.CaHasRequestor> entries = caHasRequestors.get(caName);
      MgmtEntry.CaHasRequestor entry = null;
      for (MgmtEntry.CaHasRequestor m : entries) {
        if (m.getRequestorIdent().getName().equals(requestorName)) {
          entry = m;
        }
      }
      entries.remove(entry);
    }
  } // method removeRequestorFromCa

  @Override
  public void addRequestorToCa(MgmtEntry.CaHasRequestor requestor, String caName)
      throws CaMgmtException {
    Args.notNull(requestor, "requestor");
    caName = Args.toNonBlankLower(caName, "caName");
    assertMasterModeAndSetuped();

    NameId requestorIdent = requestor.getRequestorIdent();
    NameId ident = idNameMap.getRequestor(requestorIdent.getName());
    if (ident == null) {
      throw logAndCreateException(concat("unknown requestor ", requestorIdent.getName()));
    }

    NameId caIdent = idNameMap.getCa(caName);
    if (caIdent == null) {
      String msg = concat("unknown CA ", caName);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    // Set the ID of requestor
    requestorIdent.setId(ident.getId());

    Set<MgmtEntry.CaHasRequestor> cmpRequestors = caHasRequestors.get(caName);
    if (cmpRequestors == null) {
      cmpRequestors = new HashSet<>();
      caHasRequestors.put(caName, cmpRequestors);
    } else {
      for (MgmtEntry.CaHasRequestor entry : cmpRequestors) {
        String requestorName = requestorIdent.getName();
        if (entry.getRequestorIdent().getName().equals(requestorName)) {
          String msg = concat("Requestor ", requestorName, " already associated with CA ", caName);
          throw logAndCreateException(msg);
        }
      }
    }

    cmpRequestors.add(requestor);
    queryExecutor.addRequestorToCa(requestor, caIdent);
    caHasRequestors.get(caName).add(requestor);
  } // method addRequestorToCa

  @Override
  public void removeUserFromCa(String userName, String caName) throws CaMgmtException {
    userName = Args.toNonBlankLower(userName, "userName");
    caName = Args.toNonBlankLower(caName, "caName");
    assertMasterModeAndSetuped();

    queryExecutor.removeUserFromCa(userName, caName);
  } // method removeUserFromCa

  @Override
  public void addUserToCa(MgmtEntry.CaHasUser user, String caName) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    assertMasterModeAndSetuped();

    X509Ca ca = getX509Ca(caName);
    if (ca == null) {
      throw logAndCreateException(concat("unknown CA ", caName));
    }

    queryExecutor.addUserToCa(user, ca.getCaIdent());
  } // method addUserToCa

  @Override
  public Map<String, MgmtEntry.CaHasUser> getCaHasUsersForUser(String user) throws CaMgmtException {
    Args.notBlank(user, "user");
    return queryExecutor.getCaHasUsersForUser(user, idNameMap);
  }

  @Override
  public MgmtEntry.Certprofile getCertprofile(String name) {
    return certprofileDbEntries.get(name.toLowerCase());
  }

  @Override
  public void removeCertprofile(String name) throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    assertMasterModeAndSetuped();

    for (String caName : caHasProfiles.keySet()) {
      if (caHasProfiles.get(caName).contains(name)) {
        removeCertprofileFromCa(name, caName);
      }
    }

    boolean bo = queryExecutor.deleteRowWithName(name, "PROFILE");
    if (!bo) {
      throw new CaMgmtException("unknown profile " + name);
    }

    LOG.info("removed profile '{}'", name);
    idNameMap.removeCertprofile(certprofileDbEntries.get(name).getIdent().getId());
    certprofileDbEntries.remove(name);
    IdentifiedCertprofile profile = certprofiles.remove(name);
    shutdownCertprofile(profile);
  } // method removeCertprofile

  @Override
  public void changeCertprofile(String name, String type, String conf) throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    if (type == null && conf == null) {
      throw new IllegalArgumentException("type and conf cannot be both null");
    }
    NameId ident = idNameMap.getCertprofile(name);
    if (ident == null) {
      throw logAndCreateException(concat("unknown Certprofile ", name));
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    assertMasterModeAndSetuped();

    IdentifiedCertprofile profile = queryExecutor.changeCertprofile(ident, type, conf, this);

    certprofileDbEntries.remove(name);
    IdentifiedCertprofile oldProfile = certprofiles.remove(name);
    certprofileDbEntries.put(name, profile.getDbEntry());
    certprofiles.put(name, profile);

    if (oldProfile != null) {
      shutdownCertprofile(oldProfile);
    }
  } // method changeCertprofile

  @Override
  public void addCertprofile(MgmtEntry.Certprofile certprofileEntry) throws CaMgmtException {
    Args.notNull(certprofileEntry, "certprofileEntry");
    assertMasterModeAndSetuped();
    String name = certprofileEntry.getIdent().getName();
    if (certprofileDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Certprofile named ", name, " exists"));
    }

    certprofileEntry.setFaulty(true);
    IdentifiedCertprofile profile = createCertprofile(certprofileEntry);
    if (profile == null) {
      throw new CaMgmtException("could not create Certprofile object");
    }

    certprofileEntry.setFaulty(false);
    certprofiles.put(name, profile);
    queryExecutor.addCertprofile(certprofileEntry);
    idNameMap.addCertprofile(certprofileEntry.getIdent());
    certprofileDbEntries.put(name, certprofileEntry);
  } // method addCertprofile

  @Override
  public void addSigner(MgmtEntry.Signer signerEntry) throws CaMgmtException {
    Args.notNull(signerEntry, "signerEntry");
    assertMasterModeAndSetuped();
    String name = signerEntry.getName();
    if (signerDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Signer named ", name, " exists"));
    }

    String conf = signerEntry.getConf();
    if (conf != null) {
      String newConf = canonicalizeSignerConf(signerEntry.getType(), conf, null, securityFactory);
      if (!conf.equals(newConf)) {
        signerEntry.setConf(newConf);
      }
    }

    SignerEntryWrapper signer = createSigner(signerEntry);
    queryExecutor.addSigner(signerEntry);
    signers.put(name, signer);
    signerDbEntries.put(name, signerEntry);
  } // method addSigner

  @Override
  public void removeSigner(String name) throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    assertMasterModeAndSetuped();
    boolean bo = queryExecutor.deleteRowWithName(name, "SIGNER");
    if (!bo) {
      throw new CaMgmtException("unknown signer " + name);
    }

    for (String caName : caInfos.keySet()) {
      CaInfo caInfo = caInfos.get(caName);
      if (name.equals(caInfo.getCmpResponderName())) {
        caInfo.setCmpResponderName(null);
      }

      if (name.equals(caInfo.getScepResponderName())) {
        caInfo.setScepResponderName(null);
      }

      if (name.equals(caInfo.getCrlSignerName())) {
        caInfo.setCrlSignerName(null);
      }

    }

    signerDbEntries.remove(name);
    signers.remove(name);
    LOG.info("removed signer '{}'", name);
  } // method removeSigner

  @Override
  public void changeSigner(String name, String type, String conf, String base64Cert)
      throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    assertMasterModeAndSetuped();
    if (type == null && conf == null && base64Cert == null) {
      throw new IllegalArgumentException("nothing to change");
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    SignerEntryWrapper newResponder = queryExecutor.changeSigner(name, type, conf,
        base64Cert, this, securityFactory);

    signers.remove(name);
    signerDbEntries.remove(name);
    signerDbEntries.put(name, newResponder.getDbEntry());
    signers.put(name, newResponder);

    for (String caName : scepResponders.keySet()) {
      if (getCa(caName).getScepResponderName().equals(name)) {
        // update the SCEP responder
        scepResponders.get(caName).setResponder(newResponder);
      }
    }
  } // method changeSigner

  @Override
  public MgmtEntry.Signer getSigner(String name) {
    return signerDbEntries.get(Args.toNonBlankLower(name, "name"));
  }

  public SignerEntryWrapper getSignerWrapper(String name) {
    return signers.get(Args.toNonBlankLower(name, "name"));
  }

  @Override
  public void addPublisher(MgmtEntry.Publisher entry) throws CaMgmtException {
    Args.notNull(entry, "entry");
    assertMasterModeAndSetuped();
    String name = entry.getIdent().getName();
    if (publisherDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Publisher named ", name, " exists"));
    }

    entry.setFaulty(true);
    IdentifiedCertPublisher publisher = createPublisher(entry);
    entry.setFaulty(false);

    queryExecutor.addPublisher(entry);

    publishers.put(name, publisher);
    idNameMap.addPublisher(entry.getIdent());
    publisherDbEntries.put(name, entry);
  } // method addPublisher

  @Override
  public List<MgmtEntry.Publisher> getPublishersForCa(String caName) {
    caName = Args.toNonBlankLower(caName, "caName");
    Set<String> publisherNames = caHasPublishers.get(caName);
    if (publisherNames == null) {
      return Collections.emptyList();
    }

    List<MgmtEntry.Publisher> ret = new ArrayList<>(publisherNames.size());
    for (String publisherName : publisherNames) {
      ret.add(publisherDbEntries.get(publisherName));
    }

    return ret;
  } // method getPublishersForCa

  @Override
  public MgmtEntry.Publisher getPublisher(String name) {
    name = Args.toNonBlankLower(name, "name");
    return publisherDbEntries.get(name);
  }

  @Override
  public void removePublisher(String name) throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    assertMasterModeAndSetuped();
    for (String caName : caHasPublishers.keySet()) {
      if (caHasPublishers.get(caName).contains(name)) {
        removePublisherFromCa(name, caName);
      }
    }

    boolean bo = queryExecutor.deleteRowWithName(name, "PUBLISHER");
    if (!bo) {
      throw new CaMgmtException("unknown publisher " + name);
    }

    LOG.info("removed publisher '{}'", name);
    publisherDbEntries.remove(name);
    IdentifiedCertPublisher publisher = publishers.remove(name);
    shutdownPublisher(publisher);
  } // method removePublisher

  @Override
  public void changePublisher(String name, String type, String conf) throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    assertMasterModeAndSetuped();
    if (type == null && conf == null) {
      throw new IllegalArgumentException("nothing to change");
    }
    if (type != null) {
      type = type.toLowerCase();
    }

    IdentifiedCertPublisher publisher = queryExecutor.changePublisher(name, type, conf, this);

    IdentifiedCertPublisher oldPublisher = publishers.remove(name);
    shutdownPublisher(oldPublisher);

    publisherDbEntries.put(name, publisher.getDbEntry());
    publishers.put(name, publisher);
  } // method changePublisher

  public CaServerConf getCaServerConf() {
    return caServerConf;
  }

  public void setCaServerConf(CaServerConf caServerConf) {
    this.caServerConf = Args.notNull(caServerConf, "caServerConf");
  }

  @Override
  public void addCaAlias(String aliasName, String caName) throws CaMgmtException {
    aliasName = Args.toNonBlankLower(aliasName, "aliasName");
    caName = Args.toNonBlankLower(caName, "caName");
    assertMasterModeAndSetuped();

    X509Ca ca = x509cas.get(caName);
    if (ca == null) {
      throw new CaMgmtException("unknown CA " + caName);
    }

    if (caAliases.get(aliasName) != null) {
      throw new CaMgmtException("unknown CA alias " + aliasName);
    }

    queryExecutor.addCaAlias(aliasName, ca.getCaIdent());
    caAliases.put(aliasName, ca.getCaIdent().getId());
  } // method addCaAlias

  @Override
  public void removeCaAlias(String name) throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    assertMasterModeAndSetuped();
    queryExecutor.removeCaAlias(name);
    caAliases.remove(name);
  } // method removeCaAlias

  @Override
  public String getCaNameForAlias(String aliasName) {
    aliasName = Args.toNonBlankLower(aliasName, "aliasName");
    Integer caId = caAliases.get(aliasName);
    for (String name : x509cas.keySet()) {
      X509Ca ca = x509cas.get(name);
      if (ca.getCaIdent().getId().equals(caId)) {
        return ca.getCaIdent().getName();
      }
    }
    return null;
  } // method getCaNameForAlias

  @Override
  public Set<String> getAliasesForCa(String caName) {
    caName = Args.toNonBlankLower(caName, "caName");
    Set<String> aliases = new HashSet<>();
    X509Ca ca = x509cas.get(caName);
    if (ca == null) {
      return aliases;
    }

    NameId caIdent = ca.getCaIdent();

    for (String alias : caAliases.keySet()) {
      Integer thisCaId = caAliases.get(alias);
      if (caIdent.getId().equals(thisCaId)) {
        aliases.add(alias);
      }
    }

    return aliases;
  } // method getAliasesForCa

  @Override
  public Set<String> getCaAliasNames() {
    return caAliases.keySet();
  }

  public X509Cert getCaCert(String caName) {
    caName = Args.toNonBlankLower(caName, "caName");
    X509Ca ca = x509cas.get(caName);
    return (ca == null) ? null : ca.getCaInfo().getCert();
  } // method getCaCert

  public List<X509Cert> getCaCertchain(String caName) {
    caName = Args.toNonBlankLower(caName, "caName");
    X509Ca ca = x509cas.get(caName);
    return (ca == null) ? null : ca.getCaInfo().getCertchain();
  } // method getCaCertchain

  @Override
  public void removeCa(String name) throws CaMgmtException {
    name = Args.toNonBlankLower(name, "name");
    assertMasterModeAndSetuped();

    queryExecutor.removeCa(name);

    LOG.info("removed CA '{}'", name);
    caInfos.remove(name);
    idNameMap.removeCa(name);
    idNameMap.removeCa(name);
    caHasProfiles.remove(name);
    caHasPublishers.remove(name);
    caHasRequestors.remove(name);
    X509Ca ca = x509cas.remove(name);
    cmpResponders.remove(name);
    scepResponders.remove(name);
    if (ca != null) {
      ca.close();
    }
  } // method removeCa

  @Override
  public void republishCertificates(String caName, List<String> publisherNames, int numThreads)
      throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    Args.positive(numThreads, "numThreads");
    assertMasterModeAndSetuped();
    X509Ca ca = x509cas.get(caName);
    if (ca == null) {
      throw new CaMgmtException(concat("could not find CA named ", caName));
    }

    publisherNames = CollectionUtil.toLowerCaseList(publisherNames);
    if (!ca.republishCerts(publisherNames, numThreads)) {
      throw new CaMgmtException(concat("republishing certificates of CA ", caName, " failed"));
    }
  } // method republishCertificates

  @Override
  public void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    Args.notNull(revocationInfo, "revocationInfo");
    assertMasterModeAndSetuped();

    if (!x509cas.containsKey(caName)) {
      throw new CaMgmtException(concat("unkown CA ", caName));
    }

    LOG.info("revoking CA '{}'", caName);
    X509Ca ca = x509cas.get(caName);

    CertRevocationInfo currentRevInfo = ca.getCaInfo().getRevocationInfo();
    if (currentRevInfo != null) {
      CrlReason currentReason = currentRevInfo.getReason();
      if (currentReason != CrlReason.CERTIFICATE_HOLD) {
        throw new CaMgmtException(concat("CA ", caName, " has been revoked with reason ",
            currentReason.name()));
      }
    }

    queryExecutor.revokeCa(caName, revocationInfo);

    try {
      ca.revokeCa(revocationInfo, CaAuditConstants.MSGID_ca_mgmt);
    } catch (OperationException ex) {
      throw new CaMgmtException(concat("could not revoke CA ", ex.getMessage()), ex);
    }
    LOG.info("revoked CA '{}'", caName);
    auditLogPciEvent(true, concat("REVOKE CA ", caName));
  } // method revokeCa

  @Override
  public void unrevokeCa(String caName) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    assertMasterModeAndSetuped();

    if (!x509cas.containsKey(caName)) {
      throw new CaMgmtException(concat("could not find CA named ", caName));
    }

    LOG.info("unrevoking of CA '{}'", caName);

    queryExecutor.unrevokeCa(caName);

    X509Ca ca = x509cas.get(caName);
    try {
      ca.unrevokeCa(CaAuditConstants.MSGID_ca_mgmt);
    } catch (OperationException ex) {
      throw new CaMgmtException(
          concat("could not unrevoke CA " + caName + ": ", ex.getMessage()), ex);
    }
    LOG.info("unrevoked CA '{}'", caName);

    auditLogPciEvent(true, concat("UNREVOKE CA ", caName));
  } // method unrevokeCa

  public void setCertprofileFactoryRegister(CertprofileFactoryRegister register) {
    this.certprofileFactoryRegister = register;
  }

  public void setCertPublisherFactoryRegister(CertPublisherFactoryRegister register) {
    this.certPublisherFactoryRegister = register;
  }

  private void auditLogPciEvent(boolean successful, String eventType) {
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
    Audits.getAuditService().logEvent(event);
  } // method auditLogPciEvent

  @Override
  public void clearPublishQueue(String caName, List<String> publisherNames) throws CaMgmtException {
    assertMasterModeAndSetuped();

    publisherNames = CollectionUtil.toLowerCaseList(publisherNames);

    if (caName == null) {
      if (CollectionUtil.isNotEmpty(publisherNames)) {
        throw new IllegalArgumentException("non-empty publisherNames is not allowed");
      }

      try {
        certstore.clearPublishQueue((NameId) null, (NameId) null);
      } catch (OperationException ex) {
        throw new CaMgmtException(ex.getMessage(), ex);
      }
      return;
    }

    caName = caName.toLowerCase();
    X509Ca ca = x509cas.get(caName);
    if (ca == null) {
      throw new CaMgmtException(concat("could not find CA named ", caName));
    }

    ca.clearPublishQueue(publisherNames);
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
  public void revokeCertificate(String caName, BigInteger serialNumber, CrlReason reason,
      Date invalidityTime) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    Args.notNull(serialNumber, "serialNumber");
    assertMasterModeAndSetuped();
    X509Ca ca = getX509Ca(caName);
    try {
      if (ca.revokeCert(serialNumber, reason, invalidityTime,
          CaAuditConstants.MSGID_ca_mgmt) == null) {
        throw new CaMgmtException("could not revoke non-existing certificate");
      }
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method revokeCertificate

  @Override
  public void unrevokeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    Args.notNull(serialNumber, "serialNumber");

    X509Ca ca = getX509Ca(caName);
    try {
      if (ca.unrevokeCert(serialNumber, CaAuditConstants.MSGID_ca_mgmt) == null) {
        throw new CaMgmtException("could not unrevoke non-existing certificate");
      }
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method unrevokeCertificate

  @Override
  public void removeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    Args.notNull(serialNumber, "serialNumber");
    assertMasterModeAndSetuped();
    X509Ca ca = getX509Ca(caName);
    if (ca == null) {
      throw logAndCreateException(concat("unknown CA ", caName));
    }

    try {
      if (ca.removeCert(serialNumber, CaAuditConstants.MSGID_ca_mgmt) == null) {
        throw new CaMgmtException("could not remove certificate");
      }
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method removeCertificate

  @Override
  public X509Cert generateCertificate(String caName, String profileName,
      byte[] encodedCsr, Date notBefore, Date notAfter) throws CaMgmtException {

    caName = Args.toNonBlankLower(caName, "caName");
    profileName = Args.toNonBlankLower(profileName, "profileName");
    Args.notNull(encodedCsr, "encodedCsr");

    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName(CaAuditConstants.APPNAME);
    event.setName(CaAuditConstants.NAME_perf);
    event.addEventType("CAMGMT_CRL_GEN_ONDEMAND");

    X509Ca ca = getX509Ca(caName);
    CertificationRequest csr;
    try {
      csr = X509Util.parseCsr(encodedCsr);
    } catch (Exception ex) {
      throw new CaMgmtException(concat("invalid CSR request. ERROR: ", ex.getMessage()));
    }

    if (!ca.verifyCsr(csr)) {
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

    CertificateInfo certInfo;
    try {
      certInfo = ca.generateCert(certTemplateData, byCaRequestor, RequestType.CA,
          (byte[]) null, CaAuditConstants.MSGID_ca_mgmt);
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
    name = Args.toNonBlankLower(name, "name");
    X509Ca ca = x509cas.get(name);
    if (ca == null) {
      throw new CaMgmtException("unknown CA " + name);
    }
    return ca;
  } // method getX509Ca

  public X509Ca getX509Ca(NameId ident) throws CaMgmtException {
    Args.notNull(ident, "ident");
    X509Ca ca = x509cas.get(ident.getName());
    if (ca == null) {
      throw new CaMgmtException("unknown CA " + ident);
    }
    return ca;
  } // method getX509Ca

  public IdentifiedCertprofile getIdentifiedCertprofile(String profileName) {
    profileName = Args.toNonBlankLower(profileName, "profileName");
    return certprofiles.get(profileName);
  }

  public List<IdentifiedCertPublisher> getIdentifiedPublishersForCa(String caName) {
    caName = Args.toNonBlankLower(caName, "caName");
    List<IdentifiedCertPublisher> ret = new LinkedList<>();
    Set<String> publisherNames = caHasPublishers.get(caName);
    if (publisherNames == null) {
      return ret;
    }

    for (String publisherName : publisherNames) {
      IdentifiedCertPublisher publisher = publishers.get(publisherName);
      ret.add(publisher);
    }
    return ret;
  } // method getIdentifiedPublishersForCa

  @Override
  public X509Cert generateRootCa(MgmtEntry.Ca caEntry, String profileName, byte[] encodedCsr,
      BigInteger serialNumber) throws CaMgmtException {
    Args.notNull(caEntry, "caEntry");
    profileName = Args.toNonBlankLower(profileName, "profileName");
    Args.notNull(encodedCsr, "encodedCsr");

    int numCrls = caEntry.getNumCrls();
    String signerType = caEntry.getSignerType();

    assertMasterModeAndSetuped();

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
      csr = X509Util.parseCsr(encodedCsr);
    } catch (Exception ex) {
      System.err.println("invalid encodedCsr");
      return null;
    }

    IdentifiedCertprofile certprofile = getIdentifiedCertprofile(profileName);
    if (certprofile == null) {
      throw new CaMgmtException(concat("unknown certprofile ", profileName));
    }

    BigInteger serialOfThisCert = (serialNumber != null) ? serialNumber
        : RandomSerialNumberGenerator.getInstance().nextSerialNumber(caEntry.getSerialNoLen());

    GenerateSelfSignedResult result;
    try {
      result = SelfSignedCertBuilder.generateSelfSigned(securityFactory, signerType,
          caEntry.getSignerConf(), certprofile, csr, serialOfThisCert, caEntry.getCaUris(),
          caEntry.getExtraControl());
    } catch (OperationException | InvalidConfException ex) {
      throw new CaMgmtException(concat(ex.getClass().getName(), ": ", ex.getMessage()), ex);
    }

    String signerConf = result.getSignerConf();
    X509Cert caCert = result.getCert();

    if ("PKCS12".equalsIgnoreCase(signerType) || "JCEKS".equalsIgnoreCase(signerType)) {
      try {
        signerConf = canonicalizeSignerConf(signerType, signerConf,
            new X509Cert[]{caCert}, securityFactory);
      } catch (Exception ex) {
        throw new CaMgmtException(concat(ex.getClass().getName(), ": ", ex.getMessage()), ex);
      }
    }

    String name = caEntry.getIdent().getName();
    long nextCrlNumber = caEntry.getNextCrlNumber();

    MgmtEntry.Ca entry = new MgmtEntry.Ca(new NameId(null, name), caEntry.getSerialNoLen(),
        nextCrlNumber, signerType, signerConf, caEntry.getCaUris(), numCrls, expirationPeriod);
    entry.setCert(caCert);
    entry.setCmpControl(caEntry.getCmpControl());
    entry.setCrlControl(caEntry.getCrlControl());
    entry.setScepControl(caEntry.getScepControl());
    entry.setCmpResponderName(caEntry.getCmpResponderName());
    entry.setScepResponderName(caEntry.getScepResponderName());
    entry.setCrlSignerName(caEntry.getCrlSignerName());
    entry.setExtraControl(caEntry.getExtraControl());
    entry.setKeepExpiredCertInDays(caEntry.getKeepExpiredCertInDays());
    entry.setMaxValidity(caEntry.getMaxValidity());
    entry.setPermission(caEntry.getPermission());
    entry.setProtocolSupport(caEntry.getProtocoSupport());
    entry.setSaveRequest(caEntry.isSaveRequest());
    entry.setStatus(caEntry.getStatus());
    entry.setValidityMode(caEntry.getValidityMode());

    addCa(entry);
    return caCert;
  } // method generateRootCa

  private void assertMasterModeAndSetuped() throws CaMgmtException {
    if (!masterMode) {
      throw new CaMgmtException("operation not allowed in slave mode");
    }

    if (!caSystemSetuped) {
      throw new CaMgmtException("CA system is not initialized yet.");
    }
  }

  void shutdownCertprofile(IdentifiedCertprofile profile) {
    if (profile == null) {
      return;
    }

    try {
      profile.close();
    } catch (Exception ex) {
      LogUtil.warn(LOG, ex, "could not shutdown Certprofile " + profile.getIdent());
    }
  } // method shutdownCertprofile

  void shutdownPublisher(IdentifiedCertPublisher publisher) {
    if (publisher == null) {
      return;
    }

    try {
      publisher.close();
    } catch (Exception ex) {
      LogUtil.warn(LOG, ex, "could not shutdown CertPublisher " + publisher.getIdent());
    }
  } // method shutdownPublisher

  SignerEntryWrapper createSigner(MgmtEntry.Signer entry) throws CaMgmtException {
    Args.notNull(entry, "entry");
    SignerEntryWrapper ret = new SignerEntryWrapper();
    ret.setDbEntry(entry);
    try {
      ret.initSigner(securityFactory);
    } catch (ObjectCreationException ex) {
      final String message = "createSigner";
      LOG.debug(message, ex);
      throw new CaMgmtException(ex.getMessage());
    }
    return ret;
  } // method createSigner

  IdentifiedCertprofile createCertprofile(MgmtEntry.Certprofile entry) throws CaMgmtException {
    Args.notNull(entry, "entry");

    String type = entry.getType();
    if (!certprofileFactoryRegister.canCreateProfile(type)) {
      throw new CaMgmtException("unsupported cert profile type " + type);
    }

    try {
      Certprofile profile = certprofileFactoryRegister.newCertprofile(type);
      return new IdentifiedCertprofile(entry, profile);
    } catch (ObjectCreationException | CertprofileException ex) {
      String msg = "could not initialize Certprofile " + entry.getIdent();
      LogUtil.error(LOG, ex, msg);
      throw new CaMgmtException(msg, ex);
    }
  } // method createCertprofile

  IdentifiedCertPublisher createPublisher(MgmtEntry.Publisher entry) throws CaMgmtException {
    Args.notNull(entry, "entry");
    String type = entry.getType();

    CertPublisher publisher;
    IdentifiedCertPublisher ret;
    try {
      if (certPublisherFactoryRegister.canCreatePublisher(type)) {
        publisher = certPublisherFactoryRegister.newPublisher(type);
      } else {
        throw new CaMgmtException("unsupported publisher type " + type);
      }

      ret = new IdentifiedCertPublisher(entry, publisher);
      ret.initialize(securityFactory.getPasswordResolver(), datasourceNameConfFileMap);
      return ret;
    } catch (ObjectCreationException | CertPublisherException | RuntimeException ex) {
      String msg = "invalid configuration for the publisher " + entry.getIdent();
      LogUtil.error(LOG, ex, msg);
      throw new CaMgmtException(msg, ex);
    }
  } // method createPublisher

  @Override
  public void addUser(MgmtEntry.AddUser addUserEntry) throws CaMgmtException {
    assertMasterModeAndSetuped();
    queryExecutor.addUser(addUserEntry);
  }

  @Override
  public void changeUser(MgmtEntry.ChangeUser changeUserEntry) throws CaMgmtException {
    assertMasterModeAndSetuped();
    queryExecutor.changeUser(changeUserEntry);
  }

  @Override
  public void removeUser(String username) throws CaMgmtException {
    username = Args.toNonBlankLower(username, "username");
    assertMasterModeAndSetuped();
    if (!queryExecutor.deleteRowWithName(username, "TUSER")) {
      throw new CaMgmtException("unknown user " + username);
    }
  } // method removeUser

  @Override
  public MgmtEntry.User getUser(String username) throws CaMgmtException {
    return queryExecutor.getUser(username.toLowerCase());
  }

  CaIdNameMap idNameMap() {
    return idNameMap;
  }

  @Override
  public X509CRLHolder generateCrlOnDemand(String caName) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");

    X509Ca ca = getX509Ca(caName);
    try {
      return ca.generateCrlOnDemand(CaAuditConstants.MSGID_ca_mgmt);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method generateCrlOnDemand

  @Override
  public X509CRLHolder getCrl(String caName, BigInteger crlNumber) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    Args.notNull(crlNumber, "crlNumber");
    X509Ca ca = getX509Ca(caName);
    try {
      X509CRLHolder crl = ca.getCrl(crlNumber);
      if (crl == null) {
        LOG.warn("found no CRL for CA {} and crlNumber {}", caName, crlNumber);
      }
      return crl;
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method getCrl

  @Override
  public X509CRLHolder getCurrentCrl(String caName) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    X509Ca ca = getX509Ca(caName);
    try {
      X509CRLHolder crl = ca.getCurrentCrl();
      if (crl == null) {
        LOG.warn("found no CRL for CA {}", caName);
      }
      return crl;
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method getCurrentCrl

  public ScepResponder getScepResponder(String name) {
    name = Args.toNonBlankLower(name, "name");
    return (scepResponders == null) ? null : scepResponders.get(name);
  }

  static String canonicalizeSignerConf(String keystoreType, String signerConf,
      X509Cert[] certChain, SecurityFactory securityFactory) throws CaMgmtException {
    if (!signerConf.contains("file:") && !signerConf.contains("base64:")) {
      return signerConf;
    }

    ConfPairs pairs = new ConfPairs(signerConf);

    String algo = pairs.value("algo");
    if (algo != null) {
      try {
        algo = AlgorithmUtil.canonicalizeSignatureAlgo(algo);
      } catch (NoSuchAlgorithmException ex) {
        throw new CaMgmtException("Unknown signature algo: " + ex.getMessage(), ex);
      }
      pairs.putPair("algo", algo);
    }

    String keystoreConf = pairs.value("keystore");
    String passwordHint = pairs.value("password");
    String keyLabel = pairs.value("key-label");

    byte[] ksBytes;
    if (StringUtil.startsWithIgnoreCase(keystoreConf, "file:")) {
      String keystoreFile = keystoreConf.substring("file:".length());
      try {
        ksBytes = IoUtil.read(keystoreFile);
      } catch (IOException ex) {
        throw new CaMgmtException("IOException: " + ex.getMessage(), ex);
      }
    } else if (StringUtil.startsWithIgnoreCase(keystoreConf, "base64:")) {
      ksBytes = Base64.decode(keystoreConf.substring("base64:".length()));
    } else {
      return signerConf;
    }

    try {
      char[] password = securityFactory.getPasswordResolver().resolvePassword(passwordHint);
      ksBytes = securityFactory.extractMinimalKeyStore(keystoreType, ksBytes, keyLabel,
          password, certChain);
    } catch (KeyStoreException ex) {
      throw new CaMgmtException("KeyStoreException: " + ex.getMessage(), ex);
    } catch (PasswordResolverException ex) {
      throw new CaMgmtException("PasswordResolverException: " + ex.getMessage(), ex);
    }
    pairs.putPair("keystore", "base64:" + Base64.encodeToString(ksBytes));
    return pairs.getEncoded();
  } // method canonicalizeSignerConf

  @Override
  public CertWithRevocationInfo getCert(String caName, BigInteger serialNumber)
      throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    Args.notNull(serialNumber, "serialNumber");
    X509Ca ca = getX509Ca(caName);
    try {
      return ca.getCertWithRevocationInfo(serialNumber);
    } catch (CertificateException | OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method getCert

  @Override
  public CertWithRevocationInfo getCert(X500Name issuer, BigInteger serialNumber)
      throws CaMgmtException {
    Args.notNull(issuer, "issuer");
    Args.notNull(serialNumber, "serialNumber");

    NameId caId = null;
    for (String name : caInfos.keySet()) {
      CaInfo ca = caInfos.get(name);
      if (issuer.equals(caInfos.get(name).getCert().getSubject())) {
        caId = ca.getIdent();
        break;
      }
    }

    if (caId == null) {
      return null;
    }

    try {
      return certstore.getCertWithRevocationInfo(caId.getId(), serialNumber, idNameMap);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method getCert

  @Override
  public byte[] getCertRequest(String caName, BigInteger serialNumber) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    Args.notNull(serialNumber, "serialNumber");
    X509Ca ca = getX509Ca(caName);
    try {
      return ca.getCertRequest(serialNumber);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method getCertRequest

  @Override
  public List<CertListInfo> listCertificates(String caName, X500Name subjectPattern, Date validFrom,
      Date validTo, CertListOrderBy orderBy, int numEntries) throws CaMgmtException {
    caName = Args.toNonBlankLower(caName, "caName");
    Args.range(numEntries, "numEntries", 1, 1000);
    X509Ca ca = getX509Ca(caName);
    try {
      return ca.listCerts(subjectPattern, validFrom, validTo, orderBy, numEntries);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method listCertificates

  @Override
  public void refreshTokenForSignerType(String signerType) throws CaMgmtException {
    try {
      securityFactory.refreshTokenForSignerType(signerType);
    } catch (XiSecurityException ex) {
      throw new CaMgmtException("could not refresh token for signer type " + signerType
          + ": " + ex.getMessage(), ex);
    }
  } // method refreshTokenForSignerType

  @Override
  public Map<String, X509Cert> loadConf(InputStream zippedConfStream)
      throws CaMgmtException {
    Args.notNull(zippedConfStream, "zippedConfStream");
    assertMasterModeAndSetuped();

    CaConf conf;
    try {
      conf = new CaConf(zippedConfStream, securityFactory);
    } catch (IOException | InvalidConfException ex) {
      throw new CaMgmtException("could not parse the CA configuration", ex);
    } catch (RuntimeException ex) {
      throw new CaMgmtException("caught RuntimeException while parsing the CA configuration", ex);
    }

    Map<String, X509Cert> generatedRootCerts = new HashMap<>(2);

    // Responder
    for (String name : conf.getSignerNames()) {
      MgmtEntry.Signer entry = conf.getSigner(name);
      MgmtEntry.Signer entryB = signerDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB)) {
          LOG.info("ignore existed signer {}", name);
          continue;
        } else {
          throw logAndCreateException(
              concat("signer ", name, " existed, could not re-added it"));
        }
      }

      try {
        addSigner(entry);
        LOG.info("added signer {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add signer ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    final boolean ignoreId = true;
    // Requestor
    for (String name : conf.getRequestorNames()) {
      MgmtEntry.Requestor entry = conf.getRequestor(name);
      MgmtEntry.Requestor entryB = requestorDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.info("ignore existed CMP requestor {}", name);
          continue;
        } else {
          throw logAndCreateException(
              concat("CMP requestor ", name, " existed, could not re-added it"));
        }
      }

      try {
        addRequestor(entry);
        LOG.info("added CMP requestor {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add CMP requestor ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // Publisher
    for (String name : conf.getPublisherNames()) {
      MgmtEntry.Publisher entry = conf.getPublisher(name);
      MgmtEntry.Publisher entryB = publisherDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.info("ignore existed publisher {}", name);
          continue;
        } else {
          throw logAndCreateException(
              concat("publisher ", name, " existed, could not re-added it"));
        }
      }

      try {
        addPublisher(entry);
        LOG.info("added publisher {}", name);
      } catch (CaMgmtException ex) {
        String msg = "could not add publisher " + name;
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // Certprofile
    for (String name : conf.getCertprofileNames()) {
      MgmtEntry.Certprofile entry = conf.getCertprofile(name);
      MgmtEntry.Certprofile entryB = certprofileDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.info("ignore existed certprofile {}", name);
          continue;
        } else {
          throw logAndCreateException(
              concat("certprofile ", name, " existed, could not re-added it"));
        }
      }

      try {
        addCertprofile(entry);
        LOG.info("added certprofile {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add certprofile ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // User
    for (String name : conf.getUserNames()) {
      Object obj = conf.getUser(name);
      MgmtEntry.User entryB = queryExecutor.getUser(name, true);

      if (entryB != null) {
        boolean equals = false;
        if (obj instanceof MgmtEntry.User) {
          MgmtEntry.User entry = (MgmtEntry.User) obj;
          equals = entry.equals(entryB, ignoreId);
        } else {
          MgmtEntry.AddUser entry = (MgmtEntry.AddUser) obj;
          equals = PasswordHash.validatePassword(entry.getPassword(), entryB.getHashedPassword());
        }

        if (equals) {
          LOG.info("ignore existed user {}", name);
          continue;
        } else {
          throw logAndCreateException(concat("user ", name, " existed, could not re-added it"));
        }
      }

      try {
        if (obj instanceof MgmtEntry.User) {
          queryExecutor.addUser((MgmtEntry.User) obj);
        } else {
          queryExecutor.addUser((MgmtEntry.AddUser) obj);
        }
        LOG.info("added user {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add user ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // CA
    for (String caName : conf.getCaNames()) {
      CaConf.SingleCa scc = conf.getCa(caName);
      CaConf.GenSelfIssued genSelfIssued = scc.getGenSelfIssued();
      MgmtEntry.Ca caEntry = scc.getCaEntry();
      if (caEntry != null) {
        if (caInfos.containsKey(caName)) {
          MgmtEntry.Ca entryB = caInfos.get(caName).getCaEntry();
          if (caEntry.getCert() == null && genSelfIssued != null) {
            SignerConf signerConf = new SignerConf(caEntry.getSignerConf());
            ConcurrentContentSigner signer;
            try {
              signer = securityFactory.createSigner(caEntry.getSignerType(), signerConf,
                  (X509Cert) null);
            } catch (ObjectCreationException ex) {
              throw new CaMgmtException(concat("could not create signer for CA ", caName), ex);
            }
            caEntry.setCert(signer.getCertificate());
          }

          if (caEntry.equals(entryB, true, true)) {
            LOG.info("ignore existing CA {}", caName);
          } else {
            throw logAndCreateException(concat("CA ", caName, " existed, could not re-added it"));
          }
        } else {
          if (genSelfIssued != null) {
            X509Cert cert = generateRootCa(caEntry, genSelfIssued.getProfile(),
                genSelfIssued.getCsr(), genSelfIssued.getSerialNumber());
            LOG.info("generated root CA {}", caName);
            generatedRootCerts.put(caName, cert);
          } else {
            try {
              addCa(caEntry);
              LOG.info("added CA {}", caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not add CA ", caName);
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      }

      if (scc.getAliases() != null) {
        Set<String> aliasesB = getAliasesForCa(caName);
        for (String aliasName : scc.getAliases()) {
          if (aliasesB != null && aliasesB.contains(aliasName)) {
            LOG.info("ignored adding existing CA alias {} to CA {}", aliasName, caName);
          } else {
            try {
              addCaAlias(aliasName, caName);
              LOG.info("associated alias {} to CA {}", aliasName, caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not associate alias ", aliasName, " to CA ", caName);
              LogUtil.error(LOG, ex, msg);
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
            try {
              addCertprofileToCa(profileName, caName);
              LOG.info("added certprofile {} to CA {}", profileName, caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not add certprofile ", profileName, " to CA ", caName);
              LogUtil.error(LOG, ex, msg);
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
            try {
              addPublisherToCa(publisherName, caName);
              LOG.info("added publisher {} to CA {}", publisherName, caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not add publisher ", publisherName, " to CA ", caName);
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      }

      if (scc.getRequestors() != null) {
        Set<MgmtEntry.CaHasRequestor> requestorsB = caHasRequestors.get(caName);

        for (MgmtEntry.CaHasRequestor requestor : scc.getRequestors()) {
          String requestorName = requestor.getRequestorIdent().getName();
          MgmtEntry.CaHasRequestor requestorB = null;
          if (requestorsB != null) {
            for (MgmtEntry.CaHasRequestor m : requestorsB) {
              if (m.getRequestorIdent().getName().equals(requestorName)) {
                requestorB = m;
                break;
              }
            }
          }

          if (requestorB != null) {
            if (requestor.equals(requestorB, ignoreId)) {
              LOG.info("ignored adding requestor {} to CA {}", requestorName, caName);
            } else {
              throw logAndCreateException(
                  concat("could not add requestor ", requestorName, " to CA", caName));
            }
          } else {
            try {
              addRequestorToCa(requestor, caName);
              LOG.info("added publisher {} to CA {}", requestorName, caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not add requestor ", requestorName, " to CA ", caName);
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      } // scc.getRequestors()

      if (scc.getUsers() != null) {
        List<MgmtEntry.CaHasUser> usersB = queryExecutor.getCaHasUsersForCa(caName, idNameMap);

        for (MgmtEntry.CaHasUser user : scc.getUsers()) {
          String userName = user.getUserIdent().getName();
          MgmtEntry.CaHasUser userB = null;
          if (usersB != null) {
            for (MgmtEntry.CaHasUser m : usersB) {
              if (m.getUserIdent().getName().equals(userName)) {
                userB = m;
                break;
              }
            }
          }

          if (userB != null) {
            if (user.equals(userB, ignoreId)) {
              LOG.info("ignored adding user {} to CA {}", userName, caName);
            } else {
              throw logAndCreateException(
                  concat("could not add user ", userName, " to CA", caName));
            }
          } else {
            try {
              addUserToCa(user, caName);
              LOG.info("added user {} to CA {}", userName, caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not add user ", userName, " to CA ", caName);
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      } // scc.getUsers()
    } // cas

    return generatedRootCerts.isEmpty() ? null : generatedRootCerts;
  } // method loadConf

  @Override
  public InputStream exportConf(List<String> caNames)
      throws CaMgmtException, IOException {
    assertMasterModeAndSetuped();

    if (caNames != null) {
      List<String> tmpCaNames = new ArrayList<>(caNames.size());
      for (String name : caNames) {
        name = name.toLowerCase();
        if (x509cas.containsKey(name)) {
          tmpCaNames.add(name);
        }
      }
      caNames = tmpCaNames;
    } else {
      List<String> tmpCaNames = new ArrayList<>(x509cas.size());
      for (String name : x509cas.keySet()) {
        tmpCaNames.add(name);
      }
      caNames = tmpCaNames;
    }

    ByteArrayOutputStream bytesStream = new ByteArrayOutputStream(1048576); // initial 1M
    ZipOutputStream zipStream = new ZipOutputStream(bytesStream);
    zipStream.setLevel(Deflater.BEST_SPEED);

    CaConfType.CaSystem root = new CaConfType.CaSystem();

    try {
      Set<String> includeSignerNames = new HashSet<>();
      Set<String> includeRequestorNames = new HashSet<>();
      Set<String> includeProfileNames = new HashSet<>();
      Set<String> includePublisherNames = new HashSet<>();
      Set<String> includeCrlSignerNames = new HashSet<>();
      Set<String> includeUserNames = new HashSet<>();

      // users
      List<CaConfType.User> users = new LinkedList<>();
      root.setUsers(users);

      // cas
      if (CollectionUtil.isNotEmpty(caNames)) {
        List<CaConfType.Ca> list = new LinkedList<>();

        for (String name : x509cas.keySet()) {
          if (!caNames.contains(name)) {
            continue;
          }

          CaConfType.Ca ca = new CaConfType.Ca();
          ca.setName(name);

          Set<String> strs = getAliasesForCa(name);
          if (CollectionUtil.isNotEmpty(strs)) {
            ca.setAliases(new ArrayList<>(strs));
          }

          // CaHasRequestors
          Set<MgmtEntry.CaHasRequestor> requestors = caHasRequestors.get(name);
          if (CollectionUtil.isNotEmpty(requestors)) {
            ca.setRequestors(new ArrayList<>());

            for (MgmtEntry.CaHasRequestor m : requestors) {
              String requestorName = m.getRequestorIdent().getName();
              includeRequestorNames.add(requestorName);

              CaConfType.CaHasRequestor chr = new CaConfType.CaHasRequestor();
              chr.setRequestorName(requestorName);
              chr.setRa(m.isRa());
              chr.setProfiles(new ArrayList<>(m.getProfiles()));
              chr.setPermissions(getPermissions(m.getPermission()));

              ca.getRequestors().add(chr);
            }
          }

          // CaHasUsers
          List<MgmtEntry.CaHasUser> caHasUsers = queryExecutor.getCaHasUsersForCa(name, idNameMap);
          if (CollectionUtil.isNotEmpty(caHasUsers)) {
            ca.setUsers(new ArrayList<>());

            for (MgmtEntry.CaHasUser m : caHasUsers) {
              String username = m.getUserIdent().getName();
              CaConfType.CaHasUser chu = new CaConfType.CaHasUser();
              chu.setUserName(username);
              chu.setProfiles(new ArrayList<>(m.getProfiles()));
              chu.setPermissions(getPermissions(m.getPermission()));
              ca.getUsers().add(chu);

              if (includeUserNames.contains(username)) {
                continue;
              }

              // add also the user to the users
              MgmtEntry.User userEntry = queryExecutor.getUser(username);
              CaConfType.User userType = new CaConfType.User();
              if (!userEntry.isActive()) {
                userType.setActive(Boolean.FALSE);
              }
              userType.setName(username);
              userType.setHashedPassword(userEntry.getHashedPassword());
              users.add(userType);

              includeUserNames.add(username);
            }
          }

          strs = caHasProfiles.get(name);
          if (CollectionUtil.isNotEmpty(strs)) {
            includeProfileNames.addAll(strs);
            ca.setProfiles(new ArrayList<>(strs));
          }

          strs = caHasPublishers.get(name);
          if (CollectionUtil.isNotEmpty(strs)) {
            includePublisherNames.addAll(strs);
            ca.setPublishers(new ArrayList<>(strs));
          }

          CaConfType.CaInfo caInfoType = new CaConfType.CaInfo();
          ca.setCaInfo(caInfoType);

          MgmtEntry.Ca entry = x509cas.get(name).getCaInfo().getCaEntry();
          // CA URIs
          CaUris caUris = entry.getCaUris();
          if (caUris != null) {
            CaConfType.CaUris caUrisType = new CaConfType.CaUris();
            caUrisType.setCacertUris(caUris.getCacertUris());
            caUrisType.setOcspUris(caUris.getOcspUris());
            caUrisType.setCrlUris(caUris.getCrlUris());
            caUrisType.setDeltacrlUris(caUris.getDeltaCrlUris());
            caInfoType.setCaUris(caUrisType);
          }

          // Certificate
          byte[] certBytes = entry.getCert().getEncoded();
          caInfoType.setCert(createFileOrBinary(zipStream, certBytes,
              concat("files/ca-", name, "-cert.der")));

          // certchain
          List<X509Cert> certchain = entry.getCertchain();
          if (CollectionUtil.isNotEmpty(certchain)) {
            List<FileOrBinary> ccList = new LinkedList<>();

            for (int i = 0; i < certchain.size(); i++) {
              certBytes = certchain.get(i).getEncoded();
              ccList.add(createFileOrBinary(zipStream, certBytes,
                  concat("files/ca-", name, "-certchain-" + i + ".der")));
            }
            caInfoType.setCertchain(ccList);
          }

          if (entry.getCmpControl() != null) {
            caInfoType.setCmpControl(
                new HashMap<>(new ConfPairs(entry.getCmpControl().getConf()).asMap()));
          }

          if (entry.getCmpResponderName() != null) {
            includeSignerNames.add(entry.getCmpResponderName());
            caInfoType.setCmpResponderName(entry.getCmpResponderName());
          }

          if (entry.getCrlControl() != null) {
            caInfoType.setCrlControl(
                new HashMap<>(new ConfPairs(entry.getCrlControl().getConf()).asMap()));
          }

          if (entry.getCrlSignerName() != null) {
            includeCrlSignerNames.add(entry.getCrlSignerName());
            caInfoType.setCrlSignerName(entry.getCrlSignerName());
          }

          if (entry.getCtlogControl() != null) {
            caInfoType.setCtlogControl(
                new HashMap<>(new ConfPairs(entry.getCtlogControl().getConf()).asMap()));
          }

          if (entry.getDhpocControl() != null) {
            FileOrValue fv = createFileOrValue(
                zipStream, entry.getDhpocControl(), concat("files/ca-", name, "-dhpoc.conf"));
            caInfoType.setDhpocControl(fv);
          }

          caInfoType.setExpirationPeriod(entry.getExpirationPeriod());
          if (entry.getExtraControl() != null) {
            caInfoType.setExtraControl(entry.getExtraControl().asMap());
          }

          caInfoType.setKeepExpiredCertDays(entry.getKeepExpiredCertInDays());
          caInfoType.setMaxValidity(entry.getMaxValidity().toString());
          caInfoType.setNextCrlNo(entry.getNextCrlNumber());
          caInfoType.setNumCrls(entry.getNumCrls());
          caInfoType.setPermissions(getPermissions(entry.getPermission()));

          caInfoType.setProtocolSupport(
              StringUtil.splitAsSet(entry.getProtocoSupport().getEncoded(), ","));

          if (entry.getRevokeSuspendedControl() != null) {
            caInfoType.setRevokeSuspendedControl(
                new HashMap<>(new ConfPairs(entry.getRevokeSuspendedControl().getConf()).asMap()));
          }

          caInfoType.setSaveReq(entry.isSaveRequest());
          if (entry.getScepControl() != null) {
            caInfoType.setScepControl(
                new HashMap<>(new ConfPairs(entry.getScepControl().getConf()).asMap()));
          }

          if (entry.getScepResponderName() != null) {
            includeSignerNames.add(entry.getScepResponderName());
            caInfoType.setScepResponderName(entry.getScepResponderName());
          }

          caInfoType.setSignerConf(createFileOrValue(zipStream, entry.getSignerConf(),
              concat("files/ca-", name, "-signerconf.conf")));
          caInfoType.setSignerType(entry.getSignerType());
          caInfoType.setSnSize(entry.getSerialNoLen());

          caInfoType.setStatus(entry.getStatus().getStatus());
          caInfoType.setValidityMode(entry.getValidityMode().name());

          list.add(ca);
        }

        if (!list.isEmpty()) {
          root.setCas(list);
        }
      }

      // clear the users if the list is empty
      if (users.isEmpty()) {
        root.setUsers(null);
      }

      // requestors
      if (CollectionUtil.isNotEmpty(requestorDbEntries)) {
        List<CaConfType.Requestor> list = new LinkedList<>();

        for (String name : requestorDbEntries.keySet()) {
          if (!includeRequestorNames.contains(name)) {
            continue;
          }

          MgmtEntry.Requestor entry = requestorDbEntries.get(name);
          CaConfType.Requestor type = new CaConfType.Requestor();
          type.setName(name);
          type.setType(entry.getType());

          if (MgmtEntry.Requestor.TYPE_CERT.equalsIgnoreCase(entry.getType())) {
            FileOrBinary fob = createFileOrBinary(zipStream,
                Base64.decode(entry.getConf()), concat("files/requestor-", name, ".der"));
            type.setBinaryConf(fob);
          } else {
            FileOrValue fov = createFileOrValue(zipStream,
                entry.getConf(), concat("files/requestor-", name, ".conf"));
            type.setConf(fov);
          }

          list.add(type);
        }

        if (!list.isEmpty()) {
          root.setRequestors(list);
        }
      }

      // publishers
      if (CollectionUtil.isNotEmpty(publisherDbEntries)) {
        List<NameTypeConf> list = new LinkedList<>();

        for (String name : publisherDbEntries.keySet()) {
          if (!includePublisherNames.contains(name)) {
            continue;
          }
          MgmtEntry.Publisher entry = publisherDbEntries.get(name);
          NameTypeConf conf = new NameTypeConf();
          conf.setName(name);
          conf.setType(entry.getType());
          conf.setConf(createFileOrValue(zipStream, entry.getConf(),
              concat("files/publisher-", name, ".conf")));
          list.add(conf);
        }

        if (!list.isEmpty()) {
          root.setPublishers(list);
        }
      }

      // profiles
      if (CollectionUtil.isNotEmpty(certprofileDbEntries)) {
        List<NameTypeConf> list = new LinkedList<>();
        for (String name : certprofileDbEntries.keySet()) {
          if (!includeProfileNames.contains(name)) {
            continue;
          }
          MgmtEntry.Certprofile entry = certprofileDbEntries.get(name);
          NameTypeConf conf = new NameTypeConf();
          conf.setName(name);
          conf.setType(entry.getType());
          conf.setConf(createFileOrValue(zipStream, entry.getConf(),
              concat("files/certprofile-", name, ".conf")));
          list.add(conf);
        }

        if (!list.isEmpty()) {
          root.setProfiles(list);
        }
      }

      // signers
      if (CollectionUtil.isNotEmpty(signerDbEntries)) {
        List<CaConfType.Signer> list = new LinkedList<>();

        for (String name : signerDbEntries.keySet()) {
          if (!includeSignerNames.contains(name)) {
            continue;
          }

          MgmtEntry.Signer entry = signerDbEntries.get(name);
          CaConfType.Signer conf = new CaConfType.Signer();
          conf.setName(name);
          conf.setType(entry.getType());
          conf.setConf(createFileOrValue(zipStream, entry.getConf(),
              concat("files/signer-", name, ".conf")));
          conf.setCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
              concat("files/signer-", name, ".der")));

          list.add(conf);
        }

        if (!list.isEmpty()) {
          root.setSigners(list);
        }
      }

      // add the CAConf XML file
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      try {
        root.validate();
        JSON.writeJSONString(bout, root, SerializerFeature.PrettyFormat);
      } catch (InvalidConfException ex) {
        LogUtil.error(LOG, ex, "could not marshal CAConf");
        throw new CaMgmtException(concat("could not marshal CAConf: ", ex.getMessage()), ex);
      } finally {
        bout.flush();
      }

      zipStream.putNextEntry(new ZipEntry("caconf.json"));
      try {
        zipStream.write(bout.toByteArray());
      } finally {
        zipStream.closeEntry();
      }
    } finally {
      zipStream.flush();
      zipStream.close();
    }

    return new ByteArrayInputStream(bytesStream.toByteArray());
  } // method exportConf

  public CtLogPublicKeyFinder getCtLogPublicKeyFinder() {
    return ctLogPublicKeyFinder;
  }

  private static FileOrValue createFileOrValue(ZipOutputStream zipStream,
      String content, String fileName) throws IOException {
    if (StringUtil.isBlank(content)) {
      return null;
    }

    FileOrValue ret = new FileOrValue();
    if (content.length() < 256) {
      ret.setValue(content);
    } else {
      ret.setFile(fileName);
      ZipEntry certZipEntry = new ZipEntry(fileName);
      zipStream.putNextEntry(certZipEntry);
      try {
        zipStream.write(StringUtil.toUtf8Bytes(content));
      } finally {
        zipStream.closeEntry();
      }
    }
    return ret;
  } // method createFileOrValue

  private static FileOrBinary createFileOrBase64Value(ZipOutputStream zipStream,
      String b64Content, String fileName) throws IOException {
    if (StringUtil.isBlank(b64Content)) {
      return null;
    }

    return createFileOrBinary(zipStream, Base64.decode(b64Content), fileName);
  } // method createFileOrBase64Value

  private static FileOrBinary createFileOrBinary(ZipOutputStream zipStream,
      byte[] content, String fileName) throws IOException {
    if (content == null || content.length == 0) {
      return null;
    }

    FileOrBinary ret = new FileOrBinary();
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
  } // method createFileOrBinary

  public RestResponder getRestResponder() {
    return restResponder;
  }

  private static String concat(String s1, String... strs) {
    return StringUtil.concat(s1, strs);
  }

  private static CaMgmtException logAndCreateException(String msg) {
    LOG.error(msg);
    return new CaMgmtException(msg);
  }

  private static List<String> getPermissions(int permission) {
    List<String> list = new LinkedList<>();
    if (PermissionConstants.ALL == permission) {
      list.add(PermissionConstants.getTextForCode(permission));
    } else {
      for (Integer code : PermissionConstants.getPermissions()) {
        if ((permission & code) != 0) {
          list.add(PermissionConstants.getTextForCode(code));
        }
      }
    }

    return list;
  } // method getPermissions

}
