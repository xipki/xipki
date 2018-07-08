/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.server.impl;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditServiceRegister;
import org.xipki.audit.AuditStatus;
import org.xipki.audit.PciAuditEvent;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.profile.CertValidity.Unit;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.CertprofileFactoryRegister;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertPublisherFactoryRegister;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.server.api.CaAuditConstants;
import org.xipki.ca.server.api.CmpResponder;
import org.xipki.ca.server.api.ResponderManager;
import org.xipki.ca.server.api.RestResponder;
import org.xipki.ca.server.api.ScepResponder;
import org.xipki.ca.server.impl.SelfSignedCertBuilder.GenerateSelfSignedResult;
import org.xipki.ca.server.impl.cmp.CmpResponderImpl;
import org.xipki.ca.server.impl.cmp.RequestorEntryWrapper;
import org.xipki.ca.server.impl.rest.RestResponderImpl;
import org.xipki.ca.server.impl.scep.ScepResponderImpl;
import org.xipki.ca.server.impl.store.CertStore;
import org.xipki.ca.server.impl.store.CertWithRevocationInfo;
import org.xipki.ca.server.impl.util.PasswordHash;
import org.xipki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.CaSystemStatus;
import org.xipki.ca.server.mgmt.api.CertListInfo;
import org.xipki.ca.server.mgmt.api.CertListOrderBy;
import org.xipki.ca.server.mgmt.api.CertWithStatusInfo;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.ca.server.mgmt.api.ChangeUserEntry;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.PermissionConstants;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.RequestorEntry;
import org.xipki.ca.server.mgmt.api.RequestorInfo;
import org.xipki.ca.server.mgmt.api.RevokeSuspendedCertsControl;
import org.xipki.ca.server.mgmt.api.SignerEntry;
import org.xipki.ca.server.mgmt.api.UserEntry;
import org.xipki.ca.server.mgmt.api.conf.CaConf;
import org.xipki.ca.server.mgmt.api.conf.GenSelfIssued;
import org.xipki.ca.server.mgmt.api.conf.SingleCaConf;
import org.xipki.ca.server.mgmt.api.conf.jaxb.AliasesType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaHasRequestorType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaHasUserType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaInfoType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaUrisType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaconfType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.FileOrBinaryType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.FileOrValueType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.PermissionsType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ProfileType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ProfilesType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.PublisherType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.PublishersType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.RequestorType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.SignerType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.UrisType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.UserType;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.CrlReason;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.DateUtil;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;
import org.xml.sax.SAXException;

/**
 * TODO: unify the LOG, make sure that all events are audited even exception is thrown.
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaManagerImpl implements CaManager, ResponderManager {

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

  private final Map<String, CaInfo> caInfos = new ConcurrentHashMap<>();

  private Map<String, SignerEntryWrapper> signers = new ConcurrentHashMap<>();

  private Map<String, SignerEntry> signerDbEntries = new ConcurrentHashMap<>();

  private final Map<String, IdentifiedCertprofile> certprofiles = new ConcurrentHashMap<>();

  private final Map<String, CertprofileEntry> certprofileDbEntries = new ConcurrentHashMap<>();

  private final Map<String, IdentifiedCertPublisher> publishers = new ConcurrentHashMap<>();

  private final Map<String, PublisherEntry> publisherDbEntries = new ConcurrentHashMap<>();

  private final Map<String, RequestorEntryWrapper> requestors = new ConcurrentHashMap<>();

  private final Map<String, RequestorEntry> requestorDbEntries = new ConcurrentHashMap<>();

  private final Map<String, Set<String>> caHasProfiles = new ConcurrentHashMap<>();

  private final Map<String, Set<String>> caHasPublishers = new ConcurrentHashMap<>();

  private final Map<String, Set<CaHasRequestorEntry>> caHasRequestors = new ConcurrentHashMap<>();

  private final Map<String, Integer> caAliases = new ConcurrentHashMap<>();

  private ScheduledThreadPoolExecutor persistentScheduledThreadPoolExecutor;

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  private final Map<String, CmpResponderImpl> cmpResponders = new ConcurrentHashMap<>();

  private final Map<String, ScepResponderImpl> scepResponders = new ConcurrentHashMap<>();

  private final Map<String, X509Ca> x509cas = new ConcurrentHashMap<>();

  private final DataSourceFactory datasourceFactory;

  private final RestResponderImpl restResponder;

  private Properties caConfProperties;

  private boolean caSystemSetuped;

  private boolean signerInitialized;

  private boolean requestorsInitialized;

  private boolean caAliasesInitialized;

  private boolean certprofilesInitialized;

  private boolean publishersInitialized;

  private boolean casInitialized;

  private Date lastStartTime;

  private AuditServiceRegister auditServiceRegister;

  private CertprofileFactoryRegister certprofileFactoryRegister;

  private CertPublisherFactoryRegister certPublisherFactoryRegister;

  private DataSourceWrapper datasource;

  private CertStore certstore;

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
    this.restResponder = new RestResponderImpl(this);
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
    if (caConfProperties == null) {
      throw new IllegalStateException("caConfProperties is not set");
    }

    String caModeStr = caConfProperties.getProperty("ca.mode");
    if (caModeStr != null) {
      if ("slave".equalsIgnoreCase(caModeStr)) {
        masterMode = false;
      } else if ("master".equalsIgnoreCase(caModeStr)) {
        masterMode = true;
      } else {
        throw new CaMgmtException(concat("invalid ca.mode '", caModeStr, "'"));
      }
    } else {
      masterMode = true;
    }
    LOG.info("ca.mode: {}", caModeStr);

    int shardId;
    String shardIdStr = caConfProperties.getProperty("ca.shardId");
    if (StringUtil.isBlank(shardIdStr)) {
      throw new CaMgmtException("ca.shardId is not set");
    }
    LOG.info("ca.shardId: {}", shardIdStr);

    try {
      shardId = Integer.parseInt(shardIdStr);
    } catch (NumberFormatException ex) {
      throw new CaMgmtException(concat("invalid ca.shardId '", shardIdStr, "'"));
    }

    if (shardId < 0 || shardId > 127) {
      throw new CaMgmtException("ca.shardId is not in [0, 127]");
    }

    if (this.datasources == null) {
      this.datasources = new ConcurrentHashMap<>();
      for (Object objKey : caConfProperties.keySet()) {
        String key = (String) objKey;
        if (!StringUtil.startsWithIgnoreCase(key, "datasource.")) {
          continue;
        }

        String datasourceFile = caConfProperties.getProperty(key);
        try {
          String datasourceName = key.substring("datasource.".length());
          DataSourceWrapper datasource = datasourceFactory.createDataSourceForFile(
              datasourceName, datasourceFile, securityFactory.getPasswordResolver());

          Connection conn = datasource.getConnection();
          datasource.returnConnection(conn);

          LOG.info("datasource.{}: {}", datasourceName, datasourceFile);
          this.datasources.put(datasourceName, datasource);
        } catch (DataAccessException | PasswordResolverException | IOException
            | RuntimeException ex) {
          throw new CaMgmtException(concat(ex.getClass().getName(),
            " while parsing datasource ", datasourceFile, ": ", ex.getMessage()), ex);
        }
      }

      this.datasource = this.datasources.get("ca");
    }

    if (this.datasource == null) {
      throw new CaMgmtException("no datasource named 'ca' configured");
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

    shutdownScheduledThreadPoolExecutor();
  } // method reset

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
          sb.append(name).append(" (alias ").append(aliasName).append("), ");
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

    ConfPairs extraControl = caEntry.getCaEntry().getExtraControl();
    if (extraControl != null) {
      String str = extraControl.value(RevokeSuspendedCertsControl.KEY_REVOCATION_ENABLED);
      boolean enabled = false;
      if (str != null) {
        enabled = Boolean.parseBoolean(str);
      }

      if (enabled) {
        str = extraControl.value(RevokeSuspendedCertsControl.KEY_REVOCATION_REASON);
        CrlReason reason = (str == null) ? CrlReason.CESSATION_OF_OPERATION
            : CrlReason.forNameOrText(str);

        str = extraControl.value(RevokeSuspendedCertsControl.KEY_UNCHANGED_SINCE);
        CertValidity unchangedSince = (str == null) ? new CertValidity(15, Unit.DAY)
            : CertValidity.getInstance(str);
        RevokeSuspendedCertsControl control = new RevokeSuspendedCertsControl(reason,
            unchangedSince);
        caEntry.setRevokeSuspendedCertsControl(control);
      }
    }

    X509Ca ca;
    try {
      ca = new X509Ca(this, caEntry, certstore);
      ca.setAuditServiceRegister(auditServiceRegister);
    } catch (OperationException ex) {
      LogUtil.error(LOG, ex, concat("X509CA.<init> (ca=", caName, ")"));
      return false;
    }

    x509cas.put(caName, ca);
    CmpResponderImpl caResponder;
    try {
      caResponder = new CmpResponderImpl(this, caName);
    } catch (NoSuchAlgorithmException ex) {
      LogUtil.error(LOG, ex, concat("CmpResponderImpl.<init> (ca=", caName, ")"));
      return false;
    }

    cmpResponders.put(caName, caResponder);

    if (caEntry.supportsScep() && caEntry.getScepResponderName() != null) {
      try {
        scepResponders.put(caName, new ScepResponderImpl(this, caEntry.getCaEntry()));
      } catch (CaMgmtException ex) {
        LogUtil.error(LOG, ex, concat("X509CA.<init> (scep=", caName, ")"));
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
        LogUtil.error(LOG, th, concat("could not call ca.shutdown() for CA ", caName));
      }
    }

    if (caLockedByMe) {
      try {
        unlockCa();
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not unlock CA system");
      }
    }

    File caLockFile = new File("calock");
    if (caLockFile.exists()) {
      caLockFile.delete();
    }

    for (String dsName :datasources.keySet()) {
      DataSourceWrapper ds = datasources.get(dsName);
      try {
        ds.close();
      } catch (Exception ex) {
        LogUtil.warn(LOG, ex, concat("could not close datasource ", dsName));
      }
    }

    auditLogPciEvent(true, "SHUTDOWN");
    LOG.info("stopped CA system");
  } // method shutdown

  @Override
  public CmpResponder getX509CaResponder(String name) {
    return cmpResponders.get(ParamUtil.requireNonBlankLower("name", name));
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
  }

  @Override
  public Set<String> getFailedCaNames() {
    Set<String> ret = new HashSet<>();
    for (String name : caInfos.keySet()) {
      if (CaStatus.ACTIVE == caInfos.get(name).getStatus() && !x509cas.containsKey(name)) {
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
    List<String> names = queryExecutor.namesFromTable("REQUESTOR");
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
        RequestorEntry requestorDbEntry = queryExecutor.createRequestor(name);
        if (requestorDbEntry == null) {
          LOG.error("could not load requestor {}", name);
          continue;
        }

        idNameMap.addRequestor(requestorDbEntry.getIdent());
        requestorDbEntries.put(name, requestorDbEntry);
        RequestorEntryWrapper requestor = new RequestorEntryWrapper();
        requestor.setDbEntry(requestorDbEntry);
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
      SignerEntry dbEntry = queryExecutor.createSigner(name);
      if (dbEntry == null) {
        LOG.error("could not initialize signer '{}'", name);
        continue;
      }

      dbEntry.setConfFaulty(true);
      signerDbEntries.put(name, dbEntry);

      SignerEntryWrapper signer = createSigner(dbEntry);
      if (signer != null) {
        dbEntry.setConfFaulty(false);
        signers.put(name, signer);
        LOG.info("loaded signer {}", name);
      } else {
        LOG.error("could not load signer {}", name);
      }
    }
    signerInitialized = true;
  } // method initResponders

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
      CertprofileEntry dbEntry = queryExecutor.createCertprofile(name);
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
      PublisherEntry dbEntry = queryExecutor.createPublisher(name);
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
      oldCa.shutdown();
    }

    CaInfo ca = queryExecutor.createCaInfo(name, masterMode, certstore);
    LOG.info("created CA {}: {}", name, ca.toString(false));
    caInfos.put(name, ca);
    idNameMap.addCa(ca.getIdent());
    Set<CaHasRequestorEntry> caReqEntries = queryExecutor.createCaHasRequestors(ca.getIdent());
    caHasRequestors.put(name, caReqEntries);
    if (LOG.isInfoEnabled()) {
      StringBuilder sb = new StringBuilder();
      for (CaHasRequestorEntry entry : caReqEntries) {
        sb.append("\n    ").append(entry);
      }
      LOG.info("CA {} is associated with following requestors:{}", name, sb);
    }

    Set<Integer> profileIds = queryExecutor.createCaHasProfiles(ca.getIdent());
    Set<String> profileNames = new HashSet<>();
    for (Integer id : profileIds) {
      profileNames.add(idNameMap.getCertprofileName(id));
    }
    caHasProfiles.put(name, profileNames);
    LOG.info("CA {} is associated with following profiles: {}", name, profileNames);

    Set<Integer> publisherIds = queryExecutor.createCaHasPublishers(ca.getIdent());
    Set<String> publisherNames = new HashSet<>();
    for (Integer id : publisherIds) {
      publisherNames.add(idNameMap.getPublisherName(id));
    }
    caHasPublishers.put(name, publisherNames);
    LOG.info("CA {} is associated with following publishers: {}", name, publisherNames);

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
  }

  public ByUserRequestorInfo createByUserRequestor(CaHasUserEntry caHasUser) {
    return new ByUserRequestorInfo(byUserRequestorId, caHasUser);
  }

  @Override
  public void addCa(CaEntry caEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("caEntry", caEntry);
    asssertMasterMode();
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
      List<String[]> signerConfs = CaEntry.splitCaSignerConfs(caEntry.getSignerConf());
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
  public CaEntry getCa(String name) {
    CaInfo caInfo = caInfos.get(ParamUtil.requireNonBlankLower("name", name));
    return (caInfo == null) ? null : caInfo.getCaEntry();
  }

  @Override
  public void changeCa(ChangeCaEntry entry) throws CaMgmtException {
    ParamUtil.requireNonNull("entry", entry);
    asssertMasterMode();
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
    profileName = ParamUtil.requireNonBlankLower("profileName", profileName);
    caName = ParamUtil.requireNonBlankLower("caName", caName);
    asssertMasterMode();

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
    profileName = ParamUtil.requireNonBlankLower("profileName", profileName);
    caName = ParamUtil.requireNonBlankLower("caName", caName);
    asssertMasterMode();

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
    publisherName = ParamUtil.requireNonBlankLower("publisherName", publisherName);
    caName = ParamUtil.requireNonBlankLower("caName", caName);
    asssertMasterMode();

    queryExecutor.removePublisherFromCa(publisherName, caName);

    Set<String> publisherNames = caHasPublishers.get(caName);
    if (publisherNames != null) {
      publisherNames.remove(publisherName);
    }
  } // method removePublisherFromCa

  @Override
  public void addPublisherToCa(String publisherName, String caName) throws CaMgmtException {
    publisherName = ParamUtil.requireNonBlankLower("publisherName", publisherName);
    caName = ParamUtil.requireNonBlankLower("caName", caName);
    asssertMasterMode();

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
    return caHasProfiles.get(ParamUtil.requireNonBlankLower("caName", caName));
  }

  @Override
  public Set<CaHasRequestorEntry> getRequestorsForCa(String caName) {
    return caHasRequestors.get(ParamUtil.requireNonBlankLower("caName", caName));
  }

  @Override
  public RequestorEntry getRequestor(String name) {
    return requestorDbEntries.get(ParamUtil.requireNonBlankLower("name", name));
  }

  public RequestorEntryWrapper getRequestorWrapper(String name) {
    return requestors.get(ParamUtil.requireNonBlankLower("name", name));
  }

  @Override
  public void addRequestor(RequestorEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    asssertMasterMode();
    String name = dbEntry.getIdent().getName();
    if (requestorDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Requestor named ", name, " exists"));
    }

    RequestorEntryWrapper requestor = new RequestorEntryWrapper();
    requestor.setDbEntry(dbEntry);

    queryExecutor.addRequestor(dbEntry);
    idNameMap.addRequestor(dbEntry.getIdent());
    requestorDbEntries.put(name, dbEntry);
    requestors.put(name, requestor);
  } // method addRequestor

  @Override
  public void removeRequestor(String name) throws CaMgmtException {
    name = ParamUtil.requireNonBlankLower("requestorName", name);
    asssertMasterMode();

    for (String caName : caHasRequestors.keySet()) {
      boolean removeMe = false;
      for (CaHasRequestorEntry caHasRequestor : caHasRequestors.get(caName)) {
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
  public void changeRequestor(String name, String base64Cert) throws CaMgmtException {
    ParamUtil.requireNonNull("base64Cert", base64Cert);
    name = ParamUtil.requireNonBlankLower("name", name);
    asssertMasterMode();

    NameId ident = idNameMap.getRequestor(name);
    if (ident == null) {
      throw logAndCreateException(concat("unknown requestor ", name));
    }

    RequestorEntryWrapper requestor = queryExecutor.changeRequestor(ident, base64Cert);

    requestorDbEntries.remove(name);
    requestors.remove(name);

    requestorDbEntries.put(name, requestor.getDbEntry());
    requestors.put(name, requestor);
  } // method changeRequestor

  @Override
  public void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    requestorName = ParamUtil.requireNonBlankLower("requestorName", requestorName);
    caName = ParamUtil.requireNonBlankLower("caName", caName);
    asssertMasterMode();

    if (requestorName.equals(RequestorInfo.NAME_BY_CA)
        || requestorName.equals(RequestorInfo.NAME_BY_USER)) {
      throw new CaMgmtException(concat("removing requestor ", requestorName, " is not permitted"));
    }

    queryExecutor.removeRequestorFromCa(requestorName, caName);
    if (caHasRequestors.containsKey(caName)) {
      Set<CaHasRequestorEntry> entries = caHasRequestors.get(caName);
      CaHasRequestorEntry entry = null;
      for (CaHasRequestorEntry m : entries) {
        if (m.getRequestorIdent().getName().equals(requestorName)) {
          entry = m;
        }
      }
      entries.remove(entry);
    }
  } // method removeRequestorFromCa

  @Override
  public void addRequestorToCa(CaHasRequestorEntry requestor, String caName)
      throws CaMgmtException {
    ParamUtil.requireNonNull("requestor", requestor);
    caName = ParamUtil.requireNonBlankLower("caName", caName);
    asssertMasterMode();

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

    Set<CaHasRequestorEntry> cmpRequestors = caHasRequestors.get(caName);
    if (cmpRequestors == null) {
      cmpRequestors = new HashSet<>();
      caHasRequestors.put(caName, cmpRequestors);
    } else {
      for (CaHasRequestorEntry entry : cmpRequestors) {
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
    userName = ParamUtil.requireNonBlankLower("userName", userName);
    caName = ParamUtil.requireNonBlankLower("caName", caName);
    asssertMasterMode();

    queryExecutor.removeUserFromCa(userName, caName);
  }

  @Override
  public void addUserToCa(CaHasUserEntry user, String caName) throws CaMgmtException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    asssertMasterMode();

    X509Ca ca = getX509Ca(caName);
    if (ca == null) {
      throw logAndCreateException(concat("unknown CA ", caName));
    }

    queryExecutor.addUserToCa(user, ca.getCaIdent());
  }

  @Override
  public Map<String, CaHasUserEntry> getCaHasUsersForUser(String user) throws CaMgmtException {
    ParamUtil.requireNonBlank("user", user);
    return queryExecutor.getCaHasUsersForUser(user, idNameMap);
  }

  @Override
  public CertprofileEntry getCertprofile(String name) {
    return certprofileDbEntries.get(name.toLowerCase());
  }

  @Override
  public void removeCertprofile(String name) throws CaMgmtException {
    name = ParamUtil.requireNonBlankLower("name", name);
    asssertMasterMode();

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
    name = ParamUtil.requireNonBlankLower("name", name);
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

    asssertMasterMode();

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
  public void addCertprofile(CertprofileEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    asssertMasterMode();
    String name = dbEntry.getIdent().getName();
    if (certprofileDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Certprofile named ", name, " exists"));
    }

    dbEntry.setFaulty(true);
    IdentifiedCertprofile profile = createCertprofile(dbEntry);
    if (profile == null) {
      throw new CaMgmtException("could not create Certprofile object");
    }

    dbEntry.setFaulty(false);
    certprofiles.put(name, profile);
    queryExecutor.addCertprofile(dbEntry);
    idNameMap.addCertprofile(dbEntry.getIdent());
    certprofileDbEntries.put(name, dbEntry);
  } // method addCertprofile

  @Override
  public void addSigner(SignerEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    asssertMasterMode();
    String name = dbEntry.getName();
    if (signerDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Signer named ", name, " exists"));
    }

    String conf = dbEntry.getConf();
    if (conf != null) {
      String newConf = canonicalizeSignerConf(dbEntry.getType(), conf, null, securityFactory);
      if (!conf.equals(newConf)) {
        dbEntry.setConf(newConf);
      }
    }

    SignerEntryWrapper signer = createSigner(dbEntry);
    queryExecutor.addSigner(dbEntry);
    signers.put(name, signer);
    signerDbEntries.put(name, dbEntry);
  } // method addResponder

  @Override
  public void removeSigner(String name) throws CaMgmtException {
    name = ParamUtil.requireNonBlankLower("name", name);
    asssertMasterMode();
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
    name = ParamUtil.requireNonBlankLower("name", name);
    asssertMasterMode();
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
  public SignerEntry getSigner(String name) {
    return signerDbEntries.get(ParamUtil.requireNonBlankLower("name", name));
  }

  public SignerEntryWrapper getSignerWrapper(String name) {
    return signers.get(ParamUtil.requireNonBlankLower("name", name));
  }

  @Override
  public void addPublisher(PublisherEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    asssertMasterMode();
    String name = dbEntry.getIdent().getName();
    if (publisherDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Publisher named ", name, " exists"));
    }

    dbEntry.setFaulty(true);
    IdentifiedCertPublisher publisher = createPublisher(dbEntry);
    dbEntry.setFaulty(false);

    queryExecutor.addPublisher(dbEntry);

    publishers.put(name, publisher);
    idNameMap.addPublisher(dbEntry.getIdent());
    publisherDbEntries.put(name, dbEntry);
  } // method addPublisher

  @Override
  public List<PublisherEntry> getPublishersForCa(String caName) {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
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
  public PublisherEntry getPublisher(String name) {
    name = ParamUtil.requireNonBlankLower("name", name);
    return publisherDbEntries.get(name);
  }

  @Override
  public void removePublisher(String name) throws CaMgmtException {
    name = ParamUtil.requireNonBlankLower("name", name);
    asssertMasterMode();
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
    name = ParamUtil.requireNonBlankLower("name", name);
    asssertMasterMode();
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

  public Properties getCaConfProperties() {
    return caConfProperties;
  }

  public void setCaConfProperties(Properties caConfProperties) {
    this.caConfProperties = ParamUtil.requireNonNull("caConfProperties", caConfProperties);
  }

  public void setCaConfFile(String caConfFile) {
    ParamUtil.requireNonBlank("caConfFile", caConfFile);

    Properties caConfProps = new Properties();
    try {
      caConfProps.load(new FileInputStream(IoUtil.expandFilepath(caConfFile)));
    } catch (IOException ex) {
      throw new IllegalArgumentException("could not parse CA configuration file " + caConfFile, ex);
    }
    this.caConfProperties = caConfProps;
  }

  @Override
  public void addCaAlias(String aliasName, String caName) throws CaMgmtException {
    aliasName = ParamUtil.requireNonBlankLower("aliasName", aliasName);
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    asssertMasterMode();

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
    name = ParamUtil.requireNonBlankLower("name", name);
    asssertMasterMode();
    queryExecutor.removeCaAlias(name);
    caAliases.remove(name);
  }

  @Override
  public String getCaNameForAlias(String aliasName) {
    aliasName = ParamUtil.requireNonBlankLower("aliasName", aliasName);
    Integer caId = caAliases.get(aliasName);
    for (String name : x509cas.keySet()) {
      X509Ca ca = x509cas.get(name);
      if (ca.getCaIdent().getId().equals(caId)) {
        return ca.getCaIdent().getName();
      }
    }
    return null;
  }

  @Override
  public Set<String> getAliasesForCa(String caName) {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
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

  @Override
  public void removeCa(String name) throws CaMgmtException {
    name = ParamUtil.requireNonBlankLower("name", name);
    asssertMasterMode();

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
      ca.shutdown();
    }
  } // method removeCa

  @Override
  public void republishCertificates(String caName, List<String> publisherNames, int numThreads)
      throws CaMgmtException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    ParamUtil.requireMin("numThreads", numThreads, 1);
    asssertMasterMode();
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
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    ParamUtil.requireNonNull("revocationInfo", revocationInfo);
    asssertMasterMode();

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
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    asssertMasterMode();

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

  public void setAuditServiceRegister(AuditServiceRegister register) {
    this.auditServiceRegister = ParamUtil.requireNonNull("serviceRegister", register);

    for (String name : publishers.keySet()) {
      IdentifiedCertPublisher publisherEntry = publishers.get(name);
      publisherEntry.setAuditServiceRegister(register);
    }

    for (String name : x509cas.keySet()) {
      X509Ca ca = x509cas.get(name);
      ca.setAuditServiceRegister(register);
    }
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
    auditServiceRegister.getAuditService().logEvent(event);
  } // method auditLogPciEvent

  @Override
  public void clearPublishQueue(String caName, List<String> publisherNames) throws CaMgmtException {
    asssertMasterMode();

    publisherNames = CollectionUtil.toLowerCaseList(publisherNames);

    if (caName == null) {
      if (CollectionUtil.isNonEmpty(publisherNames)) {
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
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    ParamUtil.requireNonNull("serialNumber", serialNumber);
    asssertMasterMode();
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
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    ParamUtil.requireNonNull("serialNumber", serialNumber);
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
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    ParamUtil.requireNonNull("serialNumber", serialNumber);
    asssertMasterMode();
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
  public X509Certificate generateCertificate(String caName, String profileName, byte[] encodedCsr,
      Date notBefore, Date notAfter) throws CaMgmtException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    profileName = ParamUtil.requireNonBlankLower("profileName", profileName);
    ParamUtil.requireNonNull("encodedCsr", encodedCsr);

    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName(CaAuditConstants.APPNAME);
    event.setName(CaAuditConstants.NAME_perf);
    event.addEventType("CAMGMT_CRL_GEN_ONDEMAND");

    X509Ca ca = getX509Ca(caName);
    CertificationRequest csr;
    try {
      csr = CertificationRequest.getInstance(encodedCsr);
    } catch (Exception ex) {
      throw new CaMgmtException(concat("invalid CSR request. ERROR: ", ex.getMessage()));
    }

    CmpControl cmpControl = ca.getCaInfo().getCmpControl();
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
    name = ParamUtil.requireNonBlankLower("name", name);
    X509Ca ca = x509cas.get(name);
    if (ca == null) {
      throw new CaMgmtException("unknown CA " + name);
    }
    return ca;
  }

  public X509Ca getX509Ca(NameId ident) throws CaMgmtException {
    ParamUtil.requireNonNull("ident", ident);
    X509Ca ca = x509cas.get(ident.getName());
    if (ca == null) {
      throw new CaMgmtException("unknown CA " + ident);
    }
    return ca;
  }

  public IdentifiedCertprofile getIdentifiedCertprofile(String profileName) {
    profileName = ParamUtil.requireNonBlankLower("profileName", profileName);
    return certprofiles.get(profileName);
  }

  public List<IdentifiedCertPublisher> getIdentifiedPublishersForCa(String caName) {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
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
  public X509Certificate generateRootCa(CaEntry caEntry, String profileName, byte[] encodedCsr,
      BigInteger serialNumber) throws CaMgmtException {
    ParamUtil.requireNonNull("caEntry", caEntry);
    profileName = ParamUtil.requireNonBlankLower("profileName", profileName);
    ParamUtil.requireNonNull("encodedCsr", encodedCsr);

    int numCrls = caEntry.getNumCrls();
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

    IdentifiedCertprofile certprofile = getIdentifiedCertprofile(profileName);
    if (certprofile == null) {
      throw new CaMgmtException(concat("unknown certprofile ", profileName));
    }

    BigInteger serialOfThisCert = (serialNumber != null) ? serialNumber
        : RandomSerialNumberGenerator.getInstance().nextSerialNumber(caEntry.getSerialNoBitLen());

    GenerateSelfSignedResult result;
    try {
      result = SelfSignedCertBuilder.generateSelfSigned(securityFactory, signerType,
          caEntry.getSignerConf(), certprofile, csr, serialOfThisCert, caEntry.getCaUris(),
          caEntry.getExtraControl());
    } catch (OperationException | InvalidConfException ex) {
      throw new CaMgmtException(concat(ex.getClass().getName(), ": ", ex.getMessage()), ex);
    }

    String signerConf = result.getSignerConf();
    X509Certificate caCert = result.getCert();

    if ("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType)) {
      try {
        signerConf = canonicalizeSignerConf(signerType, signerConf,
            new X509Certificate[]{caCert}, securityFactory);
      } catch (Exception ex) {
        throw new CaMgmtException(concat(ex.getClass().getName(), ": ", ex.getMessage()), ex);
      }
    }

    String name = caEntry.getIdent().getName();
    long nextCrlNumber = caEntry.getNextCrlNumber();

    CaEntry entry = new CaEntry(new NameId(null, name), caEntry.getSerialNoBitLen(),
        nextCrlNumber, signerType, signerConf, caEntry.getCaUris(), numCrls, expirationPeriod);
    entry.setCert(caCert);
    entry.setCmpControl(caEntry.getCmpControl());
    entry.setCrlControl(caEntry.getCrlControl());
    entry.setScepControl(caEntry.getScepControl());
    entry.setCmpResponderName(caEntry.getCmpResponderName());
    entry.setScepResponderName(caEntry.getScepResponderName());
    entry.setCrlSignerName(caEntry.getCrlSignerName());
    entry.setDuplicateKeyPermitted(caEntry.isDuplicateKeyPermitted());
    entry.setDuplicateSubjectPermitted(caEntry.isDuplicateSubjectPermitted());
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

  private void asssertMasterMode() throws CaMgmtException {
    if (!masterMode) {
      throw new CaMgmtException("operation not allowed in slave mode");
    }
  }

  void shutdownCertprofile(IdentifiedCertprofile profile) {
    if (profile == null) {
      return;
    }

    try {
      profile.shutdown();
    } catch (Exception ex) {
      LogUtil.warn(LOG, ex, "could not shutdown Certprofile " + profile.getIdent());
    }
  } // method shutdownCertprofile

  void shutdownPublisher(IdentifiedCertPublisher publisher) {
    if (publisher == null) {
      return;
    }

    try {
      publisher.shutdown();
    } catch (Exception ex) {
      LogUtil.warn(LOG, ex, "could not shutdown CertPublisher " + publisher.getIdent());
    }
  } // method shutdownPublisher

  SignerEntryWrapper createSigner(SignerEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    SignerEntryWrapper ret = new SignerEntryWrapper();
    ret.setDbEntry(dbEntry);
    try {
      ret.initSigner(securityFactory);
    } catch (ObjectCreationException ex) {
      final String message = "createSigner";
      LOG.debug(message, ex);
      throw new CaMgmtException(ex.getMessage());
    }
    return ret;
  } // method createSigner

  IdentifiedCertprofile createCertprofile(CertprofileEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);

    String type = dbEntry.getType();
    if (!certprofileFactoryRegister.canCreateProfile(type)) {
      throw new CaMgmtException("unsupported cert profile type " + type);
    }

    try {
      Certprofile profile = certprofileFactoryRegister.newCertprofile(type);
      IdentifiedCertprofile ret = new IdentifiedCertprofile(dbEntry, profile);
      ret.validate();
      return ret;
    } catch (ObjectCreationException | CertprofileException ex) {
      String msg = "could not initialize Certprofile " + dbEntry.getIdent();
      LogUtil.error(LOG, ex, msg);
      throw new CaMgmtException(msg, ex);
    }
  } // method createCertprofile

  IdentifiedCertPublisher createPublisher(PublisherEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    String type = dbEntry.getType();

    CertPublisher publisher;
    IdentifiedCertPublisher ret;
    try {
      if (certPublisherFactoryRegister.canCreatePublisher(type)) {
        publisher = certPublisherFactoryRegister.newPublisher(type);
      } else {
        throw new CaMgmtException("unsupported publisher type " + type);
      }

      ret = new IdentifiedCertPublisher(dbEntry, publisher);
      ret.initialize(securityFactory.getPasswordResolver(), datasources);
      return ret;
    } catch (ObjectCreationException | CertPublisherException | RuntimeException ex) {
      String msg = "invalid configuration for the publisher " + dbEntry.getIdent();
      LogUtil.error(LOG, ex, msg);
      throw new CaMgmtException(msg, ex);
    }
  } // method createPublisher

  @Override
  public void addUser(AddUserEntry userEntry) throws CaMgmtException {
    asssertMasterMode();
    queryExecutor.addUser(userEntry);
  }

  @Override
  public void changeUser(ChangeUserEntry userEntry) throws CaMgmtException {
    asssertMasterMode();
    queryExecutor.changeUser(userEntry);
  }

  @Override
  public void removeUser(String username) throws CaMgmtException {
    username = ParamUtil.requireNonBlankLower("username", username);
    asssertMasterMode();
    if (!queryExecutor.deleteRowWithName(username, "TUSER")) {
      throw new CaMgmtException("unknown user " + username);
    }
  }

  @Override
  public UserEntry getUser(String username) throws CaMgmtException {
    return queryExecutor.getUser(username.toLowerCase());
  }

  CaIdNameMap idNameMap() {
    return idNameMap;
  }

  @Override
  public X509CRL generateCrlOnDemand(String caName) throws CaMgmtException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;

    X509Ca ca = getX509Ca(caName);
    try {
      return ca.generateCrlOnDemand(CaAuditConstants.MSGID_ca_mgmt);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method generateCrlOnDemand

  @Override
  public X509CRL getCrl(String caName, BigInteger crlNumber) throws CaMgmtException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    ParamUtil.requireNonNull("crlNumber", crlNumber);
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
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
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
  public ScepResponder getScepResponder(String name) {
    name = ParamUtil.requireNonBlankLower("name", name);
    return (scepResponders == null) ? null : scepResponders.get(name);
  }

  static String canonicalizeSignerConf(String keystoreType, String signerConf,
      X509Certificate[] certChain, SecurityFactory securityFactory) throws CaMgmtException {
    if (!signerConf.contains("file:") && !signerConf.contains("base64:")) {
      return signerConf;
    }

    ConfPairs pairs = new ConfPairs(signerConf);
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
  public CertWithStatusInfo getCert(String caName, BigInteger serialNumber) throws CaMgmtException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    ParamUtil.requireNonNull("serialNumber", serialNumber);
    X509Ca ca = getX509Ca(caName);
    CertWithRevocationInfo certInfo;
    try {
      certInfo = ca.getCertWithRevocationInfo(serialNumber);
    } catch (CertificateException | OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
    return (certInfo != null) ? certInfo.toCertWithStatusInfo() : new CertWithStatusInfo();
  }

  @Override
  public byte[] getCertRequest(String caName, BigInteger serialNumber) throws CaMgmtException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    ParamUtil.requireNonNull("serialNumber", serialNumber);
    X509Ca ca = getX509Ca(caName);
    try {
      return ca.getCertRequest(serialNumber);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  }

  @Override
  public List<CertListInfo> listCertificates(String caName, X500Name subjectPattern, Date validFrom,
      Date validTo, CertListOrderBy orderBy, int numEntries) throws CaMgmtException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);;
    ParamUtil.requireRange("numEntries", numEntries, 1, 1000);
    X509Ca ca = getX509Ca(caName);
    try {
      return ca.listCerts(subjectPattern, validFrom, validTo, orderBy, numEntries);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  }

  @Override
  public void loadConf(CaConf conf) throws CaMgmtException {
    ParamUtil.requireNonNull("conf", conf);

    if (!caSystemSetuped) {
      throw new CaMgmtException("CA system is not initialized yet.");
    }

    // Responder
    for (String name : conf.getSignerNames()) {
      SignerEntry entry = conf.getSigner(name);
      SignerEntry entryB = signerDbEntries.get(name);
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
      RequestorEntry entry = conf.getRequestor(name);
      RequestorEntry entryB = requestorDbEntries.get(name);
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
      PublisherEntry entry = conf.getPublisher(name);
      PublisherEntry entryB = publisherDbEntries.get(name);
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
      CertprofileEntry entry = conf.getCertprofile(name);
      CertprofileEntry entryB = certprofileDbEntries.get(name);
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
      UserEntry entryB = queryExecutor.getUser(name, true);

      if (entryB != null) {
        boolean equals = false;
        if (obj instanceof UserEntry) {
          UserEntry entry = (UserEntry) obj;
          equals = entry.equals(entryB, ignoreId);
        } else {
          AddUserEntry entry = (AddUserEntry) obj;
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
        if (obj instanceof UserEntry) {
          queryExecutor.addUser((UserEntry) obj);
        } else {
          queryExecutor.addUser((AddUserEntry) obj);
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
      SingleCaConf scc = conf.getCa(caName);
      GenSelfIssued genSelfIssued = scc.getGenSelfIssued();
      CaEntry caEntry = scc.getCaEntry();
      if (caEntry != null) {
        if (caInfos.containsKey(caName)) {
          CaEntry entryB = caInfos.get(caName).getCaEntry();
          if (caEntry.getCert() == null && genSelfIssued != null) {
            SignerConf signerConf = new SignerConf(caEntry.getSignerConf());
            ConcurrentContentSigner signer;
            try {
              signer = securityFactory.createSigner(caEntry.getSignerType(), signerConf,
                  (X509Certificate) null);
            } catch (ObjectCreationException ex) {
              throw new CaMgmtException(concat("could not create signer for CA ", caName), ex);
            }
            caEntry.setCert(signer.getCertificate());
          }

          if (caEntry.equals(entryB, true, true)) {
            LOG.info("ignore existed CA {}", caName);
          } else {
            throw logAndCreateException(concat("CA ", caName, " existed, could not re-added it"));
          }
        } else {
          if (genSelfIssued != null) {
            X509Certificate cert = generateRootCa(caEntry, genSelfIssued.getProfile(),
                genSelfIssued.getCsr(), genSelfIssued.getSerialNumber());
            LOG.info("generated root CA {}", caName);
            String fn = genSelfIssued.getCertFilename();
            if (fn != null) {
              try {
                IoUtil.save(fn, cert.getEncoded());
                LOG.info("saved generated certificate of root CA {} to {}",
                    caName, fn);
              } catch (CertificateEncodingException ex) {
                LogUtil.error(LOG, ex, concat("could not encode certificate of CA ", caName));
              } catch (IOException ex) {
                LogUtil.error(LOG, ex,
                    concat("error while saving certificate of root CA ", caName, " to ", fn));
              }
            }
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
        List<CaHasUserEntry> usersB = queryExecutor.getCaHasUsersForCa(caName, idNameMap);

        for (CaHasUserEntry user : scc.getUsers()) {
          String userName = user.getUserIdent().getName();
          CaHasUserEntry userB = null;
          if (usersB != null) {
            for (CaHasUserEntry m : usersB) {
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
  }

  @Override
  public void exportConf(String zipFilename, List<String> caNames)
      throws CaMgmtException, IOException {
    ParamUtil.requireNonBlank("zipFilename", zipFilename);
    if (!caSystemSetuped) {
      throw new CaMgmtException("CA system is not initialized yet.");
    }

    zipFilename = IoUtil.expandFilepath(zipFilename);
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

    File zipFile = new File(zipFilename);
    if (zipFile.exists()) {
      throw new IOException(concat("File ", zipFilename, " exists."));
    }

    File parentFile = zipFile.getParentFile();
    if (parentFile != null && !parentFile.exists()) {
      parentFile.mkdirs();
    }

    CaconfType root = new CaconfType();

    ZipOutputStream zipStream = getZipOutputStream(zipFile);
    try {
      Set<String> includeSignerNames = new HashSet<>();
      Set<String> includeRequestorNames = new HashSet<>();
      Set<String> includeProfileNames = new HashSet<>();
      Set<String> includePublisherNames = new HashSet<>();
      Set<String> includeCrlSignerNames = new HashSet<>();
      Set<String> includeUserNames = new HashSet<>();

      // users
      root.setUsers(new CaconfType.Users());
      List<UserType> users = root.getUsers().getUser();

      // cas
      if (CollectionUtil.isNonEmpty(caNames)) {
        List<CaType> list = new LinkedList<>();

        for (String name : x509cas.keySet()) {
          if (!caNames.contains(name)) {
            continue;
          }

          CaType jaxb = new CaType();
          jaxb.setName(name);

          Set<String> strs = getAliasesForCa(name);
          if (CollectionUtil.isNonEmpty(strs)) {
            AliasesType type = new AliasesType();
            for (String str : strs) {
              type.getAlias().add(str);
            }
            jaxb.setAliases(type);
          }

          strs = caHasProfiles.get(name);
          if (CollectionUtil.isNonEmpty(strs)) {
            includeProfileNames.addAll(strs);
            jaxb.setProfiles(createProfiles(strs));
          }

          strs = caHasPublishers.get(name);
          if (CollectionUtil.isNonEmpty(strs)) {
            includePublisherNames.addAll(strs);
            PublishersType type = new PublishersType();
            for (String str : strs) {
              type.getPublisher().add(str);
            }
            jaxb.setPublishers(type);
          }

          // CaHasRequestors
          Set<CaHasRequestorEntry> requestors = caHasRequestors.get(name);
          if (CollectionUtil.isNonEmpty(requestors)) {
            jaxb.setRequestors(new CaType.Requestors());

            for (CaHasRequestorEntry m : requestors) {
              String requestorName = m.getRequestorIdent().getName();
              includeRequestorNames.add(requestorName);

              CaHasRequestorType jaxb2 = new CaHasRequestorType();
              jaxb2.setRequestorName(requestorName);
              jaxb2.setRa(m.isRa());
              jaxb2.setProfiles(createProfiles(m.getProfiles()));
              jaxb2.setPermissions(getPermissions(m.getPermission()));

              jaxb.getRequestors().getRequestor().add(jaxb2);
            }
          }

          // CaHasUsers
          List<CaHasUserEntry> caHasUsers = queryExecutor.getCaHasUsersForCa(name, idNameMap);
          if (CollectionUtil.isNonEmpty(caHasUsers)) {
            jaxb.setUsers(new CaType.Users());
            List<CaHasUserType> list2 = jaxb.getUsers().getUser();
            for (CaHasUserEntry m : caHasUsers) {
              String username = m.getUserIdent().getName();
              CaHasUserType jaxb2 = new CaHasUserType();
              jaxb2.setUserName(username);
              jaxb2.setPermissions(getPermissions(m.getPermission()));
              jaxb2.setProfiles(createProfiles(m.getProfiles()));
              list2.add(jaxb2);

              if (includeUserNames.contains(username)) {
                continue;
              }

              // add also the user to the users
              UserEntry userEntry = queryExecutor.getUser(username);
              UserType jaxb3 = new UserType();
              if (!userEntry.isActive()) {
                jaxb3.setActive(Boolean.FALSE);
              }
              jaxb3.setName(username);
              jaxb3.setHashedPassword(userEntry.getHashedPassword());
              users.add(jaxb3);

              includeUserNames.add(username);
            }
          }

          CaEntry entry = x509cas.get(name).getCaInfo().getCaEntry();
          CaInfoType ciJaxb = new CaInfoType();
          byte[] certBytes;
          try {
            certBytes = entry.getCert().getEncoded();
          } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(concat("could not encode CA certificate ", name));
          }
          ciJaxb.setCert(createFileOrBinary(zipStream, certBytes,
              concat("files/ca-", name, "-cert.der")));

          if (entry.getCrlSignerName() != null) {
            includeCrlSignerNames.add(entry.getCrlSignerName());
            ciJaxb.setCrlSignerName(entry.getCrlSignerName());
          }

          if (entry.getCmpResponderName() != null) {
            includeSignerNames.add(entry.getCmpResponderName());
            ciJaxb.setCmpResponderName(entry.getCmpResponderName());
          }

          if (entry.getScepResponderName() != null) {
            includeSignerNames.add(entry.getScepResponderName());
            ciJaxb.setScepResponderName(entry.getScepResponderName());
          }

          if (entry.getCmpControl() != null) {
            ciJaxb.setCmpControl(entry.getCmpControl().getConf());
          }

          if (entry.getCrlControl() != null) {
            ciJaxb.setCrlControl(entry.getCrlControl().getConf());
          }

          if (entry.getScepControl() != null) {
            ciJaxb.setScepControl(entry.getScepControl().getConf());
          }

          CaUris caUris = entry.getCaUris();
          if (caUris != null) {
            CaUrisType caUrisType = new CaUrisType();
            caUrisType.setCacertUris(createUris(caUris.getCacertUris()));
            caUrisType.setOcspUris(createUris(caUris.getOcspUris()));
            caUrisType.setCrlUris(createUris(caUris.getCrlUris()));
            caUrisType.setDeltacrlUris(createUris(caUris.getDeltaCrlUris()));
            ciJaxb.setCaUris(caUrisType);
          }

          ciJaxb.setDuplicateKey(entry.isDuplicateKeyPermitted());
          ciJaxb.setDuplicateSubject(entry.isDuplicateSubjectPermitted());
          ciJaxb.setExpirationPeriod(entry.getExpirationPeriod());
          if (entry.getExtraControl() != null) {
            ciJaxb.setExtraControl(
                createFileOrValue(zipStream, entry.getExtraControl().getEncoded(),
                    concat("files/ca-", name, "-extracontrol.conf")));
          }
          ciJaxb.setKeepExpiredCertDays(entry.getKeepExpiredCertInDays());
          ciJaxb.setMaxValidity(entry.getMaxValidity().toString());
          ciJaxb.setNextCrlNo(entry.getNextCrlNumber());
          ciJaxb.setNumCrls(entry.getNumCrls());
          ciJaxb.setPermissions(getPermissions(entry.getPermission()));
          ciJaxb.setSaveReq(entry.isSaveRequest());
          ciJaxb.setSignerConf(createFileOrValue(zipStream, entry.getSignerConf(),
              concat("files/ca-", name, "-signerconf.conf")));
          ciJaxb.setSignerType(entry.getSignerType());
          ciJaxb.setSnSize(entry.getSerialNoBitLen());
          ciJaxb.setStatus(entry.getStatus().getStatus());
          ciJaxb.setValidityMode(entry.getValidityMode().name());
          ciJaxb.setProtocolSupport(entry.getProtocoSupport().getEncoded());

          jaxb.setCaInfo(ciJaxb);

          list.add(jaxb);
        }

        if (!list.isEmpty()) {
          root.setCas(new CaconfType.Cas());
          root.getCas().getCa().addAll(list);
        }
      }

      // clear the users if the list is empty
      if (users.isEmpty()) {
        root.setUsers(null);
      }

      // requestors
      if (CollectionUtil.isNonEmpty(requestorDbEntries)) {
        List<RequestorType> list = new LinkedList<>();
        for (String name : requestorDbEntries.keySet()) {
          if (!includeRequestorNames.contains(name)) {
            continue;
          }

          RequestorEntry entry = requestorDbEntries.get(name);
          RequestorType jaxb = new RequestorType();
          jaxb.setName(name);
          jaxb.setCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
              concat("files/requestor-", name, ".der")));

          list.add(jaxb);
        }

        if (!list.isEmpty()) {
          root.setRequestors(new CaconfType.Requestors());
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
              concat("files/publisher-", name, ".conf")));
          list.add(jaxb);
        }

        if (!list.isEmpty()) {
          root.setPublishers(new CaconfType.Publishers());
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
              concat("files/certprofile-", name, ".conf")));
          list.add(jaxb);
        }

        if (!list.isEmpty()) {
          root.setProfiles(new CaconfType.Profiles());
          root.getProfiles().getProfile().addAll(list);
        }
      }

      // signers
      if (CollectionUtil.isNonEmpty(signerDbEntries)) {
        List<SignerType> list = new LinkedList<>();

        for (String name : signerDbEntries.keySet()) {
          if (!includeSignerNames.contains(name)) {
            continue;
          }

          SignerEntry entry = signerDbEntries.get(name);
          SignerType jaxb = new SignerType();
          jaxb.setName(name);
          jaxb.setType(entry.getType());
          jaxb.setConf(createFileOrValue(zipStream, entry.getConf(),
              concat("files/responder-", name, ".conf")));
          jaxb.setCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
              concat("files/responder-", name, ".der")));

          list.add(jaxb);
        }

        if (!list.isEmpty()) {
          root.setSigners(new CaconfType.Signers());
          root.getSigners().getSigner().addAll(list);
        }
      }

      // add the CAConf XML file
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      try {
        CaConf.marshal(root, bout);
      } catch (JAXBException | SAXException ex) {
        LogUtil.error(LOG, ex, "could not marshal CAConf");
        throw new CaMgmtException(concat("could not marshal CAConf: ", ex.getMessage()), ex);
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
  }

  private static FileOrValueType createFileOrValue(ZipOutputStream zipStream,
      String content, String fileName) throws IOException {
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

  private static FileOrBinaryType createFileOrBase64Value(ZipOutputStream zipStream,
      String b64Content, String fileName) throws IOException {
    if (StringUtil.isBlank(b64Content)) {
      return null;
    }

    return createFileOrBinary(zipStream, Base64.decode(b64Content), fileName);
  }

  private static FileOrBinaryType createFileOrBinary(ZipOutputStream zipStream,
      byte[] content, String fileName) throws IOException {
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

  private static ZipOutputStream getZipOutputStream(File zipFile) throws FileNotFoundException {
    ParamUtil.requireNonNull("zipFile", zipFile);

    BufferedOutputStream out = new BufferedOutputStream(
        new FileOutputStream(zipFile), 1048576); // 1M
    ZipOutputStream zipOutStream = new ZipOutputStream(out);
    zipOutStream.setLevel(Deflater.BEST_SPEED);
    return zipOutStream;
  }

  private static UrisType createUris(Collection<String> uris) {
    if (CollectionUtil.isEmpty(uris)) {
      return null;
    }

    UrisType ret = new UrisType();
    for (String uri : uris) {
      ret.getUri().add(uri);
    }
    return ret;
  }

  private static ProfilesType createProfiles(Collection<String> profiles) {
    if (CollectionUtil.isEmpty(profiles)) {
      return null;
    }

    ProfilesType ret = new ProfilesType();
    for (String profile : profiles) {
      ret.getProfile().add(profile);
    }
    return ret;
  }

  @Override
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

  private static PermissionsType getPermissions(int permission) {
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
    PermissionsType ret = new PermissionsType();
    ret.getPermission().addAll(list);
    return ret;
  }

}
