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
import org.xipki.ca.api.DfltEnvParameterResolver;
import org.xipki.ca.api.EnvParameterResolver;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.profile.CertValidity.Unit;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.x509.X509Certprofile;
import org.xipki.ca.api.profile.x509.X509CertprofileFactoryRegister;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.x509.X509CertPublisher;
import org.xipki.ca.api.publisher.x509.X509CertPublisherFactoryRegister;
import org.xipki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.ca.server.api.CaAuditConstants;
import org.xipki.ca.server.api.ResponderManager;
import org.xipki.ca.server.api.Rest;
import org.xipki.ca.server.api.Scep;
import org.xipki.ca.server.api.X509CaCmpResponder;
import org.xipki.ca.server.impl.X509SelfSignedCertBuilder.GenerateSelfSignedResult;
import org.xipki.ca.server.impl.cmp.RequestorEntryWrapper;
import org.xipki.ca.server.impl.cmp.ResponderEntryWrapper;
import org.xipki.ca.server.impl.cmp.X509CaCmpResponderImpl;
import org.xipki.ca.server.impl.ocsp.OcspCertPublisher;
import org.xipki.ca.server.impl.rest.RestImpl;
import org.xipki.ca.server.impl.scep.ScepImpl;
import org.xipki.ca.server.impl.store.CertStore;
import org.xipki.ca.server.impl.store.X509CertWithRevocationInfo;
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
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.ca.server.mgmt.api.ChangeUserEntry;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.ca.server.mgmt.api.RequestorEntry;
import org.xipki.ca.server.mgmt.api.ResponderEntry;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.RequestorInfo;
import org.xipki.ca.server.mgmt.api.UserEntry;
import org.xipki.ca.server.mgmt.api.conf.CaConf;
import org.xipki.ca.server.mgmt.api.conf.GenSelfIssued;
import org.xipki.ca.server.mgmt.api.conf.SingleCaConf;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CAConfType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaHasRequestorType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaHasUserType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CmpcontrolType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CrlsignerType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.FileOrBinaryType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.FileOrValueType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.NameValueType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ProfileType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.PublisherType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.RequestorType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ResponderType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ScepType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.StringsType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.UserType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.X509CaInfoType;
import org.xipki.ca.server.mgmt.api.x509.CertWithStatusInfo;
import org.xipki.ca.server.mgmt.api.x509.ChangeScepEntry;
import org.xipki.ca.server.mgmt.api.x509.RevokeSuspendedCertsControl;
import org.xipki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CaUris;
import org.xipki.ca.server.mgmt.api.x509.X509ChangeCrlSignerEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xipki.common.ConfPairs;
import org.xipki.common.InvalidConfException;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.Base64;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
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

  private static final String PUBLISHER_TYPE_OCSP = "ocsp";

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

  private Map<String, ResponderEntryWrapper> responders = new ConcurrentHashMap<>();

  private Map<String, ResponderEntry> responderDbEntries = new ConcurrentHashMap<>();

  private final Map<String, IdentifiedX509Certprofile> certprofiles = new ConcurrentHashMap<>();

  private final Map<String, CertprofileEntry> certprofileDbEntries = new ConcurrentHashMap<>();

  private final Map<String, IdentifiedX509CertPublisher> publishers = new ConcurrentHashMap<>();

  private final Map<String, PublisherEntry> publisherDbEntries = new ConcurrentHashMap<>();

  private final Map<String, CmpControl> cmpControls = new ConcurrentHashMap<>();

  private final Map<String, CmpControlEntry> cmpControlDbEntries = new ConcurrentHashMap<>();

  private final Map<String, RequestorEntryWrapper> requestors = new ConcurrentHashMap<>();

  private final Map<String, RequestorEntry> requestorDbEntries = new ConcurrentHashMap<>();

  private final Map<String, X509CrlSignerEntryWrapper> crlSigners = new ConcurrentHashMap<>();

  private final Map<String, X509CrlSignerEntry> crlSignerDbEntries = new ConcurrentHashMap<>();

  private final Map<String, ScepImpl> sceps = new ConcurrentHashMap<>();

  private final Map<String, ScepEntry> scepDbEntries = new ConcurrentHashMap<>();

  private final Map<String, Set<String>> caHasProfiles = new ConcurrentHashMap<>();

  private final Map<String, Set<String>> caHasPublishers = new ConcurrentHashMap<>();

  private final Map<String, Set<CaHasRequestorEntry>> caHasRequestors = new ConcurrentHashMap<>();

  private final Map<String, Integer> caAliases = new ConcurrentHashMap<>();

  private final DfltEnvParameterResolver envParameterResolver = new DfltEnvParameterResolver();

  private ScheduledThreadPoolExecutor persistentScheduledThreadPoolExecutor;

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  private final Map<String, X509CaCmpResponderImpl> x509Responders = new ConcurrentHashMap<>();

  private final Map<String, X509Ca> x509cas = new ConcurrentHashMap<>();

  private final DataSourceFactory datasourceFactory;

  private final RestImpl rest;

  private Properties caConfProperties;

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
    this.rest = new RestImpl(this);
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
  public Set<String> getSupportedCertProfileTypes() {
    return x509CertProfileFactoryRegister.getSupportedTypes();
  }

  @Override
  public Set<String> getSupportedPublisherTypes() {
    Set<String> types = new HashSet<>();
    types.add(PUBLISHER_TYPE_OCSP);
    types.addAll(x509CertPublisherFactoryRegister.getSupportedTypes());
    return Collections.unmodifiableSet(types);
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

    initEnvironmentParamters();
    String envEpoch = envParameterResolver.getParameter(ENV_EPOCH);

    if (masterMode) {
      lockCa(true);

      if (envEpoch == null) {
        final long day = 24L * 60 * 60 * 1000;
        envEpoch = queryExecutor.setEpoch(new Date(System.currentTimeMillis() - day));
        LOG.info("set environment {} to {}", ENV_EPOCH, envEpoch);
      }

      queryExecutor.addRequestorIfNeeded(RequestorInfo.NAME_BY_CA);
      queryExecutor.addRequestorIfNeeded(RequestorInfo.NAME_BY_USER);
    } else {
      if (envEpoch == null) {
        throw new CaMgmtException("The CA system must be started first with ca.mode = master");
      }
    }

    LOG.info("use EPOCH: {}", envEpoch);
    long epoch = DateUtil.parseUtcTimeyyyyMMdd(envEpoch).getTime();

    UniqueIdGenerator idGen = new UniqueIdGenerator(epoch, shardId);

    try {
      this.certstore = new CertStore(datasource, idGen);
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
        LOG.error(msg);
        throw new CaMgmtException(msg);
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
      String msg = "could not unlock CA in slave mode";
      LOG.error(msg);
      throw new CaMgmtException(msg);
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
  public void restartCaSystem() throws CaMgmtException {
    reset();
    boolean caSystemStarted = startCaSystem0();
    auditLogPciEvent(caSystemStarted, "CA_CHANGE");

    if (!caSystemStarted) {
      String msg = "could not restart CA system";
      LOG.error(msg);
      throw new CaMgmtException(msg);
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
      String msg = "could not start CA system";
      LOG.error(msg);
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
    X509CaInfo caEntry = caInfos.get(caName);

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
            concat("X09CrlSignerEntryWrapper.initSigner (name=", crlSignerName, ")"));
        return false;
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
    X509CaCmpResponderImpl caResponder = new X509CaCmpResponderImpl(this, caName);
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
  public X509CaCmpResponder getX509CaResponder(String name) {
    return x509Responders.get(ParamUtil.requireNonBlank("name", name).toLowerCase());
  }

  public ScheduledThreadPoolExecutor scheduledThreadPoolExecutor() {
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
          continue;
        }

        idNameMap.addRequestor(requestorDbEntry.getIdent());
        requestorDbEntries.put(name, requestorDbEntry);
        RequestorEntryWrapper requestor = new RequestorEntryWrapper();
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

    List<String> names = queryExecutor.namesFromTable("RESPONDER");
    for (String name : names) {
      ResponderEntry dbEntry = queryExecutor.createResponder(name);
      if (dbEntry == null) {
        LOG.error("could not initialize Responder '{}'", name);
        continue;
      }

      dbEntry.setConfFaulty(true);
      responderDbEntries.put(name, dbEntry);

      ResponderEntryWrapper responder = createResponder(dbEntry);
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
      envParameterResolver.addParameter(name, map.get(name));
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

    List<String> names = queryExecutor.namesFromTable("CRLSIGNER");
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

    List<String> names = queryExecutor.namesFromTable("CMPCONTROL");
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
        LogUtil.error(LOG, ex, concat("could not initialize CMP control ", name, ", ignore it"));
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

    List<String> names = queryExecutor.namesFromTable("SCEP");
    for (String name : names) {
      ScepEntry scepDb = queryExecutor.getScep(name, idNameMap);
      if (scepDb == null) {
        continue;
      }

      scepDbEntries.put(name, scepDb);

      try {
        ScepImpl scep = new ScepImpl(scepDb, this);
        sceps.put(name, scep);
      } catch (CaMgmtException ex) {
        LogUtil.error(LOG, ex, concat("could not initialize SCEP entry ", name, ", ignore it"));
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
    x509Responders.remove(name);
    if (oldCa != null) {
      oldCa.shutdown();
    }

    X509CaInfo ca = queryExecutor.createCaInfo(name, masterMode, certstore);
    caInfos.put(name, ca);
    idNameMap.addCa(ca.getIdent());
    caHasRequestors.put(name, queryExecutor.createCaHasRequestors(ca.getIdent()));

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

    if (caEntry instanceof X509CaEntry) {
      try {
        X509CaEntry tmpCaEntry = (X509CaEntry) caEntry;
        List<String[]> signerConfs = CaEntry.splitCaSignerConfs(tmpCaEntry.getSignerConf());
        ConcurrentContentSigner signer;
        for (String[] m : signerConfs) {
          SignerConf signerConf = new SignerConf(m[1]);
          signer = securityFactory.createSigner(tmpCaEntry.getSignerType(), signerConf,
              tmpCaEntry.getCert());
          if (tmpCaEntry.getCert() == null) {
            if (signer.getCertificate() == null) {
              throw new CaMgmtException("CA signer without certificate is not allowed");
            }
            tmpCaEntry.setCert(signer.getCertificate());
          }
        }
      } catch (XiSecurityException | ObjectCreationException ex) {
        throw new CaMgmtException(
          concat("could not create signer for new CA ", name, ": ", ex.getMessage()), ex);
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
  } // method addCa

  @Override
  public X509CaEntry getCa(String name) {
    X509CaInfo caInfo = caInfos.get(ParamUtil.requireNonBlank("name", name).toLowerCase());
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

    queryExecutor.changeCa(entry, securityFactory);

    if (!createCa(name)) {
      LOG.error("could not create CA {}", name);
    } else {
      X509CaInfo caInfo = caInfos.get(name);
      if (CaStatus.ACTIVE != caInfo.getCaEntry().getStatus()) {
        return;
      }

      if (startCa(name)) {
        LOG.info("started CA {}", name);
      } else {
        LOG.error("could not start CA {}", name);
      }
    }
  } // method changeCa

  @Override
  public void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    profileName = ParamUtil.requireNonBlank("profileName", profileName).toLowerCase();
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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
    profileName = ParamUtil.requireNonBlank("profileName", profileName).toLowerCase();
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    asssertMasterMode();

    NameId ident = idNameMap.getCertprofile(profileName);
    if (ident == null) {
      String msg = concat("unknown CertProfile ", profileName);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    NameId caIdent = idNameMap.getCa(caName);
    if (caIdent == null) {
      String msg = concat("unknown CA ", caName);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    Set<String> set = caHasProfiles.get(caName);
    if (set == null) {
      set = new HashSet<>();
      caHasProfiles.put(caName, set);
    } else {
      if (set.contains(profileName)) {
        String msg = concat("CertProfile ", profileName, " already associated with CA ", caName);
        LOG.warn(msg);
        throw new CaMgmtException(msg);
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
    publisherName = ParamUtil.requireNonBlank("publisherName", publisherName).toLowerCase();
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    asssertMasterMode();

    queryExecutor.removePublisherFromCa(publisherName, caName);

    Set<String> publisherNames = caHasPublishers.get(caName);
    if (publisherNames != null) {
      publisherNames.remove(publisherName);
    }
  } // method removePublisherFromCa

  @Override
  public void addPublisherToCa(String publisherName, String caName) throws CaMgmtException {
    publisherName = ParamUtil.requireNonBlank("publisherName", publisherName).toLowerCase();
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    asssertMasterMode();

    NameId ident = idNameMap.getPublisher(publisherName);
    if (ident == null) {
      String msg = concat("unknown publisher ", publisherName);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    NameId caIdent = idNameMap.getCa(caName);
    if (caIdent == null) {
      String msg = concat("unknown CA ", caName);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    Set<String> publisherNames = caHasPublishers.get(caName);
    if (publisherNames == null) {
      publisherNames = new HashSet<>();
      caHasPublishers.put(caName, publisherNames);
    } else {
      if (publisherNames.contains(publisherName)) {
        String msg = concat("publisher ", publisherName, " already associated with CA ", caName);
        LOG.warn(msg);
        throw new CaMgmtException(msg);
      }
    }

    IdentifiedX509CertPublisher publisher = publishers.get(publisherName);
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
    return caHasProfiles.get(ParamUtil.requireNonBlank("caName", caName).toLowerCase());
  }

  @Override
  public Set<CaHasRequestorEntry> getRequestorsForCa(String caName) {
    return caHasRequestors.get(ParamUtil.requireNonBlank("caName", caName).toLowerCase());
  }

  @Override
  public RequestorEntry getRequestor(String name) {
    return requestorDbEntries.get(ParamUtil.requireNonBlank("name", name).toLowerCase());
  }

  public RequestorEntryWrapper getRequestorWrapper(String name) {
    return requestors.get(ParamUtil.requireNonBlank("name", name).toLowerCase());
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
  public void removeRequestor(String requestorName) throws CaMgmtException {
    requestorName = ParamUtil.requireNonBlank("requestorName", requestorName).toLowerCase();
    asssertMasterMode();

    for (String caName : caHasRequestors.keySet()) {
      boolean removeMe = false;
      for (CaHasRequestorEntry caHasRequestor : caHasRequestors.get(caName)) {
        if (caHasRequestor.getRequestorIdent().getName().equals(requestorName)) {
          removeMe = true;
          break;
        }
      }

      if (removeMe) {
        removeRequestorFromCa(requestorName, caName);
      }
    }

    boolean bo = queryExecutor.deleteRowWithName(requestorName, "REQUESTOR");
    if (!bo) {
      throw new CaMgmtException("unknown requestor " + requestorName);
    }

    idNameMap.removeRequestor(requestorDbEntries.get(requestorName).getIdent().getId());
    requestorDbEntries.remove(requestorName);
    requestors.remove(requestorName);
    LOG.info("removed requestor '{}'", requestorName);
  } // method removeRequestor

  @Override
  public void changeRequestor(String name, String base64Cert) throws CaMgmtException {
    ParamUtil.requireNonNull("base64Cert", base64Cert);
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    asssertMasterMode();

    NameId ident = idNameMap.getRequestor(name);
    if (ident == null) {
      String msg = concat("unknown requestor ", name);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    RequestorEntryWrapper requestor = queryExecutor.changeRequestor(ident, base64Cert);

    requestorDbEntries.remove(name);
    requestors.remove(name);

    requestorDbEntries.put(name, requestor.getDbEntry());
    requestors.put(name, requestor);
  } // method changeRequestor

  @Override
  public void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    requestorName = ParamUtil.requireNonBlank("requestorName", requestorName).toLowerCase();
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    asssertMasterMode();

    NameId requestorIdent = requestor.getRequestorIdent();
    NameId ident = idNameMap.getRequestor(requestorIdent.getName());
    if (ident == null) {
      String msg = concat("unknown requestor ", requestorIdent.getName());
      LOG.warn(msg);
      throw new CaMgmtException(msg);
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
          LOG.warn(msg);
          throw new CaMgmtException(msg);
        }
      }
    }

    cmpRequestors.add(requestor);
    queryExecutor.addRequestorToCa(requestor, caIdent);
    caHasRequestors.get(caName).add(requestor);
  } // method addRequestorToCa

  @Override
  public void removeUserFromCa(String userName, String caName) throws CaMgmtException {
    userName = ParamUtil.requireNonBlank("userName", userName).toLowerCase();
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    asssertMasterMode();

    queryExecutor.removeUserFromCa(userName, caName);
  }

  @Override
  public void addUserToCa(CaHasUserEntry user, String caName) throws CaMgmtException {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    asssertMasterMode();

    X509Ca ca = getX509Ca(caName);
    if (ca == null) {
      String msg = concat("unknown CA ", caName);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    queryExecutor.addUserToCa(user, ca.getCaIdent());
  }

  @Override
  public Map<String, CaHasUserEntry> getCaHasUsersForUser(String user) throws CaMgmtException {
    ParamUtil.requireNonBlank("user", user);
    return queryExecutor.getCaHasUsersForUser(user, idNameMap);
  }

  @Override
  public CertprofileEntry getCertprofile(String profileName) {
    profileName = ParamUtil.requireNonBlank("profileName", profileName).toLowerCase();
    return certprofileDbEntries.get(profileName);
  }

  @Override
  public void removeCertprofile(String profileName) throws CaMgmtException {
    profileName = ParamUtil.requireNonBlank("profileName", profileName).toLowerCase();
    asssertMasterMode();

    for (String caName : caHasProfiles.keySet()) {
      if (caHasProfiles.get(caName).contains(profileName)) {
        removeCertprofileFromCa(profileName, caName);
      }
    }

    boolean bo = queryExecutor.deleteRowWithName(profileName, "PROFILE");
    if (!bo) {
      throw new CaMgmtException("unknown profile " + profileName);
    }

    LOG.info("removed profile '{}'", profileName);
    idNameMap.removeCertprofile(certprofileDbEntries.get(profileName).getIdent().getId());
    certprofileDbEntries.remove(profileName);
    IdentifiedX509Certprofile profile = certprofiles.remove(profileName);
    shutdownCertprofile(profile);
  } // method removeCertprofile

  @Override
  public void changeCertprofile(String name, String type, String conf) throws CaMgmtException {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    if (type == null && conf == null) {
      throw new IllegalArgumentException("type and conf cannot be both null");
    }
    NameId ident = idNameMap.getCertprofile(name);
    if (ident == null) {
      String msg = concat("unknown Certprofile ", name);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    asssertMasterMode();

    IdentifiedX509Certprofile profile = queryExecutor.changeCertprofile(ident, type, conf, this);

    certprofileDbEntries.remove(name);
    IdentifiedX509Certprofile oldProfile = certprofiles.remove(name);
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
      throw new CaMgmtException(concat("CertProfile named ", name, " exists"));
    }

    dbEntry.setFaulty(true);
    IdentifiedX509Certprofile profile = createCertprofile(dbEntry);
    if (profile == null) {
      throw new CaMgmtException("could not create CertProfile object");
    }

    dbEntry.setFaulty(false);
    certprofiles.put(name, profile);

    queryExecutor.addCertprofile(dbEntry);

    idNameMap.addCertprofile(dbEntry.getIdent());
    certprofileDbEntries.put(name, dbEntry);
  } // method addCertprofile

  @Override
  public void addResponder(ResponderEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    asssertMasterMode();
    String name = dbEntry.getName();
    if (responderDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("Responder named ", name, " exists"));
    }

    String conf = dbEntry.getConf();
    if (conf != null) {
      String newConf = canonicalizeSignerConf(dbEntry.getType(), conf, null, securityFactory);
      if (!conf.equals(newConf)) {
        dbEntry.setConf(newConf);
      }
    }

    ResponderEntryWrapper responder = createResponder(dbEntry);
    queryExecutor.addResponder(dbEntry);
    responders.put(name, responder);
    responderDbEntries.put(name, dbEntry);
  } // method addResponder

  @Override
  public void removeResponder(String name) throws CaMgmtException {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    asssertMasterMode();
    boolean bo = queryExecutor.deleteRowWithName(name, "RESPONDER");
    if (!bo) {
      throw new CaMgmtException("unknown Responder " + name);
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
  } // method removeResponder

  @Override
  public void changeResponder(String name, String type, String conf, String base64Cert)
      throws CaMgmtException {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    asssertMasterMode();
    if (type == null && conf == null && base64Cert == null) {
      throw new IllegalArgumentException("nothing to change");
    }

    if (type != null) {
      type = type.toLowerCase();
    }

    ResponderEntryWrapper newResponder = queryExecutor.changeResponder(name, type, conf,
        base64Cert, this, securityFactory);

    // Update SCEP

    responders.remove(name);
    responderDbEntries.remove(name);
    responderDbEntries.put(name, newResponder.getDbEntry());
    responders.put(name, newResponder);
  } // method changeResponder

  @Override
  public ResponderEntry getResponder(String name) {
    ParamUtil.requireNonBlank("name", name);
    return responderDbEntries.get(name.toLowerCase());
  }

  public ResponderEntryWrapper getResponderWrapper(String name) {
    ParamUtil.requireNonBlank("name", name);
    return responders.get(name.toLowerCase());
  }

  @Override
  public void addCrlSigner(X509CrlSignerEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    asssertMasterMode();
    String name = dbEntry.getName();
    if (crlSigners.containsKey(name)) {
      throw new CaMgmtException(concat("CRL signer named ", name, " exists"));
    }

    String conf = dbEntry.getConf();
    if (conf != null) {
      String newConf = canonicalizeSignerConf(dbEntry.getType(), conf, null, securityFactory);
      if (!conf.equals(newConf)) {
        dbEntry.setConf(newConf);
      }
    }

    X509CrlSignerEntryWrapper crlSigner = createX509CrlSigner(dbEntry);
    X509CrlSignerEntry tmpDbEntry = crlSigner.getDbEntry();
    queryExecutor.addCrlSigner(tmpDbEntry);
    crlSigners.put(name, crlSigner);
    crlSignerDbEntries.put(name, tmpDbEntry);
  } // method addCrlSigner

  @Override
  public void removeCrlSigner(String name) throws CaMgmtException {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    asssertMasterMode();
    boolean bo = queryExecutor.deleteRowWithName(name, "CRLSIGNER");
    if (!bo) {
      throw new CaMgmtException("unknown CRL signer " + name);
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
  } // method removeCrlSigner

  @Override
  public void changeCrlSigner(X509ChangeCrlSignerEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    asssertMasterMode();

    String name = dbEntry.getName();
    String signerType = dbEntry.getSignerType();
    String signerConf = dbEntry.getSignerConf();
    String signerCert = dbEntry.getBase64Cert();
    String crlControl = dbEntry.getCrlControl();

    X509CrlSignerEntryWrapper crlSigner = queryExecutor.changeCrlSigner(name, signerType,
        signerConf, signerCert, crlControl, this, securityFactory);

    crlSigners.remove(name);
    crlSignerDbEntries.remove(name);
    crlSignerDbEntries.put(name, crlSigner.getDbEntry());
    crlSigners.put(name, crlSigner);
  } // method changeCrlSigner

  @Override
  public X509CrlSignerEntry getCrlSigner(String name) {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    return crlSignerDbEntries.get(name);
  }

  public X509CrlSignerEntryWrapper getCrlSignerWrapper(String name) {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    return crlSigners.get(name);
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
    IdentifiedX509CertPublisher publisher = createPublisher(dbEntry);
    dbEntry.setFaulty(false);

    queryExecutor.addPublisher(dbEntry);

    publishers.put(name, publisher);
    idNameMap.addPublisher(dbEntry.getIdent());
    publisherDbEntries.put(name, dbEntry);
  } // method addPublisher

  @Override
  public List<PublisherEntry> getPublishersForCa(String caName) {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    return publisherDbEntries.get(name);
  }

  @Override
  public void removePublisher(String name) throws CaMgmtException {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
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
    IdentifiedX509CertPublisher publisher = publishers.remove(name);
    shutdownPublisher(publisher);
  } // method removePublisher

  @Override
  public void changePublisher(String name, String type, String conf) throws CaMgmtException {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    asssertMasterMode();
    if (type == null && conf == null) {
      throw new IllegalArgumentException("nothing to change");
    }
    if (type != null) {
      type = type.toLowerCase();
    }

    IdentifiedX509CertPublisher publisher = queryExecutor.changePublisher(name, type, conf, this);

    IdentifiedX509CertPublisher oldPublisher = publishers.remove(name);
    shutdownPublisher(oldPublisher);

    publisherDbEntries.put(name, publisher.getDbEntry());
    publishers.put(name, publisher);
  } // method changePublisher

  @Override
  public CmpControlEntry getCmpControl(String name) {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    return cmpControlDbEntries.get(name);
  }

  public CmpControl getCmpControlObject(String name) {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    return cmpControls.get(name);
  }

  @Override
  public void addCmpControl(CmpControlEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    asssertMasterMode();
    final String name = dbEntry.getName();
    if (cmpControlDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("CMP control named ", name, " exists"));
    }

    CmpControl cmpControl;
    try {
      cmpControl = new CmpControl(dbEntry);
    } catch (InvalidConfException ex) {
      LogUtil.error(LOG, ex, "could not add CMP control to certStore");
      throw new CaMgmtException(ex);
    }

    CmpControlEntry tmpDbEntry = cmpControl.getDbEntry();
    queryExecutor.addCmpControl(tmpDbEntry);
    cmpControls.put(name, cmpControl);
    cmpControlDbEntries.put(name, tmpDbEntry);
  } // method addCmpControl

  @Override
  public void removeCmpControl(String name) throws CaMgmtException {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    asssertMasterMode();
    boolean bo = queryExecutor.deleteRowWithName(name, "CMPCONTROL");
    if (!bo) {
      throw new CaMgmtException("unknown CMP control " + name);
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
  } // method removeCmpControl

  @Override
  public void changeCmpControl(String name, String conf) throws CaMgmtException {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    ParamUtil.requireNonBlank("conf", conf);
    asssertMasterMode();
    CmpControl newCmpControl = queryExecutor.changeCmpControl(name, conf);

    cmpControlDbEntries.put(name, newCmpControl.getDbEntry());
    cmpControls.put(name, newCmpControl);
  } // method changeCmpControl

  public EnvParameterResolver getEnvParameterResolver() {
    return envParameterResolver;
  }

  @Override
  public Set<String> getEnvParamNames() {
    return envParameterResolver.allParameterNames();
  }

  @Override
  public String getEnvParam(String name) {
    ParamUtil.requireNonBlank("name", name);
    return envParameterResolver.getParameter(name);
  }

  @Override
  public void addEnvParam(String name, String value) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonBlank("value", value);
    asssertMasterMode();
    if (envParameterResolver.getParameter(name) != null) {
      throw new CaMgmtException(concat("Environment named ", name, " exists"));
    }

    queryExecutor.addEnvParam(name, value);
    envParameterResolver.addParameter(name, value);
  }

  @Override
  public void removeEnvParam(String name) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    asssertMasterMode();
    boolean bo = queryExecutor.deleteRowWithName(name, "ENVIRONMENT");
    if (!bo) {
      throw new CaMgmtException("unknown environment param " + name);
    }

    LOG.info("removed environment param '{}'", name);
    envParameterResolver.removeParamater(name);
  }

  @Override
  public void changeEnvParam(String name, String value) throws CaMgmtException {
    ParamUtil.requireNonBlank("name", name);
    ParamUtil.requireNonNull("value", value);
    asssertMasterMode();
    assertNotNull("value", value);

    if (envParameterResolver.getParameter(name) == null) {
      throw new CaMgmtException(concat("could not find environment paramter ", name));
    }

    queryExecutor.changeEnvParam(name, value);

    envParameterResolver.addParameter(name, value);
  } // method changeEnvParam

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
      throw new IllegalArgumentException("could not parse CA configuration" + caConfFile, ex);
    }
    this.caConfProperties = caConfProps;
  }

  @Override
  public void addCaAlias(String aliasName, String caName) throws CaMgmtException {
    aliasName = ParamUtil.requireNonBlank("aliasName", aliasName).toLowerCase();
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    asssertMasterMode();
    queryExecutor.removeCaAlias(name);
    caAliases.remove(name);
  }

  @Override
  public String getCaNameForAlias(String aliasName) {
    aliasName = ParamUtil.requireNonBlank("aliasName", aliasName).toLowerCase();
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
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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
  public void removeCa(String caName) throws CaMgmtException {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    asssertMasterMode();

    queryExecutor.removeCa(caName);

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
  } // method removeCa

  @Override
  public void republishCertificates(String caName, List<String> publisherNames, int numThreads)
      throws CaMgmtException {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    ParamUtil.requireMin("numThreads", numThreads, 1);
    asssertMasterMode();
    X509Ca ca = x509cas.get(caName);
    if (ca == null) {
      throw new CaMgmtException(concat("could not find CA named ", caName));
    }

    publisherNames = CollectionUtil.toLowerCaseList(publisherNames);
    boolean successful = ca.republishCertificates(publisherNames, numThreads);
    if (!successful) {
      throw new CaMgmtException(concat("republishing certificates of CA ", caName, " failed"));
    }
  } // method republishCertificates

  @Override
  public void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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

  public void setX509CertProfileFactoryRegister(
      X509CertprofileFactoryRegister x509CertProfileFactoryRegister) {
    this.x509CertProfileFactoryRegister = x509CertProfileFactoryRegister;
  }

  public void setX509CertPublisherFactoryRegister(
      X509CertPublisherFactoryRegister x509CertPublisherFactoryRegister) {
    this.x509CertPublisherFactoryRegister = x509CertPublisherFactoryRegister;
  }

  public void setAuditServiceRegister(AuditServiceRegister serviceRegister) {
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
  public void clearPublishQueue(String caName, List<String> publisherNames)
      throws CaMgmtException {
    asssertMasterMode();

    publisherNames = CollectionUtil.toLowerCaseList(publisherNames);

    if (caName == null) {
      if (CollectionUtil.isNonEmpty(publisherNames)) {
        throw new IllegalArgumentException("non-empty publisherNames is not allowed");
      }

      try {
        certstore.clearPublishQueue((NameId) null, (NameId) null);
        return;
      } catch (OperationException ex) {
        throw new CaMgmtException(ex.getMessage(), ex);
      }
    } else {
      caName = caName.toLowerCase();
    }

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
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    ParamUtil.requireNonNull("serialNumber", serialNumber);
    asssertMasterMode();
    X509Ca ca = getX509Ca(caName);
    try {
      if (ca.revokeCertificate(serialNumber, reason, invalidityTime,
          CaAuditConstants.MSGID_ca_mgmt) == null) {
        throw new CaMgmtException("could not revoke non-existing certificate");
      }
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method revokeCertificate

  @Override
  public void unrevokeCertificate(String caName, BigInteger serialNumber)
      throws CaMgmtException {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    ParamUtil.requireNonNull("serialNumber", serialNumber);
    X509Ca ca = getX509Ca(caName);
    try {
      if (ca.unrevokeCertificate(serialNumber, CaAuditConstants.MSGID_ca_mgmt) == null) {
        throw new CaMgmtException("could not unrevoke non-existing certificate");
      }
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method unrevokeCertificate

  @Override
  public void removeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    ParamUtil.requireNonNull("serialNumber", serialNumber);
    asssertMasterMode();
    X509Ca ca = getX509Ca(caName);
    if (ca == null) {
      String msg = concat("unknown CA ", caName);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    try {
      if (ca.removeCertificate(serialNumber, CaAuditConstants.MSGID_ca_mgmt) == null) {
        throw new CaMgmtException("could not remove certificate");
      }
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method removeCertificate

  @Override
  public X509Certificate generateCertificate(String caName, String profileName, byte[] encodedCsr,
      Date notBefore, Date notAfter) throws CaMgmtException {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    profileName = ParamUtil.requireNonBlank("profileName", profileName).toLowerCase();
    ParamUtil.requireNonNull("encodedCsr", encodedCsr);

    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName(CaAuditConstants.APPNAME);
    event.setName(CaAuditConstants.NAME_PERF);
    event.addEventType("CAMGMT_CRL_GEN_ONDEMAND");

    X509Ca ca = getX509Ca(caName);
    CertificationRequest csr;
    try {
      csr = CertificationRequest.getInstance(encodedCsr);
    } catch (Exception ex) {
      throw new CaMgmtException(concat("invalid CSR request. ERROR: ", ex.getMessage()));
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
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
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

  public IdentifiedX509Certprofile getIdentifiedCertprofile(String profileName) {
    profileName = ParamUtil.requireNonBlank("profileName", profileName).toLowerCase();
    return certprofiles.get(profileName);
  }

  public List<IdentifiedX509CertPublisher> getIdentifiedPublishersForCa(String caName) {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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
  public X509Certificate generateRootCa(X509CaEntry caEntry, String profileName,
      byte[] encodedCsr, BigInteger serialNumber) throws CaMgmtException {
    ParamUtil.requireNonNull("caEntry", caEntry);
    profileName = ParamUtil.requireNonBlank("profileName", profileName).toLowerCase();
    ParamUtil.requireNonNull("encodedCsr", encodedCsr);

    int numCrls = caEntry.getNumCrls();
    List<String> crlUris = caEntry.getCrlUris();
    List<String> deltaCrlUris = caEntry.getDeltaCrlUris();
    List<String> ocspUris = caEntry.getOcspUris();
    List<String> caCertUris = caEntry.getCaCertUris();
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

    IdentifiedX509Certprofile certprofile = getIdentifiedCertprofile(profileName);
    if (certprofile == null) {
      throw new CaMgmtException(concat("unknown certprofile ", profileName));
    }

    BigInteger serialOfThisCert = (serialNumber != null) ? serialNumber
        : RandomSerialNumberGenerator.getInstance().nextSerialNumber(caEntry.getSerialNoBitLen());

    GenerateSelfSignedResult result;
    try {
      result = X509SelfSignedCertBuilder.generateSelfSigned(securityFactory, signerType,
          caEntry.getSignerConf(), certprofile, csr, serialOfThisCert, caCertUris, ocspUris,
          crlUris, deltaCrlUris, caEntry.getExtraControl());
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

    X509CaUris caUris = new X509CaUris(caCertUris, ocspUris, crlUris, deltaCrlUris);

    String name = caEntry.getIdent().getName();
    long nextCrlNumber = caEntry.getNextCrlNumber();
    CaStatus status = caEntry.getStatus();

    X509CaEntry entry = new X509CaEntry(new NameId(null, name), caEntry.getSerialNoBitLen(),
        nextCrlNumber, signerType, signerConf, caUris, numCrls, expirationPeriod);
    entry.setCert(caCert);
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

  void shutdownCertprofile(IdentifiedX509Certprofile profile) {
    if (profile == null) {
      return;
    }

    try {
      profile.shutdown();
    } catch (Exception ex) {
      LogUtil.warn(LOG, ex, "could not shutdown Certprofile " + profile.getIdent());
    }
  } // method shutdownCertprofile

  void shutdownPublisher(IdentifiedX509CertPublisher publisher) {
    if (publisher == null) {
      return;
    }

    try {
      publisher.shutdown();
    } catch (Exception ex) {
      LogUtil.warn(LOG, ex, "could not shutdown CertPublisher " + publisher.getIdent());
    }
  } // method shutdownPublisher

  ResponderEntryWrapper createResponder(ResponderEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    ResponderEntryWrapper ret = new ResponderEntryWrapper();
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

  X509CrlSignerEntryWrapper createX509CrlSigner(X509CrlSignerEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    X509CrlSignerEntryWrapper signer = new X509CrlSignerEntryWrapper();
    try {
      signer.setDbEntry(dbEntry);
    } catch (InvalidConfException ex) {
      throw new CaMgmtException(concat("InvalidConfException: ", ex.getMessage()));
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
        throw new CaMgmtException(concat(message, ": ", ex.getMessage()));
      }
    }

    return signer;
  } // method createX509CrlSigner

  IdentifiedX509Certprofile createCertprofile(CertprofileEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);

    String type = dbEntry.getType();
    if (!x509CertProfileFactoryRegister.canCreateProfile(type)) {
      throw new CaMgmtException("unsupported cert profile type " + type);
    }

    try {
      X509Certprofile profile = x509CertProfileFactoryRegister.newCertprofile(type);
      IdentifiedX509Certprofile ret = new IdentifiedX509Certprofile(dbEntry, profile);
      ret.setEnvParameterResolver(envParameterResolver);
      ret.validate();
      return ret;
    } catch (ObjectCreationException | CertprofileException ex) {
      String msg = "could not initialize Certprofile " + dbEntry.getIdent();
      LogUtil.error(LOG, ex, msg);
      throw new CaMgmtException(msg, ex);
    }
  } // method createCertprofile

  IdentifiedX509CertPublisher createPublisher(PublisherEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    String type = dbEntry.getType();

    X509CertPublisher publisher;
    IdentifiedX509CertPublisher ret;
    try {
      if (PUBLISHER_TYPE_OCSP.equalsIgnoreCase(type)) {
        publisher = new OcspCertPublisher();
      } else if (x509CertPublisherFactoryRegister.canCreatePublisher(type)) {
        publisher = x509CertPublisherFactoryRegister.newPublisher(type);
      } else {
        throw new CaMgmtException("unsupported publisher type " + type);
      }

      ret = new IdentifiedX509CertPublisher(dbEntry, publisher);
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
  public void changeUser(ChangeUserEntry userEntry)
      throws CaMgmtException {
    asssertMasterMode();
    queryExecutor.changeUser(userEntry);
  }

  @Override
  public void removeUser(String username) throws CaMgmtException {
    username = ParamUtil.requireNonBlank("username", username).toLowerCase();
    asssertMasterMode();
    boolean bo = queryExecutor.deleteRowWithName(username, "TUSER");
    if (!bo) {
      throw new CaMgmtException("unknown user " + username);
    }
  }

  @Override
  public UserEntry getUser(String username) throws CaMgmtException {
    username = ParamUtil.requireNonBlank("username", username).toLowerCase();
    return queryExecutor.getUser(username);
  }

  CaIdNameMap idNameMap() {
    return idNameMap;
  }

  @Override
  public X509CRL generateCrlOnDemand(String caName) throws CaMgmtException {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();

    X509Ca ca = getX509Ca(caName);
    try {
      return ca.generateCrlOnDemand(CaAuditConstants.MSGID_ca_mgmt);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method generateCrlOnDemand

  @Override
  public X509CRL getCrl(String caName, BigInteger crlNumber) throws CaMgmtException {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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
  public void addScep(ScepEntry dbEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("dbEntry", dbEntry);
    asssertMasterMode();

    final String name = dbEntry.getName();
    if (scepDbEntries.containsKey(name)) {
      throw new CaMgmtException(concat("SCEP named ", name, " exists"));
    }
    String caName = dbEntry.getCaIdent().getName();
    NameId caIdent = idNameMap.getCa(caName);
    if (caIdent == null) {
      String msg = concat("unknown CA ", caName);
      LOG.warn(msg);
      throw new CaMgmtException(msg);
    }

    dbEntry.getCaIdent().setId(caIdent.getId());

    ScepImpl scep = new ScepImpl(dbEntry, this);
    queryExecutor.addScep(dbEntry);
    scepDbEntries.put(name, dbEntry);
    sceps.put(name, scep);
  } // method addScep

  @Override
  public void removeScep(String name) throws CaMgmtException {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    asssertMasterMode();
    boolean bo = queryExecutor.deleteRowWithName(name, "TUSER");
    if (!bo) {
      throw new CaMgmtException("unknown SCEP " + name);
    }
    scepDbEntries.remove(name);
    sceps.remove(name);
  } // method removeScep

  public void changeScep(ChangeScepEntry scepEntry) throws CaMgmtException {
    ParamUtil.requireNonNull("scepEntry", scepEntry);
    asssertMasterMode();

    String name = scepEntry.getName();
    NameId caId = scepEntry.getCaIdent();
    Boolean active = scepEntry.getActive();
    String responderName = scepEntry.getResponderName();
    String control = scepEntry.getControl();

    if (caId == null && responderName == null && control == null) {
      throw new IllegalArgumentException("nothing to change or SCEP " + name);
    }

    if (caId != null && caId.getId() == null) {
      String caName = caId.getName();
      caId = idNameMap.getCa(caName);
      if (caId == null) {
        throw new CaMgmtException(concat("Unknown CA ", caName));
      }
    }

    ScepImpl scep = queryExecutor.changeScep(name, caId, active, responderName,
        scepEntry.getCertProfiles(), control, this, securityFactory);
    if (scep == null) {
      throw new CaMgmtException("could not chagne SCEP " + name);
    }

    sceps.remove(name);
    scepDbEntries.remove(name);
    scepDbEntries.put(name, scep.getDbEntry());
    sceps.put(name, scep);
  } // method changeScep

  @Override
  public ScepEntry getScepEntry(String name) {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    return (scepDbEntries == null) ? null : scepDbEntries.get(name);
  }

  @Override
  public Scep getScep(String name) {
    name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    return (sceps == null) ? null : sceps.get(name);
  }

  @Override
  public Set<String> getScepNames() {
    return (scepDbEntries == null) ? null : Collections.unmodifiableSet(scepDbEntries.keySet());
  }

  private static void assertNotNull(String parameterName, String parameterValue) {
    if (CaManager.NULL.equalsIgnoreCase(parameterValue)) {
      throw new IllegalArgumentException(concat(parameterName, " must not be ", CaManager.NULL));
    }
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
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    ParamUtil.requireNonNull("serialNumber", serialNumber);
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
  public byte[] getCertRequest(String caName, BigInteger serialNumber) throws CaMgmtException {
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
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
    caName = ParamUtil.requireNonBlank("caName", caName).toLowerCase();
    ParamUtil.requireRange("numEntries", numEntries, 1, 1000);
    X509Ca ca = getX509Ca(caName);
    try {
      return ca.listCertificates(subjectPattern, validFrom, validTo, orderBy, numEntries);
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

    // CMP control
    for (String name : conf.getCmpControlNames()) {
      CmpControlEntry entry = conf.getCmpControl(name);
      CmpControlEntry entryB = cmpControlDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB)) {
          LOG.info("ignore existed CMP control {}", name);
          continue;
        } else {
          String msg = concat("CMP control ", name, " existed, could not re-added it");
          LOG.error(msg);
          throw new CaMgmtException(msg);
        }
      }

      try {
        addCmpControl(entry);
        LOG.info("added CMP control {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add CMP control ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // Responder
    for (String name : conf.getResponderNames()) {
      ResponderEntry entry = conf.getResponder(name);
      ResponderEntry entryB = responderDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB)) {
          LOG.info("ignore existed CMP responder {}", name);
          continue;
        } else {
          String msg = concat("CMP responder ", name, " existed, could not re-added it");
          LOG.error(msg);
          throw new CaMgmtException(msg);
        }
      }

      try {
        addResponder(entry);
        LOG.info("added CMP responder {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add CMP responder ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // Environment
    for (String name : conf.getEnvironmentNames()) {
      String entry = conf.getEnvironment(name);
      String entryB = envParameterResolver.getParameter(name);
      if (entryB != null) {
        if (entry.equals(entryB)) {
          LOG.info("ignore existed environment parameter {}", name);
          continue;
        } else {
          String msg = concat("environment parameter ", name, " existed, could not re-added it");
          LOG.error(msg);
          throw new CaMgmtException(msg);
        }
      }

      try {
        addEnvParam(name, entry);
        LOG.info("could not add environment parameter {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add environment parameter ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // CRL signer
    for (String name : conf.getCrlSignerNames()) {
      X509CrlSignerEntry entry = conf.getCrlSigner(name);
      X509CrlSignerEntry entryB = crlSignerDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB)) {
          LOG.info("ignore existed CRL signer {}", name);
          continue;
        } else {
          String msg = concat("CRL signer ", name, " existed, could not re-added it");
          LOG.error(msg);
          throw new CaMgmtException(msg);
        }
      }

      try {
        addCrlSigner(entry);
        LOG.info("added CRL signer {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add CRL signer ", name);
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
          String msg = concat("CMP requestor ", name, " existed, could not re-added it");
          LOG.error(msg);
          throw new CaMgmtException(msg);
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
          String msg = concat("publisher ", name, " existed, could not re-added it");
          LOG.error(msg);
          throw new CaMgmtException(msg);
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

    // CertProfile
    for (String name : conf.getCertProfileNames()) {
      CertprofileEntry entry = conf.getCertProfile(name);
      CertprofileEntry entryB = certprofileDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.info("ignore existed certProfile {}", name);
          continue;
        } else {
          String msg = concat("certProfile ", name, " existed, could not re-added it");
          LOG.error(msg);
          throw new CaMgmtException(msg);
        }
      }

      try {
        addCertprofile(entry);
        LOG.info("added certProfile {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add certProfile ", name);
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
          String msg = concat("user ", name, " existed, could not re-added it");
          LOG.error(msg);
          throw new CaMgmtException(msg);
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
        if (! (caEntry instanceof X509CaEntry)) {
          throw new CaMgmtException(
            concat("Unsupported CaEntry ", caName, " (only X509CaEntry is supported"));
        }

        X509CaEntry entry = (X509CaEntry) caEntry;
        if (caInfos.containsKey(caName)) {
          CaEntry entryB = caInfos.get(caName).getCaEntry();
          if (entry.getCert() == null && genSelfIssued != null) {
            SignerConf signerConf = new SignerConf(entry.getSignerConf());
            ConcurrentContentSigner signer;
            try {
              signer = securityFactory.createSigner(entry.getSignerType(), signerConf,
                  (X509Certificate) null);
            } catch (ObjectCreationException ex) {
              throw new CaMgmtException(concat("could not create signer for CA ", caName), ex);
            }
            entry.setCert(signer.getCertificate());
          }

          if (entry.equals(entryB, true, true)) {
            LOG.info("ignore existed CA {}", caName);
          } else {
            String msg = concat("CA ", caName, " existed, could not re-added it");
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
                LogUtil.error(LOG, ex, concat("could not encode certificate of CA ", caName));
              } catch (IOException ex) {
                LogUtil.error(LOG, ex,
                    concat("error while saving certificate of root CA ", caName, " to ", fn));
              }
            }
          } else {
            try {
              addCa(entry);
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
              String msg = concat("could not add requestor ", requestorName, " to CA", caName);
              LOG.error(msg);
              throw new CaMgmtException(msg);
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
              String msg = concat("could not add user ", userName, " to CA", caName);
              LOG.error(msg);
              throw new CaMgmtException(msg);
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

    // SCEP
    for (String name : conf.getScepNames()) {
      ScepEntry entry = conf.getScep(name);
      ScepEntry entryB = scepDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.error("ignore existed SCEP {}", name);
          continue;
        } else {
          String msg = concat("SCEP ", name, " existed, could not re-added it");
          LOG.error(msg);
          throw new CaMgmtException(msg);
        }
      } else {
        try {
          addScep(entry);
          LOG.info("added SCEP {}", name);
        } catch (CaMgmtException ex) {
          String msg = concat("could not add SCEP ", name);
          LogUtil.error(LOG, ex, msg);
          throw new CaMgmtException(msg);
        }
      }
    }
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

    CAConfType root = new CAConfType();
    root.setVersion(1);

    ZipOutputStream zipStream = getZipOutputStream(zipFile);
    try {
      Set<String> includeCmpControlNames = new HashSet<>();
      Set<String> includeResponderNames = new HashSet<>();
      Set<String> includeRequestorNames = new HashSet<>();
      Set<String> includeProfileNames = new HashSet<>();
      Set<String> includePublisherNames = new HashSet<>();
      Set<String> includeCrlSignerNames = new HashSet<>();
      Set<String> includeUserNames = new HashSet<>();

      // users
      root.setUsers(new CAConfType.Users());
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
              jaxb2.setProfiles(createStrings(m.getProfiles()));
              jaxb2.setPermission(m.getPermission());

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
              jaxb2.setPermission(m.getPermission());
              jaxb2.setProfiles(createStrings(m.getProfiles()));
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

          X509CaEntry entry = x509cas.get(name).getCaInfo().getCaEntry();
          X509CaInfoType ciJaxb = new X509CaInfoType();
          ciJaxb.setCacertUris(createStrings(entry.getCaCertUris()));
          byte[] certBytes;
          try {
            certBytes = entry.getCert().getEncoded();
          } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(concat("could not encode CA certificate ", name));
          }
          ciJaxb.setCert(createFileOrBinary(zipStream, certBytes,
              concat("files/ca-", name, "-cert.der")));

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
          if (entry.getExtraControl() != null) {
            ciJaxb.setExtraControl(
                createFileOrValue(zipStream, entry.getExtraControl().getEncoded(),
                    concat("files/ca-", name, "-extracontrol.conf")));
          }
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
              concat("files/ca-", name, "-signerconf.conf")));
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

      // clear the users if the list is empty
      if (users.isEmpty()) {
        root.setUsers(null);
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
              concat("files/cmpcontrol-", name, ".conf")));
          list.add(jaxb);
        }

        if (!list.isEmpty()) {
          root.setCmpcontrols(new CAConfType.Cmpcontrols());
          root.getCmpcontrols().getCmpcontrol().addAll(list);
        }
      }

      // environments
      Set<String> names = envParameterResolver.allParameterNames();
      if (CollectionUtil.isNonEmpty(names)) {
        List<NameValueType> list = new LinkedList<>();

        for (String name : names) {
          if (ENV_EPOCH.equalsIgnoreCase(name)) {
            continue;
          }

          NameValueType jaxb = new NameValueType();
          jaxb.setName(name);
          jaxb.setValue(envParameterResolver.getParameter(name));

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
              concat("files/crlsigner-", name, ".conf")));
          jaxb.setSignerCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
              concat("files/crlsigner-", name, ".der")));
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

          RequestorEntry entry = requestorDbEntries.get(name);
          RequestorType jaxb = new RequestorType();
          jaxb.setName(name);
          jaxb.setCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
              concat("files/requestor-", name, ".der")));

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
              concat("files/publisher-", name, ".conf")));
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
              concat("files/certprofile-", name, ".conf")));
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
          ScepEntry entry = scepDbEntries.get(name);
          String caName = entry.getCaIdent().getName();
          if (!caNames.contains(caName)) {
            continue;
          }

          String responderName = entry.getResponderName();
          includeResponderNames.add(responderName);

          ScepType jaxb = new ScepType();
          jaxb.setName(name);
          jaxb.setCaName(caName);
          jaxb.setResponderName(responderName);
          jaxb.setProfiles(createStrings(entry.getCertProfiles()));
          jaxb.setControl(entry.getControl());

          list.add(jaxb);
        }

        if (!list.isEmpty()) {
          root.setSceps(new CAConfType.Sceps());
          root.getSceps().getScep().addAll(list);
        }
      }

      // responders
      if (CollectionUtil.isNonEmpty(responderDbEntries)) {
        List<ResponderType> list = new LinkedList<>();

        for (String name : responderDbEntries.keySet()) {
          if (!includeResponderNames.contains(name)) {
            continue;
          }

          ResponderEntry entry = responderDbEntries.get(name);
          ResponderType jaxb = new ResponderType();
          jaxb.setName(name);
          jaxb.setType(entry.getType());
          jaxb.setConf(createFileOrValue(zipStream, entry.getConf(),
              concat("files/responder-", name, ".conf")));
          jaxb.setCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
              concat("files/responder-", name, ".der")));

          list.add(jaxb);
        }

        if (!list.isEmpty()) {
          root.setResponders(new CAConfType.Responders());
          root.getResponders().getResponder().addAll(list);
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

  private static ZipOutputStream getZipOutputStream(File zipFile)
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

  @Override
  public Rest getRest() {
    return rest;
  }

  private static String concat(String s1, String... strs) {
    return StringUtil.concat(s1, strs);
  }

}
