/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.mgmt;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.SocketException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.PCIAuditEvent;
import org.xipki.ca.api.CAMgmtException;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.cmp.server.CmpControl;
import org.xipki.ca.common.CASystemStatus;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.CmpRequestorInfo;
import org.xipki.ca.server.CrlSigner;
import org.xipki.ca.server.X509CA;
import org.xipki.ca.server.X509CACmpResponder;
import org.xipki.ca.server.store.CertificateStore;
import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.DfltEnvironmentParameterResolver;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CAManagerImpl implements CAManager
{
    private static final Logger LOG = LoggerFactory.getLogger(CAManagerImpl.class);

    private final CertificateFactory certFact;
    private final String lockInstanceId;

    private CertificateStore certstore;
    private DataSource dataSource;
    private CmpResponderEntry responder;

    private boolean caLockedByMe = false;

    private Map<String, DataSource> dataSources = null;

    private final Map<String, CAEntry> cas = new ConcurrentHashMap<>();
    private final Map<String, CertProfileEntry> certProfiles = new ConcurrentHashMap<>();
    private final Map<String, PublisherEntry> publishers = new ConcurrentHashMap<>();
    private final Map<String, CmpRequestorEntry> requestors = new ConcurrentHashMap<>();
    private final Map<String, CrlSignerEntry> crlSigners = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> ca_has_profiles = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> ca_has_publishers = new ConcurrentHashMap<>();
    private final Map<String, Set<CAHasRequestorEntry>> ca_has_requestors = new ConcurrentHashMap<>();
    private final Map<String, String> caAliases = new ConcurrentHashMap<>();

    private final DfltEnvironmentParameterResolver envParameterResolver = new DfltEnvironmentParameterResolver();

    private CmpControl cmpControl;

    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;
    private static final Map<String, X509CACmpResponder> responders = new ConcurrentHashMap<>();

    private static final Map<String, X509CA> x509cas = new ConcurrentHashMap<>();

    private PasswordResolver passwordResolver;
    private SecurityFactory securityFactory;
    private DataSourceFactory dataSourceFactory;
    private String caConfFile;

    private boolean caSystemSetuped = false;
    private boolean responderInitialized = false;
    private boolean requestorsInitialized = false;
    private boolean caAliasesInitialized = false;
    private boolean certProfilesInitialized = false;
    private boolean publishersInitialized = false;
    private boolean crlSignersInitialized = false;
    private boolean cmpControlInitialized = false;
    private boolean cAsInitialized = false;
    private boolean environmentParametersInitialized = false;

    private AuditLoggingService auditLoggingService;

    public CAManagerImpl()
    throws ConfigurationException
    {
        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        CertificateFactory cf;
        try
        {
            cf = CertificateFactory.getInstance("X.509", "BC");
        } catch (CertificateException e)
        {
            throw new ConfigurationException(e);
        } catch (NoSuchProviderException e)
        {
            try
            {
                cf = CertificateFactory.getInstance("X.509");
            } catch (CertificateException e1)
            {
                throw new ConfigurationException(e);
            }
        }

        this.certFact = cf;

        String calockId = null;
        File caLockFile = new File("calock");
        if(caLockFile.exists())
        {
            try
            {
                calockId = new String(IoCertUtil.read(caLockFile));
            } catch (IOException e)
            {
            }
        }

        if(calockId == null)
        {
            calockId = UUID.randomUUID().toString();
            try
            {
                IoCertUtil.save(caLockFile, calockId.getBytes());
            } catch (IOException e)
            {
            }
        }

        String hostAddress = null;
        try
        {
            hostAddress = IoCertUtil.getHostAddress();
        } catch (SocketException e)
        {
        }

        this.lockInstanceId = (hostAddress == null) ? calockId :hostAddress + "/" + calockId;
    }

    private void init()
    throws CAMgmtException
    {
        if(securityFactory == null)
        {
            throw new IllegalStateException("securityFactory is not set");
        }
        if(passwordResolver == null)
        {
            throw new IllegalStateException("passwordResolver is not set");
        }
        if(dataSourceFactory == null)
        {
            throw new IllegalStateException("dataSourceFactory is not set");
        }
        if(caConfFile == null)
        {
            throw new IllegalStateException("caConfFile is not set");
        }

        if(this.dataSources == null)
        {
            Properties caConfProps = new Properties();
            try
            {
                caConfProps.load(new FileInputStream(caConfFile));
            } catch (IOException e)
            {
                throw new CAMgmtException("IOException while parsing ca configuration" + caConfFile, e);
            }

            this.dataSources = new ConcurrentHashMap<>();
            for(Object objKey : caConfProps.keySet())
            {
                String key = (String) objKey;
                if(key.startsWith("datasource."))
                {
                    String datasourceFile = caConfProps.getProperty(key);
                    try
                    {
                        String datasourceName = key.substring("datasource.".length());
                        DataSource datasource = dataSourceFactory.createDataSourceForFile(datasourceFile, passwordResolver);
                        this.dataSources.put(datasourceName, datasource);
                    } catch (SQLException e)
                    {
                        throw new CAMgmtException("SQLException while paring datasoure " + datasourceFile, e);
                    } catch (PasswordResolverException e)
                    {
                        throw new CAMgmtException("PasswordResolverException while paring datasoure " + datasourceFile, e);
                    } catch (IOException e)
                    {
                        throw new CAMgmtException("IOException while paring datasoure " + datasourceFile, e);
                    }
                }
            }

            this.dataSource = this.dataSources.get("ca");
        }

        if(this.dataSource == null)
        {
            throw new CAMgmtException("no datasource configured with name 'ca'");
        }

        boolean successfull;
        try
        {
            successfull = lockCA();
        }catch(SQLException e)
        {
            throw new CAMgmtException("SQLException while locking CA", e);
        }

        if(successfull == false)
        {
            String msg = "Could not lock the CA database. In general this indicates that another CA software is accessing the "
                    + "database or the last shutdown of CA software is not normal.";
            throw new CAMgmtException(msg);
        }

        try
        {
            this.certstore = new CertificateStore(dataSource);
        } catch (SQLException e)
        {
            throw new CAMgmtException(e);
        }

        initDataObjects();
    }

    @Override
    public CASystemStatus getCASystemStatus()
    {
        if(caSystemSetuped)
        {
            return CASystemStatus.STARTED;
        }
        else if(initializing)
        {
            return CASystemStatus.INITIALIZING;
        }
        else if(caLockedByMe == false)
        {
            return CASystemStatus.LOCK_FAILED;
        }
        else
        {
            return CASystemStatus.ERROR;
        }
    }

    private boolean lockCA()
    throws SQLException, CAMgmtException
    {
        if(caLockedByMe)
        {
            return true;
        }

        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            String sql = "SELECT LOCKED, LOCKGRANTED, LOCKEDBY FROM CALOCK WHERE NAME='default'";
            rs = stmt.executeQuery(sql);

            if(rs.next())
            {
                boolean alreadyLocked = rs.getBoolean("LOCKED");
                if(alreadyLocked)
                {
                    long lockGranted = rs.getLong("LOCKGRANTED");
                    String lockedBy = rs.getString("LOCKEDBY");
                    if(this.lockInstanceId.equals(lockedBy))
                    {
                        LOG.info("CA has been locked by me since {}, relock it",
                                new Date(lockGranted * 1000));
                    }
                    else
                    {
                        LOG.error("Cannot lock CA, it has been locked by {} since {}", lockedBy,
                                new Date(lockGranted * 1000));
                        return false;
                    }
                }
            }

            stmt.execute("DELETE FROM CALOCK");
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        String lockSql = "INSERT INTO CALOCK (NAME, LOCKED, LOCKGRANTED, LOCKGRANTED2, LOCKEDBY)"
                + " VALUES ('default', ?, ?, ?, ?)";

        PreparedStatement ps = null;
        try
        {
            long nowMillis = System.currentTimeMillis();
            ps = prepareStatement(lockSql);
            int idx = 1;
            ps.setInt(idx++, 1);
            ps.setLong(idx++, nowMillis / 1000);
            ps.setTimestamp(idx++, new Timestamp(nowMillis));
            ps.setString(idx++, lockInstanceId);
            int numColumns = ps.executeUpdate();
            caLockedByMe = numColumns > 0;
            return caLockedByMe;
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public boolean unlockCA()
    {
        boolean successfull = false;

        Statement stmt = null;
        try
        {
            stmt = createStatement();
            stmt.execute("DELETE FROM CALOCK");
            successfull = true;
        }catch(SQLException e)
        {
            LOG.warn("Error in unlockCA(), SQLException: {}", e.getMessage());
            LOG.debug("Error in unlockCA()", e);
        } catch (CAMgmtException e)
        {
            LOG.warn("Error in unlockCA(), SQLException: {}", e.getMessage());
            LOG.debug("Error in unlockCA()", e);
        }finally
        {
            dataSource.releaseResources(stmt, null);
        }

        if(successfull)
        {
            LOG.info("Unlocked CA");
        }
        else
        {
            LOG.error("Unlocking CA failed");
        }
        auditLogPCIEvent(successfull, "UNLOCK");
        return successfull;
    }

    private void reset()
    {
        caSystemSetuped = false;
        responderInitialized = false;
        requestorsInitialized = false;
        caAliasesInitialized = false;
        certProfilesInitialized = false;
        publishersInitialized = false;
        crlSignersInitialized = false;
        cmpControlInitialized = false;
        cAsInitialized = false;
        environmentParametersInitialized = false;

        shutdownScheduledThreadPoolExecutor();
    }

    private void initDataObjects()
    throws CAMgmtException
    {
        initEnvironemtParamters();
        initCaAliases();
        initCertProfiles();
        initPublishers();
        initCmpControl();
        initRequestors();
        initResponder();
        initCrlSigners();
        initCAs();
    }

    @Override
    public boolean restartCaSystem()
    {
        reset();
        boolean caSystemStarted = do_startCaSystem();

        if(caSystemStarted == false)
        {
            String msg = "Could not restart CA system";
            LOG.error(msg);
        }

        auditLogPCIEvent(caSystemStarted, "RESTART");
        return caSystemStarted;
    }

    public void startCaSystem()
    {
        boolean caSystemStarted = do_startCaSystem();
        if(caSystemStarted == false)
        {
            String msg = "Could not start CA system";
            LOG.error(msg);
        }

        auditLogPCIEvent(caSystemStarted, "START");
    }

    private boolean initializing = false;
    private boolean do_startCaSystem()
    {
        if(caSystemSetuped)
        {
            return true;
        }

        initializing = true;
        shutdownScheduledThreadPoolExecutor();

        try
        {
            LOG.info("Starting CA system");
            try
            {
                init();
            }catch(Exception e)
            {
                LOG.error("do_startCaSystem().init(). {}: {}", e.getClass().getName(), e.getMessage());
                LOG.debug("do_startCaSystem().init()", e);
                return false;
            }

            // check the configuration of certificate profiles
            for(CertProfileEntry entry : certProfiles.values())
            {
                try
                {
                    entry.getCertProfile();
                } catch (CertProfileException e)
                {
                    String event = "Invalid configuration for the certProfile " + entry.getName();
                    LOG.error("{},  message: {}", event, e.getMessage());
                    LOG.debug(event, e);
                    return false;
                }
            }

            // check the configuration of certificate publishers
            for(PublisherEntry entry : publishers.values())
            {
                try
                {
                    entry.getCertPublisher();
                } catch (CertPublisherException e)
                {
                    final String event = "Invalid configuration for the certPublisher " + entry.getName();
                    LOG.error("{},  message: {}", event, e.getMessage());
                    LOG.debug(event, e);
                    return false;
                }
            }

            x509cas.clear();
            responders.clear();

            ConcurrentContentSigner cmpSigner = null;
            if(responder != null)
            {
                try
                {
                    X509Certificate responderCert = responder.getCertificate();
                    cmpSigner = securityFactory.createSigner(
                            responder.getType(), responder.getConf(), responderCert,
                            passwordResolver);
                    if(responderCert == null)
                    {
                        responder.setCertificate(cmpSigner.getCertificate());
                    }
                } catch (PasswordResolverException e)
                {
                    String event = "security.createSigner cmpResponder";
                    LOG.error("{}. {}, {}", new Object[]{event, e.getClass().getName(), e.getMessage()});
                    LOG.debug(event, e);
                    return false;
                } catch (SignerException e)
                {
                    String event = "security.createSigner cmpResponder";
                    LOG.error("{}. {}, {}", new Object[]{event, e.getClass().getName(), e.getMessage()});
                    LOG.debug(event, e);
                    return false;
                }
            }

            if(cas.isEmpty() == false)
            {
                scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(10);
            }

            // Add the CAs to the store
            for(String caName : cas.keySet())
            {
                CAEntry caEntry = cas.get(caName);

                CrlSigner crlSigner = null;
                if(caEntry.getCrlSignerName() != null)
                {
                    CrlSignerEntry crlSignerEntry = crlSigners.get(caEntry.getCrlSignerName());
                    String signerType = crlSignerEntry.getType();

                    ConcurrentContentSigner identifiedSigner = null;
                    if("CA".equals(signerType))
                    {
                    }
                    else
                    {
                        try
                        {
                            X509Certificate crlSignerCert = crlSignerEntry.getCertificate();
                            identifiedSigner = securityFactory.createSigner(
                                    signerType, crlSignerEntry.getConf(), crlSignerCert,
                                    passwordResolver);
                            if(crlSignerCert == null)
                            {
                                crlSignerEntry.setCertificate(identifiedSigner.getCertificate());
                            }
                        } catch (PasswordResolverException e)
                        {
                            String event = "security.createSigner crlSigner (ca=" + caName + ")";
                            LOG.error("{}. {}, {}", new Object[]{event, e.getClass().getName(), e.getMessage()});
                            LOG.debug(event, e);
                            return false;
                        } catch (SignerException e)
                        {
                            String event = "security.createSigner crlSigner (ca=" + caName + ")";
                            LOG.error("{}. {}, {}", new Object[]{event, e.getClass().getName(), e.getMessage()});
                            LOG.debug(event, e);
                            return false;
                        }
                        caEntry.getPublicCAInfo().setCrlSignerCertificate(identifiedSigner.getCertificate());
                    }

                    try
                    {
                        crlSigner = new CrlSigner(identifiedSigner, crlSignerEntry.getPeriod(), crlSignerEntry.getOverlap());
                    } catch (OperationException e)
                    {
                        String event = "CrlSigner.<init> crlSigner (ca=" + caName + ")";
                        LOG.error("{}. {}, {}", new Object[]{event, e.getClass().getName(), e.getMessage()});
                        LOG.debug(event, e);
                        return false;
                    }
                    crlSigner.setIncludeCertsInCrl(crlSignerEntry.includeCertsInCRL());
                    crlSigner.setIncludeExpiredCerts(crlSignerEntry.includeExpiredCerts());
                }

                ConcurrentContentSigner caSigner;
                try
                {
                    caSigner = securityFactory.createSigner(
                            caEntry.getSignerType(), caEntry.getSignerConf(),
                            caEntry.getCertificate().getCert(),
                            passwordResolver);
                } catch (PasswordResolverException e)
                {
                    String event = "security.createSigner caSigner (ca=" + caName + ")";
                    LOG.error("{}. {}, {}", new Object[]{event, e.getClass().getName(), e.getMessage()});
                    LOG.debug(event, e);
                    return false;
                } catch (SignerException e)
                {
                    String event = "security.createSigner caSigner (ca=" + caName + ")";
                    LOG.error("{}. {}, {}", new Object[]{event, e.getClass().getName(), e.getMessage()});
                    LOG.debug(event, e);
                    return false;
                }

                X509CA ca;
                try
                {
                    ca = new X509CA(this, caEntry, caSigner, certstore, crlSigner);
                } catch (OperationException e)
                {
                    String event = "X509CA.<init> (ca=" + caName + ")";
                    LOG.error("{}. {}, {}", new Object[]{event, e.getClass().getName(), e.getMessage()});
                    LOG.debug(event, e);
                    return false;
                }

                x509cas.put(caName, ca);

                if(cmpSigner != null)
                {
                    X509CACmpResponder caResponder = new X509CACmpResponder(ca, cmpSigner, securityFactory);
                    Set<CAHasRequestorEntry> caHasRequestorEntries = getCmpRequestorsForCA(caName);
                    if(caHasRequestorEntries != null)
                    {
                        for(CAHasRequestorEntry entry : caHasRequestorEntries)
                        {
                            CmpRequestorEntry cmpRequestorEntry = getCmpRequestor(entry.getRequestorName());
                            CmpRequestorInfo requestorInfo = new CmpRequestorInfo(
                                    cmpRequestorEntry.getName(),
                                    new X509CertificateWithMetaInfo(cmpRequestorEntry.getCert()),
                                    entry.isRa());
                            requestorInfo.setPermissions(entry.getPermissions());
                            requestorInfo.setProfiles(entry.getProfiles());
                            caResponder.addAutorizatedRequestor(requestorInfo);
                        }
                    }

                    responders.put(caName, caResponder);
                }
            }

            caSystemSetuped = true;
            StringBuilder sb = new StringBuilder();
            sb.append("Started CA system");
            Set<String> names = new HashSet<>(getCANames());

            if(names.size() > 0)
            {
                sb.append(" with following CAs: ");
                Set<String> caAliasNames = getCaAliasNames();
                 for(String aliasName : caAliasNames)
                {
                     String name = getCaName(aliasName);
                     names.remove(name);

                    sb.append(name).append(" (alias ").append(aliasName).append(")").append(", ");
                }

                 for(String name : names)
                 {
                    sb.append(name).append(", ");
                 }

                 int len = sb.length();
                 sb.delete(len-2, len);

                 ScheduledPublishQueueCleaner publishQueueCleaner = new ScheduledPublishQueueCleaner();
                 scheduledThreadPoolExecutor.scheduleAtFixedRate(
                         publishQueueCleaner, 120, 120, TimeUnit.SECONDS);
            }
            else
            {
                sb.append(": no CA is configured");
            }

            LOG.info("{}", sb);
        } finally
        {
            initializing = false;
        }

        return true;
    }

    public void shutdown()
    {
        LOG.info("Stopping CA system");

        shutdownScheduledThreadPoolExecutor();

        for(String caName : x509cas.keySet())
        {
            X509CA ca = x509cas.get(caName);
            try
            {
                ca.commitNextSerial();
            } catch (Throwable t)
            {
                LOG.info("Exception while calling ca.commitNextSerial for ca {}: {}", caName, t.getMessage());
            }
        }

        if(caLockedByMe)
        {
            unlockCA();
        }

        File caLockFile = new File("calock");
        if(caLockFile.exists())
        {
            caLockFile.delete();
        }

        LOG.info("Stopped CA system");
        auditLogPCIEvent(true, "SHUTDOWN");
    }

    @Override
    public X509CA getX509CA(String caName)
    {
        return x509cas.get(caName);
    }

    @Override
    public X509CACmpResponder getX509CACmpResponder(String caName)
    {
        return responders.get(caName);
    }

    public ScheduledThreadPoolExecutor getScheduledThreadPoolExecutor()
    {
        return scheduledThreadPoolExecutor;
    }

    @Override
    public Set<String> getCertProfileNames()
    {
        return certProfiles.keySet();
    }

    @Override
    public Set<String> getPublisherNames()
    {
        return publishers.keySet();
    }

    @Override
    public Set<String> getCmpRequestorNames()
    {
        return requestors.keySet();
    }

    @Override
    public Set<String> getCrlSignerNames()
    {
        return crlSigners.keySet();
    }

    @Override
    public Set<String> getCANames()
    {
        return cas.keySet();
    }

    private void initRequestors()
    throws CAMgmtException
    {
        if(requestorsInitialized)
        {
            return;
        }

        requestors.clear();
        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery("SELECT NAME, CERT FROM REQUESTOR");

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String b64Cert = rs.getString("CERT");
                X509Certificate cert = generateCert(b64Cert);
                CmpRequestorEntry entry = new CmpRequestorEntry(name);
                entry.setCert(cert);
                requestors.put(entry.getName(), entry);
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        requestorsInitialized = true;
    }

    private void initResponder()
    throws CAMgmtException
    {
        if(responderInitialized) return;

        this.responder = null;
        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery("SELECT TYPE, CONF, CERT FROM RESPONDER");

            String errorMsg = null;
            while(rs.next())
            {
                if(this.responder != null)
                {
                    errorMsg = "More than one CMPResponder is configured, but maximal one is allowed";
                    break;
                }

                CmpResponderEntry entry = new CmpResponderEntry();

                String type = rs.getString("TYPE");
                entry.setType(type);

                String conf = rs.getString("CONF");
                entry.setConf(conf);

                String b64Cert = rs.getString("CERT");
                if(b64Cert != null)
                {
                    X509Certificate cert = generateCert(b64Cert);
                    entry.setCertificate(cert);
                }

                this.responder = entry;
            }

            if(errorMsg != null)
            {
                throw new CAMgmtException(errorMsg);
            }

        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        responderInitialized = true;
    }

    private X509Certificate generateCert(String b64Cert)
    throws CAMgmtException
    {
        if(b64Cert == null)
        {
            return null;
        }

        byte[] encodedCert = Base64.decode(b64Cert);
        try
        {
            return (X509Certificate) certFact.generateCertificate(new ByteArrayInputStream(encodedCert));
        } catch (CertificateException e)
        {
            throw new CAMgmtException(e);
        }
    }

    private void initEnvironemtParamters()
    throws CAMgmtException
    {
        if(environmentParametersInitialized) return;

        envParameterResolver.clear();

        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            String sql = "SELECT NAME, VALUE2 FROM ENVIRONMENT";
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String value = rs.getString("VALUE2");
                envParameterResolver.addEnvParam(name, value);
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        environmentParametersInitialized = true;
    }

    private void initCaAliases()
    throws CAMgmtException
    {
        if(caAliasesInitialized) return;

        caAliases.clear();

        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            String sql = "SELECT NAME, CA_NAME FROM CAALIAS";
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String caName = rs.getString("CA_NAME");

                caAliases.put(name, caName);
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        caAliasesInitialized = true;
    }

    private void initCertProfiles()
    throws CAMgmtException
    {
        if(certProfilesInitialized) return;

        certProfiles.clear();

        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            String sql = "SELECT NAME, TYPE, CONF FROM CERTPROFILE";
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");

                CertProfileEntry entry = new CertProfileEntry(name);
                entry.setEnvironmentParamterResolver(envParameterResolver);
                entry.setType(type);
                entry.setConf(conf);
                certProfiles.put(entry.getName(), entry);
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        } finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        certProfilesInitialized = true;
    }

    private void initPublishers()
    throws CAMgmtException
    {
        if(publishersInitialized) return;

        publishers.clear();

        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            String sql = "SELECT NAME, TYPE, CONF FROM PUBLISHER";
            rs = stmt.executeQuery(sql);

            String errorMsg = null;

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");

                String datasourceName = null;
                CmpUtf8Pairs confPairs = null;
                try
                {
                    confPairs = new CmpUtf8Pairs(conf);
                    datasourceName = confPairs.getValue("datasource");
                }catch(Exception e)
                {
                }

                DataSource ocspDataSource = null;
                if(datasourceName != null)
                {
                    ocspDataSource = dataSources.get(datasourceName);
                    if(ocspDataSource == null)
                    {
                        errorMsg = "Cound not find datasource named '" + datasourceName + "'";
                        break;
                    }
                }

                PublisherEntry entry = new PublisherEntry(name);
                entry.setType(type);
                entry.setConf(confPairs.getEncoded());
                entry.setPasswordResolver(passwordResolver);
                entry.setDataSource(ocspDataSource);
                publishers.put(entry.getName(), entry);
            }

            if(errorMsg != null)
            {
                throw new CAMgmtException(errorMsg);
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        publishersInitialized = true;
    }

    private void initCrlSigners()
    throws CAMgmtException
    {
        if(crlSignersInitialized) return;

        crlSigners.clear();

        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();

            String sql = "SELECT NAME, SIGNER_TYPE, SIGNER_CONF, SIGNER_CERT, PERIOD,"
                    + " OVERLAP, INCLUDE_CERTS_IN_CRL, INCLUDE_EXPIRED_CERTS"
                    + " FROM CRLSIGNER";
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String signer_type = rs.getString("SIGNER_TYPE");
                String signer_conf = rs.getString("SIGNER_CONF");
                String signer_cert = rs.getString("SIGNER_CERT");
                int period = rs.getInt("PERIOD");
                int overlap = rs.getInt("OVERLAP");
                boolean include_certs_in_crl = rs.getBoolean("INCLUDE_CERTS_IN_CRL");
                boolean include_expired_certs = rs.getBoolean("INCLUDE_EXPIRED_CERTS");

                CrlSignerEntry entry = new CrlSignerEntry(name);
                entry.setType(signer_type);
                if("CA".equalsIgnoreCase(signer_type) == false)
                {
                    entry.setConf(signer_conf);
                    if(signer_cert != null)
                    {
                        entry.setCertificate(generateCert(signer_cert));
                    }
                }
                entry.setPeriod(period);
                entry.setOverlap(overlap);
                entry.setIncludeCertsInCrl(include_certs_in_crl);
                entry.setIncludeExpiredCerts(include_expired_certs);
                crlSigners.put(entry.getName(), entry);
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        } catch (ConfigurationException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        crlSignersInitialized = true;
    }

    private void initCmpControl()
    throws CAMgmtException
    {
        if(cmpControlInitialized) return;

        cmpControl = null;

        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            String sql = "SELECT REQUIRE_CONFIRM_CERT, SEND_CA_CERT, SEND_RESPONDER_CERT,"
                    + " REQUIRE_MESSAGE_TIME, MESSAGE_TIME_BIAS, CONFIRM_WAIT_TIME"
                    + " FROM CMPCONTROL";

            rs = stmt.executeQuery(sql);

            if(rs.next())
            {
                boolean requireConfirmCert = rs.getBoolean("REQUIRE_CONFIRM_CERT");
                boolean sendCaCert = rs.getBoolean("SEND_CA_CERT");
                boolean sendResponderCert = rs.getBoolean("SEND_RESPONDER_CERT");
                boolean requireMessageTime = rs.getBoolean("REQUIRE_MESSAGE_TIME");
                int messageTimeBias = rs.getInt("MESSAGE_TIME_BIAS");
                int confirmWaitTime = rs.getInt("CONFIRM_WAIT_TIME");

                CmpControl entry = new CmpControl();
                entry.setRequireConfirmCert(requireConfirmCert);
                entry.setSendCaCert(sendCaCert);
                entry.setSendResponderCert(sendResponderCert);
                entry.setMessageTimeRequired(requireMessageTime);
                if(messageTimeBias != 0)
                {
                    entry.setMessageBias(messageTimeBias);
                }
                if(confirmWaitTime != 0)
                {
                    entry.setConfirmWaitTime(confirmWaitTime);
                }

                cmpControl = entry;
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        cmpControlInitialized = true;
    }

    private void initCAs()
    throws CAMgmtException
    {
        if(cAsInitialized) return;

        cas.clear();
        ca_has_requestors.clear();
        ca_has_publishers.clear();
        ca_has_profiles.clear();

        Statement stmt = null;
        try
        {
            stmt = createStatement();

            ResultSet rs = stmt.executeQuery(
                    "SELECT NAME, NEXT_SERIAL, STATUS, CRL_URIS, OCSP_URIS, MAX_VALIDITY, "
                    + "CERT, SIGNER_TYPE, SIGNER_CONF, CRLSIGNER_NAME, "
                    + "DUPLICATE_KEY_MODE, DUPLICATE_SUBJECT_MODE, PERMISSIONS, NUM_CRLS, "
                    + "EXPIRATION_PERIOD, REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME FROM CA");

            while(rs.next())
            {
                String name = rs.getString("NAME");
                long next_serial = rs.getLong("NEXT_SERIAL");
                String status = rs.getString("STATUS");
                String crl_uris = rs.getString("CRL_URIS");
                String ocsp_uris = rs.getString("OCSP_URIS");
                int max_validity = rs.getInt("MAX_VALIDITY");
                String b64cert = rs.getString("CERT");
                String signer_type = rs.getString("SIGNER_TYPE");
                String signer_conf = rs.getString("SIGNER_CONF");
                String crlsigner_name = rs.getString("CRLSIGNER_NAME");
                int duplicateKeyI = rs.getInt("DUPLICATE_KEY_MODE");
                int duplicateSubjectI = rs.getInt("DUPLICATE_SUBJECT_MODE");
                int numCrls = rs.getInt("NUM_CRLS");
                int expirationPeriod = rs.getInt("EXPIRATION_PERIOD");

                CertRevocationInfo revocationInfo = null;
                boolean revoked = rs.getBoolean("REVOKED");
                if(revoked)
                {
                    int rev_reason = rs.getInt("REV_REASON");
                    long rev_time = rs.getInt("REV_TIME");
                    long rev_invalidity_time = rs.getInt("REV_INVALIDITY_TIME");
                    revocationInfo = new CertRevocationInfo(rev_reason, new Date(rev_time * 1000),
                            rev_invalidity_time == 0 ? null : new Date(rev_invalidity_time * 1000));
                }

                String s = rs.getString("PERMISSIONS");
                Set<Permission> permissions = getPermissions(s);

                List<String> lCrlUris = null;
                if(crl_uris != null && crl_uris.isEmpty() == false)
                {
                    lCrlUris = tokensAsList(crl_uris, " \t");
                }

                List<String> lOcspUris = null;
                if(ocsp_uris != null && ocsp_uris.isEmpty() == false)
                {
                    lOcspUris = tokensAsList(ocsp_uris, " \t");
                }

                X509Certificate cert = generateCert(b64cert);

                CAEntry entry = new CAEntry(name, next_serial, signer_type, signer_conf, cert,
                        lOcspUris, lCrlUris, null, numCrls, expirationPeriod);
                entry.setLastCommittedNextSerial(next_serial);

                CAStatus caStatus = CAStatus.getCAStatus(status);
                if(caStatus == null)
                {
                    caStatus = CAStatus.INACTIVE;
                }
                entry.setStatus(caStatus);

                entry.setMaxValidity(max_validity);

                if(crlsigner_name != null)
                {
                    entry.setCrlSignerName(crlsigner_name);
                }

                entry.setDuplicateKeyMode(DuplicationMode.getInstance(duplicateKeyI));
                entry.setDuplicateSubjectMode(DuplicationMode.getInstance(duplicateSubjectI));
                entry.setPermissions(permissions);
                entry.setRevocationInfo(revocationInfo);

                cas.put(entry.getName(), entry);
            }

            rs.close();

            rs = stmt.executeQuery("SELECT CA_NAME, REQUESTOR_NAME, RA, PERMISSIONS, PROFILES"
                    + " FROM CA_HAS_REQUESTOR");
            while(rs.next())
            {
                String ca_name = rs.getString("CA_NAME");
                String requestor_name = rs.getString("REQUESTOR_NAME");
                boolean ra = rs.getBoolean("RA");
                String s = rs.getString("PERMISSIONS");
                Set<Permission> permissions = getPermissions(s);

                s = rs.getString("PROFILES");
                List<String> list = tokensAsList(s, ",");
                Set<String> profiles = (list == null)? null : new HashSet<>(list);

                Set<CAHasRequestorEntry> requestors = ca_has_requestors.get(ca_name);
                if(requestors == null)
                {
                    requestors = new HashSet<>();
                    ca_has_requestors.put(ca_name, requestors);
                }

                CAHasRequestorEntry entry = new CAHasRequestorEntry(requestor_name);
                entry.setRa(ra);
                entry.setPermissions(permissions);
                entry.setProfiles(profiles);
                requestors.add(entry);
            }
            rs.close();

            rs = stmt.executeQuery("SELECT CA_NAME, CERTPROFILE_NAME FROM CA_HAS_CERTPROFILE");
            while(rs.next())
            {
                String ca_name = rs.getString("CA_NAME");
                String certprofile_name = rs.getString("CERTPROFILE_NAME");
                Set<String> certprofile_names = ca_has_profiles.get(ca_name);
                if(certprofile_names == null)
                {
                    certprofile_names = new HashSet<>();
                    ca_has_profiles.put(ca_name, certprofile_names);
                }
                certprofile_names.add(certprofile_name);
            }
            rs.close();

            rs = stmt.executeQuery(
                    "SELECT CA_NAME, PUBLISHER_NAME FROM CA_HAS_PUBLISHER");
            while(rs.next())
            {
                String ca_name = rs.getString("CA_NAME");
                String publisher_name = rs.getString("PUBLISHER_NAME");
                Set<String> publisher_names = ca_has_publishers.get(ca_name);
                if(publisher_names == null)
                {
                    publisher_names = new HashSet<>();
                    ca_has_publishers.put(ca_name, publisher_names);
                }
                publisher_names.add(publisher_name);
            }

            rs.close();
            rs = null;
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(stmt, null);
        }

        cAsInitialized = true;
    }

    @Override
    public void addCA(CAEntry newCaDbEntry)
    throws CAMgmtException
    {
        String name = newCaDbEntry.getName();

        if(cas.containsKey(name))
        {
            throw new CAMgmtException("CA named " + name + " exists");
        }

        // insert to table ca
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(
                    "INSERT INTO CA (NAME, SUBJECT, NEXT_SERIAL, STATUS, CRL_URIS, OCSP_URIS, MAX_VALIDITY, "
                    + "CERT, SIGNER_TYPE, SIGNER_CONF, CRLSIGNER_NAME, "
                    + "DUPLICATE_KEY_MODE, DUPLICATE_SUBJECT_MODE, PERMISSIONS, NUM_CRLS, EXPIRATION_PERIOD) "
                    + "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            int idx = 1;
            ps.setString(idx++, name);
            ps.setString(idx++, newCaDbEntry.getSubject());

            long nextSerial = newCaDbEntry.getNextSerial();
            if(nextSerial < 0)
            {
                nextSerial = 0;
            }
            ps.setLong(idx++, nextSerial);

            ps.setString(idx++, newCaDbEntry.getStatus().getStatus());
            ps.setString(idx++, newCaDbEntry.getCrlUrisAsString());
            ps.setString(idx++, newCaDbEntry.getOcspUrisAsString());
            ps.setInt(idx++, newCaDbEntry.getMaxValidity());
            ps.setString(idx++, Base64.toBase64String(newCaDbEntry.getCertificate().getEncodedCert()));
            ps.setString(idx++, newCaDbEntry.getSignerType());
            ps.setString(idx++, newCaDbEntry.getSignerConf());
            ps.setString(idx++, newCaDbEntry.getCrlSignerName());
            ps.setInt(idx++, newCaDbEntry.getDuplicateKeyMode().getMode());
            ps.setInt(idx++, newCaDbEntry.getDuplicateSubjectMode().getMode());
            ps.setString(idx++, Permission.toString(newCaDbEntry.getPermissions()));
            ps.setInt(idx++, newCaDbEntry.getNumCrls());
            ps.setInt(idx++, newCaDbEntry.getExpirationPeriod());

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        cas.put(newCaDbEntry.getName(), newCaDbEntry);
    }

    @Override
    public CAEntry getCA(String caName)
    {
        return cas.get(caName);
    }

    @Override
    public void changeCA(String name, CAStatus status, Long nextSerial,
            X509Certificate cert,
            Set<String> crl_uris, Set<String> ocsp_uris,
            Integer max_validity, String signer_type, String signer_conf,
            String crlsigner_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod)
    throws CAMgmtException
    {
        if(nextSerial != null && nextSerial > 0) // 0 for random serial
        {
            if(cas.containsKey(name) == false)
            {
                throw new CAMgmtException("Could not find CA named " + name);
            }

            CAEntry caEntry = cas.get(name);
            if(caEntry.getNextSerial() > nextSerial + 1) // 1 as buffer
            {
                throw new CAMgmtException("the nextSerial " + nextSerial + " is not allowed");
            }
        }

        if(nextSerial != null && nextSerial < 0)
        {
            nextSerial = 0L;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("UPDATE CA SET ");

        int i = 1;

        Integer iStatus = null;
        if(status != null)
        {
            sb.append("STATUS=?,");
            iStatus = i++;
        }

        Integer iNext_serial = null;
        if(nextSerial != null)
        {
            sb.append("NEXT_SERIAL=?,");
            iNext_serial = i++;
        }

        Integer iSubject = null;
        Integer iCert = null;
        if(cert != null)
        {
            sb.append("SUBJECT=?,");
            iSubject = i++;

            sb.append("CERT=?,");
            iCert = i++;
        }

        Integer iCrl_uris = null;
        if(crl_uris != null)
        {
            sb.append("CRL_URIS=?,");
            iCrl_uris = i++;
        }

        Integer iOcsp_uris = null;
        if(ocsp_uris != null)
        {
            sb.append("OCSP_URIS=?,");
            iOcsp_uris = i++;
        }

        Integer iMax_validity = null;
        if(max_validity != null)
        {
            sb.append("MAX_VALIDITY=?,");
            iMax_validity = i++;
        }

        Integer iSigner_type = null;
        if(signer_type != null)
        {
            sb.append("SIGNER_TYPE=?,");
            iSigner_type = i++;
        }

        Integer iSigner_conf = null;
        if(signer_conf != null)
        {
            sb.append("SIGNER_CONF=?,");
            iSigner_conf = i++;
        }

        Integer iCrlsigner_name = null;
        if(crlsigner_name != null)
        {
            sb.append("CRLSIGNER_NAME=?,");
            iCrlsigner_name = i++;
        }

        Integer iDuplicate_key = null;
        if(duplicate_key != null)
        {
            sb.append("DUPLICATE_KEY_MODE=?,");
            iDuplicate_key = i++;
        }

        Integer iDuplicate_subject = null;
        if(duplicate_subject != null)
        {
            sb.append("DUPLICATE_SUBJECT_MODE=?,");
            iDuplicate_subject = i++;
        }

        Integer iPermissions = null;
        if(permissions != null)
        {
            sb.append("PERMISSIONS=?,");
            iPermissions = i++;
        }

        Integer iNum_crls = null;
        if(numCrls != null)
        {
            sb.append("NUM_CRLS=?,");
            iNum_crls = i++;
        }

        Integer iExpiration_period = null;
        if(expirationPeriod != null)
        {
            sb.append("EXPIRATION_PERIOD=?,");
            iExpiration_period = i++;
        }

        // delete the last ','
        sb.deleteCharAt(sb.length() - 1);
        sb.append(" WHERE NAME=?");

        if(i == 1)
        {
            return;
        }
        int iName = i;

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sb.toString());

            if(iStatus != null)
            {
                ps.setString(iStatus, status.name());
            }

            if(iNext_serial != null)
            {
                ps.setLong(iNext_serial, nextSerial.longValue());
            }

            if(iCert != null)
            {
                ps.setString(iSubject, IoCertUtil.canonicalizeName(cert.getSubjectX500Principal()));

                String base64Cert = Base64.toBase64String(cert.getEncoded());
                ps.setString(iCert, base64Cert);
            }

            if(iCrl_uris != null)
            {
                ps.setString(iCrl_uris, toString(crl_uris, ","));
            }

            if(iOcsp_uris != null)
            {
                ps.setString(iOcsp_uris, toString(ocsp_uris, ","));
            }

            if(iMax_validity != null)
            {
                ps.setInt(iMax_validity, max_validity);
            }

            if(iSigner_type != null)
            {
                ps.setString(iSigner_type, signer_type);
            }

            if(iSigner_conf != null)
            {
                ps.setString(iSigner_conf, signer_conf);
            }

            if(iCrlsigner_name != null)
            {
                ps.setString(iCrlsigner_name, getRealString(crlsigner_name));
            }

            if(iDuplicate_key != null)
            {
                ps.setInt(iDuplicate_key, duplicate_key.getMode());
            }

            if(iDuplicate_subject != null)
            {
                ps.setInt(iDuplicate_subject, duplicate_subject.getMode());
            }

            if(iPermissions != null)
            {
                ps.setString(iPermissions, Permission.toString(permissions));
            }

            if(iNum_crls != null)
            {
                ps.setInt(iNum_crls, numCrls);
            }

            if(iExpiration_period != null)
            {
                ps.setInt(iExpiration_period, expirationPeriod);
            }

            ps.setString(iName, name);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        } catch (CertificateEncodingException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public void setCANextSerial(String caName, long nextSerial)
    throws CAMgmtException
    {
        CAEntry caInfo = cas.get(caName);
        if(caInfo == null)
        {
            throw new CAMgmtException("Could not find CA named " + caName);
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("UPDATE CA SET NEXT_SERIAL=? WHERE NAME=?");
            ps.setLong(1, nextSerial);
            ps.setString(2, caName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public void removeCertProfileFromCA(String profileName, String caName)
    throws CAMgmtException
    {
        Set<String> profileNames = ca_has_profiles.get(caName);

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("DELETE FROM CA_HAS_CERTPROFILE WHERE CA_NAME=? AND CERTPROFILE_NAME=?");
            ps.setString(1, caName);
            ps.setString(2, profileName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        if(profileNames != null)
        {
            profileNames.remove(profileName);
        }
    }

    @Override
    public void addCertProfileToCA(String profileName, String caName)
    throws CAMgmtException
    {
        Set<String> profileNames = ca_has_profiles.get(caName);
        if(profileNames == null)
        {
            profileNames = new HashSet<>();
            ca_has_profiles.put(caName, profileNames);
        }
        else
        {
            if(profileNames.contains(profileName))
            {
                return;
            }
        }
        profileNames.add(profileName);

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO CA_HAS_CERTPROFILE (CA_NAME, CERTPROFILE_NAME) VALUES (?, ?)");
            ps.setString(1, caName);
            ps.setString(2, profileName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public void removePublisherFromCA(String publisherName, String caName)
    throws CAMgmtException
    {
        Set<String> publisherNames = ca_has_publishers.get(caName);
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("DELETE FROM CA_HAS_PUBLISHER WHERE CA_NAME=? AND PUBLISHER_NAME=?");
            ps.setString(1, caName);
            ps.setString(2, publisherName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        if(publisherNames != null)
        {
            publisherNames.remove(publisherName);
        }
    }

    @Override
    public void addPublisherToCA(String publisherName, String caName)
    throws CAMgmtException
    {
        Set<String> publisherNames = ca_has_publishers.get(caName);
        if(publisherNames == null)
        {
            publisherNames = new HashSet<>();
            ca_has_publishers.put(caName, publisherNames);
        }
        else
        {
            if(publisherNames.contains(publisherName))
            {
                return;
            }
        }
        publisherNames.add(publisherName);

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO CA_HAS_PUBLISHER (CA_NAME, PUBLISHER_NAME) VALUES (?, ?)");
            ps.setString(1, caName);
            ps.setString(2, publisherName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public Set<String> getCertProfilesForCA(String caName)
    {
        return ca_has_profiles.get(caName);
    }

    @Override
    public Set<CAHasRequestorEntry> getCmpRequestorsForCA(String caName)
    {
        return ca_has_requestors.get(caName);
    }

    @Override
    public CmpRequestorEntry getCmpRequestor(String name)
    {
        return requestors.get(name);
    }

    @Override
    public void addCmpRequestor(CmpRequestorEntry dbEntry)
    throws CAMgmtException
    {
        String name = dbEntry.getName();
        if(requestors.containsKey(name))
        {
            throw new CAMgmtException("CMP requestor named " + name + " exists");
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO REQUESTOR (NAME, CERT) VALUES (?, ?)");
            int idx = 1;
            ps.setString(idx++, name);
            ps.setString(idx++, Base64.toBase64String(dbEntry.getCert().getEncoded()));

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        } catch (CertificateEncodingException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        requestors.put(name, dbEntry);
    }

    @Override
    public void removeCmpRequestor(String requestorName)
    throws CAMgmtException
    {
        for(String caName : ca_has_requestors.keySet())
        {
            removeCmpRequestorFromCA(requestorName, caName);
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("DELETE FROM REQUESTOR WHERE NAME=?");
            ps.setString(1, requestorName);
            int rows = ps.executeUpdate();
            if(rows != 1)
            {
                throw new CAMgmtException("Could not remove cmpRequestor " + requestorName);
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        requestors.remove(requestorName);
    }

    @Override
    public void changeCmpRequestor(String name, String cert)
    throws CAMgmtException
    {
        if(cert == null)
        {
            return;
        }

        String sql = "UPDATE REQUESTOR SET CERT=? WHERE NAME=?";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, getRealString(cert));
            ps.setString(2, name);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public void removeCmpRequestorFromCA(String requestorName, String caName)
    throws CAMgmtException
    {
        Set<CAHasRequestorEntry> requestors = ca_has_requestors.get(caName);
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("DELETE FROM CA_HAS_REQUESTOR WHERE CA_NAME=? AND REQUESTOR_NAME=?");
            ps.setString(1, caName);
            ps.setString(2, requestorName);
            ps.executeUpdate();

            if(requestors != null)
            {
                requestors.remove(requestorName);
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public void addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
    throws CAMgmtException
    {
        String requestorName = requestor.getRequestorName();
        Set<CAHasRequestorEntry> cmpRequestors = ca_has_requestors.get(caName);
        if(cmpRequestors == null)
        {
            cmpRequestors = new HashSet<>();
            ca_has_requestors.put(caName, cmpRequestors);
        }
        else
        {
            boolean foundEntry = false;
            for(CAHasRequestorEntry entry : cmpRequestors)
            {
                if(entry.getRequestorName().equals(requestorName))
                {
                    foundEntry = true;
                    break;
                }
            }

            // already added
            if(foundEntry)
            {
                throw new CAMgmtException("ca_has_requestor with CANAME=" + caName +
                        " and REQUESTOR_NAME="+ requestorName + " exists");
            }
        }

        cmpRequestors.add(requestor);

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO CA_HAS_REQUESTOR "
                    + "(CA_NAME, REQUESTOR_NAME, RA, PERMISSIONS, PROFILES) VALUES (?, ?, ?, ?, ?)");
            int idx = 1;
            ps.setString(idx++, caName);
            ps.setString(idx++, requestorName);
            setBoolean(ps, idx++, requestor.isRa());
            ps.setString(idx++, Permission.toString(requestor.getPermissions()));

            Set<String> profiles = requestor.getProfiles();
            ps.setString(idx++, toString(profiles, ","));

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

    }

    @Override
    public CertProfileEntry getCertProfile(String profileName)
    {
        return certProfiles.get(profileName);
    }

    @Override
    public void removeCertProfile(String profileName)
    throws CAMgmtException
    {
        for(String caName : ca_has_profiles.keySet())
        {
            removeCertProfileFromCA(profileName, caName);
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("DELETE FROM CERTPROFILE WHERE NAME=?");
            ps.setString(1, profileName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        certProfiles.remove(profileName);
    }

    @Override
    public void changeCertProfile(String name, String type, String conf)
    throws CAMgmtException
    {
        if(type == null && conf == null)
        {
            throw new IllegalArgumentException("at least one of type and conf should not be null");
        }
        assertNotNULL("type", type);

        StringBuilder sb = new StringBuilder();
        sb.append("UPDATE CERTPROFILE SET ");

        Integer iType = null;
        Integer iConf = null;

        int i = 1;
        if(type != null)
        {
            sb.append("TYPE=?,");
            iType = i++;
        }
        if(conf != null)
        {
            sb.append("CONF=?,");
            iConf = i++;
        }

        sb.deleteCharAt(sb.length() - 1);
        sb.append(" WHERE NAME=?");

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sb.toString());
            if(iType != null)
            {
                ps.setString(iType, type);
            }

            if(iConf != null)
            {
                ps.setString(iConf, getRealString(conf));
            }

            ps.setString(i, name);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public void addCertProfile(CertProfileEntry dbEntry)
    throws CAMgmtException
    {
        String name = dbEntry.getName();
        if(certProfiles.containsKey(name))
        {
            throw new CAMgmtException("CertProfile named " + name + " exists");
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO CERTPROFILE (NAME, TYPE, CONF) VALUES (?, ?, ?)");
            ps.setString(1, name);
            ps.setString(2, dbEntry.getType());
            String conf = dbEntry.getConf();
            ps.setString(3, conf);

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        dbEntry.setEnvironmentParamterResolver(envParameterResolver);
        certProfiles.put(name, dbEntry);
    }

    @Override
    public void setCmpResponder(CmpResponderEntry dbEntry)
    throws CAMgmtException
    {
        if(responder != null)
        {
            removeCmpResponder();
        }

        responder = dbEntry;

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO RESPONDER (NAME, TYPE, CONF, CERT) VALUES (?, ?, ?, ?)");
            int idx = 1;
            ps.setString(idx++, CmpResponderEntry.name);
            ps.setString(idx++, dbEntry.getType());
            ps.setString(idx++, dbEntry.getConf());

            String b64Cert = null;
            X509Certificate cert = dbEntry.getCertificate();
            if(cert != null)
            {
                b64Cert = Base64.toBase64String(dbEntry.getCertificate().getEncoded());
            }
            ps.setString(idx++, b64Cert);

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        } catch (CertificateEncodingException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public void removeCmpResponder()
    throws CAMgmtException
    {
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            stmt.execute("DELETE FROM responder");
        } catch (SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(stmt, null);
        }

        responder = null;
    }

    @Override
    public void changeCmpResponder(String type, String conf, String cert)
    throws CAMgmtException
    {
        if(type == null && conf == null && cert == null)
        {
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("UPDATE RESPONDER SET ");

        Integer iType = null;
        Integer iConf = null;
        Integer iCert = null;

        int i = 1;
        if(type != null)
        {
            sb.append("TYPE=?,");
            iType = i++;
        }
        if(conf != null)
        {
            sb.append("CONF=?,");
            iConf = i++;
        }
        if(cert != null)
        {
            sb.append("CERT=?,");
            iCert = i++;
        }

        sb.deleteCharAt(sb.length() - 1);
        sb.append(" WHERE NAME=?");

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sb.toString());
            if(iType != null)
            {
                ps.setString(iType, getRealString(type));
            }

            if(iConf != null)
            {
                ps.setString(iConf, getRealString(conf));
            }

            if(iCert != null)
            {
                ps.setString(iCert, getRealString(cert));
            }
            ps.setString(i, CmpResponderEntry.name);

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public CmpResponderEntry getCmpResponder()
    {
        return responder;
    }

    @Override
    public void addCrlSigner(CrlSignerEntry dbEntry)
    throws CAMgmtException
    {
        String name = dbEntry.getName();
        if(crlSigners.containsKey(name))
        {
            throw new CAMgmtException("CRL signer named " + name + " exists");
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(
                    "INSERT INTO CRLSIGNER (NAME, SIGNER_TYPE, SIGNER_CONF, SIGNER_CERT,"
                    + " PERIOD, OVERLAP, INCLUDE_CERTS_IN_CRL, INCLUDE_EXPIRED_CERTS)"
                    + " VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            int idx = 1;
            ps.setString(idx++, name);
            ps.setString(idx++, dbEntry.getType());
            ps.setString(idx++, dbEntry.getConf());
            ps.setString(idx++, dbEntry.getCertificate() == null ? null :
                    Base64.toBase64String(dbEntry.getCertificate().getEncoded()));
            ps.setInt(idx++, dbEntry.getPeriod());
            ps.setInt(idx++, dbEntry.getOverlap());
            setBoolean(ps, idx++, dbEntry.includeCertsInCRL());
            setBoolean(ps, idx++, dbEntry.includeExpiredCerts());

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        } catch (CertificateEncodingException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        crlSigners.put(name, dbEntry);
    }

    @Override
    public void removeCrlSigner(String crlSignerName)
    throws CAMgmtException
    {
        for(String caName : cas.keySet())
        {
            CAEntry caInfo = cas.get(caName);
            if(crlSignerName.equals(caInfo.getCrlSignerName()))
            {
                setCrlSignerInCA(null, caName);
            }
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("DELETE FROM CRLSIGNER WHERE NAME=?");
            ps.setString(1, crlSignerName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        crlSigners.remove(crlSignerName);
    }

    @Override
    public void changeCrlSigner(String name, String signer_type, String signer_conf, String signer_cert,
            Integer period, Integer overlap, Boolean includeCerts, Boolean includeExpiredCerts)
    throws CAMgmtException
    {
        StringBuilder sb = new StringBuilder();
        sb.append("UPDATE CRLSIGNER SET ");

        int i = 1;

        Integer iSigner_type = null;
        if(signer_type != null)
        {
            sb.append("SIGNER_TYPE=?,");
            iSigner_type = i++;
        }

        Integer iSigner_conf = null;
        if(signer_conf != null)
        {
            sb.append("SIGNER_CONF=?,");
            iSigner_conf = i++;
        }

        Integer iSigner_cert = null;
        if(signer_cert != null)
        {
            sb.append("SIGNER_CERT=?,");
            iSigner_cert = i++;
        }

        Integer iPeriod = null;
        if(period != null)
        {
            sb.append("PERIOD=?,");
            iPeriod = i++;
        }

        Integer iOverlap = null;
        if(overlap != null)
        {
            sb.append("OVERLAP=?,");
            iOverlap = i++;
        }

        Integer iIncludeCerts = null;
        if(includeCerts != null)
        {
            sb.append("INCLUDE_CERTS_IN_CRL=?,");
            iIncludeCerts = i++;
        }

        Integer iIncludeExpiredCerts = null;
        if(includeExpiredCerts != null)
        {
            sb.append("INCLUDE_EXPIRED_CERTS=?,");
            iIncludeExpiredCerts = i++;
        }

        sb.deleteCharAt(sb.length() - 1);
        sb.append(" WHERE NAME=?");

        if(i == 1)
        {
            return;
        }
        int iName = i;

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sb.toString());

            if(iSigner_type != null)
            {
                ps.setString(iSigner_type, signer_type);
            }

            if(iSigner_conf != null)
            {
                ps.setString(iSigner_conf, getRealString(signer_conf));
            }

            if(iSigner_cert != null)
            {
                ps.setString(iSigner_cert, getRealString(signer_cert));
            }

            if(iPeriod != null)
            {
                ps.setInt(iPeriod, period);
            }

            if(iOverlap != null)
            {
                ps.setInt(iPeriod, overlap);
            }

            if(iIncludeCerts != null)
            {
                setBoolean(ps, iIncludeCerts, includeCerts);
            }

            if(iIncludeExpiredCerts != null)
            {
                setBoolean(ps, iIncludeExpiredCerts, includeExpiredCerts);
            }

            ps.setString(iName, name);

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public CrlSignerEntry getCrlSigner(String name)
    {
        return crlSigners.get(name);
    }

    @Override
    public void setCrlSignerInCA(String crlSignerName, String caName)
    throws CAMgmtException
    {
        CAEntry caInfo = cas.get(caName);
        if(caInfo == null)
        {
            throw new CAMgmtException("Unknown CA " + caName);
        }

        String oldCrlSignerName = caInfo.getCrlSignerName();
        if(oldCrlSignerName == crlSignerName)
        {
            return;
        }

        if(crlSignerName != null && !crlSigners.containsKey(crlSignerName))
        {
            throw new CAMgmtException("Unknown CRL signer " + crlSignerName);
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("UPDATE CA SET CRLSIGNER_NAME=? WHERE NAME=?");
            ps.setString(1, crlSignerName);
            ps.setString(2, caName);

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public void addPublisher(PublisherEntry dbEntry)
    throws CAMgmtException
    {
        String name = dbEntry.getName();
        if(publishers.containsKey(name))
        {
            throw new CAMgmtException("Publisher named " + name + " exists");
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO PUBLISHER (NAME, TYPE, CONF) VALUES (?, ?, ?)");
            ps.setString(1, name);
            ps.setString(2, dbEntry.getType());
            String conf = dbEntry.getConf();
            ps.setString(3, conf);

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        dbEntry.setPasswordResolver(passwordResolver);

        publishers.put(name, dbEntry);
    }

    @Override
    public List<PublisherEntry> getPublishersForCA(String caName)
    {
        ParamChecker.assertNotEmpty("caName", caName);

        Set<String> publisherNames = ca_has_publishers.get(caName);
        if(publisherNames == null)
        {
            return Collections.emptyList();
        }

        List<PublisherEntry> ret = new ArrayList<>(publisherNames.size());
        for(String publisherName : publisherNames)
        {
            ret.add(publishers.get(publisherName));
        }

        return ret;
    }

    @Override
    public PublisherEntry getPublisher(String publisherName)
    {
        return publishers.get(publisherName);
    }

    @Override
    public void removePublisher(String publisherName)
    throws CAMgmtException
    {
        for(String caName : ca_has_publishers.keySet())
        {
            removePublisherFromCA(publisherName, caName);
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("DELETE FROM PUBLISHER WHERE NAME=?");
            ps.setString(1, publisherName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        publishers.remove(publisherName);
    }

    @Override
    public void changePublisher(String name, String type, String conf)
    throws CAMgmtException
    {
        StringBuilder sb = new StringBuilder();
        sb.append("UPDATE PUBLISHER SET ");

        Integer iType = null;
        Integer iConf = null;

        int i = 1;
        if(type != null)
        {
            sb.append("TYPE=?,");
            iType = i++;
        }
        if(conf != null)
        {
            sb.append("CONF=?,");
            iConf = i++;
        }

        sb.deleteCharAt(sb.length() - 1);
        sb.append(" WHERE NAME=?");

        if(i == 1)
        {
            return;
        }
        int iName = i;

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sb.toString());
            if(iType != null)
            {
                ps.setString(iType, getRealString(type));
            }

            if(iConf != null)
            {
                ps.setString(iConf, getRealString(conf));
            }

            ps.setString(iName, name);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public CmpControl getCmpControl()
    {
        return cmpControl;
    }

    @Override
    public void setCmpControl(CmpControl dbEntry)
    throws CAMgmtException
    {
        if(cmpControl != null)
        {
            removeCmpControl();
        }

        cmpControl = dbEntry;

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(
                    "INSERT INTO CMPCONTROL (NAME, REQUIRE_CONFIRM_CERT, SEND_CA_CERT, SEND_RESPONDER_CERT,"
                    + " REQUIRE_MESSAGE_TIME, MESSAGE_TIME_BIAS, CONFIRM_WAIT_TIME)"
                    + " VALUES (?, ?, ?, ?, ?, ?, ?)");

            int idx = 1;
            ps.setString(idx++, CmpControl.name);
            setBoolean(ps, idx++, dbEntry.isRequireConfirmCert());
            setBoolean(ps, idx++, dbEntry.isSendCaCert());
            setBoolean(ps, idx++, dbEntry.isSendResponderCert());
            setBoolean(ps, idx++, dbEntry.isMessageTimeRequired());
            ps.setInt(idx++, dbEntry.getMessageTimeBias());
            ps.setInt(idx++, dbEntry.getConfirmWaitTime());

            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public void removeCmpControl()
    throws CAMgmtException
    {
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            stmt.execute("DELETE FROM CMPCONTROL");
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(stmt, null);
        }

        cmpControl = null;
    }

    @Override
    public void changeCmpControl(Boolean requireConfirmCert,
            Boolean requireMessageTime, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert, Boolean sendResponderCert)
    throws CAMgmtException
    {
        if(requireConfirmCert == null && requireMessageTime == null && messageTimeBias == null
                && confirmWaitTime == null && sendCaCert == null && sendResponderCert == null)
        {
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("UPDATE CMPCONTROL SET ");

        Integer iConfirmCert = null;

        int i = 1;
        if(requireConfirmCert != null)
        {
            sb.append("REQUIRE_CONFIRM_CERT=?,");
            iConfirmCert = i++;
        }

        Integer iRequireMessageTime = null;
        if(requireMessageTime != null)
        {
            sb.append("REQUIRE_MESSAGE_TIME=?,");
            iRequireMessageTime = i++;
        }

        Integer iMessageTimeBias = null;
        if(messageTimeBias != null)
        {
            sb.append("MESSAGE_TIME_BIAS=?,");
            iMessageTimeBias = i++;
        }

        Integer iConfirmWaitTime = null;
        if(confirmWaitTime != null)
        {
            sb.append("CONFIRM_WAIT_TIME=?,");
            iConfirmWaitTime = i++;
        }

        Integer iSendCaCert = null;
        if(sendCaCert != null)
        {
            sb.append("SEND_CA_CERT=?,");
            iSendCaCert = i++;
        }

        Integer iSendResponderCert = null;
        if(sendResponderCert != null)
        {
            sb.append("SEND_RESPONDER_CERT=?,");
            iSendResponderCert = i++;
        }

        sb.deleteCharAt(sb.length() - 1);
        sb.append(" WHERE NAME=?");

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sb.toString());
            if(iConfirmCert != null)
            {
                setBoolean(ps, iConfirmCert, requireConfirmCert);
            }

            if(iRequireMessageTime != null)
            {
                setBoolean(ps, iRequireMessageTime, requireMessageTime);
            }

            if(iMessageTimeBias != null)
            {
                ps.setInt(iMessageTimeBias, messageTimeBias);
            }

            if(iConfirmWaitTime != null)
            {
                ps.setInt(iConfirmWaitTime, confirmWaitTime);
            }

            if(iSendCaCert != null)
            {
                setBoolean(ps, iSendCaCert, sendCaCert);
            }

            if(iSendResponderCert != null)
            {
                setBoolean(ps, iSendResponderCert, sendResponderCert);
            }

            ps.setString(i, "default");
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public EnvironmentParameterResolver getEnvParameterResolver()
    {
        return envParameterResolver;
    }

    @Override
    public void addEnvParam(String name, String value)
    throws CAMgmtException
    {
        if(envParameterResolver.getEnvParam(name) != null)
        {
            throw new CAMgmtException("Environemt parameter named " + name + " exists");
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO ENVIRONMENT (NAME, VALUE2) VALUES (?, ?)");
            ps.setString(1, name);
            ps.setString(2, value);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        envParameterResolver.addEnvParam(name, value);
    }

    @Override
    public void removeEnvParam(String envParamName)
    throws CAMgmtException
    {
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("DELETE FROM ENVIRONMENT WHERE NAME=?");
            ps.setString(1, envParamName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        envParameterResolver.removeEnvParam(envParamName);
    }

    @Override
    public void changeEnvParam(String name, String value)
    throws CAMgmtException
    {
        ParamChecker.assertNotEmpty("name", name);
        assertNotNULL("value", value);

        if(envParameterResolver.getAllParameterNames().contains(name) == false)
        {
            throw new CAMgmtException("Could not find environment paramter " + name);
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("UPDATE ENVIRONMENT SET VALUE2=? WHERE NAME=?");
            ps.setString(1, getRealString(value));
            ps.setString(2, name);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    static List<String> tokensAsList(String tokens, String seperator)
    {
        StringTokenizer st = new StringTokenizer(tokens, seperator);
        List<String> ret = new ArrayList<>(st.countTokens());
        while(st.hasMoreTokens())
        {
            ret.add(st.nextToken());
        }
        return ret;
    }

    private static String toString(Set<String> tokens, String seperator)
    {
        if(tokens == null || tokens.isEmpty())
        {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        for(String token : tokens)
        {
            sb.append(seperator);
            sb.append(token);
        }
        return sb.substring(seperator.length()); // remove the leading seperator
    }

    public static Set<Permission> getPermissions(String permissionsText)
    throws CAMgmtException
    {
        ParamChecker.assertNotEmpty("permissionsText", permissionsText);

        List<String> l = tokensAsList(permissionsText, ", ");
        Set<Permission> permissions = new HashSet<>();
        for(String permissionText : l)
        {
            Permission p = Permission.getPermission(permissionText);
            if(p == null)
            {
                throw new CAMgmtException("Unknown permission " + permissionText);
            }
            if(p == Permission.ALL)
            {
                permissions.clear();
                permissions.add(p);
                break;
            }
            else
            {
                permissions.add(p);
            }
        }

        return permissions;
    }

    public PasswordResolver getPasswordResolver()
    {
        return passwordResolver;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

    private static String getRealString(String s)
    {
        return NULL.equalsIgnoreCase(s) ? null : s;
    }

    public SecurityFactory getSecurityFactory()
    {
        return securityFactory;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    public DataSourceFactory getDataSourceFactory()
    {
        return dataSourceFactory;
    }

    public void setDataSourceFactory(DataSourceFactory dataSourceFactory)
    {
        this.dataSourceFactory = dataSourceFactory;
    }

    public String getCaConfFile()
    {
        return caConfFile;
    }

    public void setCaConfFile(String caConfFile)
    {
        this.caConfFile = caConfFile;

    }

    @Override
    public void addCaAlias(String aliasName, String caName)
    throws CAMgmtException
    {
        if(caAliases.get(aliasName) != null)
        {
            throw new CAMgmtException("CA alias " + aliasName + " exists");
        }

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("INSERT INTO CAALIAS (NAME, CA_NAME) VALUES (?, ?)");
            ps.setString(1, aliasName);
            ps.setString(2, caName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        caAliases.put(aliasName, caName);
    }

    @Override
    public void removeCaAlias(String aliasName)
    throws CAMgmtException
    {
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("DELETE FROM CAALIAS WHERE NAME=?");
            ps.setString(1, aliasName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        caAliases.remove(aliasName);
    }

    @Override
    public String getCaName(String aliasName)
    {
        return caAliases.get(aliasName);
    }

    @Override
    public String getAliasName(String caName)
    {
        for(String alias : caAliases.keySet())
        {
            String thisCaName = caAliases.get(alias);
            if(thisCaName.equals(caName))
            {
                return alias;
            }
        }

        return null;
    }

    @Override
    public Set<String> getCaAliasNames()
    {
        return caAliases.keySet();
    }

    @Override
    public void removeCA(String caName)
    throws CAMgmtException
    {
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("DELETE FROM CA WHERE NAME=?");
            ps.setString(1, caName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        cas.remove(caName);
    }

    @Override
    public void publishRootCA(String caName, String certprofile)
    throws CAMgmtException
    {
        X509CA ca = x509cas.get(caName);
        if(ca == null)
        {
            throw new CAMgmtException("Cannot find CA named " + caName);
        }

        X509CertificateWithMetaInfo certInfo = ca.getCAInfo().getCertificate();
        if(certInfo.getCert().getSubjectX500Principal().equals(
                certInfo.getCert().getIssuerX500Principal()) == false)
        {
            throw new CAMgmtException("CA named " + caName + " is not a self-signed CA");
        }

        byte[] encodedSubjectPublicKey = certInfo.getCert().getPublicKey().getEncoded();
        CertificateInfo ci;
        try
        {
            ci = new CertificateInfo(
                    certInfo, certInfo, encodedSubjectPublicKey,
                    certprofile == null ? "UNKNOWN" : certprofile);
        } catch (CertificateEncodingException e)
        {
            throw new CAMgmtException(e);
        }
        ca.publishCertificate(ci);
    }

    private static void assertNotNULL(String parameterName, String parameterValue)
    {
        if(NULL.equalsIgnoreCase(parameterValue))
        {
            throw new IllegalArgumentException(parameterName + " could not be " + NULL);
        }
    }

    private Statement createStatement()
    throws CAMgmtException
    {
        Connection dsConnection;
        try
        {
            dsConnection = dataSource.getConnection();
        } catch (SQLException e)
        {
            throw new CAMgmtException("Could not get connection", e);
        }

        try
        {
           return dataSource.createStatement(dsConnection);
        }catch(SQLException e)
        {
            throw new CAMgmtException("Could not create statement", e);
        }
    }

    private PreparedStatement prepareStatement(String sql)
    throws CAMgmtException
    {
        Connection dsConnection;
        try
        {
            dsConnection = dataSource.getConnection();
        } catch (SQLException e)
        {
            throw new CAMgmtException("Could not get connection", e);
        }

        try
        {
            return dataSource.prepareStatement(dsConnection, sql);
        }catch(SQLException e)
        {
            throw new CAMgmtException("Could not get connection", e);
        }
    }

    @Override
    public boolean republishCertificates(String caName, List<String> publisherNames)
    throws CAMgmtException
    {
        Set<String> caNames;
        if(caName == null)
        {
            caNames = x509cas.keySet();
        }
        else
        {
            caNames = new HashSet<>();
            caNames.add(caName);
        }

        for(String name : caNames)
        {
            X509CA ca = x509cas.get(name);
            if(ca == null)
            {
                throw new CAMgmtException("Cannot find CA named " + name);
            }

            boolean successfull = ca.republishCertificates(publisherNames);
            if(successfull == false)
            {
                throw new CAMgmtException("Republishing certificates to CA " + name + " failed");
            }
        }

        return true;
    }

    @Override
    public void revokeCa(String caName, CertRevocationInfo revocationInfo)
    throws CAMgmtException
    {
        ParamChecker.assertNotEmpty("caName", caName);
        ParamChecker.assertNotNull("revocationInfo", revocationInfo);
        if(x509cas.containsKey(caName) == false)
        {
            throw new CAMgmtException("Could not find CA named " + caName);
        }

        LOG.info("Revoking CA {}", caName);
        X509CA ca = x509cas.get(caName);

        CRLReason currentReason = null;
        CertRevocationInfo currentRevInfo = ca.getCAInfo().getRevocationInfo();
        if(currentRevInfo != null)
        {
            currentReason = currentRevInfo.getReason();
        }

        PreparedStatement ps = null;
        try
        {
            if(currentReason == CRLReason.CERTIFICATE_HOLD || currentReason == CRLReason.SUPERSEDED)
            {
                String sql = "UPDATE CA SET REV_REASON=? WHERE NAME=?";
                ps = prepareStatement(sql);
                int i = 1;
                ps.setInt(i++, revocationInfo.getReason().getCode());
                ps.setString(i++, caName);
                ps.executeUpdate();

                revocationInfo.setRevocationTime(currentRevInfo.getRevocationTime());
                revocationInfo.setInvalidityTime(currentRevInfo.getInvalidityTime());
            }
            else
            {
                if(revocationInfo.getInvalidityTime() == null)
                {
                    revocationInfo.setInvalidityTime(revocationInfo.getRevocationTime());
                }

                String sql = "UPDATE CA SET REVOKED=?, REV_REASON=?, REV_TIME=?, REV_INVALIDITY_TIME=? WHERE NAME=?";
                ps = prepareStatement(sql);
                int i = 1;
                setBoolean(ps, i++, true);
                ps.setInt(i++, revocationInfo.getReason().getCode());
                ps.setLong(i++, revocationInfo.getRevocationTime().getTime() / 1000);
                ps.setLong(i++, revocationInfo.getInvalidityTime().getTime() / 1000);
                ps.setString(i++, caName);
                ps.executeUpdate();
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        try
        {
            ca.revoke(revocationInfo);
        } catch (OperationException e)
        {
            throw new CAMgmtException("Error while revoking CA " + e.getMessage(), e);
        }
        LOG.info("Revoked CA {}", caName);

        auditLogPCIEvent(true, "REVOKE CA " + caName);
    }

    @Override
    public void unrevokeCa(String caName)
    throws CAMgmtException
    {
        ParamChecker.assertNotEmpty("caName", caName);
        if(x509cas.containsKey(caName) == false)
        {
            throw new CAMgmtException("Could not find CA named " + caName);
        }

        LOG.info("Unrevoking of CA {}", caName);

        String sql = "UPDATE CA SET REVOKED=?, REV_REASON, REV_TIME=?, REV_INVALIDITY_TIME=? WHERE NAME=?";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            int i = 1;
            setBoolean(ps, i++, false);
            ps.setNull(i++, Types.INTEGER);
            ps.setNull(i++, Types.INTEGER);
            ps.setNull(i++, Types.INTEGER);
            ps.setString(i++, caName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            throw new CAMgmtException(e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        X509CA ca = x509cas.get(caName);
        try
        {
            ca.unrevoke();
        } catch (OperationException e)
        {
            throw new CAMgmtException("Error while unrevoking of CA " + e.getMessage(), e);
        }
        LOG.info("Unrevoked CA {}", caName);

        auditLogPCIEvent(true, "UNREVOKE CA " + caName);
    }

    public AuditLoggingService getAuditLoggingService()
    {
        return auditLoggingService;
    }

    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        this.auditLoggingService = auditLoggingService;

        for(String name : publishers.keySet())
        {
            PublisherEntry publisherEntry = publishers.get(name);
            publisherEntry.setAuditLoggingService(auditLoggingService);
        }
    }

    private void auditLogPCIEvent(boolean successfull, String eventType)
    {
        if(auditLoggingService != null)
        {
            PCIAuditEvent auditEvent = new PCIAuditEvent(new Date());
            auditEvent.setUserId("SYSTEM");
            auditEvent.setEventType(eventType);
            auditEvent.setAffectedResource("CORE");
            if(successfull)
            {
                auditEvent.setStatus(AuditStatus.SUCCSEEFULL.name());
                auditEvent.setLevel(AuditLevel.INFO);
            }
            else
            {
                auditEvent.setStatus(AuditStatus.ERROR.name());
                auditEvent.setLevel(AuditLevel.ERROR);
            }
            auditLoggingService.logEvent(auditEvent);
        }
    }

    @Override
    public boolean clearPublishQueue(String caName, List<String> publisherNames)
    throws CAMgmtException
    {
        if(caName == null)
        {
            try
            {
                certstore.clearPublishQueue((X509CertificateWithMetaInfo) null, (String) null);
                return true;
            } catch (SQLException e)
            {
                throw new CAMgmtException(e);
            }
        }
        else
        {
            X509CA ca = x509cas.get(caName);
            if(ca == null)
            {
                throw new CAMgmtException("Cannot find CA named " + caName);
            }
            return ca.clearPublishQueue(publisherNames);
        }
    }

    private void shutdownScheduledThreadPoolExecutor()
    {
        if(scheduledThreadPoolExecutor != null)
        {
            scheduledThreadPoolExecutor.shutdown();
            while(scheduledThreadPoolExecutor.isTerminated() == false)
            {
                try
                {
                    Thread.sleep(100);
                }catch(InterruptedException e)
                {
                }
            }
            scheduledThreadPoolExecutor = null;
        }
    }

    private class ScheduledPublishQueueCleaner implements Runnable
    {
        private boolean inProcess = false;

        @Override
        public void run()
        {
            if(inProcess || caSystemSetuped == false)
            {
                return;
            }

            inProcess = true;
            try
            {
                LOG.debug("Publishing certificates in PUBLISHQUEUE");
                for(String name : x509cas.keySet())
                {
                    X509CA ca = x509cas.get(name);
                    boolean b = ca.publishCertsInQueue();
                    if(b)
                    {
                        LOG.debug(" Published certificates of CA {} in PUBLISHQUEUE", name);
                    }
                    else
                    {
                        LOG.error("Publishing certificates of CA {} in PUBLISHQUEUE failed", name);
                    }
                }
            }catch(Throwable t)
            {
            }finally
            {
                inProcess = false;
            }
        }
    }

    private static void setBoolean(PreparedStatement ps, int index, boolean b)
    throws SQLException
    {
        ps.setInt(index, b ? 1 : 0);
    }

}
