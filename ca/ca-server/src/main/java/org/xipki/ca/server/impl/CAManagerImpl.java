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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

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
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.PCIAuditEvent;
import org.xipki.ca.api.DfltEnvironmentParameterResolver;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.X509CertWithId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.publisher.X509CertificateInfo;
import org.xipki.ca.server.impl.X509SelfSignedCertBuilder.GenerateSelfSignedResult;
import org.xipki.ca.server.impl.store.CertificateStore;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.ca.server.mgmt.api.CAMgmtException;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.CASystemStatus;
import org.xipki.ca.server.mgmt.api.CRLControl;
import org.xipki.ca.server.mgmt.api.CertArt;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.ca.server.mgmt.api.X509CrlSignerEntry;
import org.xipki.common.CRLReason;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.ConfigurationException;
import org.xipki.common.IoUtil;
import org.xipki.common.LogUtil;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class CAManagerImpl extends BaseCAManager
implements CAManager, CmpResponderManager
{

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
                        LOG.debug(" Published certificates of CA '{}' in PUBLISHQUEUE", name);
                    }
                    else
                    {
                        LOG.error("Publishing certificates of CA '{}' in PUBLISHQUEUE failed", name);
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

    private class ScheduledDeleteCertsInProcessService implements Runnable
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
                    // older than 10 minutes
                    certstore.deleteCertsInProcessOlderThan(new Date(System.currentTimeMillis() - 10 * 60 * 1000L));
                } catch (Throwable t)
                {
                    final String message = "Could not call certstore.deleteCertsInProcessOlderThan";
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

    private class ScheduledCARestarter implements Runnable
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
                Statement stmt = null;
                ResultSet rs = null;

                long caChangedTime = 0;
                try
                {
                    stmt = createStatement();
                    String sql = "SELECT EVENT_TIME FROM SYSTEM_EVENT WHERE NAME='CA_CHANGE'";
                    rs = stmt.executeQuery(sql);

                    if(rs.next())
                    {
                        caChangedTime = rs.getLong("EVENT_TIME");
                    }
                }finally
                {
                    dataSource.releaseResources(stmt, rs);
                }

                if(LOG.isDebugEnabled())
                {
                    LOG.debug("Check the restart CA system event: CA changed at={}, lastStartTime={}",
                            new Date(caChangedTime * 1000L), lastStartTime);
                }

                if(caChangedTime > lastStartTime.getTime() / 1000L)
                {
                    LOG.info("Received event to restart CA");
                    restartCaSystem();
                } else
                {
                    LOG.debug("Received no event to restart CA");
                }
            }catch(Throwable t)
            {
                LOG.error("ScheduledCArestarter: " + t.getMessage(), t);
            }finally
            {
                inProcess = false;
            }
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(CAManagerImpl.class);

    private final String lockInstanceId;

    private CmpResponderEntryWrapper responder;

    private boolean caLockedByMe = false;
    private boolean masterMode = false;

    private Map<String, DataSourceWrapper> dataSources = null;

    private final Map<String, X509CAInfo> caInfos = new ConcurrentHashMap<>();
    private final Map<String, IdentifiedX509Certprofile> certprofiles = new ConcurrentHashMap<>();
    private final Map<String, IdentifiedX509CertPublisher> publishers = new ConcurrentHashMap<>();
    private final Map<String, CmpRequestorEntryWrapper> requestors = new ConcurrentHashMap<>();
    private final Map<String, X509CrlSignerEntryWrapper> crlSigners = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> ca_has_profiles = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> ca_has_publishers = new ConcurrentHashMap<>();
    private final Map<String, Set<CAHasRequestorEntry>> ca_has_requestors = new ConcurrentHashMap<>();
    private final Map<String, String> caAliases = new ConcurrentHashMap<>();

    private final DfltEnvironmentParameterResolver envParameterResolver = new DfltEnvironmentParameterResolver();

    private final Map<String, CmpControl> cmpControls = new ConcurrentHashMap<>();

    private ScheduledThreadPoolExecutor persistentScheduledThreadPoolExecutor;
    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;
    private final Map<String, X509CACmpResponder> responders = new ConcurrentHashMap<>();
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
    private Date lastStartTime;

    private AuditLoggingServiceRegister auditServiceRegister;

    public CAManagerImpl()
    throws ConfigurationException
    {
        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        String calockId = null;
        File caLockFile = new File("calock");
        if(caLockFile.exists())
        {
            try
            {
                calockId = new String(IoUtil.read(caLockFile));
            } catch (IOException e)
            {
            }
        }

        if(calockId == null)
        {
            calockId = UUID.randomUUID().toString();
            try
            {
                IoUtil.save(caLockFile, calockId.getBytes());
            } catch (IOException e)
            {
            }
        }

        String hostAddress = null;
        try
        {
            hostAddress = IoUtil.getHostAddress();
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
        if(dataSourceFactory == null)
        {
            throw new IllegalStateException("dataSourceFactory is not set");
        }
        if(caConfFile == null)
        {
            throw new IllegalStateException("caConfFile is not set");
        }

        Properties caConfProps = new Properties();
        try
        {
            caConfProps.load(new FileInputStream(IoUtil.expandFilepath(caConfFile)));
        } catch (IOException e)
        {
            throw new CAMgmtException("IOException while parsing ca configuration" + caConfFile, e);
        }

        String caModeStr = caConfProps.getProperty("ca.mode");
        if(caModeStr != null)
        {
            if(caModeStr.equalsIgnoreCase("slave"))
            {
                masterMode = false;
            }
            else if(caModeStr.equalsIgnoreCase("master"))
            {
                masterMode = true;
            }
            else
            {
                throw new CAMgmtException("invalid ca.mode '" + caModeStr + "'");
            }
        }
        else
        {
            masterMode = true;
        }

        if(this.dataSources == null)
        {
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
                        DataSourceWrapper datasource = dataSourceFactory.createDataSourceForFile(
                                datasourceName, datasourceFile, securityFactory.getPasswordResolver());

                        Connection conn = datasource.getConnection();
                        datasource.returnConnection(conn);

                        this.dataSources.put(datasourceName, datasource);
                    } catch (DataAccessException | PasswordResolverException | IOException | RuntimeException e)
                    {
                        throw new CAMgmtException(e.getClass().getName() + " while parsing datasoure " + datasourceFile, e);
                    }
                }
            }

            this.dataSource = this.dataSources.get("ca");
        }

        if(this.dataSource == null)
        {
            throw new CAMgmtException("no datasource configured with name 'ca'");
        }

        if(masterMode)
        {
            boolean lockedSuccessfull;
            try
            {
                lockedSuccessfull = lockCA(true);
            }catch(DataAccessException e)
            {
                throw new CAMgmtException("DataAccessException while locking CA", e);
            }

            if(lockedSuccessfull == false)
            {
                final String msg = "Could not lock the CA database. In general this indicates that another CA software in "
                        + "active mode is accessing the "
                        + "database or the last shutdown of CA software in active mode is not normal.";
                throw new CAMgmtException(msg);
            }
        }

        try
        {
            this.certstore = new CertificateStore(dataSource);
        } catch (DataAccessException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }

        initDataObjects();
    }

    @Override
    public CASystemStatus getCASystemStatus()
    {
        if(caSystemSetuped)
        {
            return masterMode ? CASystemStatus.STARTED_AS_MASTER : CASystemStatus.STARTED_AS_SLAVE;
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

    private boolean lockCA(boolean forceRelock)
    throws DataAccessException, CAMgmtException
    {
        String sql = "SELECT EVENT_TIME, EVENT_OWNER FROM SYSTEM_EVENT WHERE NAME='LOCK'";
        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            if(rs.next())
            {
                long lockGranted = rs.getLong("EVENT_TIME");
                String lockedBy = rs.getString("EVENT_OWNER");
                if(this.lockInstanceId.equals(lockedBy))
                {
                    if(forceRelock == false)
                    {
                        return true;
                    } else
                    {
                        LOG.info("CA has been locked by me since {}, relock it", new Date(lockGranted * 1000));
                    }
                }
                else
                {
                    LOG.error("Cannot lock CA, it has been locked by {} since {}", lockedBy, new Date(lockGranted * 1000));
                    return false;
                }
            }

            sql = "DELETE FROM SYSTEM_EVENT WHERE NAME='LOCK'";
            stmt.execute(sql);
        } catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }
        finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        final String lockSql = "INSERT INTO SYSTEM_EVENT (NAME, EVENT_TIME, EVENT_TIME2, EVENT_OWNER)"
                + " VALUES ('LOCK', ?, ?, ?)";

        PreparedStatement ps = null;
        try
        {
            long nowMillis = System.currentTimeMillis();
            ps = prepareStatement(lockSql);
            int idx = 1;
            ps.setLong(idx++, nowMillis / 1000);
            ps.setTimestamp(idx++, new Timestamp(nowMillis));
            ps.setString(idx++, lockInstanceId);
            int numColumns = ps.executeUpdate();
            caLockedByMe = numColumns > 0;
            return caLockedByMe;
        } catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(lockSql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    @Override
    public boolean unlockCA()
    {
        if(masterMode == false)
        {
            LOG.error("Could not unlock CA in slave mode");
            return false;
        }

        caLockedByMe = false;

        boolean successfull = false;
        final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME='LOCK'";
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            stmt.execute(sql);
            successfull = true;
        }catch(SQLException e)
        {
            final String message = "Error in unlockCA()";
            DataAccessException tEx = dataSource.translate(sql, e);
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), tEx.getClass().getName(), tEx.getMessage());
            }
            LOG.debug(message, tEx);
        }catch(CAMgmtException e)
        {
            final String message = "Error in unlockCA()";
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
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
        certprofilesInitialized = false;
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
        initCertprofiles();
        initPublishers();
        initCmpControls();
        initRequestors();
        initResponder();
        initCrlSigners();
        initCAs();
        markLastSeqValues();
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

        auditLogPCIEvent(caSystemStarted, "CA_CHANGE");
        return caSystemStarted;
    }

    @Override
    public void notifyCAChange()
    {
        String sql = null;

        try
        {
            Statement stmt = null;
            sql = "DELETE FROM SYSTEM_EVENT WHERE NAME='CA_CHANGE'";
            try
            {
                stmt = createStatement();
                stmt.execute(sql);
            }finally
            {
                dataSource.releaseResources(stmt, null);
            }

            sql = "INSERT INTO SYSTEM_EVENT (NAME, EVENT_TIME, EVENT_TIME2, EVENT_OWNER)"
                    + " VALUES ('CA_CHANGE', ?, ?, ?)";

            PreparedStatement ps = null;
            try
            {
                // notify the slave CAs
                ps = prepareStatement(sql);

                long nowMillis = System.currentTimeMillis();
                int idx = 1;
                ps.setLong(idx++, nowMillis / 1000);
                ps.setTimestamp(idx++, new Timestamp(nowMillis));
                ps.setString(idx++, lockInstanceId);
                ps.executeUpdate();
            }finally
            {
                dataSource.releaseResources(ps, null);
            }

            LOG.info("notified the change of CA system");
        }catch(SQLException e)
        {
            final String message = "Error while notifying Slave CAs to restart";
            DataAccessException tEx = dataSource.translate(sql, e);
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), tEx.getClass().getName(), tEx.getMessage());
            }
            LOG.debug(message, tEx);
        }catch(CAMgmtException e)
        {
            final String message = "Error while notifying Slave CAs to restart";
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    public void startCaSystem()
    {
        boolean caSystemStarted = false;
        try
        {
            caSystemStarted = do_startCaSystem();
        }catch(Throwable t)
        {
            final String message = "do_startCaSystem()";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
            }
            LOG.debug(message, t);
            LOG.error(message);
        }

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
                final String message = "do_startCaSystem().init()";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
                return false;
            }

            this.lastStartTime = new Date();

            x509cas.clear();
            responders.clear();

            scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(10);

            // Add the CAs to the store
            for(String caName : caInfos.keySet())
            {
                if(startCA(caName) == false)
                {
                    return false;
                }
            }

            caSystemSetuped = true;
            StringBuilder sb = new StringBuilder();
            sb.append("Started CA system");
            Set<String> names = new HashSet<>(getCaNames());

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
                sb.delete(len - 2, len);

                scheduledThreadPoolExecutor.scheduleAtFixedRate(new ScheduledPublishQueueCleaner(),
                        120, 120, TimeUnit.SECONDS);
                scheduledThreadPoolExecutor.scheduleAtFixedRate(new ScheduledDeleteCertsInProcessService(),
                        120, 120, TimeUnit.SECONDS);
            }
            else
            {
                sb.append(": no CA is configured");
            }
            LOG.info("{}", sb);
        } finally
        {
            initializing = false;
            if(masterMode == false)
            {
                if(persistentScheduledThreadPoolExecutor == null)
                {
                    persistentScheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
                    ScheduledCARestarter caRestarter = new ScheduledCARestarter();
                    persistentScheduledThreadPoolExecutor.scheduleAtFixedRate(caRestarter, 300, 300, TimeUnit.SECONDS);
                }
            }
        }

        return true;
    }

    private boolean startCA(String caName)
    {
        X509CAInfo caEntry = caInfos.get(caName);
        boolean signerRequired = caEntry.isSignerRequired();

        X509CrlSignerEntryWrapper crlSignerEntry = null;
        String crlSignerName = caEntry.getCrlSignerName();
        // CRL will be generated only in master mode
        if(signerRequired && masterMode && crlSignerName != null)
        {
            crlSignerEntry = crlSigners.get(crlSignerName);
            try
            {
                crlSignerEntry.initSigner(securityFactory);
            } catch (SignerException | OperationException | ConfigurationException e)
            {
                final String message = "X09CrlSignerEntryWrapper.initSigner (name=" + crlSignerName + ")";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
                return false;
            }
        }

        X509CA ca;
        try
        {
            ca = new X509CA(this, caEntry, certstore, securityFactory, masterMode);
            if(auditServiceRegister != null)
            {
                ca.setAuditServiceRegister(auditServiceRegister);
            }
        } catch (OperationException e)
        {
            final String message = "X509CA.<init> (ca=" + caName + ")";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            return false;
        }

        x509cas.put(caName, ca);

        X509CACmpResponder caResponder = new X509CACmpResponder(this, caName);
        responders.put(caName, caResponder);
        return true;
    }

    public void shutdown()
    {
        LOG.info("Stopping CA system");
        shutdownScheduledThreadPoolExecutor();

        if(persistentScheduledThreadPoolExecutor != null)
        {
            persistentScheduledThreadPoolExecutor.shutdown();
            while(persistentScheduledThreadPoolExecutor.isTerminated() == false)
            {
                try
                {
                    Thread.sleep(100);
                }catch(InterruptedException e)
                {
                }
            }
            persistentScheduledThreadPoolExecutor = null;
        }

        for(String caName : x509cas.keySet())
        {
            X509CA ca = x509cas.get(caName);
            try
            {
                ca.getCAInfo().commitNextSerial();
            } catch (Throwable t)
            {
                LOG.info("Exception while calling CAInfo.commitNextSerial for CA '{}': {}", caName, t.getMessage());
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

        for(String dsName :dataSources.keySet())
        {
            DataSourceWrapper ds = dataSources.get(dsName);
            try
            {
                ds.shutdown();
            } catch(Exception e)
            {
                final String message = "could not shutdown datasource " + dsName;
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
            }
        }

        LOG.info("Stopped CA system");
        auditLogPCIEvent(true, "SHUTDOWN");
    }

    @Override
    public X509CACmpResponder getX509CACmpResponder(String caName)
    {
        caName = caName.toUpperCase();
        return responders.get(caName);
    }

    public ScheduledThreadPoolExecutor getScheduledThreadPoolExecutor()
    {
        return scheduledThreadPoolExecutor;
    }

    @Override
    public Set<String> getCertprofileNames()
    {
        return certprofiles.keySet();
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
    public Set<String> getCmpControlNames()
    {
        return cmpControls.keySet();
    }

    @Override
    public Set<String> getCaNames()
    {
        return caInfos.keySet();
    }

    private void initRequestors()
    throws CAMgmtException
    {
        if(requestorsInitialized)
        {
            return;
        }

        requestors.clear();
        List<String> names = getNamesFromTable("REQUESTOR");

        if(names.isEmpty() == false)
        {
            for(String name : names)
            {
                CmpRequestorEntryWrapper requestor = createRequestor(name);
                if(requestor != null)
                {
                    requestors.put(name, requestor);
                }
            }
        }

        requestorsInitialized = true;
    }

    private void initResponder()
    throws CAMgmtException
    {
        if(responderInitialized)
        {
            return;
        }

        responder = createResponder();
        responderInitialized = true;
    }

    private void initEnvironemtParamters()
    throws CAMgmtException
    {
        if(environmentParametersInitialized) return;

        envParameterResolver.clear();

        final String sql = "SELECT NAME, VALUE2 FROM ENVIRONMENT";
        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String value = rs.getString("VALUE2");
                envParameterResolver.addEnvParam(name, value);
            }
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        environmentParametersInitialized = true;
    }

    private void initCaAliases()
    throws CAMgmtException
    {
        if(caAliasesInitialized)
        {
            return;
        }

        caAliases.clear();

        final String sql = "SELECT NAME, CA_NAME FROM CAALIAS";
        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                String name = rs.getString("NAME");
                String caName = rs.getString("CA_NAME");

                caAliases.put(name, caName);
            }
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        caAliasesInitialized = true;
    }

    private void initCertprofiles()
    throws CAMgmtException
    {
        if(certprofilesInitialized)
        {
            return;
        }

        for(String name : certprofiles.keySet())
        {
            shutdownCertprofile(certprofiles.get(name));
        }
        certprofiles.clear();

        List<String> names = getNamesFromTable("CERTPROFILE");

        if(names.isEmpty() == false)
        {
            for(String name : names)
            {
                IdentifiedX509Certprofile profile = createCertprofile(name, envParameterResolver);
                if(profile != null)
                {
                    certprofiles.put(name, profile);
                }
            }
        }

        certprofilesInitialized = true;
    }

    private void initPublishers()
    throws CAMgmtException
    {
        if(publishersInitialized)
        {
            return;
        }

        for(String name : publishers.keySet())
        {
            shutdownPublisher(publishers.get(name));
        }
        publishers.clear();

        List<String> names = getNamesFromTable("PUBLISHER");

        if(names.isEmpty() == false)
        {
            for(String name : names)
            {
                IdentifiedX509CertPublisher publisher = createPublisher(name, dataSources);
                if(publisher != null)
                {
                    publishers.put(name, publisher);
                }
            }
        }

        publishersInitialized = true;
    }

    private void initCrlSigners()
    throws CAMgmtException
    {
        if(crlSignersInitialized)
        {
            return;
        }
        crlSigners.clear();

        List<String> names = getNamesFromTable("CRLSIGNER");

        if(names.isEmpty() == false)
        {
            for(String name : names)
            {
                X509CrlSignerEntryWrapper crlSigner = createCrlSigner(name);
                if(crlSigner != null)
                {
                    crlSigners.put(name, crlSigner);
                }
            }
        }

        crlSignersInitialized = true;
    }

    private void initCmpControls()
    throws CAMgmtException
    {
        if(cmpControlInitialized)
        {
            return;
        }

        cmpControls.clear();

        List<String> names = getNamesFromTable("CMPCONTROL");

        if(names.isEmpty() == false)
        {
            for(String name : names)
            {
                CmpControl cmpControl = createCmpControl(name);
                if(cmpControl != null)
                {
                    cmpControls.put(name, cmpControl);
                }
            }
        }

        cmpControlInitialized = true;
    }

    private void initCAs()
    throws CAMgmtException
    {
        if(cAsInitialized)
        {
            return;
        }

        caInfos.clear();
        ca_has_requestors.clear();
        ca_has_publishers.clear();
        ca_has_profiles.clear();

        List<String> names = getNamesFromTable("CA");
        if(names.isEmpty() == false)
        {
            for(String name : names)
            {
                createCA(name);
            }
        }

        cAsInitialized = true;
    }

    private void createCA(String name)
    throws CAMgmtException
    {
        caInfos.remove(name);
        ca_has_profiles.remove(name);
        ca_has_publishers.remove(name);
        ca_has_requestors.remove(name);

        X509CAInfo ca = createCAInfo(name, masterMode);
        try
        {
            ca.markMaxSerial();
        }catch(OperationException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }
        caInfos.put(name, ca);

        Set<CAHasRequestorEntry> caHasRequestors = createCAhasRequestors(name);
        ca_has_requestors.put(name, caHasRequestors);

        Set<String> profileNames = createCAhasCertprofiles(name);
        ca_has_profiles.put(name, profileNames);

        Set<String> publisherNames = createCAhasPublishers(name);
        ca_has_publishers.put(name, publisherNames);
    }

    private void markLastSeqValues()
    throws CAMgmtException
    {
        try
        {
            // sequence DCC_ID
            long maxId = dataSource.getMax(null, "DELTACRL_CACHE", "ID");
            dataSource.setLastUsedSeqValue("DCC_ID", maxId);

            // sequence CERT_ID
            maxId = dataSource.getMax(null, "CERT", "ID");
            dataSource.setLastUsedSeqValue("CERT_ID", maxId);
        }catch(DataAccessException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }
    }

    @Override
    public void addCA(X509CAEntry newCaDbEntry)
    throws CAMgmtException
    {
        asssertMasterMode();
        String name = newCaDbEntry.getName();

        if(caInfos.containsKey(name))
        {
            throw new CAMgmtException("CA named " + name + " exists");
        }

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("INSERT INTO CA (");
        sqlBuilder.append("NAME, ART, SUBJECT, NEXT_SERIAL, NEXT_CRLNO, STATUS, CRL_URIS, OCSP_URIS, MAX_VALIDITY");
        sqlBuilder.append(", CERT, SIGNER_TYPE, SIGNER_CONF, CRLSIGNER_NAME, CMPCONTROL_NAME");
        sqlBuilder.append(", DUPLICATE_KEY_MODE, DUPLICATE_SUBJECT_MODE, PERMISSIONS, NUM_CRLS, EXPIRATION_PERIOD");
        sqlBuilder.append(", VALIDITY_MODE, DELTA_CRL_URIS");
        sqlBuilder.append(") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        final String sql = sqlBuilder.toString();

        // insert to table ca
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, name);
            ps.setInt(idx++, CertArt.X509PKC.getCode());
            ps.setString(idx++, newCaDbEntry.getSubject());

            long nextSerial = newCaDbEntry.getNextSerial();
            if(nextSerial < 0)
            {
                nextSerial = 0;
            }
            ps.setLong(idx++, nextSerial);

            ps.setInt(idx++, newCaDbEntry.getNextCRLNumber());
            ps.setString(idx++, newCaDbEntry.getStatus().getStatus());
            ps.setString(idx++, newCaDbEntry.getCrlUrisAsString());
            ps.setString(idx++, newCaDbEntry.getOcspUrisAsString());
            ps.setString(idx++, newCaDbEntry.getMaxValidity().toString());
            byte[] encodedCert = newCaDbEntry.getCertificate().getEncoded();
            ps.setString(idx++, Base64.toBase64String(encodedCert));
            ps.setString(idx++, newCaDbEntry.getSignerType());
            ps.setString(idx++, newCaDbEntry.getSignerConf());
            ps.setString(idx++, newCaDbEntry.getCrlSignerName());
            ps.setString(idx++, newCaDbEntry.getCmpControlName());
            ps.setInt(idx++, newCaDbEntry.getDuplicateKeyMode().getMode());
            ps.setInt(idx++, newCaDbEntry.getDuplicateSubjectMode().getMode());
            ps.setString(idx++, Permission.toString(newCaDbEntry.getPermissions()));
            ps.setInt(idx++, newCaDbEntry.getNumCrls());
            ps.setInt(idx++, newCaDbEntry.getExpirationPeriod());
            ps.setString(idx++, newCaDbEntry.getValidityMode().name());
            ps.setString(idx++, newCaDbEntry.getDeltaCrlUrisAsString());

            ps.executeUpdate();

            // create serial sequence
            if(nextSerial > 0)
            {
                dataSource.createSequence(newCaDbEntry.getSerialSeqName(), nextSerial);
            }

            if(LOG.isInfoEnabled())
            {
                LOG.info("added CA '{}': {}", name, newCaDbEntry.toString(false, true));
            }
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        } catch (CertificateEncodingException | DataAccessException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        createCA(name);
        startCA(name);
    }

    @Override
    public X509CAEntry getCA(String caName)
    {
        caName = caName.toUpperCase();
        X509CAInfo caInfo = caInfos.get(caName);
        return caInfo == null ? null : caInfo.getCaEntry();
    }

    @Override
    public void changeCA(String name, CAStatus status, X509Certificate cert,
            Set<String> crl_uris, Set<String> delta_crl_uris, Set<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, String cmpcontrol_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException
    {
        asssertMasterMode();
        name = name.toUpperCase();

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE CA SET ");

        AtomicInteger index = new AtomicInteger(1);

        Integer iStatus = addToSqlIfNotNull(sqlBuilder, index, status, "STATUS");
        Integer iSubject = addToSqlIfNotNull(sqlBuilder, index, cert, "SUBJECT");
        Integer iCert = addToSqlIfNotNull(sqlBuilder, index, cert, "CERT");
        Integer iCrl_uris = addToSqlIfNotNull(sqlBuilder, index, crl_uris, "CRL_URIS");
        Integer iDelta_crl_uris = addToSqlIfNotNull(sqlBuilder, index, delta_crl_uris, "DELTA_CRL_URIS");
        Integer iOcsp_uris = addToSqlIfNotNull(sqlBuilder, index, ocsp_uris, "OCSP_URIS");
        Integer iMax_validity = addToSqlIfNotNull(sqlBuilder, index, max_validity, "MAX_VALIDITY");
        Integer iSigner_type = addToSqlIfNotNull(sqlBuilder, index, signer_type, "SIGNER_TYPE");
        Integer iSigner_conf = addToSqlIfNotNull(sqlBuilder, index, signer_conf, "SIGNER_CONF");
        Integer iCrlsigner_name = addToSqlIfNotNull(sqlBuilder, index, crlsigner_name, "CRLSIGNER_NAME");
        Integer iCmpcontrol_name = addToSqlIfNotNull(sqlBuilder, index, cmpcontrol_name, "CMPCONTROL_NAME");
        Integer iDuplicate_key = addToSqlIfNotNull(sqlBuilder, index, duplicate_key, "DUPLICATE_KEY_MODE");
        Integer iDuplicate_subject = addToSqlIfNotNull(sqlBuilder, index, duplicate_subject, "DUPLICATE_SUBJECT_MODE");
        Integer iPermissions = addToSqlIfNotNull(sqlBuilder, index, permissions, "PERMISSIONS");
        Integer iNum_crls = addToSqlIfNotNull(sqlBuilder, index, numCrls, "NUM_CRLS");
        Integer iExpiration_period = addToSqlIfNotNull(sqlBuilder, index, expirationPeriod, "EXPIRATION_PERIOD");
        Integer iValidity_mode = addToSqlIfNotNull(sqlBuilder, index, validityMode, "VALIDITY_MODE");

        // delete the last ','
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if(index.get() == 1)
        {
            return;
        }
        int iName = index.get();

        final String sql = sqlBuilder.toString();
        StringBuilder m = new StringBuilder();
        PreparedStatement ps = null;

        try
        {
            ps = prepareStatement(sql);

            if(iStatus != null)
            {
                m.append("status: '").append(status.name()).append("'; ");
                ps.setString(iStatus, status.name());
            }

            if(iCert != null)
            {
                String subject = SecurityUtil.getRFC4519Name(cert.getSubjectX500Principal());
                m.append("cert: '").append(subject).append("'; ");
                ps.setString(iSubject, subject);
                String base64Cert = Base64.toBase64String(cert.getEncoded());
                ps.setString(iCert, base64Cert);
            }

            if(iCrl_uris != null)
            {
                String txt = toString(crl_uris, " ");
                m.append("crlUri: '").append(txt).append("'; ");
                ps.setString(iCrl_uris, txt);
            }

            if(iDelta_crl_uris != null)
            {
                String txt = toString(delta_crl_uris, " ");
                m.append("deltaCrlUri: '").append(txt).append("'; ");
                ps.setString(iDelta_crl_uris, txt);
            }

            if(iOcsp_uris != null)
            {
                String txt = toString(ocsp_uris, " ");
                m.append("ocspUri: '").append(txt).append("'; ");
                ps.setString(iOcsp_uris, txt);
            }

            if(iMax_validity != null)
            {
                String txt = max_validity.toString();
                m.append("maxValidity: '").append(txt).append("'; ");
                ps.setString(iMax_validity, txt);
            }

            if(iSigner_type != null)
            {
                m.append("signerType: '").append(signer_type).append("'; ");
                ps.setString(iSigner_type, signer_type);
            }

            if(iSigner_conf != null)
            {
                m.append("signerConf: '");
                m.append(SecurityUtil.signerConfToString(signer_conf, false, true));
                m.append("'; ");
                ps.setString(iSigner_conf, signer_conf);
            }

            if(iCrlsigner_name != null)
            {
                String txt = getRealString(crlsigner_name);
                m.append("crlSigner: '").append(txt).append("'; ");
                ps.setString(iCrlsigner_name, txt);
            }

            if(iCmpcontrol_name != null)
            {
                String txt = getRealString(cmpcontrol_name);
                m.append("cmpControl: '").append(txt).append("'; ");
                ps.setString(iCmpcontrol_name, txt);
            }

            if(iDuplicate_key != null)
            {
                int mode = duplicate_key.getMode();
                m.append("duplicateKey: '").append(mode).append("'; ");
                ps.setInt(iDuplicate_key, mode);
            }

            if(iDuplicate_subject != null)
            {
                int mode = duplicate_subject.getMode();
                m.append("duplicateSubject: '").append(mode).append("'; ");
                ps.setInt(iDuplicate_subject, mode);
            }

            if(iPermissions != null)
            {
                String txt = Permission.toString(permissions);
                m.append("permission: '").append(txt).append("'; ");
                ps.setString(iPermissions, txt);
            }

            if(iNum_crls != null)
            {
                m.append("numCrls: '").append(numCrls).append("'; ");
                ps.setInt(iNum_crls, numCrls);
            }

            if(iExpiration_period != null)
            {
                m.append("expirationPeriod: '").append(numCrls).append("'; ");
                ps.setInt(iExpiration_period, expirationPeriod);
            }

            if(iValidity_mode != null)
            {
                String txt = validityMode.name();
                m.append("validityMode: '").append(txt).append("'; ");
                ps.setString(iValidity_mode, txt);
            }

            ps.setString(iName, name);
            ps.executeUpdate();

            if(m.length() > 0)
            {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("changed CA '{}': {}", name, m);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }catch(CertificateEncodingException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        createCA(name);
        startCA(name);
    }

    @Override
    public void removeCertprofileFromCA(String profileName, String caName)
    throws CAMgmtException
    {
        asssertMasterMode();
        caName = caName.toUpperCase();

        final String sql = "DELETE FROM CA_HAS_CERTPROFILE WHERE CA_NAME=? AND CERTPROFILE_NAME=?";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, profileName);
            ps.executeUpdate();
            LOG.info("remove profile '{}' from CA '{}'", profileName, caName);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        if(ca_has_profiles.containsKey(caName))
        {
            ca_has_profiles.get(caName).remove(profileName);
        }
    }

    @Override
    public void addCertprofileToCA(String profileName, String caName)
    throws CAMgmtException
    {
        asssertMasterMode();
        caName = caName.toUpperCase();
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

        final String sql = "INSERT INTO CA_HAS_CERTPROFILE (CA_NAME, CERTPROFILE_NAME) VALUES (?, ?)";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, profileName);
            ps.executeUpdate();
            LOG.info("add profile '{}' to CA '{}'", profileName, caName);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        ca_has_profiles.get(caName).add(profileName);
    }

    @Override
    public void removePublisherFromCA(String publisherName, String caName)
    throws CAMgmtException
    {
        asssertMasterMode();
        caName = caName.toUpperCase();
        Set<String> publisherNames = ca_has_publishers.get(caName);
        final String sql = "DELETE FROM CA_HAS_PUBLISHER WHERE CA_NAME=? AND PUBLISHER_NAME=?";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, publisherName);
            ps.executeUpdate();
            LOG.info("remove publisher '{}' from CA '{}'", publisherName, caName);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
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
        asssertMasterMode();
        caName = caName.toUpperCase();
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

        final String sql = "INSERT INTO CA_HAS_PUBLISHER (CA_NAME, PUBLISHER_NAME) VALUES (?, ?)";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, publisherName);
            ps.executeUpdate();
            LOG.info("add publisher '{}' to CA '{}'", publisherName, caName);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        ca_has_publishers.get(caName).add(publisherName);
        publishers.get(publisherName).issuerAdded(caInfos.get(caName).getCertificate());
    }

    @Override
    public Set<String> getCertprofilesForCA(String caName)
    {
        caName = caName.toUpperCase();
        return ca_has_profiles.get(caName);
    }

    @Override
    public Set<CAHasRequestorEntry> getCmpRequestorsForCA(String caName)
    {
        caName = caName.toUpperCase();
        return ca_has_requestors.get(caName);
    }

    @Override
    public CmpRequestorEntry getCmpRequestor(String name)
    {
        return requestors.containsKey(name) ? requestors.get(name).getDbEntry() : null;
    }

    public CmpRequestorEntryWrapper getCmpRequestorWrapper(String name)
    {
        return requestors.get(name);
    }

    @Override
    public void addCmpRequestor(CmpRequestorEntry dbEntry)
    throws CAMgmtException
    {
        asssertMasterMode();
        String name = dbEntry.getName();
        if(requestors.containsKey(name))
        {
            throw new CAMgmtException("CMP requestor named " + name + " exists");
        }

        final String sql = "INSERT INTO REQUESTOR (NAME, CERT) VALUES (?, ?)";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, name);
            ps.setString(idx++, Base64.toBase64String(dbEntry.getCert().getEncoded()));
            ps.executeUpdate();
            if(LOG.isInfoEnabled())
            {
                LOG.info("add requestor '{}': {}", name, dbEntry.toString(false));
            }
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }catch(CertificateEncodingException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        requestors.put(name, createRequestor(name));

        try
        {
            certstore.addRequestorName(name);
        }catch(OperationException e)
        {
            final String message = "Exception while publishing requestor name to certStore";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    @Override
    public void removeCmpRequestor(String requestorName)
    throws CAMgmtException
    {
        asssertMasterMode();
        for(String caName : ca_has_requestors.keySet())
        {
            removeCmpRequestorFromCA(requestorName, caName);
        }

        deleteRowWithName(requestorName, "REQUESTOR");
        requestors.remove(requestorName);
        LOG.info("remove requestor '{}'", requestorName);
    }

    @Override
    public void changeCmpRequestor(String name, String cert)
    throws CAMgmtException
    {
        asssertMasterMode();
        if(cert == null)
        {
            return;
        }

        final String sql = "UPDATE REQUESTOR SET CERT=? WHERE NAME=?";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            String b64Cert = getRealString(cert);
            ps.setString(1, b64Cert);
            ps.setString(2, name);
            ps.executeUpdate();
            if(LOG.isInfoEnabled())
            {
                String subject = null;
                if(b64Cert != null)
                {
                    try
                    {
                        subject = SecurityUtil.canonicalizName(
                                SecurityUtil.parseBase64EncodedCert(b64Cert).getSubjectX500Principal());
                    } catch (CertificateException | IOException e)
                    {
                        subject = "ERROR";
                    }
                }
                LOG.info("change requestor '{}': {}", name, subject);
            }
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        requestors.remove(name);
        CmpRequestorEntryWrapper requestor = createRequestor(name);
        if(requestor != null)
        {
            requestors.put(name, requestor);
        }
    }

    @Override
    public void removeCmpRequestorFromCA(String requestorName, String caName)
    throws CAMgmtException
    {
        asssertMasterMode();
        caName = caName.toUpperCase();
        Set<CAHasRequestorEntry> requestors = ca_has_requestors.get(caName);
        final String sql = "DELETE FROM CA_HAS_REQUESTOR WHERE CA_NAME=? AND REQUESTOR_NAME=?";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, requestorName);
            ps.executeUpdate();

            if(requestors != null)
            {
                requestors.remove(requestorName);
            }
            LOG.info("remove requestor '{}' from CA '{}'", requestorName, caName);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        if(ca_has_requestors.containsKey(caName))
        {
            ca_has_requestors.get(caName).remove(requestorName);
        }
    }

    @Override
    public void addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
    throws CAMgmtException
    {
        asssertMasterMode();
        caName = caName.toUpperCase();
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
        final String sql =
                "INSERT INTO CA_HAS_REQUESTOR (CA_NAME, REQUESTOR_NAME, RA, PERMISSIONS, PROFILES) VALUES (?, ?, ?, ?, ?)";
        try
        {
            boolean ra = requestor.isRa();
            String permissionText = Permission.toString(requestor.getPermissions());
            String profilesText = toString(requestor.getProfiles(), ",");

            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, caName);
            ps.setString(idx++, requestorName);

            setBoolean(ps, idx++, ra);
            ps.setString(idx++, permissionText);

            ps.setString(idx++, profilesText);

            ps.executeUpdate();
            LOG.info("add requestor '{}' to CA '{}': ra: {}; permission: {}; profile: {}",
                    requestorName, caName, ra, permissionText, profilesText);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        ca_has_requestors.get(caName).add(requestor);
    }

    @Override
    public CertprofileEntry getCertprofile(String profileName)
    {
        IdentifiedX509Certprofile entry = certprofiles.get(profileName);
        return entry == null ? null : entry.getEntry();
    }

    @Override
    public void removeCertprofile(String profileName)
    throws CAMgmtException
    {
        asssertMasterMode();
        for(String caName : ca_has_profiles.keySet())
        {
            removeCertprofileFromCA(profileName, caName);
        }

        deleteRowWithName(profileName, "CERTPROFILE");
        LOG.info("remove profile '{}'", profileName);
        IdentifiedX509Certprofile profile = certprofiles.remove(profileName);
        shutdownCertprofile(profile);
    }

    @Override
    public void changeCertprofile(String name, String type, String conf)
    throws CAMgmtException
    {
        asssertMasterMode();
        if(type == null && conf == null)
        {
            throw new IllegalArgumentException("at least one of type and conf should not be null");
        }
        assertNotNULL("type", type);

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE CERTPROFILE SET ");

        AtomicInteger index = new AtomicInteger(1);

        StringBuilder m = new StringBuilder();

        if(type != null)
        {
            m.append("type: '").append(type).append("'; ");
        }
        if(conf != null)
        {
            m.append("conf: '").append(conf).append("'; ");
        }

        Integer iType = addToSqlIfNotNull(sqlBuilder, index, type, "TYPE");
        Integer iConf = addToSqlIfNotNull(sqlBuilder, index, conf, "CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");
        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            if(iType != null)
            {
                ps.setString(iType, type);
            }

            if(iConf != null)
            {
                ps.setString(iConf, getRealString(conf));
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if(m.length() > 0)
            {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("change profile '{}': {}", name, m);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        IdentifiedX509Certprofile profile = certprofiles.remove(name);
        shutdownCertprofile(profile);
        profile = createCertprofile(name, envParameterResolver);
        if(profile != null)
        {
            certprofiles.put(name, profile);
        }
    }

    @Override
    public void addCertprofile(CertprofileEntry dbEntry)
    throws CAMgmtException
    {
        asssertMasterMode();
        String name = dbEntry.getName();
        if(certprofiles.containsKey(name))
        {
            throw new CAMgmtException("Certprofile named " + name + " exists");
        }
        final String sql = "INSERT INTO CERTPROFILE (NAME, ART, TYPE, CONF) VALUES (?, ?, ?, ?)";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            ps.setInt(2, CertArt.X509PKC.getCode());
            ps.setString(3, dbEntry.getType());
            String conf = dbEntry.getConf();
            ps.setString(4, conf);

            ps.executeUpdate();

            LOG.info("add profile '{}': {}", name, dbEntry);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        IdentifiedX509Certprofile profile = createCertprofile(name, envParameterResolver);
        if(profile != null)
        {
            certprofiles.put(name, profile);
        }

        try
        {
            certstore.addCertprofileName(name);
        }catch(OperationException e)
        {
            final String message = "Exception while publishing certprofile name to certStore";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    @Override
    public void setCmpResponder(CmpResponderEntry dbEntry)
    throws CAMgmtException
    {
        asssertMasterMode();
        if(responder != null)
        {
            removeCmpResponder();
        }
        final String sql = "INSERT INTO RESPONDER (NAME, TYPE, CONF, CERT) VALUES (?, ?, ?, ?)";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
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

            LOG.info("change responder: {}", dbEntry.toString(false, true));
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }catch(CertificateEncodingException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        responder = createResponder();
    }

    @Override
    public void removeCmpResponder()
    throws CAMgmtException
    {
        asssertMasterMode();
        deleteRows("RESPONDER");
        LOG.info("remove responder");
        responder = null;
    }

    @Override
    public void changeCmpResponder(String type, String conf, String cert)
    throws CAMgmtException
    {
        asssertMasterMode();
        if(type == null && conf == null && cert == null)
        {
            return;
        }

        StringBuilder m = new StringBuilder();
        StringBuilder sqlBuilder = new StringBuilder();

        sqlBuilder.append("UPDATE RESPONDER SET ");

        AtomicInteger index = new AtomicInteger(1);
        Integer iType = addToSqlIfNotNull(sqlBuilder, index, type, "TYPE");
        Integer iConf = addToSqlIfNotNull(sqlBuilder, index, conf, "CONF");
        Integer iCert = addToSqlIfNotNull(sqlBuilder, index, cert, "CERT");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");
        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            if(iType != null)
            {
                String txt = type;
                ps.setString(iType, txt);
                m.append("type: '").append(txt).append("'; ");
            }

            if(iConf != null)
            {
                String txt = getRealString(conf);
                m.append("conf: '").append(SecurityUtil.signerConfToString(txt, false, true));
                ps.setString(iConf, txt);
            }

            if(iCert != null)
            {
                String txt = getRealString(cert);
                m.append("cert: '");
                if(txt == null)
                {
                    m.append("null");
                } else
                {
                    if(txt != null)
                    {
                        try
                        {
                            String subject = SecurityUtil.canonicalizName(
                                    SecurityUtil.parseBase64EncodedCert(txt).getSubjectX500Principal());
                            m.append(subject);
                        } catch (CertificateException | IOException e)
                        {
                            m.append("ERROR");
                        }
                    }

                }
                m.append("'; ");
                ps.setString(iCert, txt);
            }

            ps.setString(index.get(), CmpResponderEntry.name);

            ps.executeUpdate();

            if(m.length() > 0)
            {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("set CMP responder: {}", m);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        responder = null;
        responder = createResponder();
    }

    @Override
    public CmpResponderEntry getCmpResponder()
    {
        return responder == null ? null : responder.getDbEntry();
    }

    public CmpResponderEntryWrapper getCmpResponderWrapper()
    {
        return responder;
    }

    @Override
    public void addCrlSigner(X509CrlSignerEntry dbEntry)
    throws CAMgmtException
    {
        asssertMasterMode();
        String name = dbEntry.getName();
        if(crlSigners.containsKey(name))
        {
            throw new CAMgmtException("CRL signer named " + name + " exists");
        }
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("INSERT INTO CRLSIGNER (NAME, SIGNER_TYPE, SIGNER_CONF, SIGNER_CERT, CRL_CONTROL)");
        sqlBuilder.append(" VALUES (?, ?, ?, ?, ?)");
        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try
        {

            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, name);
            ps.setString(idx++, dbEntry.getType());
            ps.setString(idx++, dbEntry.getConf());
            ps.setString(idx++, dbEntry.getCertificate() == null ? null :
                    Base64.toBase64String(dbEntry.getCertificate().getEncoded()));

            String crlControl = dbEntry.getCRLControl().getConf();
            ps.setString(idx++, crlControl);

            ps.executeUpdate();
            LOG.info("add CRL signer '{}': {}", name, dbEntry.toString(false, true));
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }catch(CertificateEncodingException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        crlSigners.put(name, createCrlSigner(name));
    }

    @Override
    public void removeCrlSigner(String crlSignerName)
    throws CAMgmtException
    {
        asssertMasterMode();
        deleteRowWithName(crlSignerName, "CRLSIGNER");
        for(String caName : caInfos.keySet())
        {
            X509CAInfo caInfo = caInfos.get(caName);
            if(crlSignerName.equals(caInfo.getCrlSignerName()))
            {
                caInfo.setCrlSignerName(null);
            }
        }

        crlSigners.remove(crlSignerName);
        LOG.info("remove CRLSigner '{}'", crlSignerName);
    }

    @Override
    public void changeCrlSigner(String name, String signer_type, String signer_conf, String signer_cert,
            CRLControl crlControl)
    throws CAMgmtException
    {
        asssertMasterMode();
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE CRLSIGNER SET ");

        AtomicInteger index = new AtomicInteger(1);

        Integer iSigner_type = addToSqlIfNotNull(sqlBuilder, index, signer_type, "SIGNER_TYPE");
        Integer iSigner_conf = addToSqlIfNotNull(sqlBuilder, index, signer_conf, "SIGNER_CONF");
        Integer iSigner_cert = addToSqlIfNotNull(sqlBuilder, index, signer_cert, "SIGNER_CERT");
        Integer iCrlControl = addToSqlIfNotNull(sqlBuilder, index, crlControl, "CRL_CONTROL");

        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if(index.get() == 1)
        {
            return;
        }
        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try
        {
            StringBuilder m = new StringBuilder();

            ps = prepareStatement(sql);

            if(iSigner_type != null)
            {
                m.append("signerType: '").append(signer_type).append("'; ");
                ps.setString(iSigner_type, signer_type);
            }

            if(iSigner_conf != null)
            {
                String txt = getRealString(signer_conf);
                m.append("signerConf: '").append(SecurityUtil.signerConfToString(txt, false, true)).append("'; ");
                ps.setString(iSigner_conf, txt);
            }

            if(iSigner_cert != null)
            {
                String txt = getRealString(signer_cert);
                String subject = null;
                if(txt != null)
                {
                    try
                    {
                        subject = SecurityUtil.canonicalizName(
                                SecurityUtil.parseBase64EncodedCert(txt).getSubjectX500Principal());
                    } catch (CertificateException | IOException e)
                    {
                        subject = "ERROR";
                    }
                }
                m.append("signerCert: '").append(subject).append("'; ");

                ps.setString(iSigner_cert, txt);
            }

            if(iCrlControl != null)
            {
                m.append("crlControl: '").append(crlControl).append("'; ");
                ps.setString(iCrlControl, crlControl.getConf());
            }

            ps.setString(index.get(), name);

            ps.executeUpdate();

            if(m.length() > 0)
            {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("set CRL signer '{}': {}", name, m);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        X509CrlSignerEntryWrapper crlSigner = crlSigners.remove(name);
        crlSigner = createCrlSigner(name);
        if(crlSigner != null)
        {
            crlSigners.put(name, crlSigner);
        }
    }

    @Override
    public X509CrlSignerEntry getCrlSigner(String name)
    {
        return crlSigners.containsKey(name) ? crlSigners.get(name).getDbEntry() : null;
    }

    public X509CrlSignerEntryWrapper getCrlSignerWrapper(String name)
    {
        return crlSigners.get(name);
    }

    @Override
    public void addPublisher(PublisherEntry dbEntry)
    throws CAMgmtException
    {
        asssertMasterMode();
        String name = dbEntry.getName();
        if(publishers.containsKey(name))
        {
            throw new CAMgmtException("Publisher named " + name + " exists");
        }
        final String sql = "INSERT INTO PUBLISHER (NAME, TYPE, CONF) VALUES (?, ?, ?)";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            ps.setString(2, dbEntry.getType());
            String conf = dbEntry.getConf();
            ps.setString(3, conf);

            ps.executeUpdate();
            LOG.info("add publisher '{}': {}", name, dbEntry);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        IdentifiedX509CertPublisher publisher = createPublisher(name, dataSources);
        if(publisher != null)
        {
            publishers.put(name, publisher);
        }

        try
        {
            certstore.addPublisherName(name);
        }catch(OperationException e)
        {
            final String message = "Exception while publishing publisher nameto certStore";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    @Override
    public List<PublisherEntry> getPublishersForCA(String caName)
    {
        ParamChecker.assertNotEmpty("caName", caName);
        caName = caName.toUpperCase();
        Set<String> publisherNames = ca_has_publishers.get(caName);
        if(publisherNames == null)
        {
            return Collections.emptyList();
        }

        List<PublisherEntry> ret = new ArrayList<>(publisherNames.size());
        for(String publisherName : publisherNames)
        {
            ret.add(publishers.get(publisherName).getEntry());
        }

        return ret;
    }

    @Override
    public PublisherEntry getPublisher(String publisherName)
    {
        IdentifiedX509CertPublisher entry = publishers.get(publisherName);
        return entry == null ? null : entry.getEntry();
    }

    @Override
    public void removePublisher(String publisherName)
    throws CAMgmtException
    {
        asssertMasterMode();
        for(String caName : ca_has_publishers.keySet())
        {
            removePublisherFromCA(publisherName, caName);
        }

        deleteRowWithName(publisherName, "PUBLISHER");
        LOG.info("remove publisher '{}'", publisherName);
        IdentifiedX509CertPublisher publisher = publishers.remove(publisherName);
        shutdownPublisher(publisher);
    }

    @Override
    public void changePublisher(String name, String type, String conf)
    throws CAMgmtException
    {
        asssertMasterMode();
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE PUBLISHER SET ");

        AtomicInteger index = new AtomicInteger(1);
        Integer iType = addToSqlIfNotNull(sqlBuilder, index, type, "TYPE");
        Integer iConf = addToSqlIfNotNull(sqlBuilder, index, conf, "CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if(index.get() == 1)
        {
            return;
        }
        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try
        {
            StringBuilder m = new StringBuilder();
            ps = prepareStatement(sql);
            if(iType != null)
            {
                m.append("type: '").append(type).append("'; ");
                ps.setString(iType, type);
            }

            if(iConf != null)
            {
                String txt = getRealString(conf);
                m.append("conf: '").append(txt).append("'; ");
                ps.setString(iConf, getRealString(conf));
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if(m.length() > 0)
            {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("change publisher {}: '{}'", name, m);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        IdentifiedX509CertPublisher publisher = publishers.remove(name);
        shutdownPublisher(publisher);
        publisher = createPublisher(name, dataSources);
        if(publisher != null)
        {
            publishers.put(name, publisher);
        }

    }

    @Override
    public CmpControl getCmpControl(String name)
    {
        return cmpControls.get(name);
    }

    @Override
    public void addCmpControl(CmpControl dbEntry)
    throws CAMgmtException
    {
        asssertMasterMode();
        final String name = dbEntry.getName();
        if(cmpControls.containsKey(name))
        {
            throw new CAMgmtException("CMPControl named " + name + " exists");
        }

        final String sql = "INSERT INTO CMPCONTROL (NAME, REQUIRE_CONFIRM_CERT, SEND_CA_CERT, SEND_RESPONDER_CERT," +
                " REQUIRE_MESSAGE_TIME, MESSAGE_TIME_BIAS, CONFIRM_WAIT_TIME) VALUES (?, ?, ?, ?, ?, ?, ?)";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);

            int idx = 1;
            ps.setString(idx++, name);
            setBoolean(ps, idx++, dbEntry.isRequireConfirmCert());
            setBoolean(ps, idx++, dbEntry.isSendCaCert());
            setBoolean(ps, idx++, dbEntry.isSendResponderCert());
            setBoolean(ps, idx++, dbEntry.isMessageTimeRequired());
            ps.setInt(idx++, dbEntry.getMessageTimeBias());
            ps.setInt(idx++, dbEntry.getConfirmWaitTime());

            ps.executeUpdate();
            LOG.info("added CMP control: {}", dbEntry);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        cmpControls.put(name, dbEntry);
    }

    @Override
    public void removeCmpControl(String name)
    throws CAMgmtException
    {
        asssertMasterMode();
        deleteRowWithName(name, "CMPCONTROL");

        for(String caName : caInfos.keySet())
        {
            X509CAInfo caInfo = caInfos.get(caName);
            if(name.equals(caInfo.getCmpControlName()))
            {
                caInfo.setCmpControlName(null);
            }
        }

        cmpControls.remove(name);
        LOG.info("remove CMPControl '{}'", name);
    }

    @Override
    public void changeCmpControl(String name, Boolean requireConfirmCert,
            Boolean requireMessageTime, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert, Boolean sendResponderCert)
    throws CAMgmtException
    {
        asssertMasterMode();
        if(requireConfirmCert == null && requireMessageTime == null && messageTimeBias == null
                && confirmWaitTime == null && sendCaCert == null && sendResponderCert == null)
        {
            return;
        }

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE CMPCONTROL SET ");

        AtomicInteger index = new AtomicInteger(1);
        Integer iConfirmCert = addToSqlIfNotNull(sqlBuilder, index, requireConfirmCert, "REQUIRE_CONFIRM_CERT");
        Integer iRequireMessageTime = addToSqlIfNotNull(sqlBuilder, index, requireMessageTime, "REQUIRE_MESSAGE_TIME");
        Integer iMessageTimeBias = addToSqlIfNotNull(sqlBuilder, index, messageTimeBias, "MESSAGE_TIME_BIAS");
        Integer iConfirmWaitTime = addToSqlIfNotNull(sqlBuilder, index, confirmWaitTime, "CONFIRM_WAIT_TIME");
        Integer iSendCaCert = addToSqlIfNotNull(sqlBuilder, index, sendCaCert, "SEND_CA_CERT");
        Integer iSendResponderCert = addToSqlIfNotNull(sqlBuilder, index, sendResponderCert, "SEND_RESPONDER_CERT");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");
        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try
        {
            StringBuilder m = new StringBuilder();

            ps = prepareStatement(sql);
            if(iConfirmCert != null)
            {
                m.append("requireConfirmCert: '").append(requireConfirmCert).append("'; ");
                setBoolean(ps, iConfirmCert, requireConfirmCert);
            }

            if(iRequireMessageTime != null)
            {
                m.append("requireMessageTime: '").append(requireMessageTime).append("'; ");
                setBoolean(ps, iRequireMessageTime, requireMessageTime);
            }

            if(iMessageTimeBias != null)
            {
                m.append("messageTimeBias: '").append(messageTimeBias).append("'; ");
                ps.setInt(iMessageTimeBias, messageTimeBias);
            }

            if(iConfirmWaitTime != null)
            {
                m.append("confirmWaitTime: '").append(confirmWaitTime).append("'; ");
                ps.setInt(iConfirmWaitTime, confirmWaitTime);
            }

            if(iSendCaCert != null)
            {
                m.append("sendCaCert: '").append(sendCaCert).append("'; ");
                setBoolean(ps, iSendCaCert, sendCaCert);
            }

            if(iSendResponderCert != null)
            {
                m.append("sendResponderCert: '").append(sendResponderCert).append("'; ");
                setBoolean(ps, iSendResponderCert, sendResponderCert);
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if(m.length() > 0)
            {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("change CMP control: {}", m);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        CmpControl cmpControl = createCmpControl(name);
        cmpControls.put(name, cmpControl);
    }

    public EnvironmentParameterResolver getEnvParameterResolver()
    {
        return envParameterResolver;
    }

    @Override
    public Set<String> getEnvParamNames()
    {
        return envParameterResolver.getAllParameterNames();
    }

    @Override
    public String getEnvParam(String name)
    {
        return envParameterResolver.getEnvParam(name);
    }

    @Override
    public void addEnvParam(String name, String value)
    throws CAMgmtException
    {
        asssertMasterMode();
        if(envParameterResolver.getEnvParam(name) != null)
        {
            throw new CAMgmtException("Environemt parameter named " + name + " exists");
        }
        final String sql = "INSERT INTO ENVIRONMENT (NAME, VALUE2) VALUES (?, ?)";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            ps.setString(2, value);
            ps.executeUpdate();
            LOG.info("add environment param '{}': {}", name, value);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
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
        asssertMasterMode();
        deleteRowWithName(envParamName, "ENVIRONMENT");
        LOG.info("remove environment param '{}'", envParamName);
        envParameterResolver.removeEnvParam(envParamName);
    }

    @Override
    public void changeEnvParam(String name, String value)
    throws CAMgmtException
    {
        asssertMasterMode();
        ParamChecker.assertNotEmpty("name", name);
        assertNotNULL("value", value);

        if(envParameterResolver.getEnvParam(name) == null)
        {
            throw new CAMgmtException("Could not find environment paramter " + name);
        }
        final String sql = "UPDATE ENVIRONMENT SET VALUE2=? WHERE NAME=?";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, getRealString(value));
            ps.setString(2, name);
            ps.executeUpdate();
            envParameterResolver.addEnvParam(name, value);
            LOG.info("change environment param '{}': {}", name, value);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
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
        asssertMasterMode();
        caName = caName.toUpperCase();
        if(caAliases.get(aliasName) != null)
        {
            throw new CAMgmtException("CA alias " + aliasName + " exists");
        }
        final String sql = "INSERT INTO CAALIAS (NAME, CA_NAME) VALUES (?, ?)";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, aliasName);
            ps.setString(2, caName);
            ps.executeUpdate();
            LOG.info("add CA alias '{}' for CA '{}'", aliasName, caName);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
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
        asssertMasterMode();
        final String sql = "DELETE FROM CAALIAS WHERE NAME=?";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, aliasName);
            ps.executeUpdate();
            LOG.info("remove CA alias '{}'", aliasName);
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
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
        caName = caName.toUpperCase();
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
        asssertMasterMode();
        caName = caName.toUpperCase();
        final String sql = "DELETE FROM CA WHERE NAME=?";

        PreparedStatement ps = null;
        CAMgmtException exception = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }

        X509CAInfo caInfo = caInfos.get(caName);
        if(caInfo == null || caInfo.getCaEntry().getNextSerial() > 0)
        {
            // drop the serial number sequence
            final String sequenceName = caInfo.getCaEntry().getSerialSeqName();
            try
            {
                dataSource.dropSequence(sequenceName);
            }catch(DataAccessException e)
            {
                final String message = "Error in dropSequence " + sequenceName;
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
                if(exception == null)
                {
                    exception = new CAMgmtException(e.getMessage(), e);
                }
            }
        }

        LOG.info("remove CA '{}'", caName);
        caInfos.remove(caName);
        ca_has_profiles.remove(caName);
        ca_has_publishers.remove(caName);
        ca_has_requestors.remove(caName);
        x509cas.remove(caName);
        responders.remove(caName);

        if(exception != null)
        {
            throw exception;
        }
    }

    @Override
    public void publishRootCA(String caName, String certprofile)
    throws CAMgmtException
    {
        asssertMasterMode();
        caName = caName.toUpperCase();
        X509CA ca = x509cas.get(caName);
        if(ca == null)
        {
            throw new CAMgmtException("Cannot find CA named " + caName);
        }

        X509CertWithId certInfo = ca.getCAInfo().getCertificate();
        if(certInfo.getCert().getSubjectX500Principal().equals(
                certInfo.getCert().getIssuerX500Principal()) == false)
        {
            throw new CAMgmtException("CA named " + caName + " is not a self-signed CA");
        }

        byte[] encodedSubjectPublicKey = certInfo.getCert().getPublicKey().getEncoded();
        X509CertificateInfo ci;
        try
        {
            ci = new X509CertificateInfo(
                    certInfo, certInfo, encodedSubjectPublicKey,
                    certprofile == null ? "UNKNOWN" : certprofile);
        } catch (CertificateEncodingException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }
        ca.publishCertificate(ci);
    }

    @Override
    public boolean republishCertificates(String caName, List<String> publisherNames)
    throws CAMgmtException
    {
        asssertMasterMode();

        Set<String> caNames;
        if(caName == null)
        {
            caNames = x509cas.keySet();
        }
        else
        {
            caName = caName.toUpperCase();
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
                throw new CAMgmtException("Republishing certificates of CA " + name + " failed");
            }
        }

        return true;
    }

    @Override
    public void revokeCa(String caName, CertRevocationInfo revocationInfo)
    throws CAMgmtException
    {
        asssertMasterMode();
        ParamChecker.assertNotEmpty("caName", caName);
        ParamChecker.assertNotNull("revocationInfo", revocationInfo);

        caName = caName.toUpperCase();
        if(x509cas.containsKey(caName) == false)
        {
            throw new CAMgmtException("Could not find CA named " + caName);
        }

        LOG.info("Revoking CA '{}'", caName);
        X509CA ca = x509cas.get(caName);

        CertRevocationInfo currentRevInfo = ca.getCAInfo().getRevocationInfo();
        if(currentRevInfo != null)
        {
            CRLReason currentReason = currentRevInfo.getReason();
            if(currentReason != CRLReason.CERTIFICATE_HOLD)
            {
                throw new CAMgmtException("CA " + caName + " has been revoked with reason " + currentReason.name());
            }
        }

        String sql = "UPDATE CA SET REVOKED=?, REV_REASON=?, REV_TIME=?, REV_INVALIDITY_TIME=? WHERE NAME=?";
        PreparedStatement ps = null;
        try
        {
            if(revocationInfo.getInvalidityTime() == null)
            {
                revocationInfo.setInvalidityTime(revocationInfo.getRevocationTime());
            }

            ps = prepareStatement(sql);
            int i = 1;
            setBoolean(ps, i++, true);
            ps.setInt(i++, revocationInfo.getReason().getCode());
            ps.setLong(i++, revocationInfo.getRevocationTime().getTime() / 1000);
            ps.setLong(i++, revocationInfo.getInvalidityTime().getTime() / 1000);
            ps.setString(i++, caName);
            ps.executeUpdate();
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
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
        LOG.info("Revoked CA '{}'", caName);

        auditLogPCIEvent(true, "REVOKE CA " + caName);
    }

    @Override
    public void unrevokeCa(String caName)
    throws CAMgmtException
    {
        asssertMasterMode();
        caName = caName.toUpperCase();
        ParamChecker.assertNotEmpty("caName", caName);
        if(x509cas.containsKey(caName) == false)
        {
            throw new CAMgmtException("Could not find CA named " + caName);
        }

        LOG.info("Unrevoking of CA '{}'", caName);

        final String sql = "UPDATE CA SET REVOKED=?, REV_REASON=?, REV_TIME=?, REV_INVALIDITY_TIME=? WHERE NAME=?";
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
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
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
        LOG.info("Unrevoked CA '{}'", caName);

        auditLogPCIEvent(true, "UNREVOKE CA " + caName);
    }

    public void setAuditServiceRegister(AuditLoggingServiceRegister serviceRegister)
    {
        this.auditServiceRegister = serviceRegister;

        for(String name : publishers.keySet())
        {
            IdentifiedX509CertPublisher publisherEntry = publishers.get(name);
            publisherEntry.setAuditServiceRegister(auditServiceRegister);
        }

        for(String name : x509cas.keySet())
        {
            X509CA ca = x509cas.get(name);
            ca.setAuditServiceRegister(serviceRegister);
        }
    }

    private void auditLogPCIEvent(boolean successfull, String eventType)
    {
        AuditLoggingService auditLoggingService =
                auditServiceRegister == null ? null : auditServiceRegister.getAuditLoggingService();
        if(auditLoggingService != null)
        {
            PCIAuditEvent auditEvent = new PCIAuditEvent(new Date());
            auditEvent.setUserId("SYSTEM");
            auditEvent.setEventType(eventType);
            auditEvent.setAffectedResource("CORE");
            if(successfull)
            {
                auditEvent.setStatus(AuditStatus.SUCCESSFUL.name());
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
        asssertMasterMode();

        if(caName == null)
        {
            try
            {
                certstore.clearPublishQueue((X509CertWithId) null, (String) null);
                return true;
            } catch (OperationException e)
            {
                throw new CAMgmtException(e.getMessage(), e);
            }
        }
        else
        {
            caName = caName.toUpperCase();
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

    @Override
    public boolean revokeCertificate(String caName, BigInteger serialNumber,
            CRLReason reason, Date invalidityTime)
    throws CAMgmtException
    {
        X509CA ca = getX509CA(caName);
        try
        {
            return ca.revokeCertificate(serialNumber, reason, invalidityTime) != null;
        } catch (OperationException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }
    }

    @Override
    public boolean unrevokeCertificate(String caName, BigInteger serialNumber)
    throws CAMgmtException
    {
        X509CA ca = getX509CA(caName);
        try
        {
            return ca.unrevokeCertificate(serialNumber) != null;
        } catch (OperationException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }
    }

    @Override
    public boolean removeCertificate(String caName, BigInteger serialNumber)
    throws CAMgmtException
    {
        asssertMasterMode();
        X509CA ca = getX509CA(caName);
        if(ca == null)
        {
            return false;
        }

        try
        {
            return ca.removeCertificate(serialNumber) != null;
        } catch (OperationException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }
    }

    @Override
    public X509Certificate generateCertificate(String caName,
            String profileName, String user, byte[] encodedPkcs10Request)
    throws CAMgmtException
    {
        X509CA ca = getX509CA(caName);

        CertificationRequest p10cr;
        try
        {
            p10cr = CertificationRequest.getInstance(encodedPkcs10Request);
        }catch(Exception e)
        {
            throw new CAMgmtException("Invalid PKCS#10 request. ERROR: " + e.getMessage());
        }

        if(securityFactory.verifyPOPO(p10cr) == false)
        {
            throw new CAMgmtException("could not validate POP for the pkcs#10 requst");
        }

        CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();
        Extensions extensions = null;
        ASN1Set attrs = certTemp.getAttributes();
        for(int i = 0; i < attrs.size(); i++)
        {
            Attribute attr = (Attribute) attrs.getObjectAt(i);
            if(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType()))
            {
                extensions = (Extensions) attr.getAttributeValues()[0];
            }
        }

        X500Name subject = certTemp.getSubject();
        SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

        X509CertificateInfo certInfo;
        try
        {
            certInfo = ca.generateCertificate(false, null, profileName, user, subject, publicKeyInfo,
                        null, null, extensions);
        } catch (OperationException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }

        return certInfo.getCert().getCert();
    }

    public X509CA getX509CA(String caName)
    throws CAMgmtException
    {
        X509CA ca = x509cas.get(caName.toUpperCase());
        if(ca == null)
        {
            throw new CAMgmtException("Unknown CA " + caName);
        }
        return ca;
    }

    public IdentifiedX509Certprofile getIdentifiedCertprofile(String profileName)
    {
        return certprofiles.get(profileName);
    }

    public List<IdentifiedX509CertPublisher> getIdentifiedPublishersForCa(String caName)
    {
        caName = caName.toUpperCase();
        List<IdentifiedX509CertPublisher> ret = new LinkedList<>();
        Set<String> publisherNames = ca_has_publishers.get(caName);
        if(publisherNames != null)
        {
            for(String publisherName : publisherNames)
            {
                IdentifiedX509CertPublisher publisher = publishers.get(publisherName);
                ret.add(publisher);
            }
        }
        return ret;
    }

    @Override
    public X509Certificate generateSelfSignedCA(
            String name, String certprofileName, byte[] p10Req,
            CAStatus status, long nextSerial, int nextCrlNumber,
            List<String> crl_uris, List<String> delta_crl_uris, List<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, String cmpcontrol_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            int numCrls, int expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException
    {
        asssertMasterMode();
        if(nextSerial < 0)
        {
            System.err.println("invalid serial number: " + nextSerial);
            return null;
        }

        if(numCrls < 0)
        {
            System.err.println("invalid numCrls: " + numCrls);
            return null;
        }

        if(expirationPeriod < 0)
        {
            System.err.println("invalid expirationPeriod: " + expirationPeriod);
            return null;
        }

        CertificationRequest p10Request;
        if(p10Req == null)
        {
            System.err.println("p10Req is null");
            return null;
        } else
        {
            try
            {
                p10Request = CertificationRequest.getInstance(p10Req);
            } catch (Exception e)
            {
                System.err.println("invalid p10Req");
                return null;
            }
        }

        IdentifiedX509Certprofile certprofile = getIdentifiedCertprofile(certprofileName);
        if(certprofile == null)
        {
            throw new CAMgmtException("unknown cert profile " + certprofileName);
        }

        long serialOfThisCert;
        if(nextSerial > 0)
        {
            serialOfThisCert = nextSerial;
            nextSerial ++;
        }
        else
        {
            serialOfThisCert = RandomSerialNumberGenerator.getInstance().getSerialNumber().longValue();
        }

        GenerateSelfSignedResult result;
        try
        {
            result = X509SelfSignedCertBuilder.generateSelfSigned(securityFactory, signer_type, signer_conf,
                    certprofile, p10Request, serialOfThisCert, ocsp_uris, crl_uris, delta_crl_uris);
        } catch (OperationException | ConfigurationException e)
        {
            throw new CAMgmtException(e.getClass().getName() + ": " + e.getMessage(), e);
        }

        String signerConf = result.getSignerConf();
        X509Certificate caCert = result.getCert();

        if("PKCS12".equalsIgnoreCase(signer_type) || "JKS".equalsIgnoreCase(signer_type))
        {
            try
            {
                signerConf = canonicalizeSignerConf(signer_type, signerConf, securityFactory.getPasswordResolver());
            } catch (Exception e)
            {
                throw new CAMgmtException(e.getClass().getName() + ": " + e.getMessage(), e);
            }
        }

        X509CAEntry entry = new X509CAEntry(name, nextSerial, nextCrlNumber, signer_type, signerConf, caCert,
                ocsp_uris, crl_uris, delta_crl_uris, null, numCrls, expirationPeriod);

        entry.setDuplicateKeyMode(duplicate_key);
        entry.setDuplicateSubjectMode(duplicate_subject);
        entry.setValidityMode(validityMode);
        entry.setStatus(status);
        if(crlsigner_name != null)
        {
            entry.setCrlSignerName(crlsigner_name);
        }
        if(cmpcontrol_name != null)
        {
            entry.setCmpControlName(cmpcontrol_name);
        }
        entry.setMaxValidity(max_validity);
        entry.setPermissions(permissions);

        addCA(entry);

        return caCert;
    }

    private void asssertMasterMode()
    throws CAMgmtException
    {
        if(masterMode == false)
        {
            throw new CAMgmtException("Operation not allowed in slave mode");
        }
    }

    @Override
    protected String getRealCertprofileType(String certprofileType)
    {
        return getRealType(envParameterResolver.getEnvParam("certprofileType.map"), certprofileType);
    }

    @Override
    protected String getRealPublisherType(String publisherType)
    {
        return getRealType(envParameterResolver.getEnvParam("publisherType.map"), publisherType);
    }

    private String getRealType(String typeMap, String type)
    {
        if(typeMap == null)
        {
            return null;
        }

        typeMap = typeMap.trim();
        if(typeMap.isEmpty())
        {
            return null;
        }

        CmpUtf8Pairs pairs;
        try
        {
            pairs = new CmpUtf8Pairs(typeMap);
        }catch(IllegalArgumentException e)
        {
            LOG.error("CA environment {}: '{}' is not valid CMP UTF-8 pairs",typeMap, type);
            return null;
        }
        return pairs.getValue(type);
    }

}
