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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertProfileException;
import org.xipki.ca.api.CertPublisherException;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.X509CertWithId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.impl.store.CertificateStore;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.ca.server.mgmt.api.CAMgmtException;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.CRLControl;
import org.xipki.ca.server.mgmt.api.CertArt;
import org.xipki.ca.server.mgmt.api.CertProfileEntry;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.ca.server.mgmt.api.X509CrlSignerEntry;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.ConfigurationException;
import org.xipki.common.IoUtil;
import org.xipki.common.LogUtil;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;
import org.xipki.common.StringUtil;
import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class BaseCAManager
{

    private static final Logger LOG = LoggerFactory.getLogger(BaseCAManager.class);

    protected CertificateStore certstore;
    protected DataSourceWrapper dataSource;
    protected SecurityFactory securityFactory;
    protected DataSourceFactory dataSourceFactory;
    private final Map<String, String> certprofileTypeMapping = new ConcurrentHashMap<String, String>();
    private final Map<String, String> publisherTypeMapping = new ConcurrentHashMap<String, String>();

    public BaseCAManager()
    {
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

    public void setCertprofileTypeMap(String certprofileTypeMap)
    {
        if(certprofileTypeMap == null)
        {
            LOG.debug("certprofileTypeMap is null");
            return;
        }

        certprofileTypeMap = certprofileTypeMap.trim();
        if(certprofileTypeMap.isEmpty())
        {
            LOG.debug("certprofileTypeMap is empty");
            return;
        }

        StringTokenizer st = new StringTokenizer(certprofileTypeMap, " \t");
        while(st.hasMoreTokens())
        {
            String token = st.nextToken();
            StringTokenizer st2 = new StringTokenizer(token, "=");
            if(st2.countTokens() != 2)
            {
                LOG.warn("invalid certprofileTypeMap entry '" + token + "'");
                continue;
            }

            String alias = st2.nextToken();
            if(certprofileTypeMapping.containsKey(alias))
            {
                LOG.warn("certprofile type alias '{}' already defined, ignore map '{}'", alias, token);
                continue;
            }
            String signerType = st2.nextToken();
            certprofileTypeMapping.put(alias, signerType);
            LOG.info("add alias '{}' for certprofile type '{}'", alias, signerType);
        }
    }

    public void setPublisherTypeMap(String publisherTypeMap)
    {
        if(publisherTypeMap == null)
        {
            LOG.debug("publisherTypeMap is null");
            return;
        }

        publisherTypeMap = publisherTypeMap.trim();
        if(publisherTypeMap.isEmpty())
        {
            LOG.debug("publisherTypeMap is empty");
            return;
        }

        StringTokenizer st = new StringTokenizer(publisherTypeMap, " \t");
        while(st.hasMoreTokens())
        {
            String token = st.nextToken();
            StringTokenizer st2 = new StringTokenizer(token, "=");
            if(st2.countTokens() != 2)
            {
                LOG.warn("invalid publisherTypeMap entry '" + token + "'");
                continue;
            }

            String alias = st2.nextToken();
            if(publisherTypeMapping.containsKey(alias))
            {
                LOG.warn("publisher type alias '" + alias + "' already defined, ignore map '" + token +"'");
                continue;
            }
            String signerType = st2.nextToken();
            publisherTypeMapping.put(alias, signerType);
            LOG.info("add alias '" + alias + "' for publisher type '" + signerType + "'");
        }
    }

    protected X509Certificate generateCert(String b64Cert)
    throws CAMgmtException
    {
        if(b64Cert == null)
        {
            return null;
        }

        byte[] encodedCert = Base64.decode(b64Cert);
        try
        {
            return SecurityUtil.parseCert(encodedCert);
        } catch (CertificateException | IOException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }
    }

    protected static String toString(Set<String> tokens, String seperator)
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

        List<String> l = StringUtil.split(permissionsText, ", ");
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

    protected static String getRealString(String s)
    {
        return CAManager.NULL.equalsIgnoreCase(s) ? null : s;
    }

    protected static void assertNotNULL(String parameterName, String parameterValue)
    {
        if(CAManager.NULL.equalsIgnoreCase(parameterValue))
        {
            throw new IllegalArgumentException(parameterName + " could not be " + CAManager.NULL);
        }
    }

    protected Statement createStatement()
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

    protected PreparedStatement prepareFetchFirstStatement(String sql)
    throws CAMgmtException
    {
        return prepareStatement(dataSource.createFetchFirstSelectSQL(sql, 1));
    }

    protected PreparedStatement prepareStatement(String sql)
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

    protected static void setBoolean(PreparedStatement ps, int index, boolean b)
    throws SQLException
    {
        ps.setInt(index, b ? 1 : 0);
    }

    public static String canonicalizeSignerConf(String keystoreType, String signerConf,
            PasswordResolver passwordResolver)
    throws Exception
    {
        if(signerConf.contains("file:") == false && signerConf.contains("base64:") == false )
        {
            return signerConf;
        }

        CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(signerConf);
        String keystoreConf = utf8Pairs.getValue("keystore");
        String passwordHint = utf8Pairs.getValue("password");
        String keyLabel     = utf8Pairs.getValue("key-label");

        byte[] keystoreBytes;
        if(keystoreConf.startsWith("file:"))
        {
            String keystoreFile = keystoreConf.substring("file:".length());
            keystoreBytes = IoUtil.read(keystoreFile);
        }
        else if(keystoreConf.startsWith("base64:"))
        {
            keystoreBytes = Base64.decode(keystoreConf.substring("base64:".length()));
        }
        else
        {
            return signerConf;
        }

        keystoreBytes = SecurityUtil.extractMinimalKeyStore(keystoreType,
                keystoreBytes, keyLabel,
                passwordResolver.resolvePassword(passwordHint));

        utf8Pairs.putUtf8Pair("keystore", "base64:" + Base64.toBase64String(keystoreBytes));
        return utf8Pairs.getEncoded();
    }

    protected static Integer addToSqlIfNotNull(StringBuilder sqlBuilder, AtomicInteger index,
            Object columnObj, String columnName)
    {
        if(columnObj == null)
        {
            return null;
        }

        sqlBuilder.append(columnName).append("=?,");
        return index.getAndIncrement();
    }

    protected void shutdownCertProfile(IdentifiedX509CertProfile profile)
    {
        if(profile == null)
        {
            return;
        }

        try
        {
            profile.shutdown();
        } catch(Exception e)
        {
            final String message = "could not shutdown CertProfile " + profile.getName();
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    protected void shutdownPublisher(IdentifiedX509CertPublisher publisher)
    {
        if(publisher == null)
        {
            return;
        }

        try
        {
            publisher.shutdown();
        } catch(Exception e)
        {
            final String message = "could not shutdown CertPublisher " + publisher.getName();
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    protected IdentifiedX509CertProfile createCertProfile(String name, EnvironmentParameterResolver envParameterResolver)
    throws CAMgmtException
    {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
            final String sql = "TYPE, CONF FROM CERTPROFILE WHERE NAME=?";
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if(rs.next())
            {
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");

                try
                {
                    CertProfileEntry rawEntry = new CertProfileEntry(name, type, conf);
                    String realType = certprofileTypeMapping.get(type);
                    IdentifiedX509CertProfile ret = new IdentifiedX509CertProfile(rawEntry, realType);
                    ret.setEnvironmentParameterResolver(envParameterResolver);
                    ret.validate();
                    return ret;
                }catch(CertProfileException e)
                {
                    final String message = "could not initialize CertProfile " + name + ", ignore it";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                }
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        } finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        return null;
    }

    protected List<String> getNamesFromTable(String table)
    throws CAMgmtException
    {
        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            final String sql = new StringBuilder("SELECT NAME FROM ").append(table).toString();
            rs = stmt.executeQuery(sql);

            List<String> names = new LinkedList<>();

            while(rs.next())
            {
                String name = rs.getString("NAME");
                if(name != null && name.isEmpty() == false)
                {
                    names.add(name);
                }
            }

            return names;
        } catch(SQLException e)
        {
            throw new CAMgmtException("SQLException: " + e.getMessage(), e);
        }
        finally
        {
            dataSource.releaseResources(stmt, rs);
        }
    }

    protected IdentifiedX509CertPublisher createPublisher(String name, Map<String, DataSourceWrapper> dataSources)
    throws CAMgmtException
    {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
            final String sql = "TYPE, CONF FROM PUBLISHER WHERE NAME=?";
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if(rs.next())
            {
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");

                PublisherEntry rawEntry = new PublisherEntry(name, type, conf);
                String realType = publisherTypeMapping.get(type);
                IdentifiedX509CertPublisher ret;
                try
                {
                    ret = new IdentifiedX509CertPublisher(rawEntry, realType);
                    ret.initialize(securityFactory.getPasswordResolver(), dataSources);
                    return ret;
                } catch(CertPublisherException | RuntimeException e)
                {
                    final String message = "Invalid configuration for the certPublisher " + name;
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                }
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        return null;
    }

    protected CmpRequestorEntryWrapper createRequestor(String name)
    throws CAMgmtException
    {
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try
        {
            final String sql = "CERT FROM REQUESTOR WHERE NAME=?";
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if(rs.next())
            {
                String b64Cert = rs.getString("CERT");
                X509Certificate cert = generateCert(b64Cert);
                CmpRequestorEntry entry = new CmpRequestorEntry(name);
                entry.setCert(cert);

                CmpRequestorEntryWrapper ret = new CmpRequestorEntryWrapper();
                ret.setDbEntry(entry);
                return ret;
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        return null;
    }

    protected X509CrlSignerEntryWrapper createCrlSigner(String name)
    throws CAMgmtException
    {
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try
        {
            final String sql = "SIGNER_TYPE, SIGNER_CONF, SIGNER_CERT, CRL_CONTROL FROM CRLSIGNER WHERE NAME=?";
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if(rs.next())
            {
                String signer_type = rs.getString("SIGNER_TYPE");
                String signer_conf = rs.getString("SIGNER_CONF");
                String signer_cert = rs.getString("SIGNER_CERT");
                String crlControlConf = rs.getString("CRL_CONTROL");
                CRLControl crlControl = CRLControl.getInstance(crlControlConf);

                X509CrlSignerEntry entry = new X509CrlSignerEntry(name, signer_type, signer_conf, crlControl);
                if("CA".equalsIgnoreCase(signer_type) == false)
                {
                    if(signer_cert != null)
                    {
                        entry.setCertificate(generateCert(signer_cert));
                    }
                }
                X509CrlSignerEntryWrapper signer = new X509CrlSignerEntryWrapper();
                signer.setDbEntry(entry);
                return signer;
            }
        }catch(SQLException | ConfigurationException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }
        return null;
    }

    protected CmpControl createCmpControl()
    throws CAMgmtException
    {
        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            final String sql = "SELECT REQUIRE_CONFIRM_CERT, SEND_CA_CERT, SEND_RESPONDER_CERT" +
                    ", REQUIRE_MESSAGE_TIME, MESSAGE_TIME_BIAS, CONFIRM_WAIT_TIME" +
                    " FROM CMPCONTROL";

            rs = stmt.executeQuery(sql);

            CmpControl cmpControl = null;
            String errorMsg = null;
            while(rs.next())
            {
                if(cmpControl != null)
                {
                    errorMsg = "More than one CMPCONTROL is configured, but maximal one is allowed";
                }
                boolean requireConfirmCert = rs.getBoolean("REQUIRE_CONFIRM_CERT");
                boolean sendCaCert = rs.getBoolean("SEND_CA_CERT");
                boolean sendResponderCert = rs.getBoolean("SEND_RESPONDER_CERT");
                boolean requireMessageTime = rs.getBoolean("REQUIRE_MESSAGE_TIME");
                int messageTimeBias = rs.getInt("MESSAGE_TIME_BIAS");
                int confirmWaitTime = rs.getInt("CONFIRM_WAIT_TIME");

                cmpControl = new CmpControl();
                cmpControl.setRequireConfirmCert(requireConfirmCert);
                cmpControl.setSendCaCert(sendCaCert);
                cmpControl.setSendResponderCert(sendResponderCert);
                cmpControl.setMessageTimeRequired(requireMessageTime);
                if(messageTimeBias != 0)
                {
                    cmpControl.setMessageBias(messageTimeBias);
                }
                if(confirmWaitTime != 0)
                {
                    cmpControl.setConfirmWaitTime(confirmWaitTime);
                }
            }

            if(errorMsg != null)
            {
                throw new CAMgmtException(errorMsg);
            }

            return cmpControl;
        }catch(SQLException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }
    }

    protected CmpResponderEntryWrapper createResponder()
    throws CAMgmtException
    {
        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery("SELECT TYPE, CONF, CERT FROM RESPONDER");

            CmpResponderEntry dbEntry = null;
            String errorMsg = null;
            while(rs.next())
            {
                if(dbEntry != null)
                {
                    errorMsg = "More than one CMPResponder is configured, but maximal one is allowed";
                }

                dbEntry = new CmpResponderEntry();

                String type = rs.getString("TYPE");
                dbEntry.setType(type);

                String conf = rs.getString("CONF");
                dbEntry.setConf(conf);

                String b64Cert = rs.getString("CERT");
                if(b64Cert != null)
                {
                    X509Certificate cert = generateCert(b64Cert);
                    dbEntry.setCertificate(cert);
                }
            }

            if(errorMsg != null)
            {
                throw new CAMgmtException(errorMsg);
            }

            if(dbEntry == null)
            {
                return null;
            }

            CmpResponderEntryWrapper ret = new CmpResponderEntryWrapper();
            ret.setDbEntry(dbEntry);

            try
            {
                ret.initSigner(securityFactory);
            } catch (SignerException e)
            {
                final String message = "CmpResponderEntryWrapper.initSigner()";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
            }

            return ret;
        }catch(SQLException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }
    }

    protected X509CAInfo createCAInfo(String name, boolean masterMode)
    throws CAMgmtException
    {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
            final String sql = "NAME, ART, NEXT_SERIAL, NEXT_CRLNO, STATUS, CRL_URIS, OCSP_URIS, MAX_VALIDITY" +
                    ", CERT, SIGNER_TYPE, SIGNER_CONF, CRLSIGNER_NAME" +
                    ", DUPLICATE_KEY_MODE, DUPLICATE_SUBJECT_MODE, PERMISSIONS, NUM_CRLS" +
                    ", EXPIRATION_PERIOD, REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME" +
                    ", DELTA_CRL_URIS, VALIDITY_MODE" +
                    " FROM CA WHERE NAME=?";
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if(rs.next())
            {
                int artCode = rs.getInt("ART");
                if(artCode != CertArt.X509PKC.getCode())
                {
                    throw new CAMgmtException("CA " + name + " is not X509CA, and is not supported");
                }

                long next_serial = rs.getLong("NEXT_SERIAL");
                int next_crlNo = rs.getInt("NEXT_CRLNO");
                String status = rs.getString("STATUS");
                String crl_uris = rs.getString("CRL_URIS");
                String delta_crl_uris = rs.getString("DELTA_CRL_URIS");
                String ocsp_uris = rs.getString("OCSP_URIS");
                String max_validityS = rs.getString("MAX_VALIDITY");
                CertValidity max_validity = CertValidity.getInstance(max_validityS);
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
                    lCrlUris = StringUtil.split(crl_uris, " \t");
                }

                List<String> lDeltaCrlUris = null;
                if(delta_crl_uris != null && delta_crl_uris.isEmpty() == false)
                {
                    lDeltaCrlUris = StringUtil.split(delta_crl_uris, " \t");
                }

                List<String> lOcspUris = null;
                if(ocsp_uris != null && ocsp_uris.isEmpty() == false)
                {
                    lOcspUris = StringUtil.split(ocsp_uris, " \t");
                }

                X509Certificate cert = generateCert(b64cert);

                X509CAEntry entry = new X509CAEntry(name, next_serial, next_crlNo, signer_type, signer_conf, cert,
                        lOcspUris, lCrlUris, lDeltaCrlUris, null, numCrls, expirationPeriod);

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

                String validityModeS = rs.getString("VALIDITY_MODE");
                ValidityMode validityMode = null;
                if(validityModeS != null)
                {
                    validityMode = ValidityMode.getInstance(validityModeS);
                }
                if(validityMode == null)
                {
                    validityMode = ValidityMode.STRICT;
                }
                entry.setValidityMode(validityMode);

                try
                {
                    if(masterMode)
                    {
                        X509CertWithId cm = new X509CertWithId(entry.getCertificate());
                        certstore.addCa(cm);
                    }

                    X509CAInfo caInfo = new X509CAInfo(entry, certstore);
                    return caInfo;
                } catch (OperationException e)
                {
                    throw new CAMgmtException(e.getMessage(), e);
                }
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        return null;
    }

    protected Set<CAHasRequestorEntry> createCAhasRequestors(String caName)
    throws CAMgmtException
    {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
            final String sql = "SELECT REQUESTOR_NAME, RA, PERMISSIONS, PROFILES FROM CA_HAS_REQUESTOR" +
                    " WHERE CA_NAME=?";
            stmt = prepareStatement(sql);
            stmt.setString(1, caName);
            rs = stmt.executeQuery();

            Set<CAHasRequestorEntry> ret = new HashSet<>();
            while(rs.next())
            {
                String requestorName = rs.getString("REQUESTOR_NAME");
                boolean ra = rs.getBoolean("RA");
                String s = rs.getString("PERMISSIONS");
                Set<Permission> permissions = getPermissions(s);

                s = rs.getString("PROFILES");
                List<String> list = StringUtil.split(s, ",");
                Set<String> profiles = (list == null)? null : new HashSet<>(list);
                CAHasRequestorEntry entry = new CAHasRequestorEntry(requestorName);
                entry.setRa(ra);
                entry.setPermissions(permissions);
                entry.setProfiles(profiles);

                ret.add(entry);
            }

            return ret;
        }catch(SQLException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }
    }

    protected Set<String> createCAhasCertProfiles(String caName)
    throws CAMgmtException
    {
        return createCAhasNames(caName, "CERTPROFILE_NAME", "CA_HAS_CERTPROFILE");
    }

    protected Set<String> createCAhasPublishers(String caName)
    throws CAMgmtException
    {
        return createCAhasNames(caName, "PUBLISHER_NAME", "CA_HAS_PUBLISHER");
    }

    protected Set<String> createCAhasNames(String caName, String columnName, String table)
    throws CAMgmtException
    {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
            final String sql = new StringBuilder("SELECT ").append(columnName).append(" FROM ")
                .append(table).append(" WHERE CA_NAME=?").toString();
            stmt = prepareStatement(sql);
            stmt.setString(1, caName);
            rs = stmt.executeQuery();

            Set<String> ret = new HashSet<>();
            while(rs.next())
            {
                String certprofileName = rs.getString(columnName);
                ret.add(certprofileName);
            }

            return ret;
        }catch(SQLException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }
    }

    protected void deleteRowWithName(String name, String table)
    throws CAMgmtException
    {
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(new StringBuilder("DELETE FROM ").append(table).append(" WHERE NAME=?").toString());
            ps.setString(1, name);
            int rows = ps.executeUpdate();
            if(rows != 1)
            {
                throw new CAMgmtException("Could not remove " + table + " " + name);
            }
        }catch(SQLException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    protected void deleteRows(String table)
    throws CAMgmtException
    {
        Statement stmt = null;
        try
        {
            String sql = "DELETE FROM " + table;
            stmt = createStatement();
            stmt.executeQuery(sql);
        }catch(SQLException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(stmt, null);
        }
    }

}
