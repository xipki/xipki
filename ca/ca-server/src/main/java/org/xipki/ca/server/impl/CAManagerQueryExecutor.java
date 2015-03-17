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
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertPublisherException;
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.X509CertWithDBCertId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.impl.store.CertificateStore;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.ca.server.mgmt.api.CAMgmtException;
import org.xipki.ca.server.mgmt.api.CAStatus;
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
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.ConfigurationException;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.SecurityUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

class CAManagerQueryExecutor
{

    private static final Logger LOG = LoggerFactory.getLogger(CAManagerQueryExecutor.class);

    private DataSourceWrapper dataSource;

    CAManagerQueryExecutor(DataSourceWrapper dataSource)
    {
        ParamChecker.assertNotNull("dataSource", dataSource);
        this.dataSource = dataSource;
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
            return SecurityUtil.parseCert(encodedCert);
        } catch (CertificateException | IOException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }
    }

    private Statement createStatement()
    throws CAMgmtException
    {
        Connection dsConnection;
        try
        {
            dsConnection = dataSource.getConnection();
        } catch (DataAccessException e)
        {
            throw new CAMgmtException("Could not get connection", e);
        }

        try
        {
            return dataSource.createStatement(dsConnection);
        }catch(DataAccessException e)
        {
            throw new CAMgmtException("Could not create statement", e);
        }
    }

    private PreparedStatement prepareFetchFirstStatement(String sql)
    throws CAMgmtException
    {
        return prepareStatement(dataSource.createFetchFirstSelectSQL(sql, 1));
    }

    private PreparedStatement prepareStatement(String sql)
    throws CAMgmtException
    {
        Connection dsConnection;
        try
        {
            dsConnection = dataSource.getConnection();
        } catch (DataAccessException e)
        {
            throw new CAMgmtException("Could not get connection", e);
        }

        try
        {
            return dataSource.prepareStatement(dsConnection, sql);
        }catch(DataAccessException e)
        {
            throw new CAMgmtException("Could not get connection", e);
        }
    }

    void shutdownCertprofile(IdentifiedX509Certprofile profile)
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
            final String message = "could not shutdown Certprofile " + profile.getName();
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    void shutdownPublisher(IdentifiedX509CertPublisher publisher)
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

    SystemEvent getSystemEvent(String eventName)
    throws CAMgmtException
    {
        final String sql = "SELECT EVENT_TIME, EVENT_OWNER FROM SYSTEM_EVENT WHERE NAME=?";
        PreparedStatement ps = null;
        ResultSet rs = null;

        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, eventName);
            rs = ps.executeQuery();

            if(rs.next())
            {
                long eventTime = rs.getLong("EVENT_TIME");
                String eventOwner = rs.getString("EVENT_OWNER");
                return new SystemEvent(eventName, eventOwner, eventTime);
            } else
            {
                return null;
            }
        } catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        } finally
        {
            dataSource.releaseResources(ps, rs);
        }
    }

    void deleteSystemEvent(String eventName)
    throws CAMgmtException
    {
        final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME=?";
        PreparedStatement ps = null;

        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, eventName);
            ps.executeUpdate();
        } catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        } finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    void addSystemEvent(SystemEvent systemEvent)
    throws CAMgmtException
    {
        final String sql = "INSERT INTO SYSTEM_EVENT (NAME, EVENT_TIME, EVENT_TIME2, EVENT_OWNER)"
                + " VALUES (?, ?, ?, ?)";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, systemEvent.getName());
            ps.setLong(idx++, systemEvent.getEventTime());
            ps.setTimestamp(idx++, new Timestamp(systemEvent.getEventTime() * 1000L));
            ps.setString(idx++, systemEvent.getOwner());
        } catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean changeSystemEvent(SystemEvent systemEvent)
    throws CAMgmtException
    {
        deleteSystemEvent(systemEvent.getName());
        addSystemEvent(systemEvent);
        return true;
    }

    Map<String, String> createEnvParameters()
    throws CAMgmtException
    {
        Map<String, String> map = new HashMap<>();
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
                map.put(name, value);
            }
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        return map;
    }

    Map<String, String> createCaAliases()
    throws CAMgmtException
    {
        Map<String, String> map = new HashMap<>();

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
                map.put(name, caName);
            }
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        return map;
    }

    IdentifiedX509Certprofile createCertprofile(String name, EnvironmentParameterResolver envParamResolver)
    throws CAMgmtException
    {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        final String sql = "TYPE, CONF FROM CERTPROFILE WHERE NAME=?";
        try
        {
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if(rs.next())
            {
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");

                try
                {
                    CertprofileEntry rawEntry = new CertprofileEntry(name, type, conf);
                    String realType = getRealCertprofileType(type, envParamResolver);
                    IdentifiedX509Certprofile ret = new IdentifiedX509Certprofile(rawEntry, realType);
                    ret.setEnvironmentParameterResolver(envParamResolver);
                    ret.validate();
                    return ret;
                }catch(CertprofileException e)
                {
                    final String message = "could not initialize Certprofile " + name + ", ignore it";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                }
            }
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        } finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        return null;
    }

    List<String> getNamesFromTable(String table)
    throws CAMgmtException
    {
        final String sql = new StringBuilder("SELECT NAME FROM ").append(table).toString();
        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            List<String> names = new LinkedList<>();

            while(rs.next())
            {
                String name = rs.getString("NAME");
                if(StringUtil.isNotBlank(name))
                {
                    names.add(name);
                }
            }

            return names;
        } catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }
        finally
        {
            dataSource.releaseResources(stmt, rs);
        }
    }

    IdentifiedX509CertPublisher createPublisher(
            String name, Map<String, DataSourceWrapper> dataSources,
            PasswordResolver pwdResolver, EnvironmentParameterResolver envParamResolver)
    throws CAMgmtException
    {
        final String sql = "TYPE, CONF FROM PUBLISHER WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if(rs.next())
            {
                String type = rs.getString("TYPE");
                String conf = rs.getString("CONF");

                PublisherEntry rawEntry = new PublisherEntry(name, type, conf);
                String realType = getRealPublisherType(type, envParamResolver);
                IdentifiedX509CertPublisher ret;
                try
                {
                    ret = new IdentifiedX509CertPublisher(rawEntry, realType);
                    ret.initialize(pwdResolver, dataSources);
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
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        return null;
    }

    CmpRequestorEntryWrapper createRequestor(String name)
    throws CAMgmtException
    {
        final String sql = "CERT FROM REQUESTOR WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try
        {
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
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        return null;
    }

    X509CrlSignerEntryWrapper createCrlSigner(String name)
    throws CAMgmtException
    {
        final String sql = "SIGNER_TYPE, SIGNER_CONF, SIGNER_CERT, CRL_CONTROL FROM CRLSIGNER WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try
        {
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
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }catch(ConfigurationException e)
        {
            throw new CAMgmtException(e.getMessage(), e);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }
        return null;
    }

    CmpControl createCmpControl(String name)
    throws CAMgmtException
    {
        final String sql = "REQUIRE_CONFIRM_CERT, SEND_CA_CERT, SEND_RESPONDER_CERT" +
                ", REQUIRE_MESSAGE_TIME, MESSAGE_TIME_BIAS, CONFIRM_WAIT_TIME" +
                " FROM CMPCONTROL WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if(rs.next() == false)
            {
                return null;
            }

            boolean requireConfirmCert = rs.getBoolean("REQUIRE_CONFIRM_CERT");
            boolean sendCaCert = rs.getBoolean("SEND_CA_CERT");
            boolean sendResponderCert = rs.getBoolean("SEND_RESPONDER_CERT");
            boolean requireMessageTime = rs.getBoolean("REQUIRE_MESSAGE_TIME");
            int messageTimeBias = rs.getInt("MESSAGE_TIME_BIAS");
            int confirmWaitTime = rs.getInt("CONFIRM_WAIT_TIME");

            CmpControl cmpControl = new CmpControl(name);
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
            return cmpControl;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }
    }

    CmpResponderEntryWrapper createResponder(SecurityFactory securityFactory)
    throws CAMgmtException
    {
        final String sql = "SELECT TYPE, CONF, CERT FROM RESPONDER";
        Statement stmt = null;
        ResultSet rs = null;

        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

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
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }
    }

    X509CAInfo createCAInfo(String name, boolean masterMode, CertificateStore certstore)
    throws CAMgmtException
    {
        final String sql = "NAME, ART, NEXT_SERIAL, NEXT_CRLNO, STATUS, CRL_URIS, OCSP_URIS, MAX_VALIDITY" +
                ", CERT, SIGNER_TYPE, SIGNER_CONF, CRLSIGNER_NAME, CMPCONTROL_NAME" +
                ", DUPLICATE_KEY_MODE, DUPLICATE_SUBJECT_MODE, PERMISSIONS, NUM_CRLS" +
                ", EXPIRATION_PERIOD, REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME" +
                ", DELTA_CRL_URIS, VALIDITY_MODE" +
                " FROM CA WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
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
                String cmpcontrol_name = rs.getString("CMPCONTROL_NAME");
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
                if(StringUtil.isNotBlank(crl_uris))
                {
                    lCrlUris = StringUtil.split(crl_uris, " \t");
                }

                List<String> lDeltaCrlUris = null;
                if(StringUtil.isNotBlank(delta_crl_uris))
                {
                    lDeltaCrlUris = StringUtil.split(delta_crl_uris, " \t");
                }

                List<String> lOcspUris = null;
                if(StringUtil.isNotBlank(ocsp_uris))
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

                if(cmpcontrol_name != null)
                {
                    entry.setCmpControlName(cmpcontrol_name);
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
                        X509CertWithDBCertId cm = new X509CertWithDBCertId(entry.getCertificate());
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
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }

        return null;
    }

    Set<CAHasRequestorEntry> createCAhasRequestors(String caName)
    throws CAMgmtException
    {
        final String sql = "SELECT REQUESTOR_NAME, RA, PERMISSIONS, PROFILES FROM CA_HAS_REQUESTOR" +
                " WHERE CA_NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
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
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }
    }

    Set<String> createCAhasCertprofiles(String caName)
    throws CAMgmtException
    {
        return createCAhasNames(caName, "CERTPROFILE_NAME", "CA_HAS_CERTPROFILE");
    }

    Set<String> createCAhasPublishers(String caName)
    throws CAMgmtException
    {
        return createCAhasNames(caName, "PUBLISHER_NAME", "CA_HAS_PUBLISHER");
    }

    Set<String> createCAhasNames(String caName, String columnName, String table)
    throws CAMgmtException
    {
        final String sql = new StringBuilder("SELECT ").append(columnName).append(" FROM ")
                .append(table).append(" WHERE CA_NAME=?").toString();
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
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
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, rs);
        }
    }

    boolean deleteRowWithName(String name, String table)
    throws CAMgmtException
    {
        final String sql = new StringBuilder("DELETE FROM ").append(table).append(" WHERE NAME=?").toString();
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            return ps.executeUpdate() > 0;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean deleteRows(String table)
    throws CAMgmtException
    {
        final String sql = "DELETE FROM " + table;
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            stmt.executeQuery(sql);
            return true;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(stmt, null);
        }
    }

    void addCA(X509CAEntry newCaDbEntry)
    throws CAMgmtException
    {
        String name = newCaDbEntry.getName();

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
    }

    void addCaAlias(String aliasName, String caName)
    throws CAMgmtException
    {
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
    }

    void addCertprofile(CertprofileEntry dbEntry)
    throws CAMgmtException
    {
        final String sql = "INSERT INTO CERTPROFILE (NAME, ART, TYPE, CONF) VALUES (?, ?, ?, ?)";
        final String name = dbEntry.getName();

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
    }

    void addCertprofileToCA(String profileName, String caName)
    throws CAMgmtException
    {
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
    }

    void addCmpControl(CmpControl dbEntry)
    throws CAMgmtException
    {
        final String name = dbEntry.getName();

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
    }

    void addCmpRequestor(CmpRequestorEntry dbEntry)
    throws CAMgmtException
    {
        String name = dbEntry.getName();

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
    }

    void addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
    throws CAMgmtException
    {
        final String requestorName = requestor.getRequestorName();

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
    }

    void addCrlSigner(X509CrlSignerEntry dbEntry)
    throws CAMgmtException
    {
        String name = dbEntry.getName();
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
    }

    void addEnvParam(String name, String value)
    throws CAMgmtException
    {
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
    }

    void addPublisher(PublisherEntry dbEntry)
    throws CAMgmtException
    {
        String name = dbEntry.getName();
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
    }

    void addPublisherToCA(String publisherName, String caName)
    throws CAMgmtException
    {
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
    }

    boolean changeCA(String name, CAStatus status, X509Certificate cert,
            Set<String> crl_uris, Set<String> delta_crl_uris, Set<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, String cmpcontrol_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException
    {
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
            return false;
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
            return true;
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
    }

    boolean changeCertprofile(String name, String type, String conf)
    throws CAMgmtException
    {
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
            return true;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean changeCmpControl(String name, Boolean requireConfirmCert,
            Boolean requireMessageTime, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert, Boolean sendResponderCert)
    throws CAMgmtException
    {
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
            return true;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean changeCmpRequestor(String name, String cert)
    throws CAMgmtException
    {
        final String sql = "UPDATE REQUESTOR SET CERT=? WHERE NAME=?";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            String b64Cert = getRealString(cert);
            ps.setString(1, b64Cert);
            ps.setString(2, name);
            ps.executeUpdate();

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
            LOG.info("change CMP requestor '{}': {}", name, subject);
            return true;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean changeCmpResponder(String type, String conf, String cert)
    throws CAMgmtException
    {
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
                }
                else
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
                m.append("'; ");
                ps.setString(iCert, txt);
            }

            ps.setString(index.get(), CmpResponderEntry.name);

            ps.executeUpdate();

            if(m.length() > 0)
            {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("change CMP responder: {}", m);
            return true;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean changeCrlSigner(String name, String signer_type, String signer_conf, String signer_cert,
            CRLControl crlControl)
    throws CAMgmtException
    {
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
            return false;
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
            LOG.info("change CRL signer '{}': {}", name, m);
            return true;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean changeEnvParam(String name, String value)
    throws CAMgmtException
    {
        final String sql = "UPDATE ENVIRONMENT SET VALUE2=? WHERE NAME=?";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, getRealString(value));
            ps.setString(2, name);
            ps.executeUpdate();
            LOG.info("change environment param '{}': {}", name, value);
            return true;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean changePublisher(String name, String type, String conf)
    throws CAMgmtException
    {
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE PUBLISHER SET ");

        AtomicInteger index = new AtomicInteger(1);
        Integer iType = addToSqlIfNotNull(sqlBuilder, index, type, "TYPE");
        Integer iConf = addToSqlIfNotNull(sqlBuilder, index, conf, "CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if(index.get() == 1)
        {
            return false;
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
            LOG.info("change publisher '{}': {}", name, m);
            return true;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean removeCA(String caName)
    throws CAMgmtException
    {
        final String sql = "DELETE FROM CA WHERE NAME=?";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            return ps.executeUpdate() > 0;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean removeCaAlias(String aliasName)
    throws CAMgmtException
    {
        final String sql = "DELETE FROM CAALIAS WHERE NAME=?";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, aliasName);
            boolean b = ps.executeUpdate() > 0;
            if(b)
            {
                LOG.info("remove CA alias '{}'", aliasName);
            }
            return b;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean removeCertprofileFromCA(String profileName, String caName)
    throws CAMgmtException
    {
        final String sql = "DELETE FROM CA_HAS_CERTPROFILE WHERE CA_NAME=? AND CERTPROFILE_NAME=?";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, profileName);
            boolean b = ps.executeUpdate() > 0;
            if(b)
            {
                LOG.info("remove profile '{}' from CA '{}'", profileName, caName);
            }
            return b;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean removeCmpRequestorFromCA(String requestorName, String caName)
    throws CAMgmtException
    {
        final String sql = "DELETE FROM CA_HAS_REQUESTOR WHERE CA_NAME=? AND REQUESTOR_NAME=?";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, requestorName);
            boolean b = ps.executeUpdate() > 0;
            if(b)
            {
                LOG.info("remove requestor '{}' from CA '{}'", requestorName, caName);
            }
            return b;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean removePublisherFromCA(String publisherName, String caName)
    throws CAMgmtException
    {
        final String sql = "DELETE FROM CA_HAS_PUBLISHER WHERE CA_NAME=? AND PUBLISHER_NAME=?";
        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, publisherName);
            boolean b = ps.executeUpdate() > 0;
            if(b)
            {
                LOG.info("remove publisher '{}' from CA '{}'", publisherName, caName);
            }
            return b;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    boolean revokeCa(String caName, CertRevocationInfo revocationInfo)
    throws CAMgmtException
    {
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
            boolean b = ps.executeUpdate() > 0;
            if(b)
            {
                LOG.info("revoked CA '{}'", caName);
            }
            return b;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    void setCmpResponder(CmpResponderEntry dbEntry)
    throws CAMgmtException
    {
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
    }

    boolean unlockCA()
    throws DataAccessException, CAMgmtException
    {
        final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME='LOCK'";
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            stmt.execute(sql);
            return stmt.getUpdateCount() > 0;
        }catch(SQLException e)
        {
            throw dataSource.translate(sql, e);
        } finally
        {
            dataSource.releaseResources(stmt, null);
        }
    }

    boolean unrevokeCa(String caName)
    throws CAMgmtException
    {
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
            return ps.executeUpdate() > 0;
        }catch(SQLException e)
        {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CAMgmtException(tEx.getMessage(), tEx);
        }finally
        {
            dataSource.releaseResources(ps, null);
        }
    }

    private String getRealCertprofileType(String certprofileType, EnvironmentParameterResolver envParameterResolver)
    {
        return getRealType(envParameterResolver.getParameterValue("certprofileType.map"), certprofileType);
    }

    private String getRealPublisherType(String publisherType, EnvironmentParameterResolver envParameterResolver)
    {
        return getRealType(envParameterResolver.getParameterValue("publisherType.map"), publisherType);
    }

    private String getRealType(String typeMap, String type)
    {
        if(typeMap == null)
        {
            return null;
        }

        typeMap = typeMap.trim();
        if(StringUtil.isBlank(typeMap))
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

    private static void setBoolean(PreparedStatement ps, int index, boolean b)
    throws SQLException
    {
        ps.setInt(index, b ? 1 : 0);
    }

    private static Integer addToSqlIfNotNull(StringBuilder sqlBuilder, AtomicInteger index,
            Object columnObj, String columnName)
    {
        if(columnObj == null)
        {
            return null;
        }

        sqlBuilder.append(columnName).append("=?,");
        return index.getAndIncrement();
    }

    private static Set<Permission> getPermissions(String permissionsText)
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

    private static String toString(Set<String> tokens, String seperator)
    {
        if(CollectionUtil.isEmpty(tokens))
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

    private static String getRealString(String s)
    {
        return CAManager.NULL.equalsIgnoreCase(s) ? null : s;
    }

}
