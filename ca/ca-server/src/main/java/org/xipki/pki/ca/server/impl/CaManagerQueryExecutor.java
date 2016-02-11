/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Collection;
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
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.util.PasswordHash;
import org.xipki.commons.security.api.util.SecurityUtil;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.X509Cert;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.server.impl.cmp.CmpRequestorEntryWrapper;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderEntryWrapper;
import org.xipki.pki.ca.server.impl.scep.Scep;
import org.xipki.pki.ca.server.impl.store.CertificateStore;
import org.xipki.pki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CaManager;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.CrlControl;
import org.xipki.pki.ca.server.mgmt.api.CertArt;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControl;
import org.xipki.pki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.pki.ca.server.mgmt.api.Permission;
import org.xipki.pki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.pki.ca.server.mgmt.api.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.UserEntry;
import org.xipki.pki.ca.server.mgmt.api.ValidityMode;
import org.xipki.pki.ca.server.mgmt.api.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CaUris;
import org.xipki.pki.ca.server.mgmt.api.X509ChangeCaEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CrlSignerEntry;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaManagerQueryExecutor {

    private static final Logger LOG = LoggerFactory.getLogger(CaManagerQueryExecutor.class);

    private DataSourceWrapper dataSource;

    CaManagerQueryExecutor(
            final DataSourceWrapper dataSource) {
        ParamUtil.assertNotNull("dataSource", dataSource);
        this.dataSource = dataSource;
    }

    private X509Certificate generateCert(
            final String b64Cert)
    throws CaMgmtException {
        if (b64Cert == null) {
            return null;
        }

        byte[] encodedCert = Base64.decode(b64Cert);
        try {
            return X509Util.parseCert(encodedCert);
        } catch (CertificateException | IOException e) {
            throw new CaMgmtException(e.getMessage(), e);
        }
    } // method generateCert

    private Statement createStatement()
    throws CaMgmtException {
        Connection dsConnection;
        try {
            dsConnection = dataSource.getConnection();
        } catch (DataAccessException e) {
            throw new CaMgmtException("could not get connection", e);
        }

        try {
            return dataSource.createStatement(dsConnection);
        } catch (DataAccessException e) {
            throw new CaMgmtException("could not create statement", e);
        }
    } // method createStatement

    private PreparedStatement prepareFetchFirstStatement(
            final String sql)
    throws CaMgmtException {
        return prepareStatement(dataSource.createFetchFirstSelectSQL(sql, 1));
    }

    private PreparedStatement prepareStatement(
            final String sql)
    throws CaMgmtException {
        Connection dsConnection;
        try {
            dsConnection = dataSource.getConnection();
        } catch (DataAccessException e) {
            throw new CaMgmtException(e.getMessage(), e);
        }

        try {
            return dataSource.prepareStatement(dsConnection, sql);
        } catch (DataAccessException e) {
            throw new CaMgmtException(e.getMessage(), e);
        }
    } // method prepareStatement

    SystemEvent getSystemEvent(
            final String eventName)
    throws CaMgmtException {
        final String sql = "SELECT EVENT_TIME, EVENT_OWNER FROM SYSTEM_EVENT WHERE NAME=?";
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            ps = prepareStatement(sql);
            ps.setString(1, eventName);
            rs = ps.executeQuery();

            if (!rs.next()) {
                return null;
            }

            long eventTime = rs.getLong("EVENT_TIME");
            String eventOwner = rs.getString("EVENT_OWNER");
            return new SystemEvent(eventName, eventOwner, eventTime);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, rs);
        }
    } // method getSystemEvent

    void deleteSystemEvent(
            final String eventName)
    throws CaMgmtException {
        final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME=?";
        PreparedStatement ps = null;

        try {
            ps = prepareStatement(sql);
            ps.setString(1, eventName);
            ps.executeUpdate();
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method deleteSystemEvent

    void addSystemEvent(
            final SystemEvent systemEvent)
    throws CaMgmtException {
        final String sql = "INSERT INTO SYSTEM_EVENT (NAME, EVENT_TIME, EVENT_TIME2, EVENT_OWNER)"
                + " VALUES (?, ?, ?, ?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, systemEvent.getName());
            ps.setLong(idx++, systemEvent.getEventTime());
            ps.setTimestamp(idx++, new Timestamp(systemEvent.getEventTime() * 1000L));
            ps.setString(idx++, systemEvent.getOwner());
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addSystemEvent

    boolean changeSystemEvent(
            final SystemEvent systemEvent)
    throws CaMgmtException {
        deleteSystemEvent(systemEvent.getName());
        addSystemEvent(systemEvent);
        return true;
    }

    Map<String, String> createEnvParameters()
    throws CaMgmtException {
        Map<String, String> map = new HashMap<>();
        final String sql = "SELECT NAME, VALUE2 FROM ENVIRONMENT";
        Statement stmt = null;
        ResultSet rs = null;

        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                String value = rs.getString("VALUE2");
                map.put(name, value);
            }
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }

        return map;
    } // method createEnvParameters

    Map<String, String> createCaAliases()
    throws CaMgmtException {
        Map<String, String> map = new HashMap<>();

        final String sql = "SELECT NAME, CA_NAME FROM CAALIAS";
        Statement stmt = null;
        ResultSet rs = null;

        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                String caName = rs.getString("CA_NAME");
                map.put(name, caName);
            }
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }

        return map;
    } // method createCaAliases

    CertprofileEntry createCertprofile(
            final String name)
    throws CaMgmtException {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        final String sql = "TYPE, CONF FROM PROFILE WHERE NAME=?";
        try {
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            String type = rs.getString("TYPE");
            String conf = rs.getString("CONF");

            return new CertprofileEntry(name, type, conf);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method createCertprofile

    List<String> getNamesFromTable(
            final String table)
    throws CaMgmtException {
        return getNamesFromTable(table, "NAME");
    }

    List<String> getNamesFromTable(
            final String table,
            final String nameColumn)
    throws CaMgmtException {
        final String sql = new StringBuilder("SELECT ")
                .append(nameColumn).append(" FROM ").append(table).toString();
        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            List<String> names = new LinkedList<>();

            while (rs.next()) {
                String name = rs.getString(nameColumn);
                if (StringUtil.isNotBlank(name)) {
                    names.add(name);
                }
            }

            return names;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method getNamesFromTable

    PublisherEntry createPublisher(
            final String name)
    throws CaMgmtException {
        final String sql = "TYPE, CONF FROM PUBLISHER WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            String type = rs.getString("TYPE");
            String conf = rs.getString("CONF");
            return new PublisherEntry(name, type, conf);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method createPublisher

    CmpRequestorEntry createRequestor(
            final String name)
    throws CaMgmtException {
        final String sql = "CERT FROM REQUESTOR WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            String b64Cert = rs.getString("CERT");
            return new CmpRequestorEntry(name, b64Cert);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method createRequestor

    X509CrlSignerEntry createCrlSigner(
            final String name)
    throws CaMgmtException {
        final String sql =
                "SIGNER_TYPE, SIGNER_CERT, CRL_CONTROL, SIGNER_CONF FROM CRLSIGNER WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            String signerType = rs.getString("SIGNER_TYPE");
            String signerConf = rs.getString("SIGNER_CONF");
            String signerCert = rs.getString("SIGNER_CERT");
            String crlControlConf = rs.getString("CRL_CONTROL");
            return new X509CrlSignerEntry(name, signerType, signerConf, signerCert,
                    crlControlConf);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } catch (InvalidConfException e) {
            throw new CaMgmtException(e.getMessage(), e);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method createCrlSigner

    CmpControlEntry createCmpControl(
            final String name)
    throws CaMgmtException {
        final String sql = "CONF FROM CMPCONTROL WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            String conf = rs.getString("CONF");
            return new CmpControlEntry(name, conf);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method createCmpControl

    CmpResponderEntry createResponder(
            final String name)
    throws CaMgmtException {
        final String sql = "TYPE, CERT, CONF FROM RESPONDER WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            String type = rs.getString("TYPE");
            String conf = rs.getString("CONF");
            String b64Cert = rs.getString("CERT");
            return new CmpResponderEntry(name, type, conf, b64Cert);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method createResponder

    X509CaInfo createCaInfo(
            final String name,
            final boolean masterMode,
            final CertificateStore certstore)
    throws CaMgmtException {
        final String sql = "NAME, ART, NEXT_SN, NEXT_CRLNO, STATUS, MAX_VALIDITY"
                + ", CERT, SIGNER_TYPE, CRLSIGNER_NAME, RESPONDER_NAME, CMPCONTROL_NAME"
                + ", DUPLICATE_KEY, DUPLICATE_SUBJECT, PERMISSIONS, NUM_CRLS"
                + ", KEEP_EXPIRED_CERT_DAYS, EXPIRATION_PERIOD, REV, RR, RT, RIT, VALIDITY_MODE"
                + ", CRL_URIS, DELTACRL_URIS, OCSP_URIS, CACERT_URIS, EXTRA_CONTROL, SIGNER_CONF"
                + " FROM CA WHERE NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = prepareFetchFirstStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            int artCode = rs.getInt("ART");
            if (artCode != CertArt.X509PKC.getCode()) {
                throw new CaMgmtException(
                        "CA " + name + " is not X509CA, and is not supported");
            }

            long nextSerial = rs.getLong("NEXT_SN");
            int nextCrlNo = rs.getInt("NEXT_CRLNO");
            String status = rs.getString("STATUS");
            String crlUris = rs.getString("CRL_URIS");
            String deltaCrlUris = rs.getString("DELTACRL_URIS");
            String ocspUris = rs.getString("OCSP_URIS");
            String cacertUris = rs.getString("CACERT_URIS");
            String maxValidityS = rs.getString("MAX_VALIDITY");
            CertValidity maxValidity = CertValidity.getInstance(maxValidityS);
            String b64cert = rs.getString("CERT");
            String signerType = rs.getString("SIGNER_TYPE");
            String signerConf = rs.getString("SIGNER_CONF");
            String crlsignerName = rs.getString("CRLSIGNER_NAME");
            String responderName = rs.getString("RESPONDER_NAME");
            String cmpcontrolName = rs.getString("CMPCONTROL_NAME");
            int duplicateKeyI = rs.getInt("DUPLICATE_KEY");
            int duplicateSubjectI = rs.getInt("DUPLICATE_SUBJECT");
            int numCrls = rs.getInt("NUM_CRLS");
            int expirationPeriod = rs.getInt("EXPIRATION_PERIOD");
            int keepExpiredCertDays = rs.getInt("KEEP_EXPIRED_CERT_DAYS");
            String extraControl = rs.getString("EXTRA_CONTROL");

            CertRevocationInfo revocationInfo = null;
            boolean revoked = rs.getBoolean("REV");
            if (revoked) {
                int revReason = rs.getInt("RR");
                long revTime = rs.getInt("RT");
                long revInvalidityTime = rs.getInt("RIT");
                Date revInvTime = (revInvalidityTime == 0)
                        ? null
                        : new Date(revInvalidityTime * 1000);
                revocationInfo = new CertRevocationInfo(revReason, new Date(revTime * 1000),
                        revInvTime);
            }

            String s = rs.getString("PERMISSIONS");
            Set<Permission> permissions = getPermissions(s);

            List<String> lCrlUris = null;
            if (StringUtil.isNotBlank(crlUris)) {
                lCrlUris = StringUtil.split(crlUris, " \t");
            }

            List<String> lDeltaCrlUris = null;
            if (StringUtil.isNotBlank(deltaCrlUris)) {
                lDeltaCrlUris = StringUtil.split(deltaCrlUris, " \t");
            }

            List<String> lOcspUris = null;
            if (StringUtil.isNotBlank(ocspUris)) {
                lOcspUris = StringUtil.split(ocspUris, " \t");
            }

            List<String> lCacertUris = null;
            if (StringUtil.isNotBlank(cacertUris)) {
                lCacertUris = StringUtil.split(cacertUris, " \t");
            }

            X509CaUris caUris = new X509CaUris(lCacertUris, lOcspUris, lCrlUris, lDeltaCrlUris);

            X509CaEntry entry = new X509CaEntry(name, nextSerial, nextCrlNo,
                    signerType, signerConf, caUris, numCrls, expirationPeriod);
            X509Certificate cert = generateCert(b64cert);
            entry.setCertificate(cert);

            CaStatus caStatus = CaStatus.getCAStatus(status);
            if (caStatus == null) {
                caStatus = CaStatus.INACTIVE;
            }
            entry.setStatus(caStatus);

            entry.setMaxValidity(maxValidity);
            entry.setKeepExpiredCertInDays(keepExpiredCertDays);

            if (crlsignerName != null) {
                entry.setCrlSignerName(crlsignerName);
            }

            if (responderName != null) {
                entry.setResponderName(responderName);
            }

            if (extraControl != null) {
                entry.setExtraControl(extraControl);
            }

            if (cmpcontrolName != null) {
                entry.setCmpControlName(cmpcontrolName);
            }

            entry.setDuplicateKeyMode(DuplicationMode.getInstance(duplicateKeyI));
            entry.setDuplicateSubjectMode(DuplicationMode.getInstance(duplicateSubjectI));
            entry.setPermissions(permissions);
            entry.setRevocationInfo(revocationInfo);

            String validityModeS = rs.getString("VALIDITY_MODE");
            ValidityMode validityMode = null;
            if (validityModeS != null) {
                validityMode = ValidityMode.getInstance(validityModeS);
            }
            if (validityMode == null) {
                validityMode = ValidityMode.STRICT;
            }
            entry.setValidityMode(validityMode);

            try {
                if (masterMode) {
                    X509Cert cm = new X509Cert(entry.getCertificate());
                    certstore.addCa(cm);
                }

                return new X509CaInfo(entry, certstore);
            } catch (OperationException e) {
                throw new CaMgmtException(e.getMessage(), e);
            }
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method createCAInfo

    Set<CaHasRequestorEntry> createCaHasRequestors(
            final String caName)
    throws CaMgmtException {
        final String sql = "SELECT REQUESTOR_NAME, RA, PERMISSIONS, "
                + "PROFILES FROM CA_HAS_REQUESTOR WHERE CA_NAME=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, caName);
            rs = stmt.executeQuery();

            Set<CaHasRequestorEntry> ret = new HashSet<>();
            while (rs.next()) {
                String requestorName = rs.getString("REQUESTOR_NAME");
                boolean ra = rs.getBoolean("RA");
                String s = rs.getString("PERMISSIONS");
                Set<Permission> permissions = getPermissions(s);

                s = rs.getString("PROFILES");
                List<String> list = StringUtil.split(s, ",");
                Set<String> profiles = (list == null)
                        ? null
                        : new HashSet<>(list);
                CaHasRequestorEntry entry = new CaHasRequestorEntry(requestorName);
                entry.setRa(ra);
                entry.setPermissions(permissions);
                entry.setProfiles(profiles);

                ret.add(entry);
            }

            return ret;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method createCAhasRequestors

    Map<String, String> createCaHasProfiles(
            final String caName)
    throws CaMgmtException {
        final String sql = new StringBuilder("SELECT PROFILE_NAME, PROFILE_LOCALNAME")
                .append(" FROM CA_HAS_PROFILE")
                .append(" WHERE CA_NAME=?").toString();
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, caName);
            rs = stmt.executeQuery();

            Map<String, String> ret = new HashMap<>();
            while (rs.next()) {
                String profileName = rs.getString("PROFILE_NAME");
                String profileLocalname = rs.getString("PROFILE_LOCALNAME");
                ret.put(profileLocalname, profileName);
            }

            return ret;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method createCAhasProfiles

    Set<String> createCaHasPublishers(
            final String caName)
    throws CaMgmtException {
        return createCaHasNames(caName, "PUBLISHER_NAME", "CA_HAS_PUBLISHER");
    }

    Set<String> createCaHasNames(
            final String caName,
            final String columnName,
            final String table)
    throws CaMgmtException {
        final String sql = new StringBuilder("SELECT ").append(columnName).append(" FROM ")
                .append(table).append(" WHERE CA_NAME=?").toString();
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, caName);
            rs = stmt.executeQuery();

            Set<String> ret = new HashSet<>();
            while (rs.next()) {
                String name = rs.getString(columnName);
                ret.add(name);
            }

            return ret;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    } // method createCAhasNames

    boolean deleteRowWithName(
            final String name,
            final String table)
    throws CaMgmtException {
        final String sql = new StringBuilder("DELETE FROM ")
                .append(table)
                .append(" WHERE NAME=?").toString();
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method deleteRowWithName

    boolean deleteRows(
            final String table)
    throws CaMgmtException {
        final String sql = "DELETE FROM " + table;
        Statement stmt = null;
        try {
            stmt = createStatement();
            stmt.executeQuery(sql);
            return true;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(stmt, null);
        }
    } // method deleteRows

    void addCa(
            final CaEntry caEntry)
    throws CaMgmtException {
        if (!(caEntry instanceof X509CaEntry)) {
            throw new CaMgmtException("unsupported CAEntry " + caEntry.getClass().getName());
        }

        X509CaEntry entry = (X509CaEntry) caEntry;
        String name = entry.getName();

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("INSERT INTO CA (");
        sqlBuilder.append("NAME, ART, SUBJECT, NEXT_SN, NEXT_CRLNO, STATUS");
        sqlBuilder.append(", CRL_URIS, DELTACRL_URIS, OCSP_URIS, CACERT_URIS");
        sqlBuilder.append(", MAX_VALIDITY, CERT, SIGNER_TYPE");
        sqlBuilder.append(", CRLSIGNER_NAME, RESPONDER_NAME, CMPCONTROL_NAME");
        sqlBuilder.append(", DUPLICATE_KEY, DUPLICATE_SUBJECT, PERMISSIONS");
        sqlBuilder.append(", NUM_CRLS, EXPIRATION_PERIOD, KEEP_EXPIRED_CERT_DAYS");
        sqlBuilder.append(", VALIDITY_MODE, EXTRA_CONTROL, SIGNER_CONF");
        sqlBuilder.append(") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?");
        sqlBuilder.append(", ?, ?, ?, ?, ?, ?, ?, ?)");
        final String sql = sqlBuilder.toString();

        // insert to table ca
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, name);
            ps.setInt(idx++, CertArt.X509PKC.getCode());
            ps.setString(idx++, entry.getSubject());

            long nextSerial = entry.getNextSerial();
            if (nextSerial < 0) {
                nextSerial = 0;
            }
            ps.setLong(idx++, nextSerial);

            ps.setInt(idx++, entry.getNextCrlNumber());
            ps.setString(idx++, entry.getStatus().getStatus());
            ps.setString(idx++, entry.getCrlUrisAsString());
            ps.setString(idx++, entry.getDeltaCrlUrisAsString());
            ps.setString(idx++, entry.getOcspUrisAsString());
            ps.setString(idx++, entry.getCacertUrisAsString());
            ps.setString(idx++, entry.getMaxValidity().toString());
            byte[] encodedCert = entry.getCertificate().getEncoded();
            ps.setString(idx++, Base64.toBase64String(encodedCert));
            ps.setString(idx++, entry.getSignerType());
            ps.setString(idx++, entry.getCrlSignerName());
            ps.setString(idx++, entry.getResponderName());
            ps.setString(idx++, entry.getCmpControlName());
            ps.setInt(idx++, entry.getDuplicateKeyMode().getMode());
            ps.setInt(idx++, entry.getDuplicateSubjectMode().getMode());
            ps.setString(idx++, Permission.toString(entry.getPermissions()));
            ps.setInt(idx++, entry.getNumCrls());
            ps.setInt(idx++, entry.getExpirationPeriod());
            ps.setInt(idx++, entry.getKeepExpiredCertInDays());
            ps.setString(idx++, entry.getValidityMode().name());
            ps.setString(idx++, entry.getExtraControl());
            ps.setString(idx++, entry.getSignerConf());

            ps.executeUpdate();

            // create serial sequence
            if (nextSerial > 0) {
                dataSource.createSequence(entry.getSerialSeqName(), nextSerial);
            }

            if (LOG.isInfoEnabled()) {
                LOG.info("add CA '{}': {}", name, entry.toString(false, true));
            }
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } catch (CertificateEncodingException | DataAccessException e) {
            throw new CaMgmtException(e.getMessage(), e);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addCA

    void addCaAlias(
            final String aliasName,
            final String caName)
    throws CaMgmtException {
        final String sql = "INSERT INTO CAALIAS (NAME, CA_NAME) VALUES (?, ?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, aliasName);
            ps.setString(2, caName);
            ps.executeUpdate();
            LOG.info("added CA alias '{}' for CA '{}'", aliasName, caName);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addCaAlias

    void addCertprofile(
            final CertprofileEntry dbEntry)
    throws CaMgmtException {
        final String sql = "INSERT INTO PROFILE (NAME, ART, TYPE, CONF) VALUES (?, ?, ?, ?)";
        final String name = dbEntry.getName();

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            ps.setInt(2, CertArt.X509PKC.getCode());
            ps.setString(3, dbEntry.getType());
            String conf = dbEntry.getConf();
            ps.setString(4, conf);

            ps.executeUpdate();

            LOG.info("added profile '{}': {}", name, dbEntry);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addCertprofile

    void addCertprofileToCa(
            final String profileName,
            final String profileLocalName,
            final String caName)
    throws CaMgmtException {
        final String sql = "INSERT INTO CA_HAS_PROFILE (CA_NAME, PROFILE_NAME, PROFILE_LOCALNAME)"
                + " VALUES (?, ?, ?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, profileName);
            ps.setString(3, profileLocalName);
            ps.executeUpdate();
            LOG.info("added profile '{} (localname {})' to CA '{}'", profileName,
                    profileLocalName, caName);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addCertprofileToCA

    void addCmpControl(
            final CmpControlEntry dbEntry)
    throws CaMgmtException {
        final String name = dbEntry.getName();

        final String sql = "INSERT INTO CMPCONTROL (NAME, CONF) VALUES (?, ?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            int idx = 1;
            ps.setString(idx++, name);
            ps.setString(idx++, dbEntry.getConf());
            ps.executeUpdate();
            LOG.info("added CMP control: {}", dbEntry);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addCmpControl

    void addCmpRequestor(
            final CmpRequestorEntry dbEntry)
    throws CaMgmtException {
        String name = dbEntry.getName();

        final String sql = "INSERT INTO REQUESTOR (NAME, CERT) VALUES (?, ?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, name);
            ps.setString(idx++, Base64.toBase64String(dbEntry.getCert().getEncoded()));
            ps.executeUpdate();
            if (LOG.isInfoEnabled()) {
                LOG.info("added requestor '{}': {}", name, dbEntry.toString(false));
            }
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } catch (CertificateEncodingException e) {
            throw new CaMgmtException(e.getMessage(), e);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addCmpRequestor

    void addCmpRequestorToCa(
            final CaHasRequestorEntry requestor,
            final String caName)
    throws CaMgmtException {
        final String requestorName = requestor.getRequestorName();

        PreparedStatement ps = null;
        final String sql = "INSERT INTO CA_HAS_REQUESTOR (CA_NAME, REQUESTOR_NAME, RA,"
                + " PERMISSIONS, PROFILES) VALUES (?, ?, ?, ?, ?)";
        try {
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
            LOG.info("added requestor '{}' to CA '{}': ra: {}; permission: {}; profile: {}",
                    requestorName, caName, ra, permissionText, profilesText);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addCmpRequestorToCA

    void addCrlSigner(
            final X509CrlSignerEntry dbEntry)
    throws CaMgmtException {
        String crlControl = dbEntry.getCrlControl();
        // validate crlControl
        if (crlControl != null) {
            try {
                new CrlControl(crlControl);
            } catch (InvalidConfException e) {
                throw new CaMgmtException("invalid CRL control '" + crlControl + "'");
            }
        }

        String name = dbEntry.getName();
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("INSERT INTO CRLSIGNER (NAME, SIGNER_TYPE, SIGNER_CERT, CRL_CONTROL,");
        sqlBuilder.append("SIGNER_CONF)");
        sqlBuilder.append(" VALUES (?, ?, ?, ?, ?)");
        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, name);
            ps.setString(idx++, dbEntry.getType());
            ps.setString(idx++,
                    dbEntry.getCertificate() == null
                        ? null
                        : Base64.toBase64String(dbEntry.getCertificate().getEncoded()));
            ps.setString(idx++, crlControl);
            ps.setString(idx++, dbEntry.getConf());

            ps.executeUpdate();
            LOG.info("added CRL signer '{}': {}", name, dbEntry.toString(false, true));
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } catch (CertificateEncodingException e) {
            throw new CaMgmtException(e.getMessage(), e);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addCrlSigner

    void addEnvParam(
            final String name,
            final String value)
    throws CaMgmtException {
        final String sql = "INSERT INTO ENVIRONMENT (NAME, VALUE2) VALUES (?, ?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            ps.setString(2, value);
            ps.executeUpdate();
            LOG.info("added environment param '{}': {}", name, value);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addEnvParam

    void addPublisher(
            final PublisherEntry dbEntry)
    throws CaMgmtException {
        String name = dbEntry.getName();
        final String sql = "INSERT INTO PUBLISHER (NAME, TYPE, CONF) VALUES (?, ?, ?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            ps.setString(2, dbEntry.getType());
            String conf = dbEntry.getConf();
            ps.setString(3, conf);

            ps.executeUpdate();
            LOG.info("added publisher '{}': {}", name, dbEntry);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addPublisher

    void addPublisherToCa(
            final String publisherName,
            final String caName)
    throws CaMgmtException {
        final String sql = "INSERT INTO CA_HAS_PUBLISHER (CA_NAME, PUBLISHER_NAME) VALUES (?, ?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, publisherName);
            ps.executeUpdate();
            LOG.info("added publisher '{}' to CA '{}'", publisherName, caName);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addPublisherToCA

    boolean changeCa(
            final ChangeCaEntry changeCAEntry,
            final SecurityFactory securityFactory)
    throws CaMgmtException {
        if (!(changeCAEntry instanceof X509ChangeCaEntry)) {
            throw new CaMgmtException(
                    "unsupported ChangeCAEntry " + changeCAEntry.getClass().getName());
        }

        X509ChangeCaEntry entry = (X509ChangeCaEntry) changeCAEntry;
        String name = entry.getName();
        CaStatus status = entry.getStatus();
        X509Certificate cert = entry.getCert();
        List<String> crlUris = entry.getCrlUris();
        List<String> deltaCrlUris = entry.getDeltaCrlUris();
        List<String> ocspUris = entry.getOcspUris();
        List<String> cacertUris = entry.getCaCertUris();
        CertValidity maxValidity = entry.getMaxValidity();
        String signerType = entry.getSignerType();
        String lSignerConf = entry.getSignerConf();
        String crlsignerName = entry.getCrlSignerName();
        String responderName = entry.getResponderName();
        String cmpcontrolName = entry.getCmpControlName();
        DuplicationMode duplicateKey = entry.getDuplicateKeyMode();
        DuplicationMode duplicateSubject = entry.getDuplicateSubjectMode();
        Set<Permission> permissions = entry.getPermissions();
        Integer numCrls = entry.getNumCrls();
        Integer expirationPeriod = entry.getExpirationPeriod();
        Integer keepExpiredCertInDays = entry.getKeepExpiredCertInDays();
        ValidityMode validityMode = entry.getValidityMode();
        String extraControl = entry.getExtraControl();

        if (signerType != null || lSignerConf != null || cert != null) {
            final String sql = "SELECT SIGNER_TYPE, CERT, SIGNER_CONF FROM CA WHERE NAME=?";
            PreparedStatement stmt = null;
            ResultSet rs = null;

            try {
                stmt = prepareStatement(sql);
                stmt.setString(1, name);
                rs = stmt.executeQuery();
                if (!rs.next()) {
                    throw new CaMgmtException("no CA '" + name + "' is defined");
                }

                String localSignerType = rs.getString("SIGNER_TYPE");
                String localSignerConf = rs.getString("SIGNER_CONF");
                String localB64Cert = rs.getString("CERT");
                if (signerType != null) {
                    localSignerType = signerType;
                }

                if (lSignerConf != null) {
                    localSignerConf = getRealString(lSignerConf);
                }

                X509Certificate localCert;
                if (cert != null) {
                    localCert = cert;
                } else {
                    try {
                        localCert = X509Util.parseBase64EncodedCert(localB64Cert);
                    } catch (CertificateException | IOException e) {
                        throw new CaMgmtException(
                                "could not parse the stored certificate for CA '" + name + "'"
                                + e.getMessage(), e);
                    }
                }

                try {
                    List<String[]> signerConfs = CaManagerImpl.splitCASignerConfs(localSignerConf);
                    for (String[] m : signerConfs) {
                        String signerConf = m[1];
                        securityFactory.createSigner(localSignerType, signerConf, localCert);
                    }
                } catch (SignerException e) {
                    throw new CaMgmtException(
                            "could not create signer for    CA '" + name + "'" + e.getMessage(), e);
                }
            } catch (SQLException e) {
                DataAccessException tEx = dataSource.translate(sql, e);
                throw new CaMgmtException(tEx.getMessage(), tEx);
            } finally {
                dataSource.releaseResources(stmt, rs);
            }
        } // end if

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE CA SET ");

        AtomicInteger index = new AtomicInteger(1);

        Integer iStatus = addToSqlIfNotNull(sqlBuilder, index, status, "STATUS");
        Integer iSubject = addToSqlIfNotNull(sqlBuilder, index, cert, "SUBJECT");
        Integer iCert = addToSqlIfNotNull(sqlBuilder, index, cert, "CERT");
        Integer iCrlUris = addToSqlIfNotNull(sqlBuilder, index, crlUris, "CRL_URIS");
        Integer iDeltaCrlUris =
                addToSqlIfNotNull(sqlBuilder, index, deltaCrlUris, "DELTACRL_URIS");
        Integer iOcspUris = addToSqlIfNotNull(sqlBuilder, index, ocspUris, "OCSP_URIS");
        Integer iCacertUris = addToSqlIfNotNull(sqlBuilder, index, cacertUris, "CACERT_URIS");
        Integer iMaxValidity =
                addToSqlIfNotNull(sqlBuilder, index, maxValidity, "MAX_VALIDITY");
        Integer iSignerType = addToSqlIfNotNull(sqlBuilder, index, signerType, "SIGNER_TYPE");
        Integer iCrlsignerName =
                addToSqlIfNotNull(sqlBuilder, index, crlsignerName, "CRLSIGNER_NAME");
        Integer iResponderName =
                addToSqlIfNotNull(sqlBuilder, index, responderName, "RESPONDER_NAME");
        Integer iCmpcontrolName =
                addToSqlIfNotNull(sqlBuilder, index, cmpcontrolName, "CMPCONTROL_NAME");
        Integer iDuplicateKey =
                addToSqlIfNotNull(sqlBuilder, index, duplicateKey, "DUPLICATE_KEY");
        Integer iDuplicateSubject =
                addToSqlIfNotNull(sqlBuilder, index, duplicateSubject, "DUPLICATE_SUBJECT");
        Integer iPermissions = addToSqlIfNotNull(sqlBuilder, index, permissions, "PERMISSIONS");
        Integer iNumCrls = addToSqlIfNotNull(sqlBuilder, index, numCrls, "NUM_CRLS");
        Integer iExpirationPeriod =
                addToSqlIfNotNull(sqlBuilder, index, expirationPeriod, "EXPIRATION_PERIOD");
        Integer iExpiredCerts =
                addToSqlIfNotNull(sqlBuilder, index, keepExpiredCertInDays,
                        "KEEP_EXPIRED_CERT_DAYS");
        Integer iValidityMode =
                addToSqlIfNotNull(sqlBuilder, index, validityMode, "VALIDITY_MODE");
        Integer iExtraControl =
                addToSqlIfNotNull(sqlBuilder, index, extraControl, "EXTRA_CONTROL");
        Integer iSignerConf = addToSqlIfNotNull(sqlBuilder, index, lSignerConf, "SIGNER_CONF");

        // delete the last ','
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if (index.get() == 1) {
            return false;
        }
        int iName = index.get();

        final String sql = sqlBuilder.toString();
        StringBuilder m = new StringBuilder();
        PreparedStatement ps = null;

        try {
            ps = prepareStatement(sql);

            if (iStatus != null) {
                m.append("status: '").append(status.name()).append("'; ");
                ps.setString(iStatus, status.name());
            }

            if (iCert != null) {
                String subject = X509Util.getRfc4519Name(cert.getSubjectX500Principal());
                m.append("cert: '").append(subject).append("'; ");
                ps.setString(iSubject, subject);
                String base64Cert = Base64.toBase64String(cert.getEncoded());
                ps.setString(iCert, base64Cert);
            }

            if (iCrlUris != null) {
                String txt = toString(crlUris, ", ");
                m.append("crlUri: '").append(txt).append("'; ");
                ps.setString(iCrlUris, txt);
            }

            if (iDeltaCrlUris != null) {
                String txt = toString(deltaCrlUris, ", ");
                m.append("deltaCrlUri: '").append(txt).append("'; ");
                ps.setString(iDeltaCrlUris, txt);
            }

            if (iOcspUris != null) {
                String txt = toString(ocspUris, ", ");
                m.append("ocspUri: '").append(txt).append("'; ");
                ps.setString(iOcspUris, txt);
            }

            if (iCacertUris != null) {
                String txt = toString(cacertUris, ", ");
                m.append("caCertUri: '").append(txt).append("'; ");
                ps.setString(iCacertUris, txt);
            }

            if (iMaxValidity != null) {
                String txt = maxValidity.toString();
                m.append("maxValidity: '").append(txt).append("'; ");
                ps.setString(iMaxValidity, txt);
            }

            if (iSignerType != null) {
                m.append("signerType: '").append(signerType).append("'; ");
                ps.setString(iSignerType, signerType);
            }

            if (iSignerConf != null) {
                m.append("signerConf: '");
                m.append(SecurityUtil.signerConfToString(lSignerConf, false, true));
                m.append("'; ");
                ps.setString(iSignerConf, lSignerConf);
            }

            if (iCrlsignerName != null) {
                String txt = getRealString(crlsignerName);
                m.append("crlSigner: '").append(txt).append("'; ");
                ps.setString(iCrlsignerName, txt);
            }

            if (iResponderName != null) {
                String txt = getRealString(responderName);
                m.append("responder: '").append(txt).append("'; ");
                ps.setString(iResponderName, txt);
            }

            if (iCmpcontrolName != null) {
                String txt = getRealString(cmpcontrolName);
                m.append("cmpControl: '").append(txt).append("'; ");
                ps.setString(iCmpcontrolName, txt);
            }

            if (iDuplicateKey != null) {
                int mode = duplicateKey.getMode();
                m.append("duplicateKey: '").append(mode).append("'; ");
                ps.setInt(iDuplicateKey, mode);
            }

            if (iDuplicateSubject != null) {
                int mode = duplicateSubject.getMode();
                m.append("duplicateSubject: '").append(mode).append("'; ");
                ps.setInt(iDuplicateSubject, mode);
            }

            if (iPermissions != null) {
                String txt = Permission.toString(permissions);
                m.append("permission: '").append(txt).append("'; ");
                ps.setString(iPermissions, txt);
            }

            if (iNumCrls != null) {
                m.append("numCrls: '").append(numCrls).append("'; ");
                ps.setInt(iNumCrls, numCrls);
            }

            if (iExpirationPeriod != null) {
                m.append("expirationPeriod: '").append(expirationPeriod).append("'; ");
                ps.setInt(iExpirationPeriod, expirationPeriod);
            }

            if (iExpiredCerts != null) {
                m.append("keepExpiredCertDays: '").append(keepExpiredCertInDays).append("'; ");
                ps.setInt(iExpiredCerts, keepExpiredCertInDays);
            }

            if (iValidityMode != null) {
                String txt = validityMode.name();
                m.append("validityMode: '").append(txt).append("'; ");
                ps.setString(iValidityMode, txt);
            }

            if (iExtraControl != null) {
                m.append("extraControl: '").append(extraControl).append("'; ");
                ps.setString(iExtraControl, extraControl);
            }

            ps.setString(iName, name);
            ps.executeUpdate();

            if (m.length() > 0) {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }

            LOG.info("changed CA '{}': {}", name, m);
            return true;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } catch (CertificateEncodingException e) {
            throw new CaMgmtException(e.getMessage(), e);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method changeCA

    IdentifiedX509Certprofile changeCertprofile(
            final String name,
            final String type,
            final String conf,
            final CaManagerImpl caManager)
    throws CaMgmtException {
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE PROFILE SET ");

        AtomicInteger index = new AtomicInteger(1);

        StringBuilder m = new StringBuilder();

        String localType = type;
        String localConf = conf;

        if (localType != null) {
            m.append("type: '").append(localType).append("'; ");
        }
        if (localConf != null) {
            m.append("conf: '").append(localConf).append("'; ");
        }

        Integer iType = addToSqlIfNotNull(sqlBuilder, index, localType, "TYPE");
        Integer iConf = addToSqlIfNotNull(sqlBuilder, index, localConf, "CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");
        if (index.get() == 1) {
            return null;
        }

        CertprofileEntry currentDbEntry = createCertprofile(name);
        if (localType == null) {
            localType = currentDbEntry.getType();
        }
        if (localConf == null) {
            localConf = currentDbEntry.getConf();
        }

        localType = getRealString(localType);
        localConf = getRealString(localConf);

        CertprofileEntry newDbEntry = new CertprofileEntry(name, localType, localConf);
        IdentifiedX509Certprofile profile = caManager.createCertprofile(newDbEntry);
        if (profile == null) {
            return null;
        }

        final String sql = sqlBuilder.toString();

        boolean failed = true;
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            if (iType != null) {
                ps.setString(iType, localType);
            }

            if (iConf != null) {
                ps.setString(iConf, getRealString(localConf));
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if (m.length() > 0) {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }

            LOG.info("changed profile '{}': {}", name, m);
            failed = false;
            return profile;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
            if (failed) {
                profile.shutdown();
            }
        }
    } // method changeCertprofile

    CmpControl changeCmpControl(
            final String name,
            final String conf)
    throws CaMgmtException {
        if (conf == null) {
            return null;
        }

        CmpControlEntry newDbEntry = new CmpControlEntry(name, conf);
        CmpControl cmpControl;
        try {
            cmpControl = new CmpControl(newDbEntry);
        } catch (InvalidConfException e) {
            throw new CaMgmtException(e.getMessage(), e);
        }

        final String sql = "UPDATE CMPCONTROL SET CONF=? WHERE NAME=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, conf);
            ps.setString(2, name);
            ps.executeUpdate();

            LOG.info("changed CMP control '{}': {}", name, conf);
            return cmpControl;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method changeCmpControl

    CmpRequestorEntryWrapper changeCmpRequestor(
            final String name,
            final String base64Cert)
    throws CaMgmtException {
        CmpRequestorEntry newDbEntry = new CmpRequestorEntry(name, base64Cert);
        CmpRequestorEntryWrapper requestor = new CmpRequestorEntryWrapper();
        requestor.setDbEntry(newDbEntry);

        final String sql = "UPDATE REQUESTOR SET CERT=? WHERE NAME=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            String b64Cert = getRealString(base64Cert);
            ps.setString(1, b64Cert);
            ps.setString(2, name);
            ps.executeUpdate();

            String subject = null;
            if (b64Cert != null) {
                try {
                    subject = X509Util.canonicalizName(
                            X509Util.parseBase64EncodedCert(b64Cert).getSubjectX500Principal());
                } catch (CertificateException | IOException e) {
                    subject = "ERROR";
                }
            }
            LOG.info("changed CMP requestor '{}': {}", name, subject);
            return requestor;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method changeCmpRequestor

    CmpResponderEntryWrapper changeCmpResponder(
            final String name,
            final String type,
            final String conf,
            final String base64Cert,
            final CaManagerImpl caManager)
    throws CaMgmtException {
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE RESPONDER SET ");

        String localType = type;
        String localConf = conf;
        String localBase64Cert = base64Cert;

        AtomicInteger index = new AtomicInteger(1);
        Integer iType = addToSqlIfNotNull(sqlBuilder, index, localType, "TYPE");
        Integer iCert = addToSqlIfNotNull(sqlBuilder, index, localBase64Cert, "CERT");
        Integer iConf = addToSqlIfNotNull(sqlBuilder, index, localConf, "CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if (index.get() == 1) {
            return null;
        }

        CmpResponderEntry dbEntry = createResponder(name);

        if (localType == null) {
            localType = dbEntry.getType();
        }

        if (localConf == null) {
            localConf = dbEntry.getConf();
        }

        if (localBase64Cert == null) {
            localBase64Cert = dbEntry.getBase64Cert();
        }

        CmpResponderEntry newDbEntry = new CmpResponderEntry(name, localType,
                localConf, localBase64Cert);
        CmpResponderEntryWrapper responder = caManager.createCmpResponder(newDbEntry);

        final String sql = sqlBuilder.toString();

        StringBuilder m = new StringBuilder();

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            if (iType != null) {
                String txt = localType;
                ps.setString(iType, txt);
                m.append("type: '").append(txt).append("'; ");
            }

            if (iConf != null) {
                String txt = getRealString(localConf);
                m.append("conf: '").append(SecurityUtil.signerConfToString(txt, false, true));
                ps.setString(iConf, txt);
            }

            if (iCert != null) {
                String txt = getRealString(localBase64Cert);
                m.append("cert: '");
                if (txt == null) {
                    m.append("null");
                } else {
                    try {
                        String subject = X509Util.canonicalizName(
                                X509Util.parseBase64EncodedCert(txt).getSubjectX500Principal());
                        m.append(subject);
                    } catch (CertificateException | IOException e) {
                        m.append("ERROR");
                    }
                }
                m.append("'; ");
                ps.setString(iCert, txt);
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if (m.length() > 0) {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("changed CMP responder: {}", m);
            return responder;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method changeCmpResponder

    X509CrlSignerEntryWrapper changeCrlSigner(
            final String name,
            final String signerType,
            final String signerConf,
            final String base64Cert,
            final String crlControl,
            final CaManagerImpl caManager)
    throws CaMgmtException {
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE CRLSIGNER SET ");

        String localSignerType = signerType;
        String localSignerConf = signerConf;
        String localBase64Cert = base64Cert;
        String localCrlControl = crlControl;

        AtomicInteger index = new AtomicInteger(1);

        Integer iSignerType = addToSqlIfNotNull(sqlBuilder, index, localSignerType, "SIGNER_TYPE");
        Integer iSignerCert = addToSqlIfNotNull(sqlBuilder, index, localBase64Cert, "SIGNER_CERT");
        Integer iCrlControl = addToSqlIfNotNull(sqlBuilder, index, localCrlControl, "CRL_CONTROL");
        Integer iSignerConf = addToSqlIfNotNull(sqlBuilder, index, localSignerConf, "SIGNER_CONF");

        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if (index.get() == 1) {
            return null;
        }

        X509CrlSignerEntry dbEntry = createCrlSigner(name);
        if (localSignerType == null) {
            localSignerType = dbEntry.getType();
        }

        if ("CA".equalsIgnoreCase(localSignerType)) {
            localSignerConf = null;
            localBase64Cert = null;
        } else {
            if (localSignerConf == null) {
                localSignerConf = dbEntry.getConf();
            }

            if (localBase64Cert == null) {
                localBase64Cert = dbEntry.getBase64Cert();
            }
        }

        if (localCrlControl == null) {
            localCrlControl = dbEntry.getCrlControl();
        } else {
            // validate crlControl
            if (localCrlControl != null) {
                try {
                    new CrlControl(localCrlControl);
                } catch (InvalidConfException e) {
                    throw new CaMgmtException("invalid CRL control '" + localCrlControl + "'");
                }
            }
        }

        try {
            dbEntry = new X509CrlSignerEntry(name, localSignerType, localSignerConf,
                    localBase64Cert, localCrlControl);
        } catch (InvalidConfException e) {
            throw new CaMgmtException(e.getMessage(), e);
        }
        X509CrlSignerEntryWrapper crlSigner = caManager.createX509CrlSigner(dbEntry);

        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try {
            StringBuilder m = new StringBuilder();

            ps = prepareStatement(sql);

            if (iSignerType != null) {
                m.append("signerType: '").append(localSignerType).append("'; ");
                ps.setString(iSignerType, localSignerType);
            }

            if (iSignerConf != null) {
                String txt = getRealString(localSignerConf);
                m.append("signerConf: '")
                    .append(SecurityUtil.signerConfToString(txt, false, true))
                    .append("'; ");
                ps.setString(iSignerConf, txt);
            }

            if (iSignerCert != null) {
                String txt = getRealString(localBase64Cert);
                String subject = null;
                if (txt != null) {
                    try {
                        subject = X509Util.canonicalizName(
                                X509Util.parseBase64EncodedCert(txt).getSubjectX500Principal());
                    } catch (CertificateException | IOException e) {
                        subject = "ERROR";
                    }
                }
                m.append("signerCert: '").append(subject).append("'; ");
                ps.setString(iSignerCert, txt);
            }

            if (iCrlControl != null) {
                m.append("crlControl: '").append(localCrlControl).append("'; ");
                ps.setString(iCrlControl, localCrlControl);
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if (m.length() > 0) {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("changed CRL signer '{}': {}", name, m);
            return crlSigner;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method changeCrlSigner

    Scep changeScep(
            final String caName,
            final String responderType,
            final String responderConf,
            final String responderBase64Cert,
            final String control,
            final CaManagerImpl caManager)
    throws CaMgmtException {
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE SCEP SET ");

        String localResponderType = responderType;
        String localResponderConf = responderConf;
        String localResponderBase64Cert = responderBase64Cert;
        String localControl = control;

        AtomicInteger index = new AtomicInteger(1);
        Integer iType = addToSqlIfNotNull(sqlBuilder, index, localResponderType,
                "RESPONDER_TYPE");
        Integer iCert = addToSqlIfNotNull(sqlBuilder, index, localResponderBase64Cert,
                "RESPONDER_CERT");
        Integer iControl = addToSqlIfNotNull(sqlBuilder, index, localControl,
                "CONTROL");
        Integer iConf = addToSqlIfNotNull(sqlBuilder, index, localResponderConf,
                "RESPONDER_CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE CA_NAME=?");

        if (index.get() == 1) {
            return null;
        }

        ScepEntry dbEntry = getScep(caName);

        if (localResponderType == null) {
            localResponderType = dbEntry.getResponderType();
        }

        if (localResponderConf == null) {
            localResponderConf = dbEntry.getResponderConf();
        }

        if (localResponderBase64Cert == null) {
            localResponderBase64Cert = dbEntry.getBase64Cert();
        }

        if (localControl == null) {
            localControl = dbEntry.getControl();
        } else if (CaManager.NULL.equals(localControl)) {
            localControl = null;
        }

        ScepEntry newDbEntry;
        try {
            newDbEntry = new ScepEntry(caName, localResponderType, localResponderConf,
                    localResponderBase64Cert, localControl);
        } catch (InvalidConfException e) {
            throw new CaMgmtException(e);
        }
        Scep scep = new Scep(newDbEntry, caManager);

        final String sql = sqlBuilder.toString();

        StringBuilder m = new StringBuilder();

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            if (iType != null) {
                String txt = localResponderType;
                ps.setString(iType, txt);
                m.append("responder type: '").append(txt).append("'; ");
            }

            if (iConf != null) {
                String txt = getRealString(localResponderConf);
                m.append("responder conf: '")
                    .append(SecurityUtil.signerConfToString(txt, false, true));
                ps.setString(iConf, txt);
            }

            if (iCert != null) {
                String txt = getRealString(localResponderBase64Cert);
                m.append("responder cert: '");
                if (txt == null) {
                    m.append("null");
                } else {
                    try {
                        String subject = X509Util.canonicalizName(
                                X509Util.parseBase64EncodedCert(txt).getSubjectX500Principal());
                        m.append(subject);
                    } catch (CertificateException | IOException e) {
                        m.append("ERROR");
                    }
                }
                m.append("'; ");
                ps.setString(iCert, txt);
            }

            if (iControl != null) {
                String txt = getRealString(localControl);
                m.append("control: '").append(localControl);
                ps.setString(iControl, txt);
            }

            ps.setString(index.get(), caName);
            ps.executeUpdate();

            if (m.length() > 0) {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("changed CMP responder: {}", m);
            return scep;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method changeScep

    boolean changeEnvParam(
            final String name,
            final String value)
    throws CaMgmtException {
        if (value == null) {
            return false;
        }

        final String sql = "UPDATE ENVIRONMENT SET VALUE2=? WHERE NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, getRealString(value));
            ps.setString(2, name);
            ps.executeUpdate();
            LOG.info("changed environment param '{}': {}", name, value);
            return true;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method changeEnvParam

    IdentifiedX509CertPublisher changePublisher(
            final String name,
            final String type,
            final String conf,
            final CaManagerImpl caManager)
    throws CaMgmtException {
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE PUBLISHER SET ");

        String localType = type;
        String localConf = conf;

        AtomicInteger index = new AtomicInteger(1);
        Integer iType = addToSqlIfNotNull(sqlBuilder, index, localType, "TYPE");
        Integer iConf = addToSqlIfNotNull(sqlBuilder, index, localConf, "CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if (index.get() == 1) {
            return null;
        }

        PublisherEntry currentDbEntry = createPublisher(name);
        if (localType == null) {
            localType = currentDbEntry.getType();
        }

        if (localConf == null) {
            localConf = currentDbEntry.getConf();
        }

        PublisherEntry dbEntry = new PublisherEntry(name, localType, localConf);
        IdentifiedX509CertPublisher publisher = caManager.createPublisher(dbEntry);
        if (publisher == null) {
            return null;
        }

        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try {
            StringBuilder m = new StringBuilder();
            ps = prepareStatement(sql);
            if (iType != null) {
                m.append("type: '").append(localType).append("'; ");
                ps.setString(iType, localType);
            }

            if (iConf != null) {
                String txt = getRealString(localConf);
                m.append("conf: '").append(txt).append("'; ");
                ps.setString(iConf, getRealString(localConf));
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if (m.length() > 0) {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("changed publisher '{}': {}", name, m);
            return publisher;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method changePublisher

    boolean removeCa(
            final String caName)
    throws CaMgmtException {
        final String sql = "DELETE FROM CA WHERE NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method removeCA

    boolean removeCaAlias(
            final String aliasName)
    throws CaMgmtException {
        final String sql = "DELETE FROM CAALIAS WHERE NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, aliasName);
            boolean b = ps.executeUpdate() > 0;
            if (b) {
                LOG.info("removed CA alias '{}'", aliasName);
            }
            return b;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method removeCaAlias

    boolean removeCertprofileFromCa(
            final String profileLocalName,
            final String caName)
    throws CaMgmtException {
        final String sql = "DELETE FROM CA_HAS_PROFILE WHERE CA_NAME=? AND PROFILE_LOCALNAME=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, profileLocalName);
            boolean b = ps.executeUpdate() > 0;
            if (b) {
                LOG.info("removed profile '{}' from CA '{}'", profileLocalName, caName);
            }
            return b;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method removeCertprofileFromCA

    boolean removeCmpRequestorFromCa(
            final String requestorName,
            final String caName)
    throws CaMgmtException {
        final String sql = "DELETE FROM CA_HAS_REQUESTOR WHERE CA_NAME=? AND REQUESTOR_NAME=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, requestorName);
            boolean b = ps.executeUpdate() > 0;
            if (b) {
                LOG.info("removed requestor '{}' from CA '{}'", requestorName, caName);
            }
            return b;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method removeCmpRequestorFromCA

    boolean removePublisherFromCa(
            final String publisherName,
            final String caName)
    throws CaMgmtException {
        final String sql = "DELETE FROM CA_HAS_PUBLISHER WHERE CA_NAME=? AND PUBLISHER_NAME=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, publisherName);
            boolean b = ps.executeUpdate() > 0;
            if (b) {
                LOG.info("removed publisher '{}' from CA '{}'", publisherName, caName);
            }
            return b;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method removePublisherFromCA

    boolean revokeCa(
            final String caName,
            final CertRevocationInfo revocationInfo)
    throws CaMgmtException {
        String sql = "UPDATE CA SET REV=?, RR=?, RT=?, RIT=? WHERE NAME=?";
        PreparedStatement ps = null;
        try {
            if (revocationInfo.getInvalidityTime() == null) {
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
            if (b) {
                LOG.info("revoked CA '{}'", caName);
            }
            return b;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method revokeCa

    void addCmpResponder(
            final CmpResponderEntry dbEntry)
    throws CaMgmtException {
        final String sql = "INSERT INTO RESPONDER (NAME, TYPE, CERT, CONF) VALUES (?, ?, ?, ?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, dbEntry.getName());
            ps.setString(idx++, dbEntry.getType());

            String b64Cert = null;
            X509Certificate cert = dbEntry.getCertificate();
            if (cert != null) {
                b64Cert = Base64.toBase64String(dbEntry.getCertificate().getEncoded());
            }
            ps.setString(idx++, b64Cert);
            ps.setString(idx++, dbEntry.getConf());
            ps.executeUpdate();

            LOG.info("changed responder: {}", dbEntry.toString(false, true));
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } catch (CertificateEncodingException e) {
            throw new CaMgmtException(e.getMessage(), e);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method addCmpResponder

    boolean unlockCa()
    throws DataAccessException, CaMgmtException {
        final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME='LOCK'";
        Statement stmt = null;
        try {
            stmt = createStatement();
            stmt.execute(sql);
            return stmt.getUpdateCount() > 0;
        } catch (SQLException e) {
            throw dataSource.translate(sql, e);
        } finally {
            dataSource.releaseResources(stmt, null);
        }
    } // method unlockCA

    boolean unrevokeCa(
            final String caName)
    throws CaMgmtException {
        LOG.info("Unrevoking of CA '{}'", caName);

        final String sql = "UPDATE CA SET REV=?, RR=?, RT=?, RIT=? WHERE NAME=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int i = 1;
            setBoolean(ps, i++, false);
            ps.setNull(i++, Types.INTEGER);
            ps.setNull(i++, Types.INTEGER);
            ps.setNull(i++, Types.INTEGER);
            ps.setString(i++, caName);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method unrevokeCa

    boolean addUser(
            final AddUserEntry userEntry)
    throws CaMgmtException {
        final String name = userEntry.getName();
        Integer existingId = executeGetUserIdSql(name);
        if (existingId != null) {
            throw new CaMgmtException("user named '" + name + " ' already exists");
        }

        String hashedPassword;
        try {
            hashedPassword = PasswordHash.createHash(userEntry.getPassword());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CaMgmtException(e);
        }
        UserEntry localUserEntry = new UserEntry(name, hashedPassword, userEntry.getCnRegex());

        try {
            int maxId = (int) dataSource.getMax(null, "USERNAME", "ID");
            executeAddUserSql(maxId + 1, localUserEntry);
        } catch (DataAccessException e) {
            throw new CaMgmtException(e);
        }

        LOG.info("added user '{}'", name);

        return true;
    } // method addUser

    private Integer executeGetUserIdSql(
            final String user)
    throws CaMgmtException {
        final String sql = dataSource.createFetchFirstSelectSQL("ID FROM USERNAME WHERE NAME=?", 1);
        ResultSet rs = null;
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            int idx = 1;
            ps.setString(idx++, user);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }
            return rs.getInt("ID");
        } catch (SQLException e) {
            throw new CaMgmtException(dataSource.translate(sql, e));
        } finally {
            dataSource.releaseResources(ps, rs);
        }
    } // method executeGetUserIdSql

    private void executeAddUserSql(
            final int id,
            final UserEntry userEntry)
    throws DataAccessException, CaMgmtException {

        final String sql =
                "INSERT INTO USERNAME (ID, NAME, PASSWORD, CN_REGEX) VALUES (?, ?, ?, ?)";

        PreparedStatement ps = null;

        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setInt(idx++, id);
            ps.setString(idx++, userEntry.getName());
            ps.setString(idx++, userEntry.getHashedPassword());
            ps.setString(idx++, userEntry.getCnRegex());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw dataSource.translate(sql, e);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method executeAddUserSql

    boolean removeUser(
            final String userName)
    throws CaMgmtException {
        final String sql = "DELETE FROM USERNAME WHERE NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, userName);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method removeUser

    boolean changeUser(
            final String username,
            final String password,
            final String cnRegex)
    throws CaMgmtException {
        Integer existingId = executeGetUserIdSql(username);
        if (existingId == null) {
            throw new CaMgmtException("user named '" + username + " ' does not exist");
        }

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE USERNAME SET ");

        AtomicInteger index = new AtomicInteger(1);
        Integer iPassword = addToSqlIfNotNull(sqlBuilder, index, password, "PASSWORD");
        Integer iCnRegex = addToSqlIfNotNull(sqlBuilder, index, cnRegex, "CN_REGEX");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE ID=?");

        if (index.get() == 1) {
            return false;
        }

        final String sql = sqlBuilder.toString();

        StringBuilder m = new StringBuilder();

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            if (iPassword != null) {
                String txt = getRealString(password);
                ps.setString(iPassword, txt);
                m.append("password: ****; ");
            }

            if (iCnRegex != null) {
                m.append("CnRegex: '").append(cnRegex);
                ps.setString(iCnRegex, cnRegex);
            }

            ps.setInt(index.get(), existingId);

            ps.executeUpdate();

            if (m.length() > 0) {
                m.deleteCharAt(m.length() - 1).deleteCharAt(m.length() - 1);
            }
            LOG.info("changed user: {}", m);
            return true;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method changeUser

    UserEntry getUser(
            final String username)
    throws CaMgmtException {
        final String sql = dataSource.createFetchFirstSelectSQL(
                "PASSWORD, CN_REGEX FROM USERNAME WHERE NAME=?", 1);
        ResultSet rs = null;
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            int idx = 1;
            ps.setString(idx++, username);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }

            String hashedPassword = rs.getString("PASSWORD");
            String cnRegex = rs.getString("CN_REGEX");
            return new UserEntry(username, hashedPassword, cnRegex);
        } catch (SQLException e) {
            throw new CaMgmtException(dataSource.translate(sql, e));
        } finally {
            dataSource.releaseResources(ps, rs);
        }
    } // method getUser

    boolean addScep(
            final ScepEntry scepEntry)
    throws CaMgmtException {
        final String sql = "INSERT INTO SCEP (CA_NAME, CONTROL, RESPONDER_TYPE, "
                + "RESPONDER_CERT, RESPONDER_CONF) VALUES (?, ?, ?, ?, ?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, scepEntry.getCaName());
            ps.setString(idx++, scepEntry.getControl());
            ps.setString(idx++, scepEntry.getResponderType());
            ps.setString(idx++, scepEntry.getBase64Cert());
            ps.setString(idx++, scepEntry.getResponderConf());

            ps.executeUpdate();
            LOG.info("added SCEP '{}': {}", scepEntry.getCaName(), scepEntry);
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }

        return true;
    } // method addScep

    boolean removeScep(
            final String name)
    throws CaMgmtException {
        final String sql = "DELETE FROM SCEP WHERE CA_NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            DataAccessException tEx = dataSource.translate(sql, e);
            throw new CaMgmtException(tEx.getMessage(), tEx);
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method removeScep

    ScepEntry getScep(
            final String caName)
    throws CaMgmtException {
        final String sql = dataSource.createFetchFirstSelectSQL(
            "CONTROL, RESPONDER_TYPE, RESPONDER_CERT, RESPONDER_CONF FROM SCEP WHERE CA_NAME=?",
            1);
        ResultSet rs = null;
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            int idx = 1;
            ps.setString(idx++, caName);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }

            String control = rs.getString("CONTROL");
            String type = rs.getString("RESPONDER_TYPE");
            String conf = rs.getString("RESPONDER_CONF");
            String cert = rs.getString("RESPONDER_CERT");
            if (StringUtil.isBlank(cert)) {
                cert = null;
            }

            return new ScepEntry(caName, type, conf, cert, control);
        } catch (SQLException e) {
            throw new CaMgmtException(dataSource.translate(sql, e));
        } catch (InvalidConfException e) {
            throw new CaMgmtException(e);
        } finally {
            dataSource.releaseResources(ps, rs);
        }
    } // method getScep

    private static void setBoolean(
            final PreparedStatement ps,
            final int index,
            final boolean b)
    throws SQLException {
        int i = b
                ? 1
                : 0;
        ps.setInt(index, i);
    }

    private static Integer addToSqlIfNotNull(
            final StringBuilder sqlBuilder,
            final AtomicInteger index,
            final Object columnObj,
            final String columnName) {
        if (columnObj == null) {
            return null;
        }

        sqlBuilder.append(columnName).append("=?,");
        return index.getAndIncrement();
    }

    private static Set<Permission> getPermissions(
            final String permissionsText)
    throws CaMgmtException {
        ParamUtil.assertNotBlank("permissionsText", permissionsText);

        List<String> l = StringUtil.split(permissionsText, ", ");
        Set<Permission> permissions = new HashSet<>();
        for (String permissionText : l) {
            Permission p = Permission.getPermission(permissionText);
            if (p == null) {
                throw new CaMgmtException("unknown permission " + permissionText);
            }
            if (p == Permission.ALL) {
                permissions.clear();
                permissions.add(p);
                break;
            } else {
                permissions.add(p);
            }
        }

        return permissions;
    } // method getPermissions

    private static String toString(
            final Collection<String> tokens,
            final String seperator) {
        return StringUtil.collectionAsString(tokens, seperator);
    }

    private static String getRealString(
            final String s) {
        return CaManager.NULL.equalsIgnoreCase(s)
                ? null
                : s;
    }

}
