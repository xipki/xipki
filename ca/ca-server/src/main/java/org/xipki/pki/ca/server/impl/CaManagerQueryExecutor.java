/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
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
import org.xipki.commons.security.api.util.SignerConfUtil;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.X509Cert;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.server.impl.cmp.CmpRequestorEntryWrapper;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderEntryWrapper;
import org.xipki.pki.ca.server.impl.scep.Scep;
import org.xipki.pki.ca.server.impl.store.CertificateStore;
import org.xipki.pki.ca.server.impl.util.PasswordHash;
import org.xipki.pki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CaManager;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.CertArt;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControl;
import org.xipki.pki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.api.CrlControl;
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

    private DataSourceWrapper datasource;

    CaManagerQueryExecutor(
            final DataSourceWrapper datasource) {
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);
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
        } catch (CertificateException | IOException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
    } // method generateCert

    private Statement createStatement()
    throws CaMgmtException {
        Connection dsConnection;
        try {
            dsConnection = datasource.getConnection();
        } catch (DataAccessException ex) {
            throw new CaMgmtException("could not get connection", ex);
        }

        try {
            return datasource.createStatement(dsConnection);
        } catch (DataAccessException ex) {
            throw new CaMgmtException("could not create statement", ex);
        }
    } // method createStatement

    private PreparedStatement prepareFetchFirstStatement(
            final String sql)
    throws CaMgmtException {
        return prepareStatement(datasource.createFetchFirstSelectSql(sql, 1));
    }

    private PreparedStatement prepareStatement(
            final String sql)
    throws CaMgmtException {
        Connection dsConnection;
        try {
            dsConnection = datasource.getConnection();
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }

        try {
            return datasource.prepareStatement(dsConnection, sql);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, rs);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        } finally {
            datasource.releaseResources(stmt, rs);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
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

            String crlUris = rs.getString("CRL_URIS");
            String deltaCrlUris = rs.getString("DELTACRL_URIS");

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

            List<String> tmpCrlUris = null;
            if (StringUtil.isNotBlank(crlUris)) {
                tmpCrlUris = StringUtil.split(crlUris, " \t");
            }

            List<String> tmpDeltaCrlUris = null;
            if (StringUtil.isNotBlank(deltaCrlUris)) {
                tmpDeltaCrlUris = StringUtil.split(deltaCrlUris, " \t");
            }

            String ocspUris = rs.getString("OCSP_URIS");
            List<String> tmpOcspUris = null;
            if (StringUtil.isNotBlank(ocspUris)) {
                tmpOcspUris = StringUtil.split(ocspUris, " \t");
            }

            String cacertUris = rs.getString("CACERT_URIS");
            List<String> tmpCacertUris = null;
            if (StringUtil.isNotBlank(cacertUris)) {
                tmpCacertUris = StringUtil.split(cacertUris, " \t");
            }

            X509CaUris caUris = new X509CaUris(tmpCacertUris, tmpOcspUris, tmpCrlUris,
                    tmpDeltaCrlUris);

            long nextSerial = rs.getLong("NEXT_SN");
            int nextCrlNo = rs.getInt("NEXT_CRLNO");
            String signerType = rs.getString("SIGNER_TYPE");
            String signerConf = rs.getString("SIGNER_CONF");
            int numCrls = rs.getInt("NUM_CRLS");
            int expirationPeriod = rs.getInt("EXPIRATION_PERIOD");

            X509CaEntry entry = new X509CaEntry(name, nextSerial, nextCrlNo,
                    signerType, signerConf, caUris, numCrls, expirationPeriod);
            String b64cert = rs.getString("CERT");
            X509Certificate cert = generateCert(b64cert);
            entry.setCertificate(cert);

            String status = rs.getString("STATUS");
            CaStatus caStatus = CaStatus.getCaStatus(status);
            if (caStatus == null) {
                caStatus = CaStatus.INACTIVE;
            }
            entry.setStatus(caStatus);

            String maxValidityS = rs.getString("MAX_VALIDITY");
            CertValidity maxValidity = CertValidity.getInstance(maxValidityS);
            entry.setMaxValidity(maxValidity);

            int keepExpiredCertDays = rs.getInt("KEEP_EXPIRED_CERT_DAYS");
            entry.setKeepExpiredCertInDays(keepExpiredCertDays);

            String crlsignerName = rs.getString("CRLSIGNER_NAME");
            if (crlsignerName != null) {
                entry.setCrlSignerName(crlsignerName);
            }

            String responderName = rs.getString("RESPONDER_NAME");
            if (responderName != null) {
                entry.setResponderName(responderName);
            }

            String extraControl = rs.getString("EXTRA_CONTROL");
            if (extraControl != null) {
                entry.setExtraControl(extraControl);
            }

            String cmpcontrolName = rs.getString("CMPCONTROL_NAME");
            if (cmpcontrolName != null) {
                entry.setCmpControlName(cmpcontrolName);
            }

            boolean duplicateKeyPermitted = (rs.getInt("DUPLICATE_KEY") != 0);
            entry.setDuplicateKeyPermitted(duplicateKeyPermitted);

            boolean duplicateSubjectPermitted = (rs.getInt("DUPLICATE_SUBJECT") != 0);
            entry.setDuplicateSubjectPermitted(duplicateSubjectPermitted);

            String str = rs.getString("PERMISSIONS");
            Set<Permission> permissions = getPermissions(str);
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
            } catch (OperationException ex) {
                throw new CaMgmtException(ex.getMessage(), ex);
            }
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCaInfo

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
                String str = rs.getString("PERMISSIONS");
                Set<Permission> permissions = getPermissions(str);

                str = rs.getString("PROFILES");
                List<String> list = StringUtil.split(str, ",");
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCaHasRequestors

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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCaHasProfiles

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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCaHasNames

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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method deleteRowWithName

    boolean deleteRows(
            final String table)
    throws CaMgmtException {
        final String sql = "DELETE FROM " + table;
        Statement stmt = null;
        try {
            stmt = createStatement();
            return stmt.executeUpdate(sql) > 0;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(stmt, null);
        }
    } // method deleteRows

    void addCa(
            final CaEntry caEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("caEntry", caEntry);
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
            setBoolean(ps, idx++, entry.isDuplicateKeyPermitted());
            setBoolean(ps, idx++, entry.isDuplicateSubjectPermitted());
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
                datasource.createSequence(entry.getSerialSeqName(), nextSerial);
            }

            if (LOG.isInfoEnabled()) {
                LOG.info("add CA '{}': {}", name, entry.toString(false, true));
            }
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } catch (CertificateEncodingException | DataAccessException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCa

    void addCaAlias(
            final String aliasName,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonNull("aliasName", aliasName);
        ParamUtil.requireNonNull("caName", caName);

        final String sql = "INSERT INTO CAALIAS (NAME, CA_NAME) VALUES (?, ?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, aliasName);
            ps.setString(2, caName);
            ps.executeUpdate();
            LOG.info("added CA alias '{}' for CA '{}'", aliasName, caName);
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCaAlias

    void addCertprofile(
            final CertprofileEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCertprofile

    void addCertprofileToCa(
            final String profileName,
            final String profileLocalName,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonNull("profileName", profileName);
        ParamUtil.requireNonNull("profileLocalName", profileLocalName);
        ParamUtil.requireNonNull("caName", caName);

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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCertprofileToCa

    void addCmpControl(
            final CmpControlEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCmpControl

    void addCmpRequestor(
            final CmpRequestorEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCmpRequestor

    void addCmpRequestorToCa(
            final CaHasRequestorEntry requestor,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonNull("requestor", requestor);
        ParamUtil.requireNonBlank("caName", caName);

        final String requestorName = requestor.getRequestorName();

        PreparedStatement ps = null;
        final String sql = "INSERT INTO CA_HAS_REQUESTOR (CA_NAME, REQUESTOR_NAME, RA,"
                + " PERMISSIONS, PROFILES) VALUES (?, ?, ?, ?, ?)";
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, caName);
            ps.setString(idx++, requestorName);

            boolean ra = requestor.isRa();
            setBoolean(ps, idx++, ra);

            String permissionText = Permission.toString(requestor.getPermissions());
            ps.setString(idx++, permissionText);

            String profilesText = toString(requestor.getProfiles(), ",");
            ps.setString(idx++, profilesText);

            ps.executeUpdate();
            LOG.info("added requestor '{}' to CA '{}': ra: {}; permission: {}; profile: {}",
                    requestorName, caName, ra, permissionText, profilesText);
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCmpRequestorToCa

    void addCrlSigner(
            final X509CrlSignerEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        String crlControl = dbEntry.getCrlControl();
        // validate crlControl
        if (crlControl != null) {
            try {
                new CrlControl(crlControl);
            } catch (InvalidConfException ex) {
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCrlSigner

    void addEnvParam(
            final String name,
            final String value)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonNull("value", value);
        final String sql = "INSERT INTO ENVIRONMENT (NAME, VALUE2) VALUES (?, ?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            ps.setString(2, value);
            ps.executeUpdate();
            LOG.info("added environment param '{}': {}", name, value);
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addEnvParam

    void addPublisher(
            final PublisherEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addPublisherToCa

    boolean changeCa(
            final ChangeCaEntry changeCaEntry,
            final SecurityFactory securityFactory)
    throws CaMgmtException {
        ParamUtil.requireNonNull("changeCaEntry", changeCaEntry);
        ParamUtil.requireNonNull("securityFactory", securityFactory);
        if (!(changeCaEntry instanceof X509ChangeCaEntry)) {
            throw new CaMgmtException(
                    "unsupported ChangeCAEntry " + changeCaEntry.getClass().getName());
        }

        X509ChangeCaEntry entry = (X509ChangeCaEntry) changeCaEntry;
        String name = entry.getName();
        CaStatus status = entry.getStatus();
        X509Certificate cert = entry.getCert();
        List<String> crlUris = entry.getCrlUris();
        List<String> deltaCrlUris = entry.getDeltaCrlUris();
        List<String> ocspUris = entry.getOcspUris();
        List<String> cacertUris = entry.getCaCertUris();
        CertValidity maxValidity = entry.getMaxValidity();
        String signerType = entry.getSignerType();
        String signerConf = entry.getSignerConf();
        String crlsignerName = entry.getCrlSignerName();
        String responderName = entry.getResponderName();
        String cmpcontrolName = entry.getCmpControlName();
        Boolean duplicateKeyPermitted = entry.getDuplicateKeyPermitted();
        Boolean duplicateSubjectPermitted = entry.getDuplicateSubjectPermitted();
        Set<Permission> permissions = entry.getPermissions();
        Integer numCrls = entry.getNumCrls();
        Integer expirationPeriod = entry.getExpirationPeriod();
        Integer keepExpiredCertInDays = entry.getKeepExpiredCertInDays();
        ValidityMode validityMode = entry.getValidityMode();
        String extraControl = entry.getExtraControl();

        if (signerType != null || signerConf != null || cert != null) {
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

                String tmpSignerType = rs.getString("SIGNER_TYPE");
                String tmpSignerConf = rs.getString("SIGNER_CONF");
                String tmpB64Cert = rs.getString("CERT");
                if (signerType != null) {
                    tmpSignerType = signerType;
                }

                if (signerConf != null) {
                    tmpSignerConf = getRealString(signerConf);
                }

                X509Certificate tmpCert;
                if (cert != null) {
                    tmpCert = cert;
                } else {
                    try {
                        tmpCert = X509Util.parseBase64EncodedCert(tmpB64Cert);
                    } catch (CertificateException | IOException ex) {
                        throw new CaMgmtException(
                                "could not parse the stored certificate for CA '" + name + "'"
                                + ex.getMessage(), ex);
                    }
                }

                try {
                    List<String[]> signerConfs = CaManagerImpl.splitCaSignerConfs(tmpSignerConf);
                    for (String[] m : signerConfs) {
                        securityFactory.createSigner(tmpSignerType, m[1], tmpCert);
                    }
                } catch (SignerException ex) {
                    throw new CaMgmtException(
                            "could not create signer for CA '" + name + "'" + ex.getMessage(), ex);
                }
            } catch (SQLException ex) {
                DataAccessException dex = datasource.translate(sql, ex);
                throw new CaMgmtException(dex.getMessage(), dex);
            } finally {
                datasource.releaseResources(stmt, rs);
            }
        } // end if

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE CA SET ");

        AtomicInteger index = new AtomicInteger(1);

        Integer idxStatus = addToSqlIfNotNull(sqlBuilder, index, status, "STATUS");
        Integer idxSubject = addToSqlIfNotNull(sqlBuilder, index, cert, "SUBJECT");
        Integer idxCert = addToSqlIfNotNull(sqlBuilder, index, cert, "CERT");
        Integer idxCrlUris = addToSqlIfNotNull(sqlBuilder, index, crlUris, "CRL_URIS");
        Integer idxDeltaCrlUris =
                addToSqlIfNotNull(sqlBuilder, index, deltaCrlUris, "DELTACRL_URIS");
        Integer idxOcspUris = addToSqlIfNotNull(sqlBuilder, index, ocspUris, "OCSP_URIS");
        Integer idxCacertUris = addToSqlIfNotNull(sqlBuilder, index, cacertUris, "CACERT_URIS");
        Integer idxMaxValidity =
                addToSqlIfNotNull(sqlBuilder, index, maxValidity, "MAX_VALIDITY");
        Integer idxSignerType = addToSqlIfNotNull(sqlBuilder, index, signerType, "SIGNER_TYPE");
        Integer idxCrlsignerName =
                addToSqlIfNotNull(sqlBuilder, index, crlsignerName, "CRLSIGNER_NAME");
        Integer idxResponderName =
                addToSqlIfNotNull(sqlBuilder, index, responderName, "RESPONDER_NAME");
        Integer idxCmpcontrolName =
                addToSqlIfNotNull(sqlBuilder, index, cmpcontrolName, "CMPCONTROL_NAME");
        Integer idxDuplicateKey =
                addToSqlIfNotNull(sqlBuilder, index, duplicateKeyPermitted, "DUPLICATE_KEY");
        Integer idxDuplicateSubject =
                addToSqlIfNotNull(sqlBuilder, index, duplicateKeyPermitted, "DUPLICATE_SUBJECT");
        Integer idxPermissions = addToSqlIfNotNull(sqlBuilder, index, permissions, "PERMISSIONS");
        Integer idxNumCrls = addToSqlIfNotNull(sqlBuilder, index, numCrls, "NUM_CRLS");
        Integer idxExpirationPeriod =
                addToSqlIfNotNull(sqlBuilder, index, expirationPeriod, "EXPIRATION_PERIOD");
        Integer idxExpiredCerts =
                addToSqlIfNotNull(sqlBuilder, index, keepExpiredCertInDays,
                        "KEEP_EXPIRED_CERT_DAYS");
        Integer idxValidityMode =
                addToSqlIfNotNull(sqlBuilder, index, validityMode, "VALIDITY_MODE");
        Integer idxExtraControl =
                addToSqlIfNotNull(sqlBuilder, index, extraControl, "EXTRA_CONTROL");
        Integer idxSignerConf = addToSqlIfNotNull(sqlBuilder, index, signerConf, "SIGNER_CONF");

        // delete the last ','
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if (index.get() == 1) {
            return false;
        }
        int idxName = index.get();

        final String sql = sqlBuilder.toString();
        StringBuilder sb = new StringBuilder();
        PreparedStatement ps = null;

        try {
            ps = prepareStatement(sql);

            if (idxStatus != null) {
                sb.append("status: '").append(status.name()).append("'; ");
                ps.setString(idxStatus, status.name());
            }

            if (idxCert != null) {
                String subject = X509Util.getRfc4519Name(cert.getSubjectX500Principal());
                sb.append("cert: '").append(subject).append("'; ");
                ps.setString(idxSubject, subject);
                String base64Cert = Base64.toBase64String(cert.getEncoded());
                ps.setString(idxCert, base64Cert);
            }

            if (idxCrlUris != null) {
                String txt = toString(crlUris, ", ");
                sb.append("crlUri: '").append(txt).append("'; ");
                ps.setString(idxCrlUris, txt);
            }

            if (idxDeltaCrlUris != null) {
                String txt = toString(deltaCrlUris, ", ");
                sb.append("deltaCrlUri: '").append(txt).append("'; ");
                ps.setString(idxDeltaCrlUris, txt);
            }

            if (idxOcspUris != null) {
                String txt = toString(ocspUris, ", ");
                sb.append("ocspUri: '").append(txt).append("'; ");
                ps.setString(idxOcspUris, txt);
            }

            if (idxCacertUris != null) {
                String txt = toString(cacertUris, ", ");
                sb.append("caCertUri: '").append(txt).append("'; ");
                ps.setString(idxCacertUris, txt);
            }

            if (idxMaxValidity != null) {
                String txt = maxValidity.toString();
                sb.append("maxValidity: '").append(txt).append("'; ");
                ps.setString(idxMaxValidity, txt);
            }

            if (idxSignerType != null) {
                sb.append("signerType: '").append(signerType).append("'; ");
                ps.setString(idxSignerType, signerType);
            }

            if (idxSignerConf != null) {
                sb.append("signerConf: '");
                sb.append(SignerConfUtil.signerConfToString(signerConf, false, true));
                sb.append("'; ");
                ps.setString(idxSignerConf, signerConf);
            }

            if (idxCrlsignerName != null) {
                String txt = getRealString(crlsignerName);
                sb.append("crlSigner: '").append(txt).append("'; ");
                ps.setString(idxCrlsignerName, txt);
            }

            if (idxResponderName != null) {
                String txt = getRealString(responderName);
                sb.append("responder: '").append(txt).append("'; ");
                ps.setString(idxResponderName, txt);
            }

            if (idxCmpcontrolName != null) {
                String txt = getRealString(cmpcontrolName);
                sb.append("cmpControl: '").append(txt).append("'; ");
                ps.setString(idxCmpcontrolName, txt);
            }

            if (idxDuplicateKey != null) {
                sb.append("duplicateKey: '").append(duplicateKeyPermitted).append("'; ");
                setBoolean(ps, idxDuplicateKey, duplicateKeyPermitted);
            }

            if (idxDuplicateSubject != null) {
                sb.append("duplicateSubject: '").append(duplicateSubjectPermitted).append("'; ");
                setBoolean(ps, idxDuplicateSubject, duplicateSubjectPermitted);
            }

            if (idxPermissions != null) {
                String txt = Permission.toString(permissions);
                sb.append("permission: '").append(txt).append("'; ");
                ps.setString(idxPermissions, txt);
            }

            if (idxNumCrls != null) {
                sb.append("numCrls: '").append(numCrls).append("'; ");
                ps.setInt(idxNumCrls, numCrls);
            }

            if (idxExpirationPeriod != null) {
                sb.append("expirationPeriod: '").append(expirationPeriod).append("'; ");
                ps.setInt(idxExpirationPeriod, expirationPeriod);
            }

            if (idxExpiredCerts != null) {
                sb.append("keepExpiredCertDays: '").append(keepExpiredCertInDays).append("'; ");
                ps.setInt(idxExpiredCerts, keepExpiredCertInDays);
            }

            if (idxValidityMode != null) {
                String txt = validityMode.name();
                sb.append("validityMode: '").append(txt).append("'; ");
                ps.setString(idxValidityMode, txt);
            }

            if (idxExtraControl != null) {
                sb.append("extraControl: '").append(extraControl).append("'; ");
                ps.setString(idxExtraControl, extraControl);
            }

            ps.setString(idxName, name);
            ps.executeUpdate();

            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
            }

            LOG.info("changed CA '{}': {}", name, sb);
            return true;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeCa

    IdentifiedX509Certprofile changeCertprofile(
            final String name,
            final String type,
            final String conf,
            final CaManagerImpl caManager)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonNull("caManager", caManager);

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE PROFILE SET ");

        AtomicInteger index = new AtomicInteger(1);

        StringBuilder sb = new StringBuilder();

        String tmpType = type;
        String tmpConf = conf;

        if (tmpType != null) {
            sb.append("type: '").append(tmpType).append("'; ");
        }
        if (tmpConf != null) {
            sb.append("conf: '").append(tmpConf).append("'; ");
        }

        Integer idxType = addToSqlIfNotNull(sqlBuilder, index, tmpType, "TYPE");
        Integer idxConf = addToSqlIfNotNull(sqlBuilder, index, tmpConf, "CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");
        if (index.get() == 1) {
            return null;
        }

        CertprofileEntry currentDbEntry = createCertprofile(name);
        if (tmpType == null) {
            tmpType = currentDbEntry.getType();
        }
        if (tmpConf == null) {
            tmpConf = currentDbEntry.getConf();
        }

        tmpType = getRealString(tmpType);
        tmpConf = getRealString(tmpConf);

        CertprofileEntry newDbEntry = new CertprofileEntry(name, tmpType, tmpConf);
        IdentifiedX509Certprofile profile = caManager.createCertprofile(newDbEntry);
        if (profile == null) {
            return null;
        }

        final String sql = sqlBuilder.toString();

        boolean failed = true;
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            if (idxType != null) {
                ps.setString(idxType, tmpType);
            }

            if (idxConf != null) {
                ps.setString(idxConf, getRealString(tmpConf));
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
            }

            LOG.info("changed profile '{}': {}", name, sb);
            failed = false;
            return profile;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
            if (failed) {
                profile.shutdown();
            }
        }
    } // method changeCertprofile

    CmpControl changeCmpControl(
            final String name,
            final String conf)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        if (conf == null) {
            return null;
        }

        CmpControlEntry newDbEntry = new CmpControlEntry(name, conf);
        CmpControl cmpControl;
        try {
            cmpControl = new CmpControl(newDbEntry);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeCmpControl

    CmpRequestorEntryWrapper changeCmpRequestor(
            final String name,
            final String base64Cert)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);

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
                    subject = canonicalizName(
                            X509Util.parseBase64EncodedCert(b64Cert).getSubjectX500Principal());
                } catch (CertificateException | IOException ex) {
                    subject = "ERROR";
                }
            }
            LOG.info("changed CMP requestor '{}': {}", name, subject);
            return requestor;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeCmpRequestor

    CmpResponderEntryWrapper changeCmpResponder(
            final String name,
            final String type,
            final String conf,
            final String base64Cert,
            final CaManagerImpl caManager)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonNull("caManager", caManager);

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE RESPONDER SET ");

        String tmpType = type;
        String tmpConf = conf;
        String tmpBase64Cert = base64Cert;

        AtomicInteger index = new AtomicInteger(1);
        Integer idxType = addToSqlIfNotNull(sqlBuilder, index, tmpType, "TYPE");
        Integer idxCert = addToSqlIfNotNull(sqlBuilder, index, tmpBase64Cert, "CERT");
        Integer idxConf = addToSqlIfNotNull(sqlBuilder, index, tmpConf, "CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if (index.get() == 1) {
            return null;
        }

        CmpResponderEntry dbEntry = createResponder(name);

        if (tmpType == null) {
            tmpType = dbEntry.getType();
        }

        if (tmpConf == null) {
            tmpConf = dbEntry.getConf();
        }

        if (tmpBase64Cert == null) {
            tmpBase64Cert = dbEntry.getBase64Cert();
        }

        CmpResponderEntry newDbEntry = new CmpResponderEntry(name, tmpType,
                tmpConf, tmpBase64Cert);
        CmpResponderEntryWrapper responder = caManager.createCmpResponder(newDbEntry);

        final String sql = sqlBuilder.toString();

        StringBuilder sb = new StringBuilder();

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            if (idxType != null) {
                String txt = tmpType;
                ps.setString(idxType, txt);
                sb.append("type: '").append(txt).append("'; ");
            }

            if (idxConf != null) {
                String txt = getRealString(tmpConf);
                sb.append("conf: '").append(SignerConfUtil.signerConfToString(txt, false, true));
                ps.setString(idxConf, txt);
            }

            if (idxCert != null) {
                String txt = getRealString(tmpBase64Cert);
                sb.append("cert: '");
                if (txt == null) {
                    sb.append("null");
                } else {
                    try {
                        String subject = canonicalizName(
                                X509Util.parseBase64EncodedCert(txt).getSubjectX500Principal());
                        sb.append(subject);
                    } catch (CertificateException | IOException ex) {
                        sb.append("ERROR");
                    }
                }
                sb.append("'; ");
                ps.setString(idxCert, txt);
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
            }
            LOG.info("changed CMP responder: {}", sb);
            return responder;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
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
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonNull("caManager", caManager);

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE CRLSIGNER SET ");

        String tmpSignerType = signerType;
        String tmpSignerConf = signerConf;
        String tmpBase64Cert = base64Cert;
        String tmpCrlControl = crlControl;

        AtomicInteger index = new AtomicInteger(1);

        Integer idxSignerType = addToSqlIfNotNull(sqlBuilder, index, tmpSignerType, "SIGNER_TYPE");
        Integer idxSignerCert = addToSqlIfNotNull(sqlBuilder, index, tmpBase64Cert, "SIGNER_CERT");
        Integer idxCrlControl = addToSqlIfNotNull(sqlBuilder, index, tmpCrlControl, "CRL_CONTROL");
        Integer idxSignerConf = addToSqlIfNotNull(sqlBuilder, index, tmpSignerConf, "SIGNER_CONF");

        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if (index.get() == 1) {
            return null;
        }

        X509CrlSignerEntry dbEntry = createCrlSigner(name);
        if (tmpSignerType == null) {
            tmpSignerType = dbEntry.getType();
        }

        if ("CA".equalsIgnoreCase(tmpSignerType)) {
            tmpSignerConf = null;
            tmpBase64Cert = null;
        } else {
            if (tmpSignerConf == null) {
                tmpSignerConf = dbEntry.getConf();
            }

            if (tmpBase64Cert == null) {
                tmpBase64Cert = dbEntry.getBase64Cert();
            }
        }

        if (tmpCrlControl == null) {
            tmpCrlControl = dbEntry.getCrlControl();
        } else {
            // validate crlControl
            if (tmpCrlControl != null) {
                try {
                    new CrlControl(tmpCrlControl);
                } catch (InvalidConfException ex) {
                    throw new CaMgmtException("invalid CRL control '" + tmpCrlControl + "'");
                }
            }
        }

        try {
            dbEntry = new X509CrlSignerEntry(name, tmpSignerType, tmpSignerConf,
                    tmpBase64Cert, tmpCrlControl);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        }
        X509CrlSignerEntryWrapper crlSigner = caManager.createX509CrlSigner(dbEntry);

        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try {
            StringBuilder sb = new StringBuilder();

            ps = prepareStatement(sql);

            if (idxSignerType != null) {
                sb.append("signerType: '").append(tmpSignerType).append("'; ");
                ps.setString(idxSignerType, tmpSignerType);
            }

            if (idxSignerConf != null) {
                String txt = getRealString(tmpSignerConf);
                sb.append("signerConf: '")
                    .append(SignerConfUtil.signerConfToString(txt, false, true))
                    .append("'; ");
                ps.setString(idxSignerConf, txt);
            }

            if (idxSignerCert != null) {
                String txt = getRealString(tmpBase64Cert);
                String subject = null;
                if (txt != null) {
                    try {
                        subject = canonicalizName(
                                X509Util.parseBase64EncodedCert(txt).getSubjectX500Principal());
                    } catch (CertificateException | IOException ex) {
                        subject = "ERROR";
                    }
                }
                sb.append("signerCert: '").append(subject).append("'; ");
                ps.setString(idxSignerCert, txt);
            }

            if (idxCrlControl != null) {
                sb.append("crlControl: '").append(tmpCrlControl).append("'; ");
                ps.setString(idxCrlControl, tmpCrlControl);
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
            }
            LOG.info("changed CRL signer '{}': {}", name, sb);
            return crlSigner;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
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
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("caManager", caManager);

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE SCEP SET ");

        String tmpResponderType = responderType;
        String tmpResponderConf = responderConf;
        String tmpResponderBase64Cert = responderBase64Cert;
        String tmpControl = control;

        AtomicInteger index = new AtomicInteger(1);
        Integer idxType = addToSqlIfNotNull(sqlBuilder, index, tmpResponderType, "RESPONDER_TYPE");
        Integer idxCert = addToSqlIfNotNull(sqlBuilder, index, tmpResponderBase64Cert,
                "RESPONDER_CERT");
        Integer idxControl = addToSqlIfNotNull(sqlBuilder, index, tmpControl, "CONTROL");
        Integer idxConf = addToSqlIfNotNull(sqlBuilder, index, tmpResponderConf, "RESPONDER_CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE CA_NAME=?");

        if (index.get() == 1) {
            return null;
        }

        ScepEntry dbEntry = getScep(caName);

        if (tmpResponderType == null) {
            tmpResponderType = dbEntry.getResponderType();
        }

        if (tmpResponderConf == null) {
            tmpResponderConf = dbEntry.getResponderConf();
        }

        if (tmpResponderBase64Cert == null) {
            tmpResponderBase64Cert = dbEntry.getBase64Cert();
        }

        if (tmpControl == null) {
            tmpControl = dbEntry.getControl();
        } else if (CaManager.NULL.equals(tmpControl)) {
            tmpControl = null;
        }

        ScepEntry newDbEntry;
        try {
            newDbEntry = new ScepEntry(caName, tmpResponderType, tmpResponderConf,
                    tmpResponderBase64Cert, tmpControl);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException(ex);
        }
        Scep scep = new Scep(newDbEntry, caManager);

        final String sql = sqlBuilder.toString();

        StringBuilder sb = new StringBuilder();

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            if (idxType != null) {
                String txt = tmpResponderType;
                ps.setString(idxType, txt);
                sb.append("responder type: '").append(txt).append("'; ");
            }

            if (idxConf != null) {
                String txt = getRealString(tmpResponderConf);
                sb.append("responder conf: '")
                    .append(SignerConfUtil.signerConfToString(txt, false, true));
                ps.setString(idxConf, txt);
            }

            if (idxCert != null) {
                String txt = getRealString(tmpResponderBase64Cert);
                sb.append("responder cert: '");
                if (txt == null) {
                    sb.append("null");
                } else {
                    try {
                        String subject = canonicalizName(
                                X509Util.parseBase64EncodedCert(txt).getSubjectX500Principal());
                        sb.append(subject);
                    } catch (CertificateException | IOException ex) {
                        sb.append("ERROR");
                    }
                }
                sb.append("'; ");
                ps.setString(idxCert, txt);
            }

            if (idxControl != null) {
                String txt = getRealString(tmpControl);
                sb.append("control: '").append(tmpControl);
                ps.setString(idxControl, txt);
            }

            ps.setString(index.get(), caName);
            ps.executeUpdate();

            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
            }
            LOG.info("changed CMP responder: {}", sb);
            return scep;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeScep

    boolean changeEnvParam(
            final String name,
            final String value)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);

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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeEnvParam

    IdentifiedX509CertPublisher changePublisher(
            final String name,
            final String type,
            final String conf,
            final CaManagerImpl caManager)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonNull("caManager", caManager);

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE PUBLISHER SET ");

        String tmpType = type;
        String tmpConf = conf;

        AtomicInteger index = new AtomicInteger(1);
        Integer idxType = addToSqlIfNotNull(sqlBuilder, index, tmpType, "TYPE");
        Integer idxConf = addToSqlIfNotNull(sqlBuilder, index, tmpConf, "CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if (index.get() == 1) {
            return null;
        }

        PublisherEntry currentDbEntry = createPublisher(name);
        if (tmpType == null) {
            tmpType = currentDbEntry.getType();
        }

        if (tmpConf == null) {
            tmpConf = currentDbEntry.getConf();
        }

        PublisherEntry dbEntry = new PublisherEntry(name, tmpType, tmpConf);
        IdentifiedX509CertPublisher publisher = caManager.createPublisher(dbEntry);
        if (publisher == null) {
            return null;
        }

        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try {
            StringBuilder sb = new StringBuilder();
            ps = prepareStatement(sql);
            if (idxType != null) {
                sb.append("type: '").append(tmpType).append("'; ");
                ps.setString(idxType, tmpType);
            }

            if (idxConf != null) {
                String txt = getRealString(tmpConf);
                sb.append("conf: '").append(txt).append("'; ");
                ps.setString(idxConf, getRealString(tmpConf));
            }

            ps.setString(index.get(), name);
            ps.executeUpdate();

            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
            }
            LOG.info("changed publisher '{}': {}", name, sb);
            return publisher;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changePublisher

    boolean removeCa(
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        final String sql = "DELETE FROM CA WHERE NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            return ps.executeUpdate() > 0;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeCa

    boolean removeCaAlias(
            final String aliasName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("aliasName", aliasName);
        final String sql = "DELETE FROM CAALIAS WHERE NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, aliasName);
            boolean bo = ps.executeUpdate() > 0;
            if (bo) {
                LOG.info("removed CA alias '{}'", aliasName);
            }
            return bo;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeCaAlias

    boolean removeCertprofileFromCa(
            final String profileLocalName,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("profileLocalName", profileLocalName);
        ParamUtil.requireNonBlank("caName", caName);

        final String sql = "DELETE FROM CA_HAS_PROFILE WHERE CA_NAME=? AND PROFILE_LOCALNAME=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, profileLocalName);
            boolean bo = ps.executeUpdate() > 0;
            if (bo) {
                LOG.info("removed profile '{}' from CA '{}'", profileLocalName, caName);
            }
            return bo;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeCertprofileFromCa

    boolean removeCmpRequestorFromCa(
            final String requestorName,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("requestorName", requestorName);
        ParamUtil.requireNonBlank("caName", caName);

        final String sql = "DELETE FROM CA_HAS_REQUESTOR WHERE CA_NAME=? AND REQUESTOR_NAME=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, requestorName);
            boolean bo = ps.executeUpdate() > 0;
            if (bo) {
                LOG.info("removed requestor '{}' from CA '{}'", requestorName, caName);
            }
            return bo;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeCmpRequestorFromCa

    boolean removePublisherFromCa(
            final String publisherName,
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("publisherName", publisherName);
        ParamUtil.requireNonBlank("caName", caName);
        final String sql = "DELETE FROM CA_HAS_PUBLISHER WHERE CA_NAME=? AND PUBLISHER_NAME=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            ps.setString(2, publisherName);
            boolean bo = ps.executeUpdate() > 0;
            if (bo) {
                LOG.info("removed publisher '{}' from CA '{}'", publisherName, caName);
            }
            return bo;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removePublisherFromCa

    boolean revokeCa(
            final String caName,
            final CertRevocationInfo revocationInfo)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("revocationInfo", revocationInfo);
        String sql = "UPDATE CA SET REV=?, RR=?, RT=?, RIT=? WHERE NAME=?";
        PreparedStatement ps = null;
        try {
            if (revocationInfo.getInvalidityTime() == null) {
                revocationInfo.setInvalidityTime(revocationInfo.getRevocationTime());
            }

            ps = prepareStatement(sql);
            int idx = 1;
            setBoolean(ps, idx++, true);
            ps.setInt(idx++, revocationInfo.getReason().getCode());
            ps.setLong(idx++, revocationInfo.getRevocationTime().getTime() / 1000);
            ps.setLong(idx++, revocationInfo.getInvalidityTime().getTime() / 1000);
            ps.setString(idx++, caName);
            boolean bo = ps.executeUpdate() > 0;
            if (bo) {
                LOG.info("revoked CA '{}'", caName);
            }
            return bo;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method revokeCa

    void addCmpResponder(
            final CmpResponderEntry dbEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(ex.getMessage(), ex);
        } finally {
            datasource.releaseResources(ps, null);
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
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            datasource.releaseResources(stmt, null);
        }
    } // method unlockCa

    boolean unrevokeCa(
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        LOG.info("Unrevoking of CA '{}'", caName);

        final String sql = "UPDATE CA SET REV=?, RR=?, RT=?, RIT=? WHERE NAME=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            setBoolean(ps, idx++, false);
            ps.setNull(idx++, Types.INTEGER);
            ps.setNull(idx++, Types.INTEGER);
            ps.setNull(idx++, Types.INTEGER);
            ps.setString(idx++, caName);
            return ps.executeUpdate() > 0;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method unrevokeCa

    boolean addUser(
            final AddUserEntry userEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("userEntry", userEntry);
        final String name = userEntry.getName();
        Integer existingId = executeGetUserIdSql(name);
        if (existingId != null) {
            throw new CaMgmtException("user named '" + name + " ' already exists");
        }

        String hashedPassword;
        try {
            hashedPassword = PasswordHash.createHash(userEntry.getPassword());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CaMgmtException(ex);
        }
        UserEntry tmpUserEntry = new UserEntry(name, hashedPassword, userEntry.getCnRegex());

        try {
            int maxId = (int) datasource.getMax(null, "USERNAME", "ID");
            executeAddUserSql(maxId + 1, tmpUserEntry);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex);
        }

        LOG.info("added user '{}'", name);

        return true;
    } // method addUser

    private Integer executeGetUserIdSql(
            final String user)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("user", user);
        final String sql = datasource.createFetchFirstSelectSql("ID FROM USERNAME WHERE NAME=?", 1);
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
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource.translate(sql, ex));
        } finally {
            datasource.releaseResources(ps, rs);
        }
    } // method executeGetUserIdSql

    private void executeAddUserSql(
            final int id,
            final UserEntry userEntry)
    throws DataAccessException, CaMgmtException {
        ParamUtil.requireNonNull("userEntry", userEntry);
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
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method executeAddUserSql

    boolean removeUser(
            final String userName)
    throws CaMgmtException {
        ParamUtil.requireNonBlank("userName", userName);
        final String sql = "DELETE FROM USERNAME WHERE NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, userName);
            return ps.executeUpdate() > 0;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
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
        Integer idxPassword = addToSqlIfNotNull(sqlBuilder, index, password, "PASSWORD");
        Integer idxCnRegex = addToSqlIfNotNull(sqlBuilder, index, cnRegex, "CN_REGEX");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE ID=?");

        if (index.get() == 1) {
            return false;
        }

        final String sql = sqlBuilder.toString();

        StringBuilder sb = new StringBuilder();

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            if (idxPassword != null) {
                String txt = getRealString(password);
                ps.setString(idxPassword, txt);
                sb.append("password: ****; ");
            }

            if (idxCnRegex != null) {
                sb.append("CnRegex: '").append(cnRegex);
                ps.setString(idxCnRegex, cnRegex);
            }

            ps.setInt(index.get(), existingId);

            ps.executeUpdate();

            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
            }
            LOG.info("changed user: {}", sb);
            return true;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeUser

    UserEntry getUser(
            final String username)
    throws CaMgmtException {
        ParamUtil.requireNonNull("username", username);
        final String sql = datasource.createFetchFirstSelectSql(
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
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource.translate(sql, ex));
        } finally {
            datasource.releaseResources(ps, rs);
        }
    } // method getUser

    boolean addScep(
            final ScepEntry scepEntry)
    throws CaMgmtException {
        ParamUtil.requireNonNull("scepEntry", scepEntry);
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
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }

        return true;
    } // method addScep

    boolean removeScep(
            final String name)
    throws CaMgmtException {
        ParamUtil.requireNonNull("name", name);
        final String sql = "DELETE FROM SCEP WHERE CA_NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            return ps.executeUpdate() > 0;
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(sql, ex);
            throw new CaMgmtException(dex.getMessage(), dex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeScep

    ScepEntry getScep(
            final String caName)
    throws CaMgmtException {
        ParamUtil.requireNonNull("caName", caName);
        final String sql = datasource.createFetchFirstSelectSql(
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
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource.translate(sql, ex));
        } catch (InvalidConfException ex) {
            throw new CaMgmtException(ex);
        } finally {
            datasource.releaseResources(ps, rs);
        }
    } // method getScep

    private static void setBoolean(
            final PreparedStatement ps,
            final int index,
            final boolean bo)
    throws SQLException {
        int value = bo
                ? 1
                : 0;
        ps.setInt(index, value);
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
        ParamUtil.requireNonBlank("permissionsText", permissionsText);

        List<String> strs = StringUtil.split(permissionsText, ", ");
        Set<Permission> permissions = new HashSet<>();
        for (String permissionText : strs) {
            Permission permission = Permission.getPermission(permissionText);
            if (permission == null) {
                throw new CaMgmtException("unknown permission " + permissionText);
            }
            if (permission == Permission.ALL) {
                permissions.clear();
                permissions.add(permission);
                break;
            } else {
                permissions.add(permission);
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
            final String str) {
        return CaManager.NULL.equalsIgnoreCase(str)
                ? null
                : str;
    }

    public static String canonicalizName(
            final X500Principal prin) {
        ParamUtil.requireNonNull("prin", prin);
        X500Name x500Name = X500Name.getInstance(prin.getEncoded());
        return X509Util.canonicalizName(x500Name);
    }

}
