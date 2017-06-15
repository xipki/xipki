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
import org.xipki.common.InvalidConfException;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.pki.ca.api.NameId;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.server.impl.cmp.CmpRequestorEntryWrapper;
import org.xipki.pki.ca.server.impl.cmp.CmpResponderEntryWrapper;
import org.xipki.pki.ca.server.impl.scep.Scep;
import org.xipki.pki.ca.server.impl.store.CertificateStore;
import org.xipki.pki.ca.server.impl.util.PasswordHash;
import org.xipki.pki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CaManager;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.CertArt;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControl;
import org.xipki.pki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.pki.ca.server.mgmt.api.UserEntry;
import org.xipki.pki.ca.server.mgmt.api.ValidityMode;
import org.xipki.pki.ca.server.mgmt.api.x509.CrlControl;
import org.xipki.pki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaUris;
import org.xipki.pki.ca.server.mgmt.api.x509.X509ChangeCaEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
class CaManagerQueryExecutor {

    private static final Logger LOG = LoggerFactory.getLogger(CaManagerQueryExecutor.class);

    private final DataSourceWrapper datasource;

    private final SQLs sqls;

    CaManagerQueryExecutor(final DataSourceWrapper datasource) {
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);
        this.sqls = new SQLs(datasource);
    }

    private X509Certificate generateCert(final String b64Cert) throws CaMgmtException {
        if (b64Cert == null) {
            return null;
        }

        byte[] encodedCert = Base64.decode(b64Cert);
        try {
            return X509Util.parseCert(encodedCert);
        } catch (CertificateException ex) {
            throw new CaMgmtException(ex);
        }
    } // method generateCert

    private Statement createStatement() throws CaMgmtException {
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

    private PreparedStatement prepareStatement(final String sql) throws CaMgmtException {
        Connection dsConnection;
        try {
            dsConnection = datasource.getConnection();
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex);
        }

        try {
            return datasource.prepareStatement(dsConnection, sql);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex);
        }
    } // method prepareStatement

    SystemEvent getSystemEvent(final String eventName) throws CaMgmtException {
        final String sql = sqls.sqlSelectSystemEvent;
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, rs);
        }
    } // method getSystemEvent

    void deleteSystemEvent(final String eventName) throws CaMgmtException {
        final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME=?";
        PreparedStatement ps = null;

        try {
            ps = prepareStatement(sql);
            ps.setString(1, eventName);
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method deleteSystemEvent

    void addSystemEvent(final SystemEvent systemEvent) throws CaMgmtException {
        final String sql =
            "INSERT INTO SYSTEM_EVENT (NAME,EVENT_TIME,EVENT_TIME2,EVENT_OWNER) VALUES (?,?,?,?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, systemEvent.getName());
            ps.setLong(idx++, systemEvent.getEventTime());
            ps.setTimestamp(idx++, new Timestamp(systemEvent.getEventTime() * 1000L));
            ps.setString(idx++, systemEvent.getOwner());
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addSystemEvent

    boolean changeSystemEvent(final SystemEvent systemEvent) throws CaMgmtException {
        deleteSystemEvent(systemEvent.getName());
        addSystemEvent(systemEvent);
        return true;
    }

    Map<String, String> createEnvParameters() throws CaMgmtException {
        Map<String, String> map = new HashMap<>();
        final String sql = "SELECT NAME,VALUE2 FROM ENVIRONMENT";
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }

        return map;
    } // method createEnvParameters

    Map<String, Integer> createCaAliases() throws CaMgmtException {
        Map<String, Integer> map = new HashMap<>();

        final String sql = "SELECT NAME,CA_ID FROM CAALIAS";
        Statement stmt = null;
        ResultSet rs = null;

        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String name = rs.getString("NAME");
                int caId = rs.getInt("CA_ID");
                map.put(name, caId);
            }
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }

        return map;
    } // method createCaAliases

    CertprofileEntry createCertprofile(final String name) throws CaMgmtException {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        final String sql = sqls.sqlSelectProfile;
        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            int id = rs.getInt("ID");
            String type = rs.getString("TYPE");
            String conf = rs.getString("CONF");
            return new CertprofileEntry(new NameId(id, name), type, conf);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCertprofile

    List<String> getNamesFromTable(final String table) throws CaMgmtException {
        return getNamesFromTable(table, "NAME");
    }

    List<String> getNamesFromTable(final String table, final String nameColumn)
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method getNamesFromTable

    PublisherEntry createPublisher(final String name) throws CaMgmtException {
        final String sql = sqls.sqlSelectPublisher;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            int id = rs.getInt("ID");
            String type = rs.getString("TYPE");
            String conf = rs.getString("CONF");
            return new PublisherEntry(new NameId(id, name), type, conf);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createPublisher

    Integer getRequestorId(String requestorName) throws CaMgmtException {
        final String sql = sqls.sqlSelectRequestorId;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, requestorName);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            return rs.getInt("ID");
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    }

    CmpRequestorEntry createRequestor(final String name) throws CaMgmtException {
        final String sql = sqls.sqlSelectRequestor;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            int id = rs.getInt("ID");
            String b64Cert = rs.getString("CERT");
            return new CmpRequestorEntry(new NameId(id, name), b64Cert);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createRequestor

    X509CrlSignerEntry createCrlSigner(final String name) throws CaMgmtException {
        final String sql = sqls.sqlSelectCrlSigner;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            String signerType = rs.getString("SIGNER_TYPE");
            String signerConf = rs.getString("SIGNER_CONF");
            String signerCert = rs.getString("SIGNER_CERT");
            String crlControlConf = rs.getString("CRL_CONTROL");
            return new X509CrlSignerEntry(name, signerType, signerConf, signerCert, crlControlConf);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException(ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCrlSigner

    CmpControlEntry createCmpControl(final String name) throws CaMgmtException {
        final String sql = sqls.sqlSelectCmpControl;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            String conf = rs.getString("CONF");
            return new CmpControlEntry(name, conf);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCmpControl

    CmpResponderEntry createResponder(final String name) throws CaMgmtException {
        final String sql = sqls.sqlSelectResponder;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            stmt = prepareStatement(sql);
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createResponder

    X509CaInfo createCaInfo(final String name, final boolean masterMode,
            final CertificateStore certstore) throws CaMgmtException {
        final String sql = sqls.sqlSelectCa;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, name);
            rs = stmt.executeQuery();

            if (!rs.next()) {
                return null;
            }

            int artCode = rs.getInt("ART");
            if (artCode != CertArt.X509PKC.getCode()) {
                throw new CaMgmtException("CA " + name + " is not X509CA, and is not supported");
            }

            String crlUris = rs.getString("CRL_URIS");
            String deltaCrlUris = rs.getString("DELTACRL_URIS");

            CertRevocationInfo revocationInfo = null;
            boolean revoked = rs.getBoolean("REV");
            if (revoked) {
                int revReason = rs.getInt("RR");
                long revTime = rs.getInt("RT");
                long revInvalidityTime = rs.getInt("RIT");
                Date revInvTime = (revInvalidityTime == 0) ? null
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

            int id = rs.getInt("ID");
            int serialNoSize = rs.getInt("SN_SIZE");
            long nextCrlNo = rs.getLong("NEXT_CRLNO");
            String signerType = rs.getString("SIGNER_TYPE");
            String signerConf = rs.getString("SIGNER_CONF");
            int numCrls = rs.getInt("NUM_CRLS");
            int expirationPeriod = rs.getInt("EXPIRATION_PERIOD");

            X509CaEntry entry = new X509CaEntry(new NameId(id, name), serialNoSize,
                    nextCrlNo, signerType, signerConf, caUris, numCrls, expirationPeriod);
            String b64cert = rs.getString("CERT");
            X509Certificate cert = generateCert(b64cert);
            entry.setCertificate(cert);

            String status = rs.getString("STATUS");
            CaStatus caStatus = CaStatus.forName(status);
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

            boolean saveReq = (rs.getInt("SAVE_REQ") != 0);
            entry.setSaveRequest(saveReq);

            int permission = rs.getInt("PERMISSION");
            entry.setPermission(permission);
            entry.setRevocationInfo(revocationInfo);

            String validityModeS = rs.getString("VALIDITY_MODE");
            ValidityMode validityMode = null;
            if (validityModeS != null) {
                validityMode = ValidityMode.forName(validityModeS);
            }
            if (validityMode == null) {
                validityMode = ValidityMode.STRICT;
            }
            entry.setValidityMode(validityMode);

            try {
                return new X509CaInfo(entry, certstore);
            } catch (OperationException ex) {
                throw new CaMgmtException(ex);
            }
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCaInfo

    Set<CaHasRequestorEntry> createCaHasRequestors(final NameId ca)
            throws CaMgmtException {
        Map<Integer, String> idNameMap = getIdNameMap("REQUESTOR");

        final String sql =
                "SELECT REQUESTOR_ID,RA,PERMISSION,PROFILES FROM CA_HAS_REQUESTOR WHERE CA_ID=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = prepareStatement(sql);
            stmt.setInt(1, ca.getId());
            rs = stmt.executeQuery();

            Set<CaHasRequestorEntry> ret = new HashSet<>();
            while (rs.next()) {
                int id = rs.getInt("REQUESTOR_ID");
                String name = idNameMap.get(id);

                boolean ra = rs.getBoolean("RA");
                int permission = rs.getInt("PERMISSION");
                String str = rs.getString("PROFILES");
                List<String> list = StringUtil.split(str, ",");
                Set<String> profiles = (list == null) ? null : new HashSet<>(list);
                CaHasRequestorEntry entry = new CaHasRequestorEntry(new NameId(id, name));
                entry.setRa(ra);
                entry.setPermission(permission);
                entry.setProfiles(profiles);

                ret.add(entry);
            }

            return ret;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCaHasRequestors

    Set<Integer> createCaHasProfiles(final NameId ca) throws CaMgmtException {
        final String sql = "SELECT PROFILE_ID FROM CA_HAS_PROFILE WHERE CA_ID=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = prepareStatement(sql);
            stmt.setInt(1, ca.getId());
            rs = stmt.executeQuery();

            Set<Integer> ret = new HashSet<>();
            while (rs.next()) {
                int id = rs.getInt("PROFILE_ID");
                ret.add(id);
            }

            return ret;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCaHasProfiles

    Set<Integer> createCaHasPublishers(final NameId ca) throws CaMgmtException {
        final String sql = "SELECT PUBLISHER_ID FROM CA_HAS_PUBLISHER WHERE CA_ID=?";
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = prepareStatement(sql);
            stmt.setInt(1, ca.getId());
            rs = stmt.executeQuery();

            Set<Integer> ret = new HashSet<>();
            while (rs.next()) {
                int id = rs.getInt("PUBLISHER_ID");
                ret.add(id);
            }

            return ret;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // method createCaHasNames

    boolean deleteRowWithName(final String name, final String table) throws CaMgmtException {
        return deleteRowWithName(name, table, false);
    }

    private boolean deleteRowWithName(final String name, final String table, boolean force)
            throws CaMgmtException {
        if (!force) {
            if ("ENVIRONMENT".equalsIgnoreCase(table)) {
                if (CaManagerImpl.ENV_EPOCH.equalsIgnoreCase(name)) {
                    throw new CaMgmtException("environment " + name + " is reserved");
                }
            }
        }

        final String sql = new StringBuilder("DELETE FROM ").append(table)
                .append(" WHERE NAME=?").toString();
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            return ps.executeUpdate() > 0;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method deleteRowWithName

    boolean deleteRows(final String table) throws CaMgmtException {
        final String sql = "DELETE FROM " + table;
        Statement stmt = null;
        try {
            stmt = createStatement();
            return stmt.executeUpdate(sql) > 0;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, null);
        }
    } // method deleteRows

    void addCa(final CaEntry caEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("caEntry", caEntry);
        if (!(caEntry instanceof X509CaEntry)) {
            throw new CaMgmtException("unsupported CAEntry " + caEntry.getClass().getName());
        }

        try {
            int id = (int) datasource.getMax(null, "CA", "ID");
            caEntry.getIdent().setId(id + 1);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex);
        }

        X509CaEntry entry = (X509CaEntry) caEntry;

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("INSERT INTO CA (ID,NAME,ART,SUBJECT,SN_SIZE,NEXT_CRLNO,STATUS,CRL_URIS");
        sqlBuilder.append(",DELTACRL_URIS,OCSP_URIS,CACERT_URIS,MAX_VALIDITY,CERT,SIGNER_TYPE");
        sqlBuilder.append(",CRLSIGNER_NAME,RESPONDER_NAME,CMPCONTROL_NAME,DUPLICATE_KEY");
        sqlBuilder.append(",DUPLICATE_SUBJECT,SAVE_REQ,PERMISSION,NUM_CRLS,EXPIRATION_PERIOD");
        sqlBuilder.append(",KEEP_EXPIRED_CERT_DAYS,VALIDITY_MODE,EXTRA_CONTROL,SIGNER_CONF)");
        sqlBuilder.append(" VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        final String sql = sqlBuilder.toString();

        // insert to table ca
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setInt(idx++, entry.getIdent().getId());
            ps.setString(idx++, entry.getIdent().getName());
            ps.setInt(idx++, CertArt.X509PKC.getCode());
            ps.setString(idx++, entry.getSubject());
            ps.setInt(idx++, entry.getSerialNoBitLen());
            ps.setLong(idx++, entry.getNextCrlNumber());
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
            setBoolean(ps, idx++, entry.isSaveRequest());
            ps.setInt(idx++, entry.getPermission());
            ps.setInt(idx++, entry.getNumCrls());
            ps.setInt(idx++, entry.getExpirationPeriod());
            ps.setInt(idx++, entry.getKeepExpiredCertInDays());
            ps.setString(idx++, entry.getValidityMode().name());
            ps.setString(idx++, entry.getExtraControl());
            ps.setString(idx++, entry.getSignerConf());
            ps.executeUpdate();
            if (LOG.isInfoEnabled()) {
                LOG.info("add CA '{}': {}", entry.getIdent(), entry.toString(false, true));
            }
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCa

    void addCaAlias(final String aliasName, final NameId ca) throws CaMgmtException {
        ParamUtil.requireNonNull("aliasName", aliasName);
        ParamUtil.requireNonNull("ca", ca);

        final String sql = "INSERT INTO CAALIAS (NAME,CA_ID) VALUES (?,?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, aliasName);
            ps.setInt(2, ca.getId());
            ps.executeUpdate();
            LOG.info("added CA alias '{}' for CA '{}'", aliasName, ca);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCaAlias

    void addCertprofile(final CertprofileEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        final String sql = "INSERT INTO PROFILE (ID,NAME,ART,TYPE,CONF) VALUES (?,?,?,?,?)";

        try {
            int id = (int) datasource.getMax(null, "PROFILE", "ID");
            dbEntry.getIdent().setId(id + 1);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex);
        }

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setInt(idx++, dbEntry.getIdent().getId());
            ps.setString(idx++, dbEntry.getIdent().getName());
            ps.setInt(idx++, CertArt.X509PKC.getCode());
            ps.setString(idx++, dbEntry.getType());
            String conf = dbEntry.getConf();
            ps.setString(idx++, conf);
            ps.executeUpdate();
            LOG.info("added profile '{}': {}", dbEntry.getIdent(), dbEntry);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCertprofile

    void addCertprofileToCa(final NameId profile, final NameId ca)
            throws CaMgmtException {
        ParamUtil.requireNonNull("profile", profile);
        ParamUtil.requireNonNull("ca", ca);

        final String sql = "INSERT INTO CA_HAS_PROFILE (CA_ID,PROFILE_ID) VALUES (?,?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setInt(1, ca.getId());
            ps.setInt(2, profile.getId());
            ps.executeUpdate();
            LOG.info("added profile '{}' to CA '{}'", profile, ca);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCertprofileToCa

    void addCmpControl(final CmpControlEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        final String name = dbEntry.getName();
        final String sql = "INSERT INTO CMPCONTROL (NAME,CONF) VALUES (?,?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, name);
            ps.setString(idx++, dbEntry.getConf());
            ps.executeUpdate();
            LOG.info("added CMP control: {}", dbEntry);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCmpControl

    void addRequestor(final CmpRequestorEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);

        try {
            int id = (int) datasource.getMax(null, "REQUESTOR", "ID");
            dbEntry.getIdent().setId(id + 1);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex);
        }

        final String sql = "INSERT INTO REQUESTOR (ID,NAME,CERT) VALUES (?,?,?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setInt(idx++, dbEntry.getIdent().getId());
            ps.setString(idx++, dbEntry.getIdent().getName());
            ps.setString(idx++, Base64.toBase64String(dbEntry.getCert().getEncoded()));
            ps.executeUpdate();
            if (LOG.isInfoEnabled()) {
                LOG.info("added requestor '{}': {}", dbEntry.getIdent(), dbEntry.toString(false));
            }
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCmpRequestor

    void addRequestorIfNeeded(String requestorName) throws CaMgmtException {
        String sql = sqls.sqlSelectRequestorId;
        ResultSet rs = null;
        PreparedStatement stmt = null;
        try {
            stmt = prepareStatement(sql);
            stmt.setString(1, requestorName);
            rs = stmt.executeQuery();
            if (rs.next()) {
                return;
            }
            datasource.releaseResources(stmt, rs);
            stmt = null;
            rs = null;

            int id = (int) datasource.getMax(null, "REQUESTOR", "ID");

            sql = "INSERT INTO REQUESTOR (ID,NAME) VALUES (?,?)";
            stmt = prepareStatement(sql);
            stmt.setInt(1, id + 1);
            stmt.setString(2, requestorName);
            stmt.executeUpdate();
            LOG.info("added requestor '{}'", requestorName);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    }

    void addRequestorToCa(final CaHasRequestorEntry requestor, final NameId ca)
            throws CaMgmtException {
        ParamUtil.requireNonNull("requestor", requestor);
        ParamUtil.requireNonNull("ca", ca);

        final NameId requestorIdent = requestor.getRequestorIdent();

        PreparedStatement ps = null;
        final String sql = "INSERT INTO CA_HAS_REQUESTOR (CA_ID,REQUESTOR_ID,RA,"
                + " PERMISSION,PROFILES) VALUES (?,?,?,?,?)";
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setInt(idx++, ca.getId());
            ps.setInt(idx++, requestorIdent.getId());

            boolean ra = requestor.isRa();
            setBoolean(ps, idx++, ra);
            int permission = requestor.getPermission();
            ps.setInt(idx++, permission);
            String profilesText = toString(requestor.getProfiles(), ",");
            ps.setString(idx++, profilesText);

            ps.executeUpdate();
            LOG.info("added requestor '{}' to CA '{}': ra: {}; permission: {}; profile: {}",
                    requestorIdent, ca, ra, permission, profilesText);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCmpRequestorToCa

    void addCrlSigner(final X509CrlSignerEntry dbEntry) throws CaMgmtException {
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
        sqlBuilder.append("INSERT INTO CRLSIGNER (NAME,SIGNER_TYPE,SIGNER_CERT,CRL_CONTROL,");
        sqlBuilder.append("SIGNER_CONF) VALUES (?,?,?,?,?)");
        final String sql = sqlBuilder.toString();

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, name);
            ps.setString(idx++, dbEntry.getType());
            ps.setString(idx++, (dbEntry.getCertificate() == null) ? null
                        : Base64.toBase64String(dbEntry.getCertificate().getEncoded()));
            ps.setString(idx++, crlControl);
            ps.setString(idx++, dbEntry.getConf());

            ps.executeUpdate();
            LOG.info("added CRL signer '{}': {}", name, dbEntry.toString(false, true));
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCrlSigner

    String setEpoch(Date time) throws CaMgmtException {
        deleteRowWithName(CaManagerImpl.ENV_EPOCH, "ENVIRONMENT", true);
        String envEpoch = DateUtil.toUtcTimeyyyyMMdd(time);
        addEnvParam(CaManagerImpl.ENV_EPOCH, envEpoch, true);
        return envEpoch;
    }

    void addEnvParam(final String name, final String value) throws CaMgmtException {
        addEnvParam(name, value, false);
    }

    private void addEnvParam(final String name, final String value, boolean force)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonNull("value", value);
        if (!force) {
            if (CaManagerImpl.ENV_EPOCH.equalsIgnoreCase(name)) {
                throw new CaMgmtException("environment " + name + " is reserved");
            }
        }
        final String sql = "INSERT INTO ENVIRONMENT (NAME,VALUE2) VALUES (?,?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            ps.setString(2, value);
            ps.executeUpdate();
            LOG.info("added environment param '{}': {}", name, value);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addEnvParam

    void addPublisher(final PublisherEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        final String sql = "INSERT INTO PUBLISHER (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";

        try {
            int id = (int) datasource.getMax(null, "PUBLISHER", "ID");
            dbEntry.getIdent().setId(id + 1);
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex);
        }

        String name = dbEntry.getIdent().getName();
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setInt(idx++, dbEntry.getIdent().getId());
            ps.setString(idx++, name);
            ps.setString(idx++, dbEntry.getType());
            String conf = dbEntry.getConf();
            ps.setString(idx++, conf);
            ps.executeUpdate();
            LOG.info("added publisher '{}': {}", dbEntry.getIdent(), dbEntry);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addPublisher

    void addPublisherToCa(final NameId publisher, final NameId ca)
            throws CaMgmtException {
        final String sql = "INSERT INTO CA_HAS_PUBLISHER (CA_ID,PUBLISHER_ID) VALUES (?,?)";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setInt(1, ca.getId());
            ps.setInt(2, publisher.getId());
            ps.executeUpdate();
            LOG.info("added publisher '{}' to CA '{}'", publisher, ca);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addPublisherToCa

    boolean changeCa(final ChangeCaEntry changeCaEntry, final SecurityFactory securityFactory)
            throws CaMgmtException {
        ParamUtil.requireNonNull("changeCaEntry", changeCaEntry);
        ParamUtil.requireNonNull("securityFactory", securityFactory);
        if (!(changeCaEntry instanceof X509ChangeCaEntry)) {
            throw new CaMgmtException(
                    "unsupported ChangeCAEntry " + changeCaEntry.getClass().getName());
        }

        X509ChangeCaEntry entry = (X509ChangeCaEntry) changeCaEntry;
        X509Certificate cert = entry.getCert();
        if (cert != null) {
            boolean anyCertIssued;
            try {
                anyCertIssued = datasource.columnExists(null, "CERT", "CA_ID",
                        entry.getIdent().getId());
            } catch (DataAccessException ex) {
                throw new CaMgmtException(ex);
            }

            if (anyCertIssued) {
                throw new CaMgmtException(
                        "Cannot change the certificate of CA, since it has issued certificates");
            }
        }

        Integer serialNoBitLen = entry.getSerialNoBitLen();
        CaStatus status = entry.getStatus();
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
        Boolean saveReq = entry.getSaveRequest();
        Integer permission = entry.getPermission();
        Integer numCrls = entry.getNumCrls();
        Integer expirationPeriod = entry.getExpirationPeriod();
        Integer keepExpiredCertInDays = entry.getKeepExpiredCertInDays();
        ValidityMode validityMode = entry.getValidityMode();
        String extraControl = entry.getExtraControl();

        if (signerType != null || signerConf != null || cert != null) {
            final String sql = "SELECT SIGNER_TYPE,CERT,SIGNER_CONF FROM CA WHERE ID=?";
            PreparedStatement stmt = null;
            ResultSet rs = null;

            try {
                stmt = prepareStatement(sql);
                stmt.setInt(1, entry.getIdent().getId());
                rs = stmt.executeQuery();
                if (!rs.next()) {
                    throw new CaMgmtException("no CA '" + entry.getIdent() + "' is defined");
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
                    } catch (CertificateException ex) {
                        throw new CaMgmtException("could not parse the stored certificate for CA '"
                                + changeCaEntry.getIdent() + "'" + ex.getMessage(), ex);
                    }
                }

                try {
                    List<String[]> signerConfs = CaEntry.splitCaSignerConfs(tmpSignerConf);
                    for (String[] m : signerConfs) {
                        securityFactory.createSigner(tmpSignerType, new SignerConf(m[1]), tmpCert);
                    }
                } catch (XiSecurityException | ObjectCreationException ex) {
                    throw new CaMgmtException(
                            "could not create signer for CA '" + changeCaEntry.getIdent()
                            + "'" + ex.getMessage(), ex);
                }
            } catch (SQLException ex) {
                throw new CaMgmtException(datasource, sql, ex);
            } finally {
                datasource.releaseResources(stmt, rs);
            }
        } // end if (signerType)

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE CA SET ");

        AtomicInteger index = new AtomicInteger(1);

        Integer idxSnSize = addToSqlIfNotNull(sqlBuilder, index, serialNoBitLen, "SN_SIZE");
        Integer idxStatus = addToSqlIfNotNull(sqlBuilder, index, status, "STATUS");
        Integer idxSubject = addToSqlIfNotNull(sqlBuilder, index, cert, "SUBJECT");
        Integer idxCert = addToSqlIfNotNull(sqlBuilder, index, cert, "CERT");
        Integer idxCrlUris = addToSqlIfNotNull(sqlBuilder, index, crlUris, "CRL_URIS");
        Integer idxDeltaCrlUris = addToSqlIfNotNull(sqlBuilder, index, deltaCrlUris,
                "DELTACRL_URIS");
        Integer idxOcspUris = addToSqlIfNotNull(sqlBuilder, index, ocspUris, "OCSP_URIS");
        Integer idxCacertUris = addToSqlIfNotNull(sqlBuilder, index, cacertUris, "CACERT_URIS");
        Integer idxMaxValidity = addToSqlIfNotNull(sqlBuilder, index, maxValidity, "MAX_VALIDITY");
        Integer idxSignerType = addToSqlIfNotNull(sqlBuilder, index, signerType, "SIGNER_TYPE");
        Integer idxCrlsignerName = addToSqlIfNotNull(sqlBuilder, index, crlsignerName,
                "CRLSIGNER_NAME");
        Integer idxResponderName = addToSqlIfNotNull(sqlBuilder, index, responderName,
                "RESPONDER_NAME");
        Integer idxCmpcontrolName = addToSqlIfNotNull(sqlBuilder, index, cmpcontrolName,
                "CMPCONTROL_NAME");
        Integer idxDuplicateKey = addToSqlIfNotNull(sqlBuilder, index, duplicateKeyPermitted,
                "DUPLICATE_KEY");
        Integer idxDuplicateSubject = addToSqlIfNotNull(sqlBuilder, index, duplicateKeyPermitted,
                "DUPLICATE_SUBJECT");
        Integer idxSaveReq = addToSqlIfNotNull(sqlBuilder, index, saveReq,
                "SAVE_REQ");
        Integer idxPermission = addToSqlIfNotNull(sqlBuilder, index, permission, "PERMISSION");
        Integer idxNumCrls = addToSqlIfNotNull(sqlBuilder, index, numCrls, "NUM_CRLS");
        Integer idxExpirationPeriod = addToSqlIfNotNull(sqlBuilder, index, expirationPeriod,
                "EXPIRATION_PERIOD");
        Integer idxExpiredCerts = addToSqlIfNotNull(sqlBuilder, index, keepExpiredCertInDays,
                 "KEEP_EXPIRED_CERT_DAYS");
        Integer idxValidityMode = addToSqlIfNotNull(sqlBuilder, index, validityMode,
                "VALIDITY_MODE");
        Integer idxExtraControl = addToSqlIfNotNull(sqlBuilder, index, extraControl,
                "EXTRA_CONTROL");
        Integer idxSignerConf = addToSqlIfNotNull(sqlBuilder, index, signerConf, "SIGNER_CONF");

        // delete the last ','
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE ID=?");

        if (index.get() == 1) {
            return false;
        }
        int idxId = index.get();

        final String sql = sqlBuilder.toString();
        StringBuilder sb = new StringBuilder();
        PreparedStatement ps = null;

        try {
            ps = prepareStatement(sql);

            if (idxSnSize != null) {
                sb.append("sn_size: '").append(serialNoBitLen).append("'; ");
                ps.setInt(idxSnSize, serialNoBitLen.intValue());
            }

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
                sb.append("signerConf: '").append(SignerConf.toString(signerConf, false, true))
                    .append("'; ");
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

            if (idxSaveReq != null) {
                sb.append("saveReq: '").append(saveReq).append("'; ");
                setBoolean(ps, idxSaveReq, saveReq);
            }

            if (idxPermission != null) {
                sb.append("permission: '").append(permission).append("'; ");
                ps.setInt(idxPermission, permission);
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

            ps.setInt(idxId, changeCaEntry.getIdent().getId());
            ps.executeUpdate();

            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
            }

            LOG.info("changed CA '{}': {}", changeCaEntry.getIdent(), sb);
            return true;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeCa

    void commitNextCrlNoIfLess(final NameId ca, final long nextCrlNo)
            throws CaMgmtException {
        PreparedStatement ps = null;
        try {
            final String sql = sqls.sqlNextSelectCrlNo;
            ResultSet rs = null;
            long nextCrlNoInDb;

            try {
                ps = prepareStatement(sql);
                ps.setInt(1, ca.getId());
                rs = ps.executeQuery();
                rs.next();
                nextCrlNoInDb = rs.getLong("NEXT_CRLNO");
            } catch (SQLException ex) {
                throw new CaMgmtException(datasource, sql, ex);
            } finally {
                datasource.releaseResources(ps, rs);
            }

            if (nextCrlNoInDb < nextCrlNo) {
                final String updateSql = "UPDATE CA SET NEXT_CRLNO=? WHERE ID=?";
                try {
                    ps = prepareStatement(updateSql);
                    ps.setLong(1, nextCrlNo);
                    ps.setInt(2, ca.getId());
                    ps.executeUpdate();
                } catch (SQLException ex) {
                    throw new CaMgmtException(datasource, sql, ex);
                }
            }
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method commitNextCrlNoIfLess

    IdentifiedX509Certprofile changeCertprofile(final NameId nameId, final String type,
            final String conf, final CaManagerImpl caManager) throws CaMgmtException {
        ParamUtil.requireNonNull("nameId", nameId);
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
        sqlBuilder.append(" WHERE ID=?");
        if (index.get() == 1) {
            return null;
        }

        CertprofileEntry currentDbEntry = createCertprofile(nameId.getName());
        if (tmpType == null) {
            tmpType = currentDbEntry.getType();
        }
        if (tmpConf == null) {
            tmpConf = currentDbEntry.getConf();
        }

        tmpType = getRealString(tmpType);
        tmpConf = getRealString(tmpConf);

        CertprofileEntry newDbEntry = new CertprofileEntry(currentDbEntry.getIdent(),
                tmpType, tmpConf);
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

            ps.setInt(index.get(), nameId.getId());
            ps.executeUpdate();

            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
            }

            LOG.info("changed profile '{}': {}", nameId, sb);
            failed = false;
            return profile;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
            if (failed) {
                profile.shutdown();
            }
        }
    } // method changeCertprofile

    CmpControl changeCmpControl(final String name, final String conf) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        if (conf == null) {
            return null;
        }

        CmpControlEntry newDbEntry = new CmpControlEntry(name, conf);
        CmpControl cmpControl;
        try {
            cmpControl = new CmpControl(newDbEntry);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException(ex);
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeCmpControl

    CmpRequestorEntryWrapper changeRequestor(final NameId nameId, final String base64Cert)
            throws CaMgmtException {
        ParamUtil.requireNonNull("nameId", nameId);

        CmpRequestorEntry newDbEntry = new CmpRequestorEntry(nameId, base64Cert);
        CmpRequestorEntryWrapper requestor = new CmpRequestorEntryWrapper();
        requestor.setDbEntry(newDbEntry);

        final String sql = "UPDATE REQUESTOR SET CERT=? WHERE ID=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            String b64Cert = getRealString(base64Cert);
            ps.setString(1, b64Cert);
            ps.setInt(2, nameId.getId());
            ps.executeUpdate();

            String subject = null;
            if (b64Cert != null) {
                try {
                    subject = canonicalizName(
                            X509Util.parseBase64EncodedCert(b64Cert).getSubjectX500Principal());
                } catch (CertificateException ex) {
                    subject = "ERROR";
                }
            }
            LOG.info("changed CMP requestor '{}': {}", nameId, subject);
            return requestor;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeCmpRequestor

    CmpResponderEntryWrapper changeResponder(final String name, final String type,
            final String conf, final String base64Cert, final CaManagerImpl caManager)
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
                sb.append("conf: '").append(SignerConf.toString(txt, false, true));
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
                    } catch (CertificateException ex) {
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeCmpResponder

    X509CrlSignerEntryWrapper changeCrlSigner(final String name, final String signerType,
            final String signerConf, final String base64Cert, final String crlControl,
            final CaManagerImpl caManager) throws CaMgmtException {
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
            try {
                new CrlControl(tmpCrlControl);
            } catch (InvalidConfException ex) {
                throw new CaMgmtException("invalid CRL control '" + tmpCrlControl + "'");
            }
        }

        try {
            dbEntry = new X509CrlSignerEntry(name, tmpSignerType, tmpSignerConf,
                    tmpBase64Cert, tmpCrlControl);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException(ex);
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
                sb.append("signerConf: '").append(SignerConf.toString(txt, false, true))
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
                    } catch (CertificateException ex) {
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeCrlSigner

    Scep changeScep(final String name, final NameId caIdent, final Boolean active,
            final String responderType, final String responderConf,
            final String responderBase64Cert, final Set<String> certProfiles, final String control,
            final CaManagerImpl caManager)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        ParamUtil.requireNonNull("caManager", caManager);

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE SCEP SET ");

        AtomicInteger index = new AtomicInteger(1);
        Integer idxCa = addToSqlIfNotNull(sqlBuilder, index, caIdent, "CA_ID");
        Integer idxActive = addToSqlIfNotNull(sqlBuilder, index, active, "ACTIVE");
        Integer idxType = addToSqlIfNotNull(sqlBuilder, index, responderType, "RESPONDER_TYPE");
        Integer idxCert = addToSqlIfNotNull(sqlBuilder, index, responderBase64Cert,
                "RESPONDER_CERT");
        Integer idxProfiles = addToSqlIfNotNull(sqlBuilder, index, certProfiles, "PROFILES");
        Integer idxControl = addToSqlIfNotNull(sqlBuilder, index, control, "CONTROL");
        Integer idxConf = addToSqlIfNotNull(sqlBuilder, index, responderConf, "RESPONDER_CONF");
        sqlBuilder.deleteCharAt(sqlBuilder.length() - 1);
        sqlBuilder.append(" WHERE NAME=?");

        if (index.get() == 1) {
            return null;
        }

        ScepEntry dbEntry = getScep(name, caManager.getIdNameMap());

        boolean tmpActive = (active == null) ? dbEntry.isActive() : active;

        String tmpResponderType = (responderType ==  null)
                ? dbEntry.getResponderType() : responderType;

        String tmpResponderConf = (responderConf == null)
                ? dbEntry.getResponderConf() : responderConf;

        String tmpResponderBase64Cert = (responderBase64Cert == null)
                ? dbEntry.getBase64Cert() : responderBase64Cert;

        NameId tmpCaIdent;
        if (caIdent == null) {
            tmpCaIdent = dbEntry.getCaIdent();
        } else {
            tmpCaIdent = caIdent;
        }

        Set<String> tmpCertProfiles;
        if (certProfiles == null) {
            tmpCertProfiles = dbEntry.getCertProfiles();
        } else {
            tmpCertProfiles = certProfiles;
        }

        String tmpControl;
        if (control == null) {
            tmpControl = dbEntry.getControl();
        } else if (CaManager.NULL.equals(control)) {
            tmpControl = null;
        } else {
            tmpControl = control;
        }

        ScepEntry newDbEntry;
        try {
            newDbEntry = new ScepEntry(name, tmpCaIdent, tmpActive, tmpResponderType,
                    tmpResponderConf, tmpResponderBase64Cert, tmpCertProfiles, tmpControl);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException(ex);
        }
        Scep scep = new Scep(newDbEntry, caManager);
        final String sql = sqlBuilder.toString();
        StringBuilder sb = new StringBuilder();
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            if (idxActive != null) {
                setBoolean(ps, idxActive, tmpActive);
                sb.append("active: '").append(tmpActive).append("'; ");
            }

            if (idxCa != null) {
                sb.append("ca: '").append(caIdent).append("'; ");
                ps.setInt(idxCa, caIdent.getId());
            }

            if (idxType != null) {
                String txt = tmpResponderType;
                ps.setString(idxType, txt);
                sb.append("responder type: '").append(txt).append("'; ");
            }

            if (idxConf != null) {
                String txt = getRealString(tmpResponderConf);
                sb.append("responder conf: '").append(SignerConf.toString(txt, false, true));
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
                    } catch (CertificateException ex) {
                        sb.append("ERROR");
                    }
                }
                sb.append("'; ");
                ps.setString(idxCert, txt);
            }

            if (idxProfiles != null) {
                sb.append("profiles: '").append(certProfiles).append("'; ");
                ps.setString(idxProfiles, StringUtil.collectionAsString(certProfiles, ","));
            }

            if (idxControl != null) {
                String txt = getRealString(tmpControl);
                sb.append("control: '").append(tmpControl);
                ps.setString(idxControl, txt);
            }

            ps.setInt(index.get(), caIdent.getId());
            ps.executeUpdate();

            final int sbLen = sb.length();
            if (sbLen > 0) {
                sb.delete(sbLen - 2, sbLen);
            }
            LOG.info("changed SCEP: {}", sb);
            return scep;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeScep

    boolean changeEnvParam(final String name, final String value) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        if (CaManagerImpl.ENV_EPOCH.equalsIgnoreCase(name)) {
            throw new CaMgmtException("environment " + name + " is reserved");
        }
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeEnvParam

    IdentifiedX509CertPublisher changePublisher(final String name, final String type,
            final String conf, final CaManagerImpl caManager) throws CaMgmtException {
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

        PublisherEntry dbEntry = new PublisherEntry(currentDbEntry.getIdent(), tmpType, tmpConf);
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changePublisher

    boolean removeCa(final String caName) throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        final String sql = "DELETE FROM CA WHERE NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, caName);
            return ps.executeUpdate() > 0;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeCa

    boolean removeCaAlias(final String aliasName) throws CaMgmtException {
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeCaAlias

    boolean removeCertprofileFromCa(final String profileName, final String caName)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("profileName", profileName);
        ParamUtil.requireNonBlank("caName", caName);

        int caId = getNonNullIdForName(sqls.sqlSelectCaId, caName);
        int profileId = getNonNullIdForName(sqls.sqlSelectProfileId, profileName);
        final String sql = "DELETE FROM CA_HAS_PROFILE WHERE CA_ID=? AND PROFILE_ID=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setInt(1, caId);
            ps.setInt(2, profileId);
            boolean bo = ps.executeUpdate() > 0;
            if (bo) {
                LOG.info("removed profile '{}' from CA '{}'", profileName, caName);
            }
            return bo;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeCertprofileFromCa

    boolean removeRequestorFromCa(final String requestorName, final String caName)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("requestorName", requestorName);
        ParamUtil.requireNonBlank("caName", caName);

        int caId = getNonNullIdForName(sqls.sqlSelectCaId, caName);
        int requestorId = getNonNullIdForName(sqls.sqlSelectRequestorId, requestorName);
        final String sql = "DELETE FROM CA_HAS_REQUESTOR WHERE CA_ID=? AND REQUESTOR_ID=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setInt(1, caId);
            ps.setInt(2, requestorId);
            boolean bo = ps.executeUpdate() > 0;
            if (bo) {
                LOG.info("removed requestor '{}' from CA '{}'", requestorName, caName);
            }
            return bo;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeCmpRequestorFromCa

    boolean removePublisherFromCa(final String publisherName, final String caName)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("publisherName", publisherName);
        ParamUtil.requireNonBlank("caName", caName);
        int caId = getNonNullIdForName(sqls.sqlSelectCaId, caName);
        int publisherId = getNonNullIdForName(sqls.sqlSelectPublisherId, publisherName);

        final String sql = "DELETE FROM CA_HAS_PUBLISHER WHERE CA_ID=? AND PUBLISHER_ID=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setInt(1, caId);
            ps.setInt(2, publisherId);
            boolean bo = ps.executeUpdate() > 0;
            if (bo) {
                LOG.info("removed publisher '{}' from CA '{}'", publisherName, caName);
            }
            return bo;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removePublisherFromCa

    boolean revokeCa(final String caName, final CertRevocationInfo revocationInfo)
            throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        ParamUtil.requireNonNull("revocationInfo", revocationInfo);
        String sql = "UPDATE CA SET REV=?,RR=?,RT=?,RIT=? WHERE NAME=?";
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method revokeCa

    void addResponder(final CmpResponderEntry dbEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);
        final String sql = "INSERT INTO RESPONDER (NAME,TYPE,CERT,CONF) VALUES (?,?,?,?)";

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
            throw new CaMgmtException(datasource, sql, ex);
        } catch (CertificateEncodingException ex) {
            throw new CaMgmtException(ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addCmpResponder

    boolean unlockCa() throws CaMgmtException {
        final String sql = "DELETE FROM SYSTEM_EVENT WHERE NAME='LOCK'";
        Statement stmt = null;
        try {
            stmt = createStatement();
            stmt.execute(sql);
            return stmt.getUpdateCount() > 0;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(stmt, null);
        }
    } // method unlockCa

    boolean unrevokeCa(final String caName) throws CaMgmtException {
        ParamUtil.requireNonBlank("caName", caName);
        LOG.info("Unrevoking of CA '{}'", caName);

        final String sql = "UPDATE CA SET REV=?,RR=?,RT=?,RIT=? WHERE NAME=?";
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
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method unrevokeCa

    boolean addScep(final ScepEntry scepEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("scepEntry", scepEntry);
        final String sql = "INSERT INTO SCEP (NAME,CA_ID,ACTIVE,PROFILES,CONTROL,RESPONDER_TYPE"
                + ",RESPONDER_CERT,RESPONDER_CONF) VALUES (?,?,?,?,?,?,?,?)";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setString(idx++, scepEntry.getName());
            ps.setInt(idx++, scepEntry.getCaIdent().getId());
            setBoolean(ps, idx++, scepEntry.isActive());
            ps.setString(idx++, StringUtil.collectionAsString(scepEntry.getCertProfiles(), ","));
            ps.setString(idx++, scepEntry.getControl());
            ps.setString(idx++, scepEntry.getResponderType());
            ps.setString(idx++, scepEntry.getBase64Cert());
            ps.setString(idx++, scepEntry.getResponderConf());

            ps.executeUpdate();
            LOG.info("added SCEP '{}': {}", scepEntry.getCaIdent(), scepEntry);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }

        return true;
    } // method addScep

    boolean removeScep(final String name) throws CaMgmtException {
        ParamUtil.requireNonNull("name", name);
        final String sql = "DELETE FROM SCEP WHERE NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            return ps.executeUpdate() > 0;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeScep

    ScepEntry getScep(final String name, final CaIdNameMap idNameMap) throws CaMgmtException {
        ParamUtil.requireNonBlank("name", name);
        final String sql = sqls.sqlSelectScep;
        ResultSet rs = null;
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            ps.setString(1, name);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }

            int caId = rs.getInt("CA_ID");
            boolean active = rs.getBoolean("ACTIVE");
            String profilesText = rs.getString("PROFILES");
            String control = rs.getString("CONTROL");
            String type = rs.getString("RESPONDER_TYPE");
            String conf = rs.getString("RESPONDER_CONF");
            String cert = rs.getString("RESPONDER_CERT");
            if (StringUtil.isBlank(cert)) {
                cert = null;
            }

            Set<String> profiles = StringUtil.splitAsSet(profilesText, ", ");

            return new ScepEntry(name, idNameMap.getCa(caId), active, type, conf, cert, profiles,
                    control);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } catch (InvalidConfException ex) {
            throw new CaMgmtException(ex);
        } finally {
            datasource.releaseResources(ps, rs);
        }
    } // method getScep

    boolean addUser(final AddUserEntry userEntry) throws CaMgmtException {
        ParamUtil.requireNonNull("userEntry", userEntry);
        final String name = userEntry.getIdent().getName();
        Integer existingId = getIdForName(sqls.sqlSelectUserId, name);
        if (existingId != null) {
            throw new CaMgmtException("user named '" + name + " ' already exists");
        }
        userEntry.getIdent().setId(existingId);

        String hashedPassword;
        try {
            hashedPassword = PasswordHash.createHash(userEntry.getPassword());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CaMgmtException(ex);
        }

        long id;
        try {
            long maxId = datasource.getMax(null, "TUSER", "ID");
            id = maxId + 1;
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex);
        }

        final String sql = "INSERT INTO TUSER (ID,NAME,ACTIVE,PASSWORD) VALUES (?,?,?,?)";

        PreparedStatement ps = null;

        try {
            ps = prepareStatement(sql);
            int idx = 1;
            ps.setLong(idx++, id);
            ps.setString(idx++, name);
            setBoolean(ps, idx++, userEntry.isActive());
            ps.setString(idx++, hashedPassword);
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }

        LOG.info("added user '{}'", name);
        return true;
    } // method addUser

    boolean removeUser(final String user) throws CaMgmtException {
        ParamUtil.requireNonBlank("user", user);
        final String sql = "DELETE FROM TUSER WHERE NAME=?";

        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, user);
            return ps.executeUpdate() > 0;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeUser

    boolean changeUser(final ChangeUserEntry userEntry) throws CaMgmtException {
        String userName = userEntry.getIdent().getName();

        Integer existingId = getIdForName(sqls.sqlSelectUserId, userName);
        if (existingId == null) {
            throw new CaMgmtException("user '" + userName + " ' does not exist");
        }
        userEntry.getIdent().setId(existingId);

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("UPDATE TUSER SET ");

        AtomicInteger index = new AtomicInteger(1);

        Boolean active = userEntry.isActive();
        Integer idxActive = null;
        if (active != null) {
            idxActive = index.getAndIncrement();
            sqlBuilder.append("ACTIVE=?,");
        }

        String password = userEntry.getPassword();

        Integer idxPassword = null;
        if (password != null) {
            idxPassword = index.getAndIncrement();
            sqlBuilder.append("PASSWORD=?,");
        }

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

            if (idxActive != null) {
                setBoolean(ps, idxActive, active);
                sb.append("active: ").append(active).append("; ");
            }

            if (idxPassword != null) {
                String hashedPassword;
                try {
                    hashedPassword = PasswordHash.createHash(password);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                    throw new CaMgmtException(ex);
                }
                ps.setString(idxPassword, hashedPassword);
                sb.append("password: ****; ");
            }

            ps.setLong(index.get(), existingId);
            ps.executeUpdate();

            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1).deleteCharAt(sb.length() - 1);
            }
            LOG.info("changed user: {}", sb);
            return true;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method changeUser

    boolean removeUserFromCa(final String userName, final String caName)
            throws CaMgmtException {
        Integer id = getIdForName(sqls.sqlSelectUserId, userName);
        if (id == null) {
            return false;
        }

        int caId = getNonNullIdForName(sqls.sqlSelectCaId, caName);

        final String sql = "DELETE FROM CA_HAS_USER WHERE CA_ID=? AND USER_ID=?";
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setInt(1, caId);
            ps.setInt(2, id);
            boolean bo = ps.executeUpdate() > 0;
            if (bo) {
                LOG.info("removed user '{}' from CA '{}'", userName, caName);
            }
            return bo;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method removeCmpRequestorFromCa

    boolean addUserToCa(final CaHasUserEntry user, final NameId ca)
            throws CaMgmtException {
        ParamUtil.requireNonNull("user", user);
        ParamUtil.requireNonNull("ca", ca);

        final NameId userIdent = user.getUserIdent();
        Integer existingId = getIdForName(sqls.sqlSelectUserId, userIdent.getName());
        if (existingId == null) {
            throw new CaMgmtException("user '" + userIdent.getName() + " ' does not exist");
        }
        userIdent.setId(existingId);

        PreparedStatement ps = null;
        final String sql = "INSERT INTO CA_HAS_USER (ID,CA_ID,USER_ID,"
                + " PERMISSION,PROFILES) VALUES (?,?,?,?,?)";

        long maxId;
        try {
            maxId = datasource.getMax(null, "CA_HAS_USER", "ID");
        } catch (DataAccessException ex) {
            throw new CaMgmtException(ex);
        }

        try {
            ps = prepareStatement(sql);

            int idx = 1;
            ps.setLong(idx++, maxId + 1);
            ps.setInt(idx++, ca.getId());
            ps.setInt(idx++, userIdent.getId());
            ps.setInt(idx++, user.getPermission());

            String profilesText = toString(user.getProfiles(), ",");
            ps.setString(idx++, profilesText);

            int num = ps.executeUpdate();
            LOG.info("added user '{}' to CA '{}': permission: {}; profile: {}",
                    userIdent, ca, user.getPermission(), profilesText);
            return num > 0;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    } // method addUserToCa

    Map<String, CaHasUserEntry> getCaHasUsers(String user, CaIdNameMap idNameMap)
            throws CaMgmtException {
        Integer existingId = getIdForName(sqls.sqlSelectUserId, user);
        if (existingId == null) {
            throw new CaMgmtException("user '" + user + " ' does not exist");
        }

        final String sql = "SELECT CA_ID,PERMISSION,PROFILES FROM CA_HAS_USER WHERE USER_ID=?";
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            ps = prepareStatement(sql);
            ps.setInt(1, existingId);
            rs = ps.executeQuery();

            Map<String, CaHasUserEntry> ret = new HashMap<>();
            while (rs.next()) {
                int permission = rs.getInt("PERMISSION");
                String str = rs.getString("PROFILES");
                List<String> list = StringUtil.split(str, ",");
                Set<String> profiles = (list == null) ? null : new HashSet<>(list);
                CaHasUserEntry caHasUser = new CaHasUserEntry(new NameId(existingId, user));
                caHasUser.setPermission(permission);
                caHasUser.setProfiles(profiles);

                int caId = rs.getInt("CA_ID");
                String caName = idNameMap.getCaName(caId);

                ret.put(caName, caHasUser);
            }
            return ret;
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, rs);
        }
    }  // method getCaHasUsers

    UserEntry getUser(final String userName) throws CaMgmtException {
        ParamUtil.requireNonNull("userName", userName);
        NameId ident = new NameId(null, userName);

        final String sql = sqls.sqlSelectUser;
        ResultSet rs = null;
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);

            int idx = 1;
            ps.setString(idx++, ident.getName());
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }

            int id = rs.getInt("ID");
            ident.setId(id);
            boolean active = rs.getBoolean("ACTIVE");
            String hashedPassword = rs.getString("PASSWORD");
            return new UserEntry(ident, active, hashedPassword);
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, rs);
        }
    } // method getUser

    private static void setBoolean(final PreparedStatement ps, final int index, final boolean bo)
            throws SQLException {
        ps.setInt(index, bo ? 1 : 0);
    }

    private static Integer addToSqlIfNotNull(final StringBuilder sqlBuilder,
            final AtomicInteger index, final Object columnObj, final String columnName) {
        if (columnObj == null) {
            return null;
        }

        sqlBuilder.append(columnName).append("=?,");
        return index.getAndIncrement();
    }

    private static String toString(final Collection<String> tokens, final String seperator) {
        return StringUtil.collectionAsString(tokens, seperator);
    }

    private static String getRealString(final String str) {
        return CaManager.NULL.equalsIgnoreCase(str) ? null : str;
    }

    static String canonicalizName(final X500Principal prin) {
        ParamUtil.requireNonNull("prin", prin);
        X500Name x500Name = X500Name.getInstance(prin.getEncoded());
        return X509Util.canonicalizName(x500Name);
    }

    private int getNonNullIdForName(final String sql, final String name) throws CaMgmtException {
        Integer id = getIdForName(sql, name);
        if (id != null) {
            return id.intValue();
        }

        throw new CaMgmtException("Found no entry named '" + name + "'");
    }

    private Integer getIdForName(final String sql, final String name) throws CaMgmtException {
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            ps = prepareStatement(sql);
            ps.setString(1, name);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }

            return rs.getInt("ID");
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, rs);
        }
    }

    private Map<Integer, String> getIdNameMap(final String tableName) throws CaMgmtException {
        final String sql = "SELECT ID,NAME FROM " + tableName;
        Statement ps = null;
        ResultSet rs = null;

        Map<Integer, String> ret = new HashMap<>();
        try {
            ps = createStatement();
            rs = ps.executeQuery(sql);
            while (rs.next()) {
                ret.put(rs.getInt("ID"), rs.getString("NAME"));
            }
        } catch (SQLException ex) {
            throw new CaMgmtException(datasource, sql, ex);
        } finally {
            datasource.releaseResources(ps, rs);
        }

        return ret;
    }

}
