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

package org.xipki.pki.ca.server.impl.store;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.datasource.api.springframework.dao.DataIntegrityViolationException;
import org.xipki.commons.datasource.api.springframework.jdbc.DuplicateKeyException;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.commons.security.api.CrlReason;
import org.xipki.commons.security.api.FpIdCalculator;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.api.RequestorInfo;
import org.xipki.pki.ca.api.X509Cert;
import org.xipki.pki.ca.api.X509CertWithDbId;
import org.xipki.pki.ca.api.publisher.X509CertificateInfo;
import org.xipki.pki.ca.server.impl.CertRevInfoWithSerial;
import org.xipki.pki.ca.server.impl.CertStatus;
import org.xipki.pki.ca.server.impl.DbSchemaInfo;
import org.xipki.pki.ca.server.impl.KnowCertResult;
import org.xipki.pki.ca.server.impl.util.PasswordHash;
import org.xipki.pki.ca.server.mgmt.api.CertArt;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class CertStoreQueryExecutor {

    private static final String SQL_ADD_CERT =
            "INSERT INTO CERT (ID, ART, LUPDATE, SN, SUBJECT, FP_S, FP_RS, "
            + "NBEFORE, NAFTER, REV, PID, CA_ID, RID, UNAME, FP_K, EE, RTYPE, TID)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SQL_ADD_CRAW =
            "INSERT INTO CRAW (CID, SHA1, REQ_SUBJECT, CERT) VALUES (?, ?, ?, ?)";

    private static final String SQL_REVOKE_CERT =
            "UPDATE CERT SET LUPDATE=?, REV=?, RT=?, RIT=?, RR=? WHERE ID=?";

    private static final String SQL_INSERT_PUBLISHQUEUE =
            "INSERT INTO PUBLISHQUEUE (PID, CA_ID, CID) VALUES (?, ?, ?)";

    private static final String SQL_REMOVE_PUBLISHQUEUE =
            "DELETE FROM PUBLISHQUEUE WHERE PID=? AND CID=?";

    private static final String SQL_MAXID_DELTACRL_CACHE =
            "SELECT MAX(ID) FROM DELTACRL_CACHE WHERE CA_ID=?";

    private static final String CLEAR_DELTACRL_CACHE =
            "DELETE FROM DELTACRL_CACHE WHERE ID<? AND CA_ID=?";

    private static final String SQL_MAX_CRLNO =
            "SELECT MAX(CRL_NO) FROM CRL WHERE CA_ID=?";

    private static final String SQL_MAX_THISUPDAATE_CRL =
            "SELECT MAX(THISUPDATE) FROM CRL WHERE CA_ID=?";

    private static final String SQL_ADD_CRL =
            "INSERT INTO CRL (ID,CA_ID,CRL_NO,THISUPDATE,NEXTUPDATE,DELTACRL,"
            + "BASECRL_NO,CRL) VALUES (?,?,?,?,?,?,?,?)";

    private static final String SQL_ADD_DELTACRL_CACHE =
            "INSERT INTO DELTACRL_CACHE (ID, CA_ID, SN) VALUES (?, ?, ?)";

    private static final String SQL_REMOVE_CERT =
            "DELETE FROM CERT WHERE CA_ID=? AND SN=?";

    private static final String SQL_MAX_SN =
            "SELECT MAX(SN) FROM CERT WHERE CA_ID=?";

    private static final String CORESQL_CERT_FOR_ID =
            "PID, REV, RR, RT, RIT, CERT FROM CERT INNER JOIN CRAW"
            + " ON CERT.ID=? AND CRAW.CID=CERT.ID";

    private static final String CORESQL_RAWCERT_FOR_ID =
            "CERT FROM CRAW WHERE CID=?";

    private static final String CORESQL_CERT_WITH_REVINFO =
            "ID, REV, RR, RT, RIT, PID, CERT FROM CERT INNER JOIN CRAW ON CERT.CA_ID=? AND"
            + " CERT.SN=? AND CRAW.CID=CERT.ID";

    private static final String CORESQL_CERTINFO =
            "PID,REV,RR,RT,RIT,CERT FROM CERT INNER JOIN CRAW ON CERT.CA_ID=? AND CERT.SN=? AND"
            + " CRAW.CID=CERT.ID";

    private static final String SQL_ADD_CERT_INPROCESS =
            "INSERT INTO CERT_IN_PROCESS (FP_K, FP_S, TIME2) VALUES (?, ?, ?)";

    private static final String SQL_DELETE_CERT_INPROCESS =
            "DELETE FROM CERT_IN_PROCESS WHERE FP_K=? AND FP_S=?";

    private static final String SQL_DELETE_CERT_INPROCESS_OLDER_THAN =
            "DELETE FROM CERT_IN_PROCESS WHERE TIME2 < ?";

    private static final String CORESQL_ID_FOR_SN_IN_CERT =
            "SELECT COUNT(ID) FROM CERT WHERE CA_ID=? AND SN=?";

    private static final String CORESQL_CERT_FOR_SUBJECT_ISSUED_SIMPLE_CA =
            "COUNT(ID) FROM CERT WHERE FP_S=?";

    private static final String CORESQL_CERT_FOR_SUBJECT_ISSUED =
            "COUNT(ID) FROM CERT WHERE FP_S=? AND CA_ID=?";

    private static final String CORESQL_CERT_FOR_KEY_ISSUED_SIMPLE_CA =
            "COUNT(ID) FROM CERT WHERE FP_K=?";

    private static final String CORESQL_CERT_FOR_KEY_ISSUED =
            "COUNT(ID) FROM CERT WHERE FP_K=? AND CA_ID=?";

    private static final Logger LOG = LoggerFactory.getLogger(CertStoreQueryExecutor.class);

    private final DataSourceWrapper dataSource;

    @SuppressWarnings("unused")
    private final int dbSchemaVersion;

    private final int maxX500nameLen;

    private final CertBasedIdentityStore caInfoStore;

    private final NameIdStore requestorInfoStore;

    private final NameIdStore certprofileStore;

    private final NameIdStore publisherStore;

    CertStoreQueryExecutor(
            final DataSourceWrapper dataSource)
    throws DataAccessException {
        this.dataSource = dataSource;

        this.caInfoStore = initCertBasedIdentyStore("CS_CA");
        this.requestorInfoStore = initNameIdStore("CS_REQUESTOR");
        this.certprofileStore = initNameIdStore("CS_PROFILE");
        this.publisherStore = initNameIdStore("CS_PUBLISHER");

        DbSchemaInfo dbSchemaInfo = new DbSchemaInfo(dataSource);
        String s = dbSchemaInfo.getVariableValue("VERSION");
        this.dbSchemaVersion = Integer.parseInt(s);
        s = dbSchemaInfo.getVariableValue("X500NAME_MAXLEN");
        this.maxX500nameLen = Integer.parseInt(s);
    } // constructor

    private CertBasedIdentityStore initCertBasedIdentyStore(
            final String table)
    throws DataAccessException {
        final String sql = new StringBuilder("SELECT ID, SUBJECT, SHA1_CERT, CERT FROM ")
                    .append(table).toString();
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            rs = ps.executeQuery();
            List<CertBasedIdentityEntry> caInfos = new LinkedList<>();
            while (rs.next()) {
                int id = rs.getInt("ID");
                String subject = rs.getString("SUBJECT");
                String hexSha1Fp = rs.getString("SHA1_CERT");
                String b64Cert = rs.getString("CERT");

                CertBasedIdentityEntry caInfoEntry = new CertBasedIdentityEntry(id, subject,
                        hexSha1Fp, b64Cert);
                caInfos.add(caInfoEntry);
            } // end while
            return new CertBasedIdentityStore(table, caInfos);
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method initCertBasedIdentyStore

    private NameIdStore initNameIdStore(
            final String tableName)
    throws DataAccessException {
        final String sql = new StringBuilder("SELECT ID, NAME FROM ").append(tableName).toString();
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            rs = ps.executeQuery();
            Map<String, Integer> entries = new HashMap<>();
            while (rs.next()) {
                int id = rs.getInt("ID");
                String name = rs.getString("NAME");
                entries.put(name, id);
            }
            return new NameIdStore(tableName, entries);
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method initNameIdStore

    void addCert(
            final X509Cert issuer,
            final X509CertWithDbId certificate,
            final byte[] encodedSubjectPublicKey,
            final String certprofileName,
            final RequestorInfo requestor,
            final String user,
            final RequestType reqType,
            final byte[] transactionId,
            final X500Name reqSubject)
    throws DataAccessException, OperationException {
        int certId = nextCertId();
        int caId = getCaId(issuer);
        X509Certificate cert = certificate.getCert();
        // the profile name of self signed CA certificate may not be contained in table CS_PROFILE
        if (cert.getIssuerDN().equals(cert.getSubjectDN())) {
            addCertprofileName(certprofileName);
        }
        int certprofileId = getCertprofileId(certprofileName);
        Integer requestorId = (requestor == null)
                ? null
                : getRequestorId(requestor.getName());

        long fpPK = FpIdCalculator.hash(encodedSubjectPublicKey);
        String subjectText = X509Util.cutText(certificate.getSubject(), maxX500nameLen);
        long fpSubject = X509Util.fpCanonicalizedName(cert.getSubjectX500Principal());

        String reqSubjectText = null;
        Long fpReqSubject = null;
        if (reqSubject != null) {
            fpReqSubject = X509Util.fpCanonicalizedName(reqSubject);
            if (fpSubject == fpReqSubject) {
                fpReqSubject = null;
            } else {
                reqSubjectText = X509Util.cutX500Name(X509Util.sortX509Name(reqSubject),
                        maxX500nameLen);
            }
        }

        String b64FpCert = base64Fp(certificate.getEncodedCert());
        String b64Cert = Base64.toBase64String(certificate.getEncodedCert());
        String tid = (transactionId == null)
                ? null
                : Base64.toBase64String(transactionId);

        long currentTimeSeconds = System.currentTimeMillis() / 1000;
        long serialNumber = cert.getSerialNumber().longValue();
        long notBeforeSeconds = cert.getNotBefore().getTime() / 1000;
        long notAfterSeconds = cert.getNotAfter().getTime() / 1000;

        Connection conn = null;
        PreparedStatement[] pss = borrowPreparedStatements(SQL_ADD_CERT, SQL_ADD_CRAW);

        try {
            PreparedStatement psAddcert = pss[0];
            PreparedStatement psAddRawcert = pss[1];
            // all statements have the same connection
            conn = psAddcert.getConnection();

            // cert
            int idx = 2;
            psAddcert.setInt(idx++, CertArt.X509PKC.getCode());
            psAddcert.setLong(idx++, currentTimeSeconds);
            psAddcert.setLong(idx++, serialNumber);
            psAddcert.setString(idx++, subjectText);
            psAddcert.setLong(idx++, fpSubject);
            if (fpReqSubject != null) {
                psAddcert.setLong(idx++, fpReqSubject);
            } else {
                psAddcert.setNull(idx++, Types.BIGINT);
            }

            psAddcert.setLong(idx++, notBeforeSeconds);
            psAddcert.setLong(idx++, notAfterSeconds);
            setBoolean(psAddcert, idx++, false);
            psAddcert.setInt(idx++, certprofileId);
            psAddcert.setInt(idx++, caId);

            if (requestorId != null) {
                psAddcert.setInt(idx++, requestorId.intValue());
            } else {
                psAddcert.setNull(idx++, Types.INTEGER);
            }

            psAddcert.setString(idx++, user);
            psAddcert.setLong(idx++, fpPK);

            boolean isEECert = cert.getBasicConstraints() == -1;
            psAddcert.setInt(idx++,
                    isEECert
                            ? 1
                            : 0);

            psAddcert.setInt(idx++, reqType.getCode());
            psAddcert.setString(idx++, tid);

            // rawcert
            idx = 2;
            psAddRawcert.setString(idx++, b64FpCert);
            psAddRawcert.setString(idx++, reqSubjectText);
            psAddRawcert.setString(idx++, b64Cert);

            final int tries = 3;
            for (int i = 0; i < tries; i++) {
                if (i > 0) {
                    certId = nextCertId();
                }
                certificate.setCertId(certId);

                psAddcert.setInt(1, certId);
                psAddRawcert.setInt(1, certId);

                final boolean origAutoCommit = conn.getAutoCommit();
                conn.setAutoCommit(false);

                String sql = null;
                try {
                    sql = SQL_ADD_CERT;
                    psAddcert.executeUpdate();

                    sql = SQL_ADD_CRAW;
                    psAddRawcert.executeUpdate();

                    sql = "(commit add cert to CA certstore)";
                    conn.commit();
                } catch (Throwable th) {
                    conn.rollback();
                    // more secure
                    dataSource.deleteFromTable(null, "CRAW", "CID", certId);
                    dataSource.deleteFromTable(null, "CERT", "ID", certId);

                    if (th instanceof SQLException) {
                        SQLException ex = (SQLException) th;
                        DataAccessException tEx = dataSource.translate(sql, ex);
                        if (tEx instanceof DuplicateKeyException && i < tries - 1) {
                            continue;
                        }
                        LOG.error(
                            "datasource {} SQLException while adding certificate with id {}: {}",
                            dataSource.getDatasourceName(), certId, th.getMessage());
                        throw ex;
                    } else {
                        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                                th.getClass().getName() + ": " + th.getMessage());
                    }
                } finally {
                    conn.setAutoCommit(origAutoCommit);
                }

                break;
            } // end for
        } catch (SQLException ex) {
            throw dataSource.translate(null, ex);
        } finally {
            try {
                for (PreparedStatement ps : pss) {
                    releaseStatement(ps);
                }
            } finally {
                dataSource.returnConnection(conn);
            }
        }
    } // method addCert

    void addToPublishQueue(
            final String publisherName,
            final int certId,
            final X509Cert caCert)
    throws DataAccessException, OperationException {
        final String sql = SQL_INSERT_PUBLISHQUEUE;
        PreparedStatement ps = borrowPreparedStatement(sql);
        int caId = getCaId(caCert);
        try {
            int publisherId = getPublisherId(publisherName);
            int idx = 1;
            ps.setInt(idx++, publisherId);
            ps.setInt(idx++, caId);
            ps.setInt(idx++, certId);
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }
    }

    void removeFromPublishQueue(
            final String publisherName,
            final int certId)
    throws DataAccessException {
        final String sql = SQL_REMOVE_PUBLISHQUEUE;
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            int publisherId = getPublisherId(publisherName);
            int idx = 1;
            ps.setInt(idx++, publisherId);
            ps.setInt(idx++, certId);
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }
    }

    long getMaxIdOfDeltaCrlCache(
            final X509Cert caCert)
    throws OperationException, DataAccessException {
        final String sql = SQL_MAXID_DELTACRL_CACHE;
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            int caId = getCaId(caCert);
            ps.setInt(1, caId);
            ResultSet rs = ps.executeQuery();
            if (!rs.next()) {
                return 0;
            }
            return rs.getLong(1);
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }
    }

    public void clearDeltaCrlCache(
            final X509Cert caCert,
            final long maxId)
    throws OperationException, DataAccessException {
        final String sql = CLEAR_DELTACRL_CACHE;
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            ps.setLong(1, maxId + 1);
            int caId = getCaId(caCert);
            ps.setInt(2, caId);
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }
    }

    void clearPublishQueue(
            final X509Cert caCert,
            final String publisherName)
    throws OperationException, DataAccessException {
        StringBuilder sqlBuilder = new StringBuilder(80);
        sqlBuilder.append("DELETE FROM PUBLISHQUEUE");
        if (caCert != null || publisherName != null) {
            sqlBuilder.append(" WHERE");
            if (caCert != null) {
                sqlBuilder.append(" CA_ID=?");
                if (publisherName != null) {
                    sqlBuilder.append(" AND");
                }
            }
            if (publisherName != null) {
                sqlBuilder.append(" PID=?");
            }
        }

        String sql = sqlBuilder.toString();
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            int idx = 1;
            if (caCert != null) {
                int caId = getCaId(caCert);
                ps.setInt(idx++, caId);
            }

            if (publisherName != null) {
                int publisherId = getPublisherId(publisherName);
                ps.setInt(idx++, publisherId);
            }
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }
    }

    int getMaxCrlNumber(
            final X509Cert caCert)
    throws DataAccessException, OperationException {
        final String sql = SQL_MAX_CRLNO;
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            int caId = getCaId(caCert);
            ps.setInt(1, caId);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return 0;
            }
            int maxCrlNumber = rs.getInt(1);
            return (maxCrlNumber < 0)
                    ? 0
                    : maxCrlNumber;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    }

    Long getThisUpdateOfCurrentCrl(
            final X509Cert caCert)
    throws DataAccessException, OperationException {
        final String sql = SQL_MAX_THISUPDAATE_CRL;
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            int caId = getCaId(caCert);
            ps.setInt(1, caId);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return 0L;
            }
            return rs.getLong(1);
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    }

    boolean hasCrl(
            final X509Cert caCert)
    throws DataAccessException {
        Integer caId = caInfoStore.getCaIdForCert(caCert.getEncodedCert());
        if (caId == null) {
            return false;
        }

        final String sql = dataSource.createFetchFirstSelectSQL("COUNT(ID) FROM CRL WHERE CA_ID = ?", 1);
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            ps = borrowPreparedStatement(sql);
            ps.setInt(1, caId);
            rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1) > 0;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    }

    void addCrl(
            final X509Cert caCert,
            final X509CRL crl)
    throws DataAccessException, CRLException, OperationException {
        byte[] encodedExtnValue = crl.getExtensionValue(Extension.cRLNumber.getId());
        Long crlNumber = null;
        if (encodedExtnValue != null) {
            byte[] extnValue = DEROctetString.getInstance(encodedExtnValue).getOctets();
            crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue().longValue();
        }

        encodedExtnValue = crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
        Long baseCrlNumber = null;
        if (encodedExtnValue != null) {
            byte[] extnValue = DEROctetString.getInstance(encodedExtnValue).getOctets();
            baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue().longValue();
        }

        final String sql = SQL_ADD_CRL;
        int currentMaxCrlId = (int) dataSource.getMax(null, "CRL", "ID");
        int crlId = currentMaxCrlId + 1;

        String b64Crl = Base64.toBase64String(crl.getEncoded());

        PreparedStatement ps = null;

        try {
            int caId = getCaId(caCert);
            ps = borrowPreparedStatement(sql);

            int idx = 1;
            ps.setInt(idx++, crlId);
            ps.setInt(idx++, caId);
            if (crlNumber != null) {
                ps.setInt(idx++, crlNumber.intValue());
            } else {
                ps.setNull(idx++, Types.INTEGER);
            }
            Date d = crl.getThisUpdate();
            ps.setLong(idx++, d.getTime() / 1000);
            d = crl.getNextUpdate();
            if (d != null) {
                ps.setLong(idx++, d.getTime() / 1000);
            } else {
                ps.setNull(idx++, Types.BIGINT);
            }

            ps.setInt(idx++,
                    (baseCrlNumber != null)
                        ? 1
                        : 0);

            if (baseCrlNumber != null) {
                ps.setLong(idx++, baseCrlNumber);
            } else {
                ps.setNull(idx++, Types.BIGINT);
            }

            ps.setString(idx++, b64Crl);

            ps.executeUpdate();
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }
    } // method addCrl

    X509CertWithRevocationInfo revokeCert(
            final X509Cert caCert,
            final BigInteger serialNumber,
            final CertRevocationInfo revInfo,
            final boolean force,
            final boolean publishToDeltaCRLCache)
    throws OperationException, DataAccessException {
        X509CertWithRevocationInfo certWithRevInfo
                = getCertWithRevocationInfo(caCert, serialNumber);
        if (certWithRevInfo == null) {
            LOG.warn("certificate with issuer='{}' and serialNumber={} does not exist",
                    caCert.getSubject(), serialNumber);
            return null;
        }

        CertRevocationInfo currentRevInfo = certWithRevInfo.getRevInfo();
        if (currentRevInfo != null) {
            CrlReason currentReason = currentRevInfo.getReason();
            if (currentReason == CrlReason.CERTIFICATE_HOLD) {
                if (revInfo.getReason() == CrlReason.CERTIFICATE_HOLD) {
                    throw new OperationException(ErrorCode.CERT_REVOKED,
                            "certificate already issued with the requested reason "
                            + currentReason.getDescription());
                } else {
                    revInfo.setRevocationTime(currentRevInfo.getRevocationTime());
                    revInfo.setInvalidityTime(currentRevInfo.getInvalidityTime());
                }
            } else if (!force) {
                throw new OperationException(ErrorCode.CERT_REVOKED,
                        "certificate already issued with reason " + currentReason.getDescription());
            }
        }

        int certId = certWithRevInfo.getCert().getCertId().intValue();
        long revTimeSeconds = revInfo.getRevocationTime().getTime() / 1000;
        Long invTimeSeconds = null;
        if (revInfo.getInvalidityTime() != null) {
            invTimeSeconds = revInfo.getInvalidityTime().getTime() / 1000;
        }

        PreparedStatement ps = borrowPreparedStatement(SQL_REVOKE_CERT);
        try {
            int idx = 1;
            ps.setLong(idx++, System.currentTimeMillis() / 1000);
            setBoolean(ps, idx++, true);
            ps.setLong(idx++, revTimeSeconds);
            if (invTimeSeconds != null) {
                ps.setLong(idx++, invTimeSeconds);
            } else {
                ps.setNull(idx++, Types.BIGINT);
            }

            ps.setInt(idx++, revInfo.getReason().getCode());
            ps.setLong(idx++, certId);

            int count = ps.executeUpdate();
            if (count != 1) {
                String message;
                if (count > 1) {
                    message = count + " rows modified, but exactly one is expected";
                } else {
                    message = "no row is modified, but exactly one is expected";
                }
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, message);
            }
        } catch (SQLException ex) {
            throw dataSource.translate(SQL_REVOKE_CERT, ex);
        } finally {
            releaseDbResources(ps, null);
        }

        if (publishToDeltaCRLCache) {
            int caId = getCaId(caCert);
            publishToDeltaCrlCache(caId, certWithRevInfo.getCert().getCert().getSerialNumber());
        }

        certWithRevInfo.setRevInfo(revInfo);
        return certWithRevInfo;
    } // method revokeCert

    X509CertWithDbId unrevokeCert(
            final X509Cert caCert,
            final BigInteger serialNumber,
            final boolean force,
            final boolean publishToDeltaCRLCache)
    throws OperationException, DataAccessException {
        X509CertWithRevocationInfo certWithRevInfo
                = getCertWithRevocationInfo(caCert, serialNumber);
        if (certWithRevInfo == null) {
            LOG.warn("certificate with issuer='{}' and serialNumber={} does not exist",
                    caCert.getSubject(), serialNumber);
            return null;
        }

        CertRevocationInfo currentRevInfo = certWithRevInfo.getRevInfo();
        if (currentRevInfo == null) {
            throw new OperationException(ErrorCode.CERT_UNREVOKED, "certificate is not revoked");
        }

        CrlReason currentReason = currentRevInfo.getReason();
        if (!force) {
            if (currentReason != CrlReason.CERTIFICATE_HOLD) {
                throw new OperationException(ErrorCode.NOT_PERMITTED,
                        "could not unrevoke certificate revoked with reason "
                        + currentReason.getDescription());
            }
        }

        final String sql = "UPDATE CERT SET LUPDATE=?, REV=?, RT=?, RIT=?, RR=? WHERE ID=?";
        int certId = certWithRevInfo.getCert().getCertId().intValue();
        long currentTimeSeconds = System.currentTimeMillis() / 1000;

        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            int idx = 1;
            ps.setLong(idx++, currentTimeSeconds);
            setBoolean(ps, idx++, false);
            ps.setNull(idx++, Types.INTEGER);
            ps.setNull(idx++, Types.INTEGER);
            ps.setNull(idx++, Types.INTEGER);
            ps.setLong(idx++, certId);

            int count = ps.executeUpdate();
            if (count != 1) {
                String message;
                if (count > 1) {
                    message = count + " rows modified, but exactly one is expected";
                } else {
                    message = "no row is modified, but exactly one is expected";
                }
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, message);
            }
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }

        if (publishToDeltaCRLCache) {
            int caId = getCaId(caCert);
            publishToDeltaCrlCache(caId, certWithRevInfo.getCert().getCert().getSerialNumber());
        }

        return certWithRevInfo.getCert();
    } // method unrevokeCert

    private void publishToDeltaCrlCache(
            final int caId,
            final BigInteger serialNumber)
    throws DataAccessException {
        final String sql = SQL_ADD_DELTACRL_CACHE;
        PreparedStatement ps = null;
        try {
            long id = nextDccId();
            ps = borrowPreparedStatement(sql);
            int idx = 1;
            ps.setLong(idx++, id);
            ps.setInt(idx++, caId);
            ps.setLong(idx++, serialNumber.longValue());
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }
    }

    X509CertWithDbId getCert(
            final X509Cert caCert,
            final BigInteger serialNumber)
    throws OperationException, DataAccessException {
        X509CertWithRevocationInfo certWithRevInfo
                = getCertWithRevocationInfo(caCert, serialNumber);
        if (certWithRevInfo == null) {
            return null;
        }
        return certWithRevInfo.getCert();
    }

    void removeCertificate(
            final X509Cert caCert,
            final BigInteger serialNumber)
    throws OperationException, DataAccessException {
        final String sql = SQL_REMOVE_CERT;
        int caId = getCaId(caCert);
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setLong(idx++, serialNumber.longValue());

            int count = ps.executeUpdate();
            if (count != 1) {
                String message;
                if (count > 1) {
                    message = count + " rows modified, but exactly one is expected";
                } else {
                    message = "no row is modified, but exactly one is expected";
                }
                throw new OperationException(ErrorCode.SYSTEM_FAILURE, message);
            }
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }
    } // method removeCertificate

    Long getGreatestSerialNumber(
            final X509Cert caCert)
    throws DataAccessException, OperationException {
        ParamUtil.assertNotNull("caCert", caCert);

        final String sql = SQL_MAX_SN;
        int caId = getCaId(caCert);
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;
        try {
            ps.setInt(1, caId);
            rs = ps.executeQuery();
            rs.next();
            return rs.getLong(1);
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method getGreatestSerialNumber

    List<Integer> getPublishQueueEntries(
            final X509Cert caCert,
            final String publisherName,
            final int numEntries)
    throws DataAccessException, OperationException {
        ParamUtil.assertNotNull("caCert", caCert);
        if (numEntries < 1) {
            throw new IllegalArgumentException("numEntries is not positive");
        }

        Integer publisherId = publisherStore.getId(publisherName);
        if (publisherId == null) {
            return Collections.emptyList();
        }

        byte[] encodedCert = caCert.getEncodedCert();
        Integer caId = caInfoStore.getCaIdForCert(encodedCert);
        if (caId == null) {
            return Collections.emptyList();
        }

        final String sql = dataSource.createFetchFirstSelectSql(
                "CID FROM PUBLISHQUEUE WHERE CA_ID=? AND PID=?", numEntries, "CID ASC");
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setLong(idx++, publisherId);
            rs = ps.executeQuery();
            List<Integer> ret = new ArrayList<>();
            while (rs.next() && ret.size() < numEntries) {
                int certId = rs.getInt("CID");
                if (!ret.contains(certId)) {
                    ret.add(certId);
                }
            }
            return ret;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method getPublishQueueEntries

    boolean containsCertificates(
            final X509Cert caCert,
            final boolean ee)
    throws DataAccessException, OperationException {
        ParamUtil.assertNotNull("caCert", caCert);

        final String sql = dataSource.createFetchFirstSelectSQL(
                "COUNT(*) FROM CERT WHERE CA_ID=? AND EE=?", 1);
        int caId = getCaId(caCert);
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            int iEe = ee
                    ? 1
                    : 0;
            ps.setInt(2, iEe);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return false;
            }
            return rs.getInt(1) > 0;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method containsCertificates

    List<BigInteger> getSerialNumbers(
            final X509Cert caCert,
            final Date notExpiredAt,
            final BigInteger startSerial,
            final int numEntries,
            final boolean onlyRevoked,
            final boolean onlyCACerts,
            final boolean onlyUserCerts)
    throws DataAccessException, OperationException {
        ParamUtil.assertNotNull("caCert", caCert);
        if (numEntries < 1) {
            throw new IllegalArgumentException("numEntries is not positive");
        }

        int caId = getCaId(caCert);
        StringBuilder sb = new StringBuilder("SN FROM CERT WHERE CA_ID=? AND SN>?");
        if (notExpiredAt != null) {
            sb.append(" AND NAFTER>?");
        }
        if (onlyRevoked) {
            sb.append(" AND REV=1");
        }
        if (onlyCACerts) {
            sb.append(" AND EE=0");
        } else if (onlyUserCerts) {
            sb.append(" AND EE=1");
        }
        final String sql = dataSource.createFetchFirstSelectSql(sb.toString(), numEntries,
                "SN ASC");
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setLong(idx++,
                    (startSerial == null)
                            ? 0
                            : startSerial.longValue() - 1);
            if (notExpiredAt != null) {
                ps.setLong(idx++, notExpiredAt.getTime() / 1000 + 1);
            }
            rs = ps.executeQuery();
            List<BigInteger> ret = new ArrayList<>();
            while (rs.next() && ret.size() < numEntries) {
                long serial = rs.getLong("SN");
                ret.add(BigInteger.valueOf(serial));
            }
            return ret;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method getSerialNumbers

    List<BigInteger> getExpiredSerialNumbers(
            final X509Cert caCert,
            final long expiredAt,
            final int numEntries)
    throws DataAccessException, OperationException {
        ParamUtil.assertNotNull("caCert", caCert);

        if (numEntries < 1) {
            throw new IllegalArgumentException("numEntries is not positive");
        }

        int caId = getCaId(caCert);
        final String coreSql = "SN FROM CERT WHERE CA_ID=? AND NAFTER<?";
        final String sql = dataSource.createFetchFirstSelectSQL(coreSql, numEntries);
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setLong(idx++, expiredAt);
            rs = ps.executeQuery();
            List<BigInteger> ret = new ArrayList<>();
            while (rs.next() && ret.size() < numEntries) {
                long serial = rs.getLong("SN");
                ret.add(BigInteger.valueOf(serial));
            }
            return ret;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method getExpiredSerialNumbers

    byte[] getEncodedCrl(
            final X509Cert caCert,
            final BigInteger crlNumber)
    throws DataAccessException, OperationException {
        ParamUtil.assertNotNull("caCert", caCert);

        int caId = getCaId(caCert);
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("THISUPDATE, CRL FROM CRL WHERE CA_ID=?");
        if (crlNumber != null) {
            sqlBuilder.append(" AND CRL_NO=?");
        }
        String sql = dataSource.createFetchFirstSelectSql(sqlBuilder.toString(), 1,
                "THISUPDATE DESC");
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        String b64Crl = null;
        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            if (crlNumber != null) {
                ps.setLong(idx++, crlNumber.longValue());
            }
            rs = ps.executeQuery();
            long currentThisUpdate = 0;
            // iterate all entries to make sure that the latest CRL will be returned
            while (rs.next()) {
                long thisUpdate = rs.getLong("THISUPDATE");
                if (thisUpdate >= currentThisUpdate) {
                    b64Crl = rs.getString("CRL");
                    currentThisUpdate = thisUpdate;
                }
            }
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }

        if (b64Crl == null) {
            return null;
        }

        return Base64.decode(b64Crl);
    } // method getEncodedCrl

    int cleanupCrls(
            final X509Cert caCert,
            final int numCRLs)
    throws DataAccessException, OperationException {
        if (numCRLs < 1) {
            throw new IllegalArgumentException("numCRLs is not positive");
        }
        ParamUtil.assertNotNull("caCert", caCert);

        int caId = getCaId(caCert);
        String sql = "SELECT CRL_NO FROM CRL WHERE CA_ID=? AND DELTACRL=?";
        PreparedStatement ps = borrowPreparedStatement(sql);
        List<Integer> crlNumbers = new LinkedList<>();
        ResultSet rs = null;
        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            setBoolean(ps, idx++, false);
            rs = ps.executeQuery();

            while (rs.next()) {
                int crlNumber = rs.getInt("CRL_NO");
                crlNumbers.add(crlNumber);
            }
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }

        int n = crlNumbers.size();
        Collections.sort(crlNumbers);

        int numCrlsToDelete = n - numCRLs;
        if (numCrlsToDelete < 1) {
            return 0;
        }

        int crlNumber = crlNumbers.get(numCrlsToDelete - 1);
        sql = "DELETE FROM CRL WHERE CA_ID=? AND CRL_NO<?";
        ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setInt(idx++, crlNumber + 1);
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }

        return numCrlsToDelete;
    } // method cleanupCrls

    X509CertificateInfo getCertForId(
            final X509Cert caCert,
            final int certId)
    throws DataAccessException, OperationException, CertificateException {
        ParamUtil.assertNotNull("caCert", caCert);

        final String coreSql = CORESQL_CERT_FOR_ID;
        final String sql = dataSource.createFetchFirstSelectSQL(coreSql, 1);

        String b64Cert;
        int certprofileId;
        boolean revoked;
        int revReason = 0;
        long revTime = 0;
        long revInvTime = 0;

        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            ps.setInt(1, certId);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }
            b64Cert = rs.getString("CERT");
            certprofileId = rs.getInt("PID");
            revoked = rs.getBoolean("REV");
            if (revoked) {
                revReason = rs.getInt("RR");
                revTime = rs.getLong("RT");
                revInvTime = rs.getLong("RIT");
            }
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }

        try {
            byte[] encodedCert = Base64.decode(b64Cert);
            X509Certificate cert = X509Util.parseCert(encodedCert);
            String certprofileName = certprofileStore.getName(certprofileId);
            X509CertWithDbId certWithMeta = new X509CertWithDbId(cert, encodedCert);
            X509CertificateInfo certInfo = new X509CertificateInfo(certWithMeta,
                    caCert, cert.getPublicKey().getEncoded(), certprofileName);
            if (!revoked) {
                return certInfo;
            }
            Date invalidityTime = (revInvTime == 0 || revInvTime == revTime)
                    ? null
                    : new Date(revInvTime * 1000);
            CertRevocationInfo revInfo = new CertRevocationInfo(revReason,
                    new Date(revTime * 1000), invalidityTime);
            certInfo.setRevocationInfo(revInfo);
            return certInfo;
        } catch (IOException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "IOException: " + ex.getMessage());
        }
    } // method getCertForId

    X509CertWithDbId getCertForId(
            final int certId)
    throws DataAccessException, OperationException {
        final String sql = dataSource.createFetchFirstSelectSQL(CORESQL_RAWCERT_FOR_ID, 1);

        String b64Cert;
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            ps.setInt(1, certId);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }
            b64Cert = rs.getString("CERT");
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }

        if (b64Cert == null) {
            return null;
        }
        byte[] encodedCert = Base64.decode(b64Cert);
        X509Certificate cert;
        try {
            cert = X509Util.parseCert(encodedCert);
        } catch (CertificateException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "CertificateException: " + ex.getMessage());
        } catch (IOException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "IOException: " + ex.getMessage());
        }
        return new X509CertWithDbId(cert, encodedCert);
    } // method getCertForId

    X509CertWithRevocationInfo getCertWithRevocationInfo(
            final X509Cert caCert,
            final BigInteger serial)
    throws DataAccessException, OperationException {
        ParamUtil.assertNotNull("caCert", caCert);
        ParamUtil.assertNotNull("serial", serial);

        int caId = getCaId(caCert);

        final String sql = dataSource.createFetchFirstSelectSQL(CORESQL_CERT_WITH_REVINFO, 1);

        int certId;
        String b64Cert;
        boolean revoked;
        int revReason = 0;
        long revTime = 0;
        long revInvTime = 0;
        int certprofileId = 0;

        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setLong(idx++, serial.longValue());
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }
            certId = rs.getInt("ID");
            b64Cert = rs.getString("CERT");
            certprofileId = rs.getInt("PID");

            revoked = rs.getBoolean("REV");
            if (revoked) {
                revReason = rs.getInt("RR");
                revTime = rs.getLong("RT");
                revInvTime = rs.getLong("RIT");
            }
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }

        byte[] certBytes = Base64.decode(b64Cert);
        X509Certificate cert;
        try {
            cert = X509Util.parseCert(certBytes);
        } catch (CertificateException | IOException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    ex.getClass().getName() + ": " + ex.getMessage());
        }

        CertRevocationInfo revInfo = null;
        if (revoked) {
            Date invalidityTime = (revInvTime == 0)
                    ? null
                    : new Date(1000 * revInvTime);
            revInfo = new CertRevocationInfo(revReason,
                    new Date(1000 * revTime),
                    invalidityTime);
        }

        X509CertWithDbId certWithMeta = new X509CertWithDbId(cert, certBytes);
        certWithMeta.setCertId(certId);

        String profileName = certprofileStore.getName(certprofileId);
        X509CertWithRevocationInfo ret = new X509CertWithRevocationInfo();
        ret.setCertprofile(profileName);
        ret.setCert(certWithMeta);
        ret.setRevInfo(revInfo);
        return ret;
    } // method getCertWithRevocationInfo

    X509CertificateInfo getCertificateInfo(
            final X509Cert caCert,
            final BigInteger serial)
    throws DataAccessException, OperationException, CertificateException {
        ParamUtil.assertNotNull("caCert", caCert);
        ParamUtil.assertNotNull("serial", serial);

        int caId = getCaId(caCert);
        final String sql = dataSource.createFetchFirstSelectSQL(CORESQL_CERTINFO, 1);

        String b64Cert;
        boolean revoked;
        int revReason = 0;
        long revTime = 0;
        long revInvTime = 0;
        int certprofileId = 0;

        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setLong(idx++, serial.longValue());
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }
            b64Cert = rs.getString("CERT");
            certprofileId = rs.getInt("PID");
            revoked = rs.getBoolean("REV");
            if (revoked) {
                revReason = rs.getInt("RR");
                revTime = rs.getLong("RT");
                revInvTime = rs.getLong("RIT");
            }
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }

        try {
            byte[] encodedCert = Base64.decode(b64Cert);
            X509Certificate cert = X509Util.parseCert(encodedCert);

            String certprofileName = certprofileStore.getName(certprofileId);

            X509CertWithDbId certWithMeta = new X509CertWithDbId(cert, encodedCert);

            byte[] subjectPublicKeyInfo = Certificate.getInstance(encodedCert)
                    .getTBSCertificate().getSubjectPublicKeyInfo().getEncoded();
            X509CertificateInfo certInfo = new X509CertificateInfo(certWithMeta,
                    caCert, subjectPublicKeyInfo, certprofileName);

            if (!revoked) {
                return certInfo;
            }

            Date invalidityTime = (revInvTime == 0)
                    ? null
                    : new Date(revInvTime * 1000);
            CertRevocationInfo revInfo = new CertRevocationInfo(revReason,
                    new Date(revTime * 1000), invalidityTime);
            certInfo.setRevocationInfo(revInfo);
            return certInfo;
        } catch (IOException ex) {
            LOG.warn("getCertificateInfo()", ex);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "IOException: " + ex.getMessage());
        }
    } // method getCertificateInfo

    String getCertProfileForSerial(
            final X509Cert caCert,
            final BigInteger serial)
    throws OperationException, DataAccessException {
        ParamUtil.assertNotNull("caCert", caCert);
        ParamUtil.assertNotNull("serial", serial);

        int caId = getCaId(caCert);

        final String sql = dataSource.createFetchFirstSelectSQL(
                "PID FROM CERT WHERE SN=? AND CA_ID=?", 1);
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setLong(idx++, serial.longValue());
            ps.setInt(idx++, caId);

            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }

            int profileId = rs.getInt("PID");
            return certprofileStore.getName(profileId);
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method getCertProfileForSerial

    /**
     *
     * @param subjectName Subject of Certificate or requested Subject
     * @param transactionId will only be considered if there are more than one certificate
     *    matches the subject
     * @return
     * @throws DataAccessException
     */
    List<X509Certificate> getCertificate(
            final X500Name subjectName,
            final byte[] transactionId)
    throws DataAccessException, OperationException {
        final String sql;
        if (transactionId != null) {
            sql = "SELECT ID FROM CERT WHERE TID=? AND (FP_S=? OR FP_RS=?)";
        } else {
            sql = "SELECT ID FROM CERT WHERE FP_S=? OR FP_RS=?";
        }

        long fpSubject = X509Util.fpCanonicalizedName(subjectName);
        List<Integer> certIds = new LinkedList<Integer>();

        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            if (transactionId != null) {
                ps.setString(idx++, Base64.toBase64String(transactionId));
            }
            ps.setLong(idx++, fpSubject);
            ps.setLong(idx++, fpSubject);
            rs = ps.executeQuery();

            while (rs.next()) {
                int id = rs.getInt("ID");
                certIds.add(id);
            }
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }

        if (CollectionUtil.isEmpty(certIds)) {
            return Collections.emptyList();
        }

        List<X509Certificate> certs = new ArrayList<X509Certificate>(certIds.size());
        for (Integer certId : certIds) {
            X509CertWithDbId cert = getCertForId(certId);
            if (cert != null) {
                certs.add(cert.getCert());
            }
        }

        return certs;
    } // method getCertificate

    boolean authenticateUser(
            final String user,
            final byte[] password)
    throws DataAccessException, OperationException {
        final String sql = dataSource.createFetchFirstSelectSQL(
                "PASSWORD FROM USERNAME WHERE NAME=?", 1);

        String expPasswordText = null;
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            ps.setString(1, user);
            rs = ps.executeQuery();

            if (!rs.next()) {
                return false;
            }

            expPasswordText = rs.getString("PASSWORD");
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }

        if (StringUtil.isBlank(expPasswordText)) {
            return false;
        }

        try {
            return PasswordHash.validatePassword(password, expPasswordText);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
        }
    } // method authenticateUser

    String getCnRegexForUser(
            final String user)
    throws DataAccessException, OperationException {
        final String sql = dataSource.createFetchFirstSelectSQL(
                "CN_REGEX FROM USERNAME WHERE NAME=?", 1);
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            ps.setString(1, user);
            rs = ps.executeQuery();

            if (!rs.next()) {
                return null;
            }

            return rs.getString("CN_REGEX");
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    }

    KnowCertResult knowsCertForSerial(
            final X509Cert caCert,
            final BigInteger serial)
    throws DataAccessException, OperationException {
        int caId = getCaId(caCert);

        final String sql = dataSource.createFetchFirstSelectSQL(
                "UNAME FROM CERT WHERE CA_ID=? AND SN=?", 1);

        String user = null;
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            ps.setInt(1, caId);
            ps.setLong(2, serial.longValue());
            rs = ps.executeQuery();

            if (!rs.next()) {
                return KnowCertResult.UNKNOWN;
            }

            user = rs.getString("UNAME");
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }

        return new KnowCertResult(true, user);
    } // method knowsCertForSerial

    List<CertRevInfoWithSerial> getRevokedCertificates(
            final X509Cert caCert,
            final Date notExpiredAt,
            final BigInteger startSerial,
            final int numEntries,
            final boolean onlyCACerts,
            final boolean onlyUserCerts)
    throws DataAccessException, OperationException {
        ParamUtil.assertNotNull("caCert", caCert);
        ParamUtil.assertNotNull("notExpiredAt", notExpiredAt);

        if (numEntries < 1) {
            throw new IllegalArgumentException("numEntries is not positive");
        }

        int caId = getCaId(caCert);

        StringBuilder sqlBuiler = new StringBuilder();
        sqlBuiler.append("SN, RR, RT, RIT FROM CERT");
        sqlBuiler.append(" WHERE CA_ID=? AND REV=? AND SN>? AND NAFTER>?");
        if (onlyCACerts) {
            sqlBuiler.append(" AND EE=0");
        } else if (onlyUserCerts) {
            sqlBuiler.append(" AND EE=1");
        }

        String sql = dataSource.createFetchFirstSelectSql(sqlBuiler.toString(), numEntries,
                "SN ASC");

        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            setBoolean(ps, idx++, true);
            ps.setLong(idx++, startSerial.longValue() - 1);
            ps.setLong(idx++, notExpiredAt.getTime() / 1000 + 1);
            rs = ps.executeQuery();

            List<CertRevInfoWithSerial> ret = new LinkedList<>();
            while (rs.next()) {
                long serial = rs.getLong("SN");
                int revReason = rs.getInt("RR");
                long revTime = rs.getLong("RT");
                long revInvalidityTime = rs.getLong("RIT");

                Date invalidityTime = (revInvalidityTime == 0)
                        ? null
                        : new Date(1000 * revInvalidityTime);
                CertRevInfoWithSerial revInfo = new CertRevInfoWithSerial(
                        BigInteger.valueOf(serial),
                        revReason, new Date(1000 * revTime), invalidityTime);
                ret.add(revInfo);
            }

            return ret;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method getRevokedCertificates

    List<CertRevInfoWithSerial> getCertificatesForDeltaCrl(
            final X509Cert caCert,
            final BigInteger startSerial,
            final int numEntries,
            final boolean onlyCACerts,
            final boolean onlyUserCerts)
    throws DataAccessException, OperationException {
        ParamUtil.assertNotNull("caCert", caCert);

        if (numEntries < 1) {
            throw new IllegalArgumentException("numEntries is not positive");
        }

        int caId = getCaId(caCert);

        String sql = dataSource.createFetchFirstSelectSql(
                "SN FROM DELTACRL_CACHE WHERE CA_ID=? AND SN>?", numEntries, "SN ASC");
        List<Long> serials = new LinkedList<>();
        ResultSet rs = null;

        PreparedStatement ps = borrowPreparedStatement(sql);
        try {
            int idx = 1;
            ps.setInt(idx++, caId);
            ps.setLong(idx++, startSerial.longValue() - 1);
            rs = ps.executeQuery();
            while (rs.next()) {
                long serial = rs.getLong("SN");
                serials.add(serial);
            }
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("REV, RR, RT, RIT");
        sqlBuilder.append(" FROM CERT WHERE CA_ID=? AND SN=?");
        if (onlyCACerts) {
            sqlBuilder.append(" AND EE=0");
        } else if (onlyUserCerts) {
            sqlBuilder.append(" AND EE=1");
        }

        sql = dataSource.createFetchFirstSelectSQL(sqlBuilder.toString(), 1);
        ps = borrowPreparedStatement(sql);

        List<CertRevInfoWithSerial> ret = new ArrayList<>();
        for (Long serial : serials) {
            try {
                ps.setInt(1, caId);
                ps.setLong(2, serial);
                rs = ps.executeQuery();

                if (!rs.next()) {
                    continue;
                }

                CertRevInfoWithSerial revInfo;

                boolean revoked = rs.getBoolean("REVOEKD");
                if (revoked) {
                    int revReason = rs.getInt("RR");
                    long localRevTime = rs.getLong("RT");
                    long revInvalidityTime = rs.getLong("RIT");

                    Date invalidityTime = (revInvalidityTime == 0)
                            ? null
                            : new Date(1000 * revInvalidityTime);
                    revInfo = new CertRevInfoWithSerial(
                            BigInteger.valueOf(serial),
                            revReason, new Date(1000 * localRevTime), invalidityTime);
                } else {
                    long lastUpdate = rs.getLong("LUPDATE");
                    revInfo = new CertRevInfoWithSerial(BigInteger.valueOf(serial),
                            CrlReason.REMOVE_FROM_CRL.getCode(), new Date(1000 * lastUpdate), null);
                }
                ret.add(revInfo);
            } catch (SQLException ex) {
                throw dataSource.translate(sql, ex);
            } finally {
                releaseDbResources(null, rs);
            }
        } // end for

        return ret;
    } // method getCertificatesForDeltaCrl

    CertStatus getCertStatusForSubject(
            final X509Cert caCert,
            final X500Principal subject)
    throws DataAccessException {
        long subjectFp = X509Util.fpCanonicalizedName(subject);
        return getCertStatusForSubjectFp(caCert, subjectFp);
    }

    CertStatus getCertStatusForSubject(
            final X509Cert caCert,
            final X500Name subject)
    throws DataAccessException {
        long subjectFp = X509Util.fpCanonicalizedName(subject);
        return getCertStatusForSubjectFp(caCert, subjectFp);
    }

    private CertStatus getCertStatusForSubjectFp(
            final X509Cert caCert,
            final long subjectFp)
    throws DataAccessException {
        byte[] encodedCert = caCert.getEncodedCert();
        Integer caId = caInfoStore.getCaIdForCert(encodedCert);
        if (caId == null) {
            return CertStatus.Unknown;
        }

        final String sql = dataSource.createFetchFirstSelectSQL(
                "REV FROM CERT WHERE FP_S=? AND CA_ID=?", 1);
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setLong(idx++, subjectFp);
            ps.setInt(idx++, caId);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return CertStatus.Unknown;
            }
            return rs.getBoolean("REV")
                    ? CertStatus.Revoked
                    : CertStatus.Good;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method getCertStatusForSubjectFp

    boolean isCertForSubjectIssued(
            final X509Cert caCert,
            final long subjectFp)
    throws DataAccessException {
        byte[] encodedCert = caCert.getEncodedCert();
        Integer caId = caInfoStore.getCaIdForCert(encodedCert);
        if (caId == null) {
            return false;
        }

        boolean onlySingleCA = (getNumberOfCas() == 1);
        String coreSql = onlySingleCA
                ? CORESQL_CERT_FOR_SUBJECT_ISSUED_SIMPLE_CA
                : CORESQL_CERT_FOR_SUBJECT_ISSUED;
        String sql = dataSource.createFetchFirstSelectSQL(coreSql, 1);
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setLong(idx++, subjectFp);
            if (!onlySingleCA) {
                ps.setInt(idx++, caId);
            }
            rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1) > 0;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    }

    boolean isCertForKeyIssued(
            final X509Cert caCert,
            final long keyFp)
    throws DataAccessException {
        byte[] encodedCert = caCert.getEncodedCert();
        Integer caId = caInfoStore.getCaIdForCert(encodedCert);
        if (caId == null) {
            return false;
        }

        boolean onlySingleCA = (getNumberOfCas() == 1);
        String coreSql = onlySingleCA
                ? CORESQL_CERT_FOR_KEY_ISSUED_SIMPLE_CA
                : CORESQL_CERT_FOR_KEY_ISSUED;
        String sql = dataSource.createFetchFirstSelectSQL(coreSql, 1);
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setLong(idx++, keyFp);
            if (!onlySingleCA) {
                ps.setInt(idx++, caId);
            }
            rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1) > 0;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    }

    private String base64Fp(
            final byte[] data) {
        return HashCalculator.base64Sha1(data);
    }

    private int getCaId(
            final X509Cert caCert)
    throws OperationException {
        byte[] encodedCert = caCert.getEncodedCert();
        Integer id = caInfoStore.getCaIdForCert(encodedCert);
        if (id != null) {
            return id.intValue();
        }

        throw new IllegalStateException(String.format(
                "could not find CA with subject '%s' in table %s, please start XiPKI in master mode"
                + " first, then restart this XiPKI system",
                caCert.getSubject(), caInfoStore.getTable()));
    }

    private int getNumberOfCas() {
        return caInfoStore.getSize();
    }

    void addCa(
            final X509Cert caCert)
    throws DataAccessException, OperationException {
        byte[] encodedCert = caCert.getEncodedCert();
        if (caInfoStore.getCaIdForCert(encodedCert) != null) {
            return;
        }

        String b64Sha1Fp = base64Fp(encodedCert);

        String tblName = caInfoStore.getTable();
        long maxId = dataSource.getMax(null, tblName, "ID");
        int id = (int) maxId + 1;

        final StringBuilder sqlBuilder = new StringBuilder("INSERT INTO ");
        sqlBuilder.append(tblName);
        sqlBuilder.append(" (ID, SUBJECT, SHA1_CERT, CERT)");
        sqlBuilder.append(" VALUES (?, ?, ?, ?)");

        final String sql = sqlBuilder.toString();
        String b64Cert = Base64.toBase64String(encodedCert);
        String subject = caCert.getSubject();

        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, id);
            ps.setString(idx++, subject);
            ps.setString(idx++, b64Sha1Fp);
            ps.setString(idx++, b64Cert);

            ps.execute();
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }

        CertBasedIdentityEntry newInfo = new CertBasedIdentityEntry(id, subject, b64Sha1Fp,
                b64Cert);
        caInfoStore.addIdentityEntry(newInfo);
    } // method addCa

    private int getRequestorId(
            final String name) {
        return getIdForName(name, requestorInfoStore);
    }

    void addRequestorName(
            final String name)
    throws DataAccessException {
        addName(name, requestorInfoStore);
    }

    private int getPublisherId(
            final String name) {
        return getIdForName(name, publisherStore);
    }

    void addPublisherName(
            final String name)
    throws DataAccessException {
        addName(name, publisherStore);
    }

    private int getCertprofileId(
            final String name) {
        return getIdForName(name, certprofileStore);
    }

    void addCertprofileName(
            final String name)
    throws DataAccessException {
        addName(name, certprofileStore);
    }

    private int getIdForName(
            final String name,
            final NameIdStore store) {
        Integer id = store.getId(name);
        if (id != null) {
            return id.intValue();
        }

        throw new IllegalStateException(String.format(
                "could not find entry named '%s' in table %s, please start XiPKI in master mode "
                + "first and then restart this XiPKI system",
                name, store.getTable()));
    }

    private void addName(
            final String name,
            final NameIdStore store)
    throws DataAccessException {
        if (store.getId(name) != null) {
            return;
        }

        String tblName = store.getTable();
        long maxId = dataSource.getMax(null, tblName, "ID");
        int id = (int) maxId + 1;

        final String sql = new StringBuilder("INSERT INTO ").append(tblName)
                .append(" (ID, NAME) VALUES (?, ?)").toString();
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, id);
            ps.setString(idx++, name);

            ps.execute();
            store.addEntry(name, id);
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, null);
        }
    } // method addName

    private PreparedStatement[] borrowPreparedStatements(
            final String... sqlQueries)
    throws DataAccessException {
        Connection c = dataSource.getConnection();
        if (c == null) {
            throw new DataAccessException("could not get connection");
        }

        final int n = sqlQueries.length;
        PreparedStatement[] pss = new PreparedStatement[n];
        for (int i = 0; i < n; i++) {
            pss[i] = dataSource.prepareStatement(c, sqlQueries[i]);
            if (pss[i] != null) {
                continue;
            }

            // destroy all already initialized statements
            for (int j = 0; j < i; j++) {
                try {
                    pss[j].close();
                } catch (Throwable th) {
                    LOG.warn("could not close preparedStatement", th);
                }
            }

            try {
                c.close();
            } catch (Throwable th) {
                LOG.warn("could not close connection", th);
            }

            throw new DataAccessException(
                    "could not create prepared statement for " + sqlQueries[i]);
        }

        return pss;
    } // method borrowPreparedStatements

    private PreparedStatement borrowPreparedStatement(
            final String sqlQuery)
    throws DataAccessException {
        PreparedStatement ps = null;
        Connection c = dataSource.getConnection();
        if (c != null) {
            ps = dataSource.prepareStatement(c, sqlQuery);
        }

        if (ps != null) {
            return ps;
        }

        throw new DataAccessException("could not create prepared statement for " + sqlQuery);
    } // method borrowPreparedStatement

    private void releaseDbResources(
            final Statement ps,
            final ResultSet rs) {
        dataSource.releaseResources(ps, rs);
    }

    boolean isHealthy() {
        final String sql = "SELECT ID FROM CS_CA";

        try {
            PreparedStatement ps = borrowPreparedStatement(sql);

            ResultSet rs = null;
            try {
                rs = ps.executeQuery();
            } finally {
                releaseDbResources(ps, rs);
            }
            return true;
        } catch (Exception ex) {
            LOG.error("isHealthy(). {}: {}", ex.getClass().getName(), ex.getMessage());
            LOG.debug("isHealthy()", ex);
            return false;
        }
    } // method isHealthy

    String getLatestSerialNumber(
            final X500Name nameWithSN)
    throws OperationException {
        RDN[] rdns1 = nameWithSN.getRDNs();
        RDN[] rdns2 = new RDN[rdns1.length];
        for (int i = 0; i < rdns1.length; i++) {
            RDN rdn = rdns1[i];
            if (rdn.getFirst().getType().equals(ObjectIdentifiers.DN_SERIALNUMBER)) {
                rdns2[i] = new RDN(ObjectIdentifiers.DN_SERIALNUMBER, new DERPrintableString("%"));
            } else {
                rdns2[i] = rdn;
            }
        }

        String namePattern = X509Util.getRfc4519Name(new X500Name(rdns2));

        final String sql = dataSource.createFetchFirstSelectSql(
                "SUBJECT FROM CERT WHERE SUBJECT LIKE ?", 1, "NBEFORE DESC");
        ResultSet rs = null;
        PreparedStatement ps;
        try {
            ps = borrowPreparedStatement(sql);
        } catch (DataAccessException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        }

        String subjectStr;

        try {
            ps.setString(1, namePattern);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }

            subjectStr = rs.getString("SUBJECT");
        } catch (SQLException ex) {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
        } finally {
            releaseDbResources(ps, rs);
        }

        X500Name lastName = new X500Name(subjectStr);
        RDN[] rdns = lastName.getRDNs(ObjectIdentifiers.DN_SERIALNUMBER);
        if (rdns == null || rdns.length == 0) {
            return null;
        }

        return X509Util.rdnValueToString(rdns[0].getFirst().getValue());
    } // method getLatestSerialNumber

    Long getNotBeforeOfFirstCertStartsWithCommonName(
            final String commonName,
            final String profileName)
    throws DataAccessException {
        Integer profileId = certprofileStore.getId(profileName);
        if (profileId == null) {
            return null;
        }

        final String sql = dataSource.createFetchFirstSelectSql(
                "NBEFORE FROM CERT WHERE PID=? AND SUBJECT LIKE ?", 1, "NBEFORE ASC");
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, profileId.intValue());
            ps.setString(idx++, "%cn=" + commonName + "%");

            rs = ps.executeQuery();

            if (!rs.next()) {
                return null;
            }

            long notBefore = rs.getLong("NBEFORE");

            return (notBefore == 0)
                    ? null
                    : notBefore;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            releaseDbResources(ps, rs);
        }
    } // method getNotBeforeOfFirstCertStartsWithCommonName

    void markMaxSerial(
            final X509Cert caCert,
            final String seqName)
    throws DataAccessException {
        byte[] encodedCert = caCert.getEncodedCert();
        Integer caId = caInfoStore.getCaIdForCert(encodedCert);
        if (caId == null) {
            return;
        }

        final String sql = "SELECT MAX(SN) FROM CERT WHERE CA_ID=?";
        Long maxSerial = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            ps = borrowPreparedStatement(sql);
            ps.setInt(1, caId);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return;
            }
            maxSerial = rs.getLong(1);
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            dataSource.releaseResources(ps, rs);
        }

        if (maxSerial != null) {
            dataSource.setLastUsedSeqValue(seqName, maxSerial);
        }
    } // method markMaxSerial

    void commitNextSerialIfLess(
            final String caName,
            final long nextSerial)
    throws DataAccessException {
        Connection conn = dataSource.getConnection();
        PreparedStatement ps = null;
        try {
            String sql = "SELECT NEXT_SN FROM CA WHERE NAME = '" + caName + "'";
            ResultSet rs = null;
            long nextSerialInDB;

            try {
                ps = conn.prepareStatement(sql);
                rs = ps.executeQuery();
                rs.next();
                nextSerialInDB = rs.getLong("NEXT_SN");
            } catch (SQLException ex) {
                throw dataSource.translate(sql, ex);
            } finally {
                releaseStatement(ps);

                if (rs != null) {
                    releaseResultSet(rs);
                }
            }

            if (nextSerialInDB < nextSerial) {
                sql = "UPDATE CA SET NEXT_SN=? WHERE NAME=?";
                try {
                    ps = conn.prepareStatement(sql);
                    ps.setLong(1, nextSerial);
                    ps.setString(2, caName);
                    ps.executeUpdate();
                } catch (SQLException ex) {
                    throw dataSource.translate(sql, ex);
                }
            }
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method commitNextSerialIfLess

    void commitNextCrlNoIfLess(
            final String caName,
            final int nextCrlNo)
    throws DataAccessException {
        Connection conn = dataSource.getConnection();
        PreparedStatement ps = null;
        try {
            final String sql = new StringBuilder("SELECT NEXT_CRLNO FROM CA WHERE NAME = '")
                .append(caName).append("'").toString();
            ResultSet rs = null;
            int nextCrlNoInDB;

            try {
                ps = conn.prepareStatement(sql);
                rs = ps.executeQuery();
                rs.next();
                nextCrlNoInDB = rs.getInt("NEXT_CRLNO");
            } catch (SQLException ex) {
                throw dataSource.translate(sql, ex);
            } finally {
                releaseStatement(ps);
                if (rs != null) {
                    releaseResultSet(rs);
                }
            }

            if (nextCrlNoInDB < nextCrlNo) {
                final String updateSql = "UPDATE CA SET NEXT_CRLNO=? WHERE NAME=?";
                try {
                    ps = conn.prepareStatement(updateSql);
                    ps.setInt(1, nextCrlNo);
                    ps.setString(2, caName);
                    ps.executeUpdate();
                } catch (SQLException ex) {
                    throw dataSource.translate(updateSql, ex);
                }
            }
        } finally {
            dataSource.releaseResources(ps, null);
        }
    } // method commitNextCrlNoIfLess

    long nextSerial(
            final X509Cert caCert,
            final String seqName)
    throws DataAccessException {
        byte[] encodedCert = caCert.getEncodedCert();
        Integer caId = caInfoStore.getCaIdForCert(encodedCert);
        if (caId == null) {
            throw new IllegalArgumentException(
                    "unknown CA with subject '" + caCert.getSubject() + "'");
        }

        final String sql = dataSource.createFetchFirstSelectSQL(CORESQL_ID_FOR_SN_IN_CERT, 1);
        Connection conn = dataSource.getConnection();
        PreparedStatement ps = null;

        try {
            ps = dataSource.prepareStatement(conn, sql);
            ps.setInt(1, caId);

            while (true) {
                long serial = dataSource.nextSeqValue(conn, seqName);

                ResultSet rs = null;
                try {
                    ps.setLong(2, serial);
                    rs = ps.executeQuery();
                    rs.next();
                    if (rs.getInt(1) == 0) {
                        return serial;
                    }
                } catch (SQLException ex) {
                    throw dataSource.translate(sql, ex);
                } finally {
                    dataSource.releaseResources(null, rs);
                }
            }
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            if (ps != null) {
                dataSource.releaseResources(ps, null);
            } else {
                dataSource.returnConnection(conn);
            }
        }
    }

    private int nextCertId()
    throws DataAccessException {
        Connection conn = dataSource.getConnection();
        try {
            while (true) {
                int certId = (int) dataSource.nextSeqValue(conn, "CID");
                if (!dataSource.columnExists(conn, "CERT", "ID", certId)) {
                    return certId;
                }
            }
        } finally {
            dataSource.returnConnection(conn);
        }
    }

    private long nextDccId()
    throws DataAccessException {
        Connection conn = dataSource.getConnection();
        try {
            while (true) {
                long id = dataSource.nextSeqValue(conn, "DCC_ID");
                if (!dataSource.columnExists(conn, "DELTACRL_CACHE", "ID", id)) {
                    return id;
                }
            }
        } finally {
            dataSource.returnConnection(conn);
        }
    }

    void deleteCertInProcess(
            final long fpKey,
            final long fpSubject)
    throws DataAccessException {
        final String sql = SQL_DELETE_CERT_INPROCESS;
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;
        try {
            ps.setLong(1, fpKey);
            ps.setLong(2, fpSubject);
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            dataSource.releaseResources(ps, rs);
        }
    } // method deleteCertInProcess

    boolean addCertInProcess(
            final long fpKey,
            final long fpSubject)
    throws DataAccessException {
        final String sql = SQL_ADD_CERT_INPROCESS;
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;
        try {
            ps.setLong(1, fpKey);
            ps.setLong(2, fpSubject);
            ps.setLong(3, System.currentTimeMillis() / 1000);
            try {
                ps.executeUpdate();
            } catch (SQLException ex) {
                DataAccessException tEx = dataSource.translate(sql, ex);
                if (tEx instanceof DuplicateKeyException
                        || tEx instanceof DataIntegrityViolationException) {
                    return false;
                }
            }
            return true;
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            dataSource.releaseResources(ps, rs);
        }
    } // method addCertInProcess

    void deleteCertsInProcessOlderThan(
            final Date time)
    throws DataAccessException {
        final String sql = SQL_DELETE_CERT_INPROCESS_OLDER_THAN;
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;
        try {
            ps.setLong(1, time.getTime() / 1000);
            ps.executeUpdate();
        } catch (SQLException ex) {
            throw dataSource.translate(sql, ex);
        } finally {
            dataSource.releaseResources(ps, rs);
        }
    }

    private static void releaseStatement(
            Statement statment) {
        try {
            statment.close();
        } catch (SQLException ex) {
            LOG.warn("could not close Statement", ex);
        }
    }

    private static void releaseResultSet(
            ResultSet resultSet) {
        try {
            resultSet.close();
        } catch (SQLException ex) {
            LOG.warn("could not close ResultSet", ex);
        }
    }

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

}
