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

package org.xipki.pki.ca.server.impl.publisher;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.datasource.api.exception.DuplicateKeyException;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.X509Cert;
import org.xipki.pki.ca.api.X509CertWithDBCertId;
import org.xipki.pki.ca.server.impl.DbSchemaInfo;
import org.xipki.security.api.CertRevocationInfo;
import org.xipki.security.api.HashAlgoType;
import org.xipki.security.api.HashCalculator;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

class OCSPStoreQueryExecutor {
    private static final String SQL_ADD_REVOKED_CERT =
            "INSERT INTO CERT (ID,LUPDATE,SN,NBEFORE,NAFTER,REV,IID,PN,RT,RIT,RR)"
            + " VALUES (?,?,?,?,?,?,?,?,?,?,?)";

    private static final String SQL_ADD_CERT =
            "INSERT INTO CERT (ID,LUPDATE,SN,NBEFORE,NAFTER,REV,IID,PN)"
            + " VALUES (?,?,?,?,?,?,?,?)";

    private static final String SQL_ADD_CRAW =
            "INSERT INTO CRAW (CID,SUBJECT,CERT) VALUES (?,?,?)";

    private static final String SQL_ADD_CHASH =
            "INSERT INTO CHASH (CID,S1,S224,S256,S384,S512) VALUES (?,?,?,?,?,?)";

    private static final Logger LOG = LoggerFactory.getLogger(OCSPStoreQueryExecutor.class);

    private final DataSourceWrapper dataSource;

    private final IssuerStore issuerStore;

    private final boolean publishGoodCerts;

    @SuppressWarnings("unused")
    private final int dbSchemaVersion;
    private final int maxX500nameLen;

    OCSPStoreQueryExecutor(
            final DataSourceWrapper dataSource,
            final boolean publishGoodCerts)
    throws DataAccessException, NoSuchAlgorithmException {
        this.dataSource = dataSource;
        this.issuerStore = initIssuerStore();
        this.publishGoodCerts = publishGoodCerts;

        DbSchemaInfo dbSchemaInfo = new DbSchemaInfo(dataSource);
        String s = dbSchemaInfo.getVariableValue("VERSION");
        this.dbSchemaVersion = Integer.parseInt(s);
        s = dbSchemaInfo.getVariableValue("X500NAME_MAXLEN");
        this.maxX500nameLen = Integer.parseInt(s);
    }

    private IssuerStore initIssuerStore()
    throws DataAccessException {
        final String sql = "SELECT ID,SUBJECT,S1C,CERT FROM ISSUER";
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;

        try {
            rs = ps.executeQuery();
            List<IssuerEntry> caInfos = new LinkedList<>();
            while (rs.next()) {
                int id = rs.getInt("ID");
                String subject = rs.getString("SUBJECT");
                String sha1Fp = rs.getString("S1C");
                String b64Cert = rs.getString("CERT");

                IssuerEntry caInfoEntry = new IssuerEntry(id, subject, sha1Fp, b64Cert);
                caInfos.add(caInfoEntry);
            }

            return new IssuerStore(caInfos);
        } catch (SQLException e) {
            throw dataSource.translate(sql, e);
        } finally {
            releaseDbResources(ps, rs);
        }
    }

    /**
     * @throws DataAccessException if there is problem while accessing database.
     * @throws NoSuchAlgorithmException
     * @throws CertificateEncodingException
     */
    void addCert(
            final X509Cert issuer,
            final X509CertWithDBCertId certificate,
            final String certprofile)
    throws DataAccessException, CertificateEncodingException, OperationException {
        addCert(issuer, certificate, certprofile, null);
    }

    void addCert(
            final X509Cert issuer,
            final X509CertWithDBCertId certificate,
            final String certprofile,
            final CertRevocationInfo revInfo)
    throws DataAccessException, CertificateEncodingException, OperationException {
        addOrUpdateCert(issuer, certificate, certprofile, revInfo);
    }

    private void addOrUpdateCert(
            final X509Cert issuer,
            final X509CertWithDBCertId certificate,
            final String certprofile,
            final CertRevocationInfo revInfo)
    throws DataAccessException, CertificateEncodingException, OperationException {
        boolean revoked = revInfo != null;
        int issuerId = getIssuerId(issuer);

        BigInteger serialNumber = certificate.getCert().getSerialNumber();
        boolean certRegistered = certRegistered(issuerId, serialNumber);

        if (!publishGoodCerts && !revoked && !certRegistered) {
            return;
        }

        if (certRegistered) {
            final String sql =
                "UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE IID=? AND SN=?";
            PreparedStatement ps = borrowPreparedStatement(sql);

            try {
                int idx = 1;
                ps.setLong(idx++, new Date().getTime() / 1000);
                setBoolean(ps, idx++, revoked);
                if (revoked) {
                    ps.setLong(idx++, revInfo.getRevocationTime().getTime() / 1000);
                    if (revInfo.getInvalidityTime() != null) {
                        ps.setLong(idx++, revInfo.getInvalidityTime().getTime() / 1000);
                    } else {
                        ps.setNull(idx++, Types.INTEGER);
                    }
                    ps.setInt(idx++, revInfo.getReason().getCode());
                } else {
                    ps.setNull(idx++, Types.INTEGER); // rev_time
                    ps.setNull(idx++, Types.INTEGER); // rev_invalidity_time
                    ps.setNull(idx++, Types.INTEGER); // rev_reason
                }
                ps.setInt(idx++, issuerId);
                ps.setLong(idx++, serialNumber.longValue());
                ps.executeUpdate();
            } catch (SQLException e) {
                throw dataSource.translate(sql, e);
            } finally {
                releaseDbResources(ps, null);
            }
            return;
        }

        final String sql_addCert = revoked
                ? SQL_ADD_REVOKED_CERT
                : SQL_ADD_CERT;

        int certId = nextCertId();
        byte[] encodedCert = certificate.getEncodedCert();
        String b64Cert = Base64.toBase64String(encodedCert);
        String sha1Fp = HashCalculator.base64Hash(HashAlgoType.SHA1, encodedCert);
        String sha224Fp = HashCalculator.base64Hash(HashAlgoType.SHA224, encodedCert);
        String sha256Fp = HashCalculator.base64Hash(HashAlgoType.SHA256, encodedCert);
        String sha384Fp = HashCalculator.base64Hash(HashAlgoType.SHA384, encodedCert);
        String sha512Fp = HashCalculator.base64Hash(HashAlgoType.SHA512, encodedCert);

        PreparedStatement[] pss = borrowPreparedStatements(
                sql_addCert, SQL_ADD_CRAW, SQL_ADD_CHASH);
        // all statements have the same connection
        Connection conn = null;

        try {
            PreparedStatement ps_addcert = pss[0];
            PreparedStatement ps_addRawcert = pss[1];
            PreparedStatement ps_addCerthash = pss[2];
            conn = ps_addcert.getConnection();

            // CERT
            X509Certificate cert = certificate.getCert();
            int idx = 2;
            ps_addcert.setLong(idx++, System.currentTimeMillis() / 1000);
            ps_addcert.setLong(idx++, serialNumber.longValue());
            ps_addcert.setLong(idx++, cert.getNotBefore().getTime() / 1000);
            ps_addcert.setLong(idx++, cert.getNotAfter().getTime() / 1000);
            setBoolean(ps_addcert, idx++, revoked);
            ps_addcert.setInt(idx++, issuerId);
            ps_addcert.setString(idx++, certprofile);

            if (revoked) {
                ps_addcert.setLong(idx++, revInfo.getRevocationTime().getTime() / 1000);
                if (revInfo.getInvalidityTime() != null) {
                    ps_addcert.setLong(idx++, revInfo.getInvalidityTime().getTime() / 1000);
                } else {
                    ps_addcert.setNull(idx++, Types.BIGINT);
                }
                ps_addcert.setInt(idx++,
                        (revInfo.getReason() == null)
                            ? 0
                            : revInfo.getReason().getCode());
            }

            // CRAW
            idx = 2;
            ps_addRawcert.setString(idx++,
                    X509Util.cutText(certificate.getSubject(), maxX500nameLen));
            ps_addRawcert.setString(idx++, b64Cert);

            // CHASH
            idx = 2;
            ps_addCerthash.setString(idx++, sha1Fp);
            ps_addCerthash.setString(idx++, sha224Fp);
            ps_addCerthash.setString(idx++, sha256Fp);
            ps_addCerthash.setString(idx++, sha384Fp);
            ps_addCerthash.setString(idx++, sha512Fp);

            final int tries = 3;
            for (int i = 0; i < tries; i++) {
                if (i > 0) {
                    certId = nextCertId();
                }

                ps_addcert.setInt(1, certId);
                ps_addCerthash.setInt(1, certId);
                ps_addRawcert.setInt(1, certId);

                final boolean origAutoCommit = conn.getAutoCommit();
                conn.setAutoCommit(false);
                String sql = null;
                try {
                    sql = sql_addCert;
                    ps_addcert.executeUpdate();

                    sql = SQL_ADD_CHASH;
                    ps_addRawcert.executeUpdate();

                    sql = SQL_ADD_CHASH;
                    ps_addCerthash.executeUpdate();

                    sql = "(commit add cert to OCSP)";
                    conn.commit();
                } catch (Throwable t) {
                    conn.rollback();
                    // more secure
                    dataSource.deleteFromTable(null, "CRAW", "CID", certId);
                    dataSource.deleteFromTable(null, "CHASH", "CID", certId);
                    dataSource.deleteFromTable(null, "CERT", "ID", certId);

                    if (t instanceof SQLException) {
                        SQLException e = (SQLException) t;
                        DataAccessException tEx = dataSource.translate(sql, e);
                        if (tEx instanceof DuplicateKeyException && i < tries - 1) {
                            continue;
                        }
                        LOG.error(
                            "datasource {} SQLException while adding certificate with id {}: {}",
                            dataSource.getDatasourceName(), certId, t.getMessage());
                        throw e;
                    } else {
                        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                                t.getClass().getName() + ": " + t.getMessage());
                    }
                } finally {
                    conn.setAutoCommit(origAutoCommit);
                }

                break;
            }
        } catch (SQLException e) {
            throw dataSource.translate(null, e);
        } finally {
            for (PreparedStatement ps : pss) {
                try {
                    ps.close();
                } catch (Throwable t) {
                    LOG.warn("could not close PreparedStatement", t);
                }

            }
            dataSource.returnConnection(conn);
        }
    }

    void revokeCert(
            final X509Cert caCert,
            final X509CertWithDBCertId cert,
            final String certprofile,
            final CertRevocationInfo revInfo)
    throws DataAccessException, CertificateEncodingException, OperationException {
        addOrUpdateCert(caCert, cert, certprofile, revInfo);
    }

    void unrevokeCert(
            final X509Cert issuer,
            final X509CertWithDBCertId cert)
    throws DataAccessException {
        Integer issuerId =  issuerStore.getIdForCert(issuer.getEncodedCert());
        if (issuerId == null) {
            return;
        }

        BigInteger serialNumber = cert.getCert().getSerialNumber();
        boolean certRegistered = certRegistered(issuerId, serialNumber);

        if (!certRegistered) {
            return;
        }

        if (publishGoodCerts) {
            final String sql =
                    "UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE IID=? AND SN=?";
            PreparedStatement ps = borrowPreparedStatement(sql);

            try {
                int idx = 1;
                ps.setLong(idx++, new Date().getTime() / 1000);
                setBoolean(ps, idx++, false);
                ps.setNull(idx++, Types.INTEGER);
                ps.setNull(idx++, Types.INTEGER);
                ps.setNull(idx++, Types.INTEGER);
                ps.setInt(idx++, issuerId);
                ps.setLong(idx++, serialNumber.longValue());
                ps.executeUpdate();
            } catch (SQLException e) {
                throw dataSource.translate(sql, e);
            } finally {
                releaseDbResources(ps, null);
            }
        } else {
            final String sql = "DELETE FROM CERT WHERE IID=? AND SN=?";
            PreparedStatement ps = borrowPreparedStatement(sql);

            try {
                int idx = 1;
                ps.setInt(idx++, issuerId);
                ps.setLong(idx++, serialNumber.longValue());
                ps.executeUpdate();
            } catch (SQLException e) {
                throw dataSource.translate(sql, e);
            } finally {
                releaseDbResources(ps, null);
            }
        }

    }

    void removeCert(
            final X509Cert issuer,
            final X509CertWithDBCertId cert)
    throws DataAccessException {
        Integer issuerId =  issuerStore.getIdForCert(issuer.getEncodedCert());
        if (issuerId == null) {
            return;
        }

        final String sql = "DELETE FROM CERT WHERE IID=? AND SN=?";
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, issuerId);
            ps.setLong(idx++, cert.getCert().getSerialNumber().longValue());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw dataSource.translate(sql, e);
        } finally {
            releaseDbResources(ps, null);
        }
    }

    void revokeCa(
            final X509Cert caCert,
            final CertRevocationInfo revocationInfo)
    throws DataAccessException, CertificateEncodingException {
        Date revocationTime = revocationInfo.getRevocationTime();
        Date invalidityTime = revocationInfo.getInvalidityTime();
        if (invalidityTime == null) {
            invalidityTime = revocationTime;
        }

        int issuerId = getIssuerId(caCert);
        final String sql = "UPDATE ISSUER SET REV=?,RT=?,RIT=?,RR=? WHERE ID=?";
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            setBoolean(ps, idx++, true);
            ps.setLong(idx++, revocationTime.getTime() / 1000);
            ps.setLong(idx++, invalidityTime.getTime() / 1000);
            ps.setInt(idx++, revocationInfo.getReason().getCode());
            ps.setInt(idx++, issuerId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw dataSource.translate(sql, e);
        } finally {
            releaseDbResources(ps, null);
        }
    }

    void unrevokeCa(
            final X509Cert caCert)
    throws DataAccessException, CertificateEncodingException {
        int issuerId = getIssuerId(caCert);
        final String sql = "UPDATE ISSUER SET REV=?,RT=?,RIT=?,RR=? WHERE ID=?";
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            setBoolean(ps, idx++, false);
            ps.setNull(idx++, Types.INTEGER);
            ps.setNull(idx++, Types.INTEGER);
            ps.setNull(idx++, Types.INTEGER);
            ps.setInt(idx++, issuerId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw dataSource.translate(sql, e);
        } finally {
            releaseDbResources(ps, null);
        }
    }

    private int getIssuerId(
            final X509Cert issuerCert)
    throws DataAccessException, CertificateEncodingException {
        Integer id = issuerStore.getIdForCert(issuerCert.getEncodedCert());
        if (id == null) {
            throw new IllegalStateException("could not find issuer, "
                    + "please start XiPKI in master mode first the restart this XiPKI system");
        }
        return id.intValue();
    }

    void addIssuer(
            final X509Cert issuerCert)
    throws CertificateEncodingException, DataAccessException {
        if (issuerStore.getIdForCert(issuerCert.getEncodedCert()) != null) {
            return;
        }

        String sha1FpCert = HashCalculator.base64Sha1(issuerCert.getEncodedCert());

        Certificate bcCert = Certificate.getInstance(issuerCert.getEncodedCert());
        byte[] encodedName;
        try {
            encodedName = bcCert.getSubject().getEncoded("DER");
        } catch (IOException e) {
            throw new CertificateEncodingException(e.getMessage(), e);
        }
        byte[] encodedKey = bcCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

        long maxId = dataSource.getMax(null, "ISSUER", "ID");
        int id = (int) maxId + 1;

        final String sql =
            "INSERT INTO ISSUER (ID,SUBJECT,NBEFORE,NAFTER,S1S,S1K,S224S,S224K,S256S,S256K,"
            + "S384S,S384K,S512S,S512K,S1C,CERT) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            String b64Cert = Base64.toBase64String(issuerCert.getEncodedCert());
            String subject = issuerCert.getSubject();
            int idx = 1;
            ps.setInt(idx++, id);
            ps.setString(idx++, subject);
            ps.setLong(idx++, issuerCert.getCert().getNotBefore().getTime() / 1000);
            ps.setLong(idx++, issuerCert.getCert().getNotAfter() .getTime() / 1000);
            ps.setString(idx++, HashCalculator.base64Hash(HashAlgoType.SHA1, encodedName));
            ps.setString(idx++, HashCalculator.base64Hash(HashAlgoType.SHA1, encodedKey));
            ps.setString(idx++, HashCalculator.base64Hash(HashAlgoType.SHA224, encodedName));
            ps.setString(idx++, HashCalculator.base64Hash(HashAlgoType.SHA224, encodedKey));
            ps.setString(idx++, HashCalculator.base64Hash(HashAlgoType.SHA256, encodedName));
            ps.setString(idx++, HashCalculator.base64Hash(HashAlgoType.SHA256, encodedKey));
            ps.setString(idx++, HashCalculator.base64Hash(HashAlgoType.SHA384, encodedName));
            ps.setString(idx++, HashCalculator.base64Hash(HashAlgoType.SHA384, encodedKey));
            ps.setString(idx++, HashCalculator.base64Hash(HashAlgoType.SHA512, encodedName));
            ps.setString(idx++, HashCalculator.base64Hash(HashAlgoType.SHA512, encodedKey));
            ps.setString(idx++, sha1FpCert);
            ps.setString(idx++, b64Cert);

            ps.execute();

            IssuerEntry newInfo = new IssuerEntry(id, subject, sha1FpCert, b64Cert);
            issuerStore.addIdentityEntry(newInfo);
        } catch (SQLException e) {
            throw dataSource.translate(sql, e);
        } finally {
            releaseDbResources(ps, null);
        }
    }

    /**
     *
     * @return the next idle preparedStatement, {@code null} will be returned
     *         if no PreparedStament can be created within 5 seconds
     * @throws DataAccessException
     */
    private PreparedStatement borrowPreparedStatement(
            final String sqlQuery)
    throws DataAccessException {
        PreparedStatement ps = null;
        Connection c = dataSource.getConnection();
        if (c != null) {
            ps = dataSource.prepareStatement(c, sqlQuery);
        }
        if (ps == null) {
            throw new DataAccessException("could not create prepared statement for " + sqlQuery);
        }
        return ps;
    }

    private PreparedStatement[] borrowPreparedStatements(
            final String... sqlQueries)
    throws DataAccessException {
        PreparedStatement[] pss = new PreparedStatement[sqlQueries.length];

        Connection c = dataSource.getConnection();
        if (c != null) {
            final int n = sqlQueries.length;
            for (int i = 0; i < n; i++) {
                pss[i] = dataSource.prepareStatement(c, sqlQueries[i]);
                if (pss[i] != null) {
                    continue;
                }

                for (int j = 0; j < i; j++) {
                    try {
                        pss[j].close();
                    } catch (Throwable t) {
                        LOG.warn("could not close preparedStatement", t);
                    }
                }

                try {
                    c.close();
                } catch (Throwable t) {
                    LOG.warn("could not close connection", t);
                }

                throw new DataAccessException(
                        "could not create prepared statement for " + sqlQueries[i]);
            }
        }

        return pss;
    }

    private boolean certRegistered(
            final int issuerId,
            final BigInteger serialNumber)
    throws DataAccessException {
        final String sql = dataSource.createFetchFirstSelectSQL(
                "COUNT(*) FROM CERT WHERE IID=? AND SN=?", 1);
        ResultSet rs = null;
        PreparedStatement ps = borrowPreparedStatement(sql);

        try {
            int idx = 1;
            ps.setInt(idx++, issuerId);
            ps.setLong(idx++, serialNumber.longValue());

            rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            throw dataSource.translate(sql, e);
        } finally {
            releaseDbResources(ps, rs);
        }

        return false;
    }

    boolean isHealthy() {
        final String sql = "SELECT ID FROM ISSUER";

        try {
            ResultSet rs = null;
            PreparedStatement ps = borrowPreparedStatement(sql);

            try {
                rs = ps.executeQuery();
            } finally {
                releaseDbResources(ps, rs);
            }
            return true;
        } catch (Exception e) {
            final String message = "isHealthy()";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            return false;
        }
    }

    private void releaseDbResources(
            final Statement ps,
            final ResultSet rs) {
        dataSource.releaseResources(ps, rs);
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
