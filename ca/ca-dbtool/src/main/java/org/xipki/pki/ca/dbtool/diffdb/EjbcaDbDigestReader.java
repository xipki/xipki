/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.pki.ca.dbtool.diffdb;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.DbToolBase;
import org.xipki.pki.ca.dbtool.IDRange;
import org.xipki.pki.ca.dbtool.StopMe;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbSchemaType;
import org.xipki.pki.ca.dbtool.diffdb.internal.DigestDBEntrySet;
import org.xipki.pki.ca.dbtool.diffdb.internal.EjbcaCACertExtractor;
import org.xipki.pki.ca.dbtool.diffdb.internal.IdentifiedDbDigestEntry;
import org.xipki.security.api.HashCalculator;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class EjbcaDbDigestReader extends DbDigestReader {

    private class EjbcaDbRetriever implements Retriever {

        private Connection conn;

        private PreparedStatement selectCertStmt;

        private PreparedStatement selectBase64CertStmt;

        public EjbcaDbRetriever()
        throws DataAccessException {
            Connection conn = datasource.getConnection();
            try {
                selectCertStmt = datasource.prepareStatement(conn, selectCertSql);
                selectBase64CertStmt = datasource.prepareStatement(conn, selectBase64CertSql);
            } catch (DataAccessException e) {
                datasource.returnConnection(conn);
                throw e;
            }
        }

        @Override
        public void run() {
            while (!stopMe.stopMe()) {
                try {
                    IDRange idRange = inQueue.take();
                    query(idRange);
                } catch (InterruptedException e) {
                }
            }

            DbToolBase.releaseResources(selectCertStmt, null);
            releaseResources(selectBase64CertStmt, null);
            datasource.returnConnection(conn);
            selectCertStmt = null;
            selectBase64CertStmt = null;
        }

        @SuppressWarnings("resource")
        private void query(
                final IDRange idRange) {
            DigestDBEntrySet result = new DigestDBEntrySet(idRange.getFrom());

            ResultSet rs = null;
            try {
                selectCertStmt.setInt(1, idRange.getFrom());
                selectCertStmt.setInt(2, idRange.getTo() + 1);

                rs = selectCertStmt.executeQuery();

                while (rs.next()) {
                    int id = rs.getInt("id");
                    String caHash = rs.getString("cAFingerprint");
                    String hash = rs.getString("fingerprint");

                    boolean ofThisCA = caFingerprint.equals(caHash);
                    if (!ofThisCA && caHash.equals(hash)) {
                        // special case
                        try {
                            selectBase64CertStmt.setInt(1, id);
                            ResultSet base64Rs = selectBase64CertStmt.executeQuery();
                            base64Rs.next();
                            String b64Cert = base64Rs.getString("base64Cert");
                            base64Rs.close();
                            X509Certificate jceCert;
                            try {
                                jceCert = X509Util.parseBase64EncodedCert(b64Cert);
                            } catch (Exception e) {
                                throw new DataAccessException("IOException", e);
                            }
                            if (jceCert.getIssuerX500Principal()
                                    .equals(caCert.getSubjectX500Principal())) {
                                ofThisCA = true;
                            }
                        } catch (SQLException e) {
                            throw datasource.translate(selectBase64CertSql, e);
                        }
                    }

                    if (!ofThisCA) {
                        continue;
                    }

                    long serial = rs.getLong("serialNumber");
                    int status = rs.getInt("status");
                    boolean revoked = (status == 40);

                    Integer revReason = null;
                    Long revTime = null;
                    Long revInvTime = null;

                    if (revoked) {
                        revReason = rs.getInt("revocationReason");
                        long rev_timeInMs = rs.getLong("revocationDate");
                        // rev_time is milliseconds, convert it to seconds
                        revTime = rev_timeInMs / 1000;
                    }

                    DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                            revInvTime, hash);
                    result.addEntry(new IdentifiedDbDigestEntry(cert, id));
                }
            } catch (Exception e) {
                if (e instanceof SQLException) {
                    e = datasource.translate(selectCertSql, (SQLException) e);
                }
                result.setException(e);
            } finally {
                releaseResources(null, rs);
            }

            outQueue.add(result);
        }

    }

    private final int caId;

    private final String selectCertSql;

    private final String selectBase64CertSql;

    private final String caFingerprint;

    public static EjbcaDbDigestReader getInstance(
            final DataSourceWrapper datasource,
            final DbSchemaType dbSchemaType,
            final int caId,
            final boolean dbContainsOtherCA,
            final boolean revokedOnly,
            final int numThreads,
            final int numCertsToPredicate,
            final StopMe stopMe)
    throws Exception {
        ParamUtil.assertNotNull("datasource", datasource);

        Connection conn = datasource.getConnection();

        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;

        X509Certificate caCert;
        int totalAccount;
        int minId;
        int maxId;

        try {
            stmt = datasource.createStatement(conn);

            sql = "SELECT data FROM CAData WHERE cAId=" + caId;
            rs = stmt.executeQuery(sql);
            if (!rs.next()) {
                throw new IllegalArgumentException("no CA with id '" + caId + "' is available");
            }

            String caData = rs.getString("data");
            rs.close();

            caCert = EjbcaCACertExtractor.extractCACert(caData);
            // account
            if (dbContainsOtherCA) {
                // ignore it due to performance
                totalAccount = -1;
            } else {
                sql = "SELECT COUNT(*) FROM CertificateData";
                if (revokedOnly) {
                    sql += " WHERE status=40";
                }
                rs = stmt.executeQuery(sql);
                totalAccount = rs.next()
                        ? rs.getInt(1)
                        : 0;
                rs.close();
            }

            // maxId
            sql = "SELECT MAX(id) FROM CertificateData";
            if (revokedOnly) {
                sql += " WHERE status=40";
            }
            rs = stmt.executeQuery(sql);
            maxId = rs.next()
                    ? rs.getInt(1)
                    : 0;
            rs.close();

            sql = "SELECT MIN(id) FROM CertificateData";
            if (revokedOnly) {
                sql += " WHERE status=40";
            }
            rs = stmt.executeQuery(sql);
            minId = rs.next()
                    ? rs.getInt(1)
                    : 1;

        } catch (SQLException e) {
            throw datasource.translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
            datasource.returnConnection(conn);
        }

        return new EjbcaDbDigestReader(datasource, caCert, revokedOnly, totalAccount,
                minId, maxId, numThreads, dbSchemaType, caId, dbContainsOtherCA,
                numCertsToPredicate, stopMe);
    }

    private EjbcaDbDigestReader(
            final DataSourceWrapper datasource,
            final X509Certificate caCert,
            final boolean revokedOnly,
            final int totalAccount,
            final int minId,
            final int maxId,
            final int numThreads,
            final DbSchemaType dbSchemaType,
            final int caId,
            final boolean dbContainsOtherCA,
            final int numCertsToPredicate,
            final StopMe stopMe)
    throws Exception {
        super(datasource, caCert, revokedOnly, totalAccount, minId, maxId, numThreads,
                numCertsToPredicate, stopMe);
        ParamUtil.assertNotNull("datasource", datasource);

        this.caId = caId;

        this.caFingerprint = HashCalculator.hexSha1(caCert.getEncoded()).toLowerCase();

        this.selectBase64CertSql = "SELECT base64Cert FROM CertificateData WHERE id=?";

        StringBuilder sb = new StringBuilder();
        sb.append("SELECT id,serialNumber,cAFingerprint,fingerprint");
        sb.append(",status,revocationDate,revocationReason");
        sb.append(" FROM CertificateData WHERE id>=? AND id<?");
        if (revokedOnly) {
            sb.append(" AND status=40");
        }
        this.selectCertSql = sb.toString();
        if (!init()) {
            throw new Exception("could not initialize the EjbcaDigestReader");
        }
    }

    public int getCaId() {
        return caId;
    }

    @Override
    protected Retriever getRetriever()
    throws DataAccessException {
        return new EjbcaDbRetriever();
    }

    @Override
    protected int getNumSkippedCerts(
            final int fromId,
            final int toId,
            final int numCerts)
    throws DataAccessException {
        return 0;
    }

}
