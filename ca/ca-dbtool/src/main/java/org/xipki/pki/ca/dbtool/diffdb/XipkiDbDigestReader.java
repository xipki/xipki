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

package org.xipki.pki.ca.dbtool.diffdb;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.dbtool.IdRange;
import org.xipki.pki.ca.dbtool.StopMe;
import org.xipki.pki.ca.dbtool.diffdb.io.DbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.io.DbSchemaType;
import org.xipki.pki.ca.dbtool.diffdb.io.DigestDbEntrySet;
import org.xipki.pki.ca.dbtool.diffdb.io.IdentifiedDbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.io.XipkiDbControl;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XipkiDbDigestReader extends DbDigestReader {

    private int caId;

    private XipkiDbControl dbControl;

    private Connection conn;

    private String selectCertSql;

    private String numCertSql;

    private PreparedStatement numCertStmt;

    private XipkiDbDigestReader(
            final DataSourceWrapper datasource,
            final X509Certificate caCert,
            final boolean revokedOnly,
            final int totalAccount,
            final int minId,
            final int maxId,
            final int numThreads,
            final int numCertsToPredicate,
            final StopMe stopMe)
    throws Exception {
        super(datasource, caCert, revokedOnly, totalAccount, minId, maxId, numThreads,
                numCertsToPredicate, stopMe);
    } // constructor

    private class XipkiDbRetriever implements Retriever {
        private Connection conn;
        private PreparedStatement selectCertStmt;

        XipkiDbRetriever()
        throws DataAccessException {
            this.conn = datasource.getConnection();
            try {
                selectCertStmt = datasource.prepareStatement(conn, selectCertSql);
            } catch (DataAccessException ex) {
                datasource.returnConnection(conn);
                throw ex;
            }

        }

        @Override
        public void run() {
            while (!stopMe.stopMe()) {
                try {
                    IdRange idRange = inQueue.take();
                    query(idRange);
                } catch (InterruptedException ex) {
                }
            }

            releaseResources(selectCertStmt, null);
            datasource.returnConnection(conn);
            selectCertStmt = null;
        }

        private void query(
                final IdRange idRange) {
            DigestDbEntrySet result = new DigestDbEntrySet(idRange.getFrom());

            ResultSet rs = null;
            try {
                selectCertStmt.setInt(1, idRange.getFrom());
                selectCertStmt.setInt(2, idRange.getTo() + 1);

                rs = selectCertStmt.executeQuery();

                while (rs.next()) {
                    String hash = rs.getString(dbControl.getColCerthash());
                    long serial = rs.getLong(dbControl.getColSerialNumber());
                    boolean revoked = rs.getBoolean(dbControl.getColRevoked());

                    Integer revReason = null;
                    Long revTime = null;
                    Long revInvTime = null;

                    if (revoked) {
                        revReason = rs.getInt(dbControl.getColRevReason());
                        revTime = rs.getLong(dbControl.getColRevTime());
                        revInvTime = rs.getLong(dbControl.getColRevInvTime());
                        if (revInvTime == 0) {
                            revInvTime = null;
                        }
                    }

                    DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                            revInvTime, hash);
                    int id = rs.getInt("ID");
                    result.addEntry(new IdentifiedDbDigestEntry(cert, id));
                }
            } catch (Exception ex) {
                if (ex instanceof SQLException) {
                    ex = datasource.translate(selectCertSql, (SQLException) ex);
                }
                result.setException(ex);
            } finally {
                releaseResources(null, rs);
            }

            outQueue.add(result);
        } // method query

    } // class XipkiDbRetriever

    private void init(
            final DbSchemaType dbSchemaType,
            final int pCaId)
    throws Exception {
        this.caId = pCaId;
        this.conn = datasource.getConnection();
        this.dbControl = new XipkiDbControl(dbSchemaType);

        StringBuilder sb = new StringBuilder();
        sb.append("SELECT ID,");
        sb.append(dbControl.getColSerialNumber()).append(",");
        sb.append(dbControl.getColRevoked()).append(",");
        sb.append(dbControl.getColRevReason()).append(",");
        sb.append(dbControl.getColRevTime()).append(",");
        sb.append(dbControl.getColRevInvTime()).append(",");
        sb.append(dbControl.getColCerthash());
        sb.append(" FROM CERT INNER JOIN ").append(dbControl.getTblCerthash());
        sb.append(" ON CERT.").append(dbControl.getColCaId()).append("=").append(pCaId);
        sb.append(" AND CERT.ID>=? AND CERT.ID<?");

        if (revokedOnly) {
            sb.append(" AND CERT.").append(dbControl.getColRevoked()).append("=1");
        }

        sb.append(" AND CERT.ID=").append(dbControl.getTblCerthash())
            .append(".").append(dbControl.getColCertId());

        this.selectCertSql = sb.toString();

        this.numCertSql = "SELECT COUNT(*) FROM CERT WHERE CA_ID=" + pCaId + " AND ID>=? AND ID<=?";

        this.numCertStmt = datasource.prepareStatement(conn, this.numCertSql);

        if (!super.init()) {
            throw new Exception("could not initialize the EjbcaDigestReader");
        }
    }

    @Override
    protected int getNumSkippedCerts(
            final int fromId,
            final int toId,
            final int numCerts)
    throws DataAccessException {
        if (fromId > toId) {
            return 0;
        }

        ResultSet rs = null;
        try {
            numCertStmt.setInt(1, fromId);
            numCertStmt.setInt(2, toId);
            rs = numCertStmt.executeQuery();
            int n = rs.next()
                    ? rs.getInt(1)
                    : 0;
            return (n < numCerts)
                    ? n - numCerts
                    : 0;
        } catch (SQLException ex) {
            throw datasource.translate(numCertSql, ex);
        } finally {
            releaseResources(null, rs);
        }
    } // method getNumSkippedCerts

    public void close() {
        super.close();

        releaseResources(numCertStmt, null);
        datasource.returnConnection(conn);
    }

    public int getCaId() {
        return caId;
    }

    @Override
    protected Retriever getRetriever()
    throws DataAccessException {
        return new XipkiDbRetriever();
    }

    public static XipkiDbDigestReader getInstance(
            final DataSourceWrapper datasource,
            final DbSchemaType dbSchemaType,
            final int caId,
            final boolean revokedOnly,
            final int numThreads,
            final int numCertsToPredicate,
            final StopMe stopMe)
    throws Exception {
        ParamUtil.requireNonNull("datasource", datasource);

        Connection conn = datasource.getConnection();

        XipkiDbControl dbControl = new XipkiDbControl(dbSchemaType);

        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;

        X509Certificate caCert;
        int totalAccount;
        int minId;
        int maxId;

        try {
            stmt = datasource.createStatement(conn);

            sql = "SELECT CERT FROM " + dbControl.getTblCa() + " WHERE ID=" + caId;
            rs = stmt.executeQuery(sql);
            if (!rs.next()) {
                throw new IllegalArgumentException("no CA with id '" + caId + "' is available");
            }

            caCert = X509Util.parseBase64EncodedCert(rs.getString("CERT"));
            rs.close();

            sql = "SELECT COUNT(*) FROM CERT WHERE " + dbControl.getColCaId() + "=" + caId;
            if (revokedOnly) {
                sql += " AND " + dbControl.getColRevoked() + "=1";
            }
            rs = stmt.executeQuery(sql);

            totalAccount = rs.next()
                    ? rs.getInt(1)
                    : 0;
            rs.close();

            sql = "SELECT MAX(ID) FROM CERT WHERE " + dbControl.getColCaId() + "=" + caId;
            if (revokedOnly) {
                sql += " AND " + dbControl.getColRevoked() + "=1";
            }

            rs = stmt.executeQuery(sql);
            maxId = rs.next()
                    ? rs.getInt(1)
                    : 0;
            rs.close();

            sql = "SELECT MIN(ID) FROM CERT WHERE " + dbControl.getColCaId() + "=" + caId;
            if (revokedOnly) {
                sql += " AND " + dbControl.getColRevoked() + "=1";
            }

            rs = stmt.executeQuery(sql);
            minId = rs.next()
                    ? rs.getInt(1)
                    : 1;

            XipkiDbDigestReader reader = new XipkiDbDigestReader(datasource, caCert, revokedOnly,
                    totalAccount, minId, maxId, numThreads, numCertsToPredicate, stopMe);
            reader.init(dbSchemaType, caId);
            return reader;
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            releaseResources(stmt, rs);
        }
    } // method getInstance

}
