/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.dbtool.diffdb;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.DbToolBase;
import org.xipki.ca.dbtool.StopMe;
import org.xipki.ca.dbtool.diffdb.io.DbDigestEntry;
import org.xipki.ca.dbtool.diffdb.io.DbSchemaType;
import org.xipki.ca.dbtool.diffdb.io.DigestDbEntrySet;
import org.xipki.ca.dbtool.diffdb.io.IdentifiedDbDigestEntry;
import org.xipki.ca.dbtool.diffdb.io.XipkiDbControl;
import org.xipki.common.EndOfQueue;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XipkiDbDigestReader extends DbDigestReader {

    private static final Logger LOG = LoggerFactory.getLogger(XipkiDbDigestReader.class);

    private int caId;

    private XipkiDbControl dbControl;

    private Connection conn;

    private String selectCertSql;

    private class XipkiDbRetriever implements Retriever {

        private PreparedStatement selectCertStmt;
        private boolean endReached;

        XipkiDbRetriever() throws DataAccessException {
            try {
                selectCertStmt = datasource.prepareStatement(conn, selectCertSql);
            } catch (DataAccessException ex) {
                datasource.returnConnection(conn);
                throw ex;
            }

        }

        @Override
        public void run() {
            while (!endReached && !stopMe.stopMe()) {
                try {
                    query();
                } catch (InterruptedException ex) {
                    LOG.error("InterruptedException: {}", ex.getMessage());
                }
            }

            releaseResources(selectCertStmt, null);
            datasource.returnConnection(conn);
            selectCertStmt = null;
        }

        private void query() throws InterruptedException {
            long startId = lastProcessedId + 1;
            DigestDbEntrySet result = new DigestDbEntrySet(startId);

            ResultSet rs = null;
            try {
                selectCertStmt.setLong(1, startId);

                rs = selectCertStmt.executeQuery();

                while (rs.next()) {
                    long id = rs.getLong("ID");
                    if (lastProcessedId < id) {
                        lastProcessedId = id;
                    }

                    String hash = rs.getString(dbControl.colCerthash());
                    BigInteger serial = new BigInteger(rs.getString("SN"), 16);
                    boolean revoked = rs.getBoolean("REV");

                    Integer revReason = null;
                    Long revTime = null;
                    Long revInvTime = null;

                    if (revoked) {
                        revReason = rs.getInt("RR");
                        revTime = rs.getLong("RT");
                        revInvTime = rs.getLong("RIT");
                        if (revInvTime == 0) {
                            revInvTime = null;
                        }
                    }

                    DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                            revInvTime, hash);
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

            if (result.entries().isEmpty()) {
                endReached = true;
                outQueue.put(EndOfQueue.INSTANCE);
            } else {
                outQueue.put(result);
            }
        } // method query

    } // class XipkiDbRetriever

    private XipkiDbDigestReader(DataSourceWrapper datasource, X509Certificate caCert,
            int totalAccount, long minId, int numBlocksToRead, int numPerSelect, StopMe stopMe)
            throws Exception {
        super(datasource, caCert, totalAccount, minId, numBlocksToRead, stopMe);
    } // constructor

    private void init(DbSchemaType dbSchemaType, int caId, int numPerSelect) throws Exception {
        this.caId = caId;
        this.conn = datasource.getConnection();
        this.dbControl = new XipkiDbControl(dbSchemaType);

        StringBuilder sb = new StringBuilder();
        sb.append("ID,SN,REV,RR,RT,RIT,");
        sb.append(dbControl.colCerthash());
        sb.append(" FROM CERT INNER JOIN ").append(dbControl.tblCerthash());
        sb.append(" ON CERT.").append(dbControl.colCaId()).append("=").append(caId);
        sb.append(" AND CERT.ID>=? AND CERT.ID=").append(dbControl.tblCerthash()).append(".CID");

        this.selectCertSql = datasource.buildSelectFirstSql(numPerSelect, "ID ASC", sb.toString());

        if (!super.init()) {
            throw new Exception("could not initialize the " + this.getClass().getName());
        }
    }

    public int caId() {
        return caId;
    }

    @Override
    protected Retriever retriever() throws DataAccessException {
        return new XipkiDbRetriever();
    }

    public static XipkiDbDigestReader getInstance(DataSourceWrapper datasource,
            DbSchemaType dbSchemaType, int caId, int numBlocksToRead, int numPerSelect,
            StopMe stopMe) throws Exception {
        ParamUtil.requireNonNull("datasource", datasource);

        Connection conn = datasource.getConnection();

        XipkiDbControl dbControl = new XipkiDbControl(dbSchemaType);

        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;

        X509Certificate caCert;
        int totalAccount;
        long minId;

        try {
            stmt = datasource.createStatement(conn);

            sql = "SELECT CERT FROM " + dbControl.tblCa() + " WHERE ID=" + caId;
            rs = stmt.executeQuery(sql);
            if (!rs.next()) {
                throw new IllegalArgumentException("no CA with id '" + caId + "' is available");
            }

            caCert = X509Util.parseBase64EncodedCert(rs.getString("CERT"));
            rs.close();

            sql = "SELECT COUNT(*) FROM CERT WHERE " + dbControl.colCaId() + "=" + caId;
            rs = stmt.executeQuery(sql);

            totalAccount = rs.next() ? rs.getInt(1) : 0;
            rs.close();

            sql = "SELECT MIN(ID) FROM CERT WHERE " + dbControl.colCaId() + "=" + caId;
            rs = stmt.executeQuery(sql);
            minId = rs.next() ? rs.getLong(1) : 1;

            XipkiDbDigestReader reader = new XipkiDbDigestReader(datasource, caCert,
                    totalAccount, minId, numBlocksToRead, numPerSelect, stopMe);
            reader.init(dbSchemaType, caId, numPerSelect);
            return reader;
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            DbToolBase.releaseResources(datasource, stmt, rs);
        }
    } // method getInstance

}
