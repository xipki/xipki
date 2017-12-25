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

package org.xipki.ca.dbtool.diffdb.io;

import java.math.BigInteger;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.xipki.ca.dbtool.DbToolBase;
import org.xipki.ca.dbtool.StopMe;
import org.xipki.ca.dbtool.diffdb.DbDigestReporter;
import org.xipki.ca.dbtool.diffdb.DigestReader;
import org.xipki.common.ProcessLog;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.DatabaseType;
import org.xipki.datasource.springframework.dao.DataAccessException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class TargetDigestRetriever {

    private class Retriever implements Runnable {

        private final boolean revokedOnly;

        private Connection conn;

        private PreparedStatement singleSelectStmt;

        private PreparedStatement inArraySelectStmt;

        Retriever(final boolean revokedOnly) throws DataAccessException {
            this.revokedOnly = revokedOnly;
            conn = datasource.getConnection();

            try {
                singleSelectStmt = datasource.prepareStatement(conn, singleCertSql);
                inArraySelectStmt = datasource.prepareStatement(conn, inArrayCertsSql);
            } catch (DataAccessException ex) {
                releaseResources(singleSelectStmt, null);
                releaseResources(inArraySelectStmt, null);
                datasource.returnConnection(conn);
                throw ex;
            }
        }

        @Override
        public void run() {
            while (!stopMe.stopMe()) {
                CertsBundle bundle = null;
                try {
                    bundle = reader.nextCerts();
                } catch (Exception ex) {
                    exception = ex;
                    break;
                }

                if (bundle == null) {
                    break;
                }

                try {
                    Map<BigInteger, DbDigestEntry> refCerts = bundle.certs();
                    Map<BigInteger, DbDigestEntry> resp = query(bundle);

                    List<BigInteger> serialNumbers = bundle.serialNumbers();
                    int size = serialNumbers.size();

                    for (BigInteger serialNumber : serialNumbers) {
                        DbDigestEntry refCert = refCerts.get(serialNumber);
                        DbDigestEntry targetCert = resp.get(serialNumber);

                        if (revokedOnly) {
                            if (!refCert.isRevoked() && targetCert != null) {
                                reporter.addUnexpected(serialNumber);
                                continue;
                            }
                        }

                        if (targetCert != null) {
                            if (refCert.contentEquals(targetCert)) {
                                reporter.addGood(serialNumber);
                            } else {
                                reporter.addDiff(refCert, targetCert);
                            }
                        } else {
                            reporter.addMissing(serialNumber);
                        }
                    }
                    processLog.addNumProcessed(size);
                    processLog.printStatus();
                } catch (Exception ex) {
                    exception = ex;
                    break;
                }
            }

            releaseResources(singleSelectStmt, null);
            releaseResources(inArraySelectStmt, null);
            datasource.returnConnection(conn);
        } // method run

        private Map<BigInteger, DbDigestEntry> query(CertsBundle bundle)
            throws DataAccessException {
            List<BigInteger> serialNumbers = bundle.serialNumbers();
            int size = serialNumbers.size();
            boolean batchSupported = datasource.databaseType() != DatabaseType.H2;

            return (batchSupported && size == numPerSelect)
                ? getCertsViaInArraySelectInB(inArraySelectStmt, serialNumbers)
                : getCertsViaSingleSelectInB(singleSelectStmt, serialNumbers);
        } // method query

    } // class Retriever

    private final XipkiDbControl dbControl;

    private final DataSourceWrapper datasource;

    private final int numPerSelect;

    private final String singleCertSql;

    private final String inArrayCertsSql;

    private final StopMe stopMe;

    private Exception exception;

    private ExecutorService executor;

    private final DigestReader reader;

    private final DbDigestReporter reporter;

    private final ProcessLog processLog;

    private final List<Retriever> retrievers;

    public TargetDigestRetriever(final boolean revokedOnly, final ProcessLog processLog,
            final DigestReader reader, final DbDigestReporter reporter,
            final DataSourceWrapper datasource, final XipkiDbControl dbControl, final int caId,
            final int numPerSelect, final int numThreads, final StopMe stopMe)
            throws DataAccessException {
        this.processLog = ParamUtil.requireNonNull("processLog", processLog);
        this.numPerSelect = numPerSelect;
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);
        this.dbControl = ParamUtil.requireNonNull("dbControl", dbControl);
        this.reader = ParamUtil.requireNonNull("reader", reader);
        this.reporter = ParamUtil.requireNonNull("reporter", reporter);
        this.stopMe = ParamUtil.requireNonNull("stopMe", stopMe);

        StringBuilder buffer = new StringBuilder(200);
        buffer.append("REV,RR,RT,RIT,");
        buffer.append(dbControl.colCerthash());
        buffer.append(" FROM CERT INNER JOIN ").append(dbControl.tblCerthash());
        buffer.append(" ON CERT.").append(dbControl.colCaId()).append('=').append(caId);
        buffer.append(" AND CERT.SN=?");
        buffer.append(" AND CERT.ID=").append(dbControl.tblCerthash()).append(".CID");

        singleCertSql = datasource.buildSelectFirstSql(1, buffer.toString());

        buffer = new StringBuilder(200);
        buffer.append("SN,REV,RR,RT,RIT,");
        buffer.append(dbControl.colCerthash());
        buffer.append(" FROM CERT INNER JOIN ").append(dbControl.tblCerthash());
        buffer.append(" ON CERT.").append(dbControl.colCaId()).append('=').append(caId);
        buffer.append(" AND CERT.SN IN (?");
        for (int i = 1; i < numPerSelect; i++) {
            buffer.append(",?");
        }
        buffer.append(") AND CERT.ID=").append(dbControl.tblCerthash());
        buffer.append(".CID");
        inArrayCertsSql = datasource.buildSelectFirstSql(numPerSelect, buffer.toString());

        retrievers = new ArrayList<>(numThreads);

        try {
            for (int i = 0; i < numThreads; i++) {
                Retriever retriever = new Retriever(revokedOnly);
                retrievers.add(retriever);
            }

            executor = Executors.newFixedThreadPool(numThreads);
            for (Runnable runnable : retrievers) {
                executor.execute(runnable);
            }
        } catch (Exception ex) {
            close();
            throw ex;
        }
    } // constructor

    public void close() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    private Map<BigInteger, DbDigestEntry> getCertsViaSingleSelectInB(
            final PreparedStatement singleSelectStmt, final List<BigInteger> serialNumbers)
            throws DataAccessException {
        Map<BigInteger, DbDigestEntry> ret = new HashMap<>(serialNumbers.size());

        for (BigInteger serialNumber : serialNumbers) {
            DbDigestEntry certB = getSingleCert(singleSelectStmt, serialNumber);
            if (certB != null) {
                ret.put(serialNumber, certB);
            }
        }

        return ret;
    }

    private Map<BigInteger, DbDigestEntry> getCertsViaInArraySelectInB(
            final PreparedStatement batchSelectStmt, final List<BigInteger> serialNumbers)
            throws DataAccessException {
        final int n = serialNumbers.size();
        if (n != numPerSelect) {
            throw new IllegalArgumentException("size of serialNumbers is not '" + numPerSelect
                    + "': " + n);
        }

        Collections.sort(serialNumbers);
        ResultSet rs = null;

        try {
            for (int i = 0; i < n; i++) {
                batchSelectStmt.setString(i + 1, serialNumbers.get(i).toString(16));
            }

            rs = batchSelectStmt.executeQuery();
            return buildResult(rs, serialNumbers);
        } catch (SQLException ex) {
            throw datasource.translate(inArrayCertsSql, ex);
        } finally {
            releaseResources(null, rs);
        }
    }

    private Map<BigInteger, DbDigestEntry> buildResult(final ResultSet rs,
            final List<BigInteger> serialNumbers) throws SQLException {
        Map<BigInteger, DbDigestEntry> ret = new HashMap<>(serialNumbers.size());

        while (rs.next()) {
            BigInteger serialNumber = new BigInteger(rs.getString("SN"),
                    16);
            if (!serialNumbers.contains(serialNumber)) {
                continue;
            }

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
            String sha1Fp = rs.getString(dbControl.colCerthash());
            DbDigestEntry certB = new DbDigestEntry(serialNumber, revoked, revReason, revTime,
                    revInvTime, sha1Fp);
            ret.put(serialNumber, certB);
        }

        return ret;
    }

    private DbDigestEntry getSingleCert(final PreparedStatement singleSelectStmt,
            final BigInteger serialNumber) throws DataAccessException {
        ResultSet rs = null;
        try {
            singleSelectStmt.setString(1, serialNumber.toString(16));
            rs = singleSelectStmt.executeQuery();
            if (!rs.next()) {
                return null;
            }
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
            String sha1Fp = rs.getString(dbControl.colCerthash());
            return new DbDigestEntry(serialNumber, revoked, revReason, revTime, revInvTime, sha1Fp);
        } catch (SQLException ex) {
            throw datasource.translate(singleCertSql, ex);
        } finally {
            releaseResources(null, rs);
        }
    }

    private void releaseResources(final Statement ps, final ResultSet rs) {
        DbToolBase.releaseResources(datasource, ps, rs);
    }

    public void awaitTerminiation() throws Exception {
        executor.shutdown();

        while (!executor.awaitTermination(1000, TimeUnit.MILLISECONDS)) {
            if (exception != null) {
                throw exception;
            }
        }

        if (exception != null) {
            throw exception;
        }
    }

}
