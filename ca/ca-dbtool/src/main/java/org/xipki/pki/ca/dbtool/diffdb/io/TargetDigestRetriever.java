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

package org.xipki.pki.ca.dbtool.diffdb.io;

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

import org.xipki.commons.common.ProcessLog;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.DatabaseType;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.pki.ca.dbtool.StopMe;
import org.xipki.pki.ca.dbtool.diffdb.DbDigestReporter;
import org.xipki.pki.ca.dbtool.diffdb.DigestReader;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class TargetDigestRetriever {

    private class Retriever implements Runnable {

        private Connection conn;

        private PreparedStatement singleSelectStmt;

        private PreparedStatement inArraySelectStmt;

        private PreparedStatement rangeSelectStmt;

        Retriever()
        throws DataAccessException {
            conn = datasource.getConnection();

            try {
                singleSelectStmt = datasource.prepareStatement(conn, singleCertSql);
                inArraySelectStmt = datasource.prepareStatement(conn, inArrayCertsSql);
                rangeSelectStmt = datasource.prepareStatement(conn, rangeCertsSql);
            } catch (DataAccessException ex) {
                releaseResources(singleSelectStmt, null);
                releaseResources(inArraySelectStmt, null);
                releaseResources(rangeSelectStmt, null);
                datasource.returnConnection(conn);
                throw ex;
            }
        }

        @Override
        public void run() {
            while (!stopMe.stopMe()) {
                CertsBundle bundle = null;
                try {
                    bundle = reader.nextCerts(numPerSelect);
                } catch (Exception ex) {
                    exception = ex;
                    break;
                }

                if (bundle == null) {
                    break;
                }

                try {
                    Map<Long, DbDigestEntry> refCerts = bundle.getCerts();
                    Map<Long, DbDigestEntry> resp = query(bundle);

                    List<Long> serialNumbers = bundle.getSerialNumbers();
                    int n = serialNumbers.size();

                    for (Long serialNumber : serialNumbers) {
                        DbDigestEntry targetCert = resp.get(serialNumber);

                        if (targetCert != null) {
                            DbDigestEntry refCert = refCerts.get(serialNumber);
                            if (refCert.contentEquals(targetCert)) {
                                reporter.addGood(serialNumber);
                            } else {
                                reporter.addDiff(refCert, targetCert);
                            }
                        } else {
                            reporter.addMissing(serialNumber);
                        }
                    }
                    processLog.addNumProcessed(n);
                    processLog.printStatus();
                } catch (Exception ex) {
                    exception = ex;
                    break;
                }
            }

            releaseResources(singleSelectStmt, null);
            releaseResources(inArraySelectStmt, null);
            releaseResources(rangeSelectStmt, null);
            datasource.returnConnection(conn);
        } // method run

        private Map<Long, DbDigestEntry> query(CertsBundle bundle)
        throws DataAccessException {
            List<Long> serialNumbers = bundle.getSerialNumbers();
            int n = serialNumbers.size();

            int numSkipped = bundle.getNumSkipped();
            long minSerialNumber = serialNumbers.get(0);
            long maxSerialNumber = serialNumbers.get(0);
            for (Long m : serialNumbers) {
                if (minSerialNumber > m) {
                    minSerialNumber = m;
                }
                if (maxSerialNumber < m) {
                    maxSerialNumber = m;
                }
            }

            Map<Long, DbDigestEntry> certsInB;
            long serialDiff = maxSerialNumber - minSerialNumber;

            if (serialDiff < (numSkipped + numPerSelect) * 2) {
                ResultSet rs = null;
                try {
                    rangeSelectStmt.setLong(1, minSerialNumber);
                    rangeSelectStmt.setLong(2, maxSerialNumber);
                    rs = rangeSelectStmt.executeQuery();

                    certsInB = buildResult(rs, serialNumbers);
                } catch (SQLException ex) {
                    throw datasource.translate(inArrayCertsSql, ex);
                } finally {
                    releaseResources(null, rs);
                }
            } else {
                boolean batchSupported = datasource.getDatabaseType() != DatabaseType.H2;
                if (batchSupported && n == numPerSelect) {
                    certsInB = getCertsViaInArraySelectInB(inArraySelectStmt,
                            serialNumbers);
                } else {
                    certsInB = getCertsViaSingleSelectInB(
                            singleSelectStmt, serialNumbers);
                }
            }

            return certsInB;
        } // method query

    } // class Retriever

    private final XipkiDbControl dbControl;

    private final DataSourceWrapper datasource;

    private final int numPerSelect;

    private final String singleCertSql;

    private final String inArrayCertsSql;

    private final String rangeCertsSql;

    private final StopMe stopMe;

    private Exception exception;

    private ExecutorService executor;

    private final DigestReader reader;

    private final DbDigestReporter reporter;

    private final ProcessLog processLog;

    private final List<Retriever> retrievers;

    public TargetDigestRetriever(
            final ProcessLog processLog,
            final DigestReader reader,
            final DbDigestReporter reporter,
            final DataSourceWrapper datasource,
            final XipkiDbControl dbControl,
            final int caId,
            final int numPerSelect,
            final int numThreads,
            final StopMe stopMe)
    throws DataAccessException {
        this.processLog = processLog;
        this.numPerSelect = numPerSelect;
        this.datasource = datasource;
        this.dbControl = dbControl;
        this.reader = reader;
        this.reporter = reporter;
        this.stopMe = stopMe;

        StringBuilder buffer = new StringBuilder(200);
        buffer.append(dbControl.getColRevoked()).append(',');
        buffer.append(dbControl.getColRevReason()).append(',');
        buffer.append(dbControl.getColRevTime()).append(',');
        buffer.append(dbControl.getColRevInvTime()).append(',');
        buffer.append(dbControl.getColCerthash());
        buffer.append(" FROM CERT INNER JOIN ").append(dbControl.getTblCerthash());
        buffer.append(" ON CERT.").append(dbControl.getColCaId()).append('=').append(caId);
        buffer.append(" AND CERT.").append(dbControl.getColSerialNumber()).append("=?");
        buffer.append(" AND CERT.ID=").append(dbControl.getTblCerthash()).append('.');
        buffer.append(dbControl.getColCertId());

        singleCertSql = datasource.createFetchFirstSelectSQL(buffer.toString(), 1);

        buffer = new StringBuilder(200);
        buffer.append(dbControl.getColSerialNumber()).append(',');
        buffer.append(dbControl.getColRevoked()).append(',');
        buffer.append(dbControl.getColRevReason()).append(',');
        buffer.append(dbControl.getColRevTime()).append(',');
        buffer.append(dbControl.getColRevInvTime()).append(',');
        buffer.append(dbControl.getColCerthash());
        buffer.append(" FROM CERT INNER JOIN ").append(dbControl.getTblCerthash());
        buffer.append(" ON CERT.").append(dbControl.getColCaId()).append('=').append(caId);
        buffer.append(" AND CERT.").append(dbControl.getColSerialNumber()).append(" IN (?");
        for (int i = 1; i < numPerSelect; i++) {
            buffer.append(",?");
        }
        buffer.append(") AND CERT.ID=").append(dbControl.getTblCerthash());
        buffer.append(".").append(dbControl.getColCertId());

        inArrayCertsSql = datasource.createFetchFirstSelectSQL(buffer.toString(), numPerSelect);

        buffer = new StringBuilder(200);
        buffer.append("SELECT ");
        buffer.append(dbControl.getColSerialNumber()).append(',');
        buffer.append(dbControl.getColRevoked()).append(',');
        buffer.append(dbControl.getColRevReason()).append(',');
        buffer.append(dbControl.getColRevTime()).append(',');
        buffer.append(dbControl.getColRevInvTime()).append(',');
        buffer.append(dbControl.getColCerthash());
        buffer.append(" FROM CERT INNER JOIN ").append(dbControl.getTblCerthash());
        buffer.append(" ON CERT.").append(dbControl.getColCaId()).append("=").append(caId);
        buffer.append(" AND CERT.").append(dbControl.getColSerialNumber()).append(">=?");
        buffer.append(" AND CERT.").append(dbControl.getColSerialNumber()).append("<=?");
        buffer.append(" AND CERT.ID=").append(dbControl.getTblCerthash()).append(".");
        buffer.append(dbControl.getColCertId());

        rangeCertsSql = buffer.toString();

        retrievers = new ArrayList<>(numThreads);

        try {
            for (int i = 0; i < numThreads; i++) {
                Retriever retriever = new Retriever();
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

    private Map<Long, DbDigestEntry> getCertsViaSingleSelectInB(
            final PreparedStatement singleSelectStmt,
            final List<Long> serialNumbers)
    throws DataAccessException {
        Map<Long, DbDigestEntry> ret = new HashMap<>(serialNumbers.size());

        for (Long serialNumber : serialNumbers) {
            DbDigestEntry certB = getSingleCert(singleSelectStmt, serialNumber);
            if (certB != null) {
                ret.put(serialNumber, certB);
            }
        }

        return ret;
    }

    private Map<Long, DbDigestEntry> getCertsViaInArraySelectInB(
            final PreparedStatement batchSelectStmt,
            final List<Long> serialNumbers)
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
                batchSelectStmt.setLong(i + 1, serialNumbers.get(i));
            }

            rs = batchSelectStmt.executeQuery();
            return buildResult(rs, serialNumbers);
        } catch (SQLException ex) {
            throw datasource.translate(inArrayCertsSql, ex);
        } finally {
            releaseResources(null, rs);
        }
    } // method getCertsViaInArraySelectInB

    private Map<Long, DbDigestEntry> buildResult(
            final ResultSet rs,
            final List<Long> serialNumbers)
    throws SQLException {
        Map<Long, DbDigestEntry> ret = new HashMap<>(serialNumbers.size());

        while (rs.next()) {
            long serialNumber = rs.getLong(dbControl.getColSerialNumber());
            if (!serialNumbers.contains(serialNumber)) {
                continue;
            }

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
            String sha1Fp = rs.getString(dbControl.getColCerthash());
            DbDigestEntry certB = new DbDigestEntry(serialNumber,
                    revoked, revReason, revTime, revInvTime, sha1Fp);
            ret.put(serialNumber, certB);
        }

        return ret;
    }

    private DbDigestEntry getSingleCert(
            final PreparedStatement singleSelectStmt,
            final long serialNumber)
    throws DataAccessException {
        ResultSet rs = null;
        try {
            singleSelectStmt.setLong(1, serialNumber);
            rs = singleSelectStmt.executeQuery();
            if (!rs.next()) {
                return null;
            }
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
            String sha1Fp = rs.getString(dbControl.getColCerthash());
            return new DbDigestEntry(serialNumber,
                    revoked, revReason, revTime, revInvTime, sha1Fp);
        } catch (SQLException ex) {
            throw datasource.translate(singleCertSql, ex);
        } finally {
            releaseResources(null, rs);
        }
    }

    private void releaseResources(
            final Statement ps,
            final ResultSet rs) {
        if (ps != null) {
            try {
                ps.close();
            } catch (Exception ex) {
            }
        }

        if (rs != null) {
            try {
                rs.close();
            } catch (Exception ex) {
            }
        }
    }

    public void awaitTerminiation()
    throws Exception {
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
