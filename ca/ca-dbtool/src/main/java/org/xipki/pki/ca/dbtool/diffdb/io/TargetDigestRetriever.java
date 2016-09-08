/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.dbtool.diffdb.io;

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

import org.xipki.commons.common.ProcessLog;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.DataSourceWrapper;
import org.xipki.commons.datasource.DatabaseType;
import org.xipki.commons.datasource.springframework.dao.DataAccessException;
import org.xipki.pki.ca.dbtool.DbToolBase;
import org.xipki.pki.ca.dbtool.StopMe;
import org.xipki.pki.ca.dbtool.diffdb.DbDigestReporter;
import org.xipki.pki.ca.dbtool.diffdb.DigestReader;

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
                    Map<BigInteger, DbDigestEntry> refCerts = bundle.getCerts();
                    Map<BigInteger, DbDigestEntry> resp = query(bundle);

                    List<BigInteger> serialNumbers = bundle.getSerialNumbers();
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
            List<BigInteger> serialNumbers = bundle.getSerialNumbers();
            int size = serialNumbers.size();
            boolean batchSupported = datasource.getDatabaseType() != DatabaseType.H2;

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
        buffer.append(dbControl.getColCerthash());
        buffer.append(" FROM CERT INNER JOIN ").append(dbControl.getTblCerthash());
        buffer.append(" ON CERT.").append(dbControl.getColCaId()).append('=').append(caId);
        buffer.append(" AND CERT.SN=?");
        buffer.append(" AND CERT.ID=").append(dbControl.getTblCerthash()).append(".CID");

        singleCertSql = datasource.buildSelectFirstSql(buffer.toString(), 1);

        buffer = new StringBuilder(200);
        buffer.append("SN,REV,RR,RT,RIT,");
        buffer.append(dbControl.getColCerthash());
        buffer.append(" FROM CERT INNER JOIN ").append(dbControl.getTblCerthash());
        buffer.append(" ON CERT.").append(dbControl.getColCaId()).append('=').append(caId);
        buffer.append(" AND CERT.SN IN (?");
        for (int i = 1; i < numPerSelect; i++) {
            buffer.append(",?");
        }
        buffer.append(") AND CERT.ID=").append(dbControl.getTblCerthash());
        buffer.append(".CID");
        inArrayCertsSql = datasource.buildSelectFirstSql(buffer.toString(), numPerSelect);

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
            String sha1Fp = rs.getString(dbControl.getColCerthash());
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
            String sha1Fp = rs.getString(dbControl.getColCerthash());
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
