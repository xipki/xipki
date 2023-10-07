// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.diffdb;

import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.HashAlgo;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.ProcessLog;
import org.xipki.util.StringUtil;

import java.io.Closeable;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Reader of certificate information for the comparison from the target database.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class TargetDigestReader implements Closeable {

  private class Retriever implements Runnable {

    private final boolean revokedOnly;

    private final Connection conn;

    private PreparedStatement singleSelectStmt;

    private PreparedStatement inArraySelectStmt;

    Retriever(boolean revokedOnly) throws DataAccessException {
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
    } // constructor

    @Override
    public void run() {
      while (!stopMe.get()) {
        CertsBundle bundle;
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
          Map<BigInteger, DigestEntry> refCerts = bundle.getCerts();
          Map<BigInteger, DigestEntry> resp = query(bundle);

          List<BigInteger> serialNumbers = bundle.getSerialNumbers();
          int size = serialNumbers.size();

          for (BigInteger serialNumber : serialNumbers) {
            DigestEntry refCert = refCerts.get(serialNumber);
            DigestEntry targetCert = resp.get(serialNumber);

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

    private Map<BigInteger, DigestEntry> query(CertsBundle bundle)
        throws DataAccessException {
      List<BigInteger> serialNumbers = bundle.getSerialNumbers();
      int size = serialNumbers.size();

      return (datasource.getDatabaseType().supportsInArray() && size == numPerSelect)
        ? getCertsViaInArraySelect(inArraySelectStmt, serialNumbers)
        : getCertsViaSingleSelect(singleSelectStmt, serialNumbers);
    } // method query

  } // class Retriever

  private final DbType dbType;

  private final HashAlgo certhashAlgo;

  private final DataSourceWrapper datasource;

  private final int numPerSelect;

  private final String singleCertSql;

  private final String inArrayCertsSql;

  private final AtomicBoolean stopMe;

  private Exception exception;

  private final ExecutorService executor;

  private final RefDigestReader reader;

  private final DigestDiffReporter reporter;

  private final ProcessLog processLog;

  public TargetDigestReader(boolean revokedOnly, ProcessLog processLog, RefDigestReader reader,
      DigestDiffReporter reporter, DataSourceWrapper datasource, DbType dbType,
      HashAlgo certHashAlgo, int caId, int numPerSelect, int numThreads, AtomicBoolean stopMe)
      throws DataAccessException {
    this.processLog = Args.notNull(processLog, "processLog");
    this.numPerSelect = numPerSelect;
    this.dbType = Args.notNull(dbType, "dbControl");
    this.reader = Args.notNull(reader, "reader");
    this.reporter = Args.notNull(reporter, "reporter");
    this.stopMe = Args.notNull(stopMe, "stopMe");
    this.datasource = Args.notNull(datasource, "datasource");
    this.certhashAlgo = Args.notNull(certHashAlgo, "certhashAlgo");

    if (dbType == DbType.XIPKI_OCSP_v4) {
      String certHashAlgoInDb = datasource.getFirstStringValue(
          null, "DBSCHEMA", "VALUE2", "NAME='CERTHASH_ALGO'");
      HashAlgo ha;
      try {
        ha = HashAlgo.getInstance(certHashAlgoInDb);
      } catch (NoSuchAlgorithmException ex) {
        throw new IllegalArgumentException(ex);
      }

      if (certHashAlgo != ha) {
        throw new IllegalArgumentException("certHashAlgo in parameter (" + certHashAlgo
            + ") != in DB (" + certHashAlgoInDb + ")");
      }
    }

    String singleSql;
    StringBuilder arrayBuffer = new StringBuilder(200);

    if (dbType == DbType.XIPKI_OCSP_v4) {
      singleSql = StringUtil.concat("REV,RR,RT,RIT,HASH FROM CERT WHERE IID=", Integer.toString(caId), " AND SN=?");
      arrayBuffer.append("SN,REV,RR,RT,RIT,HASH FROM CERT WHERE IID=").append(caId).append(" AND SN IN (?");
      arrayBuffer.append(",?".repeat(Math.max(0, numPerSelect - 1)));
      arrayBuffer.append(")");
    } else {
      String hashOrCertColumn;
      if (certHashAlgo == HashAlgo.SHA1) {
        hashOrCertColumn = "SHA1";
      } else {
        hashOrCertColumn = "CERT";
      }

      singleSql = StringUtil.concat("REV,RR,RT,RIT,", hashOrCertColumn,
          " FROM CERT WHERE CA_ID=", Integer.toString(caId), " AND SN=?");

      arrayBuffer.append("SN,REV,RR,RT,RIT,").append(hashOrCertColumn)
          .append(" FROM CERT WHERE CA_ID=").append(caId).append(" AND SN IN (?");

      arrayBuffer.append(",?".repeat(Math.max(0, numPerSelect - 1)));
      arrayBuffer.append(")");
    }

    singleCertSql = datasource.buildSelectFirstSql(1, singleSql);
    inArrayCertsSql = datasource.buildSelectFirstSql(numPerSelect, arrayBuffer.toString());

    List<Retriever> retrievers = new ArrayList<>(numThreads);

    try {
      for (int i = 0; i < numThreads; i++) {
        Retriever retriever = new Retriever(revokedOnly);
        retrievers.add(retriever);
      }

      executor = Executors.newFixedThreadPool(numThreads);
      for (Retriever retriever : retrievers) {
        executor.execute(retriever);
      }
    } catch (Exception ex) {
      close();
      throw ex;
    }
  } // constructor

  @Override
  public final void close() {
    if (executor != null) {
      executor.shutdownNow();
    }
  }

  private Map<BigInteger, DigestEntry> getCertsViaSingleSelect(
      PreparedStatement singleSelectStmt, List<BigInteger> serialNumbers)
      throws DataAccessException {
    Map<BigInteger, DigestEntry> ret = new HashMap<>(serialNumbers.size());

    for (BigInteger serialNumber : serialNumbers) {
      DigestEntry certB = getSingleCert(singleSelectStmt, serialNumber);
      if (certB != null) {
        ret.put(serialNumber, certB);
      }
    }

    return ret;
  } // method getCertsViaSingleSelect

  private Map<BigInteger, DigestEntry> getCertsViaInArraySelect(
      PreparedStatement batchSelectStmt, List<BigInteger> serialNumbers)
      throws DataAccessException {
    final int n = serialNumbers.size();
    if (n != numPerSelect) {
      throw new IllegalArgumentException("size of serialNumbers is not '" + numPerSelect + "': " + n);
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
  } // method getCertsViaInArraySelect

  private Map<BigInteger, DigestEntry> buildResult(ResultSet rs, List<BigInteger> serialNumbers)
      throws SQLException {
    Map<BigInteger, DigestEntry> ret = new HashMap<>(serialNumbers.size());

    while (rs.next()) {
      BigInteger serialNumber = new BigInteger(rs.getString("SN"), 16);
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

      String base64Certhash = getBase64HashValue(rs);
      DigestEntry certB = new DigestEntry(serialNumber, revoked, revReason, revTime, revInvTime, base64Certhash);
      ret.put(serialNumber, certB);
    }

    return ret;
  } // method buildResult

  private DigestEntry getSingleCert(PreparedStatement singleSelectStmt, BigInteger serialNumber)
      throws DataAccessException {
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
      return new DigestEntry(serialNumber, revoked, revReason, revTime, revInvTime, getBase64HashValue(rs));
    } catch (SQLException ex) {
      throw datasource.translate(singleCertSql, ex);
    } finally {
      releaseResources(null, rs);
    }
  } // method getSingleCert

  private void releaseResources(PreparedStatement ps, ResultSet rs) {
    datasource.releaseResources(ps, rs);
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
  } // method awaitTerminiation

  private String getBase64HashValue(ResultSet rs) throws SQLException {
    if (dbType == DbType.XIPKI_OCSP_v4) {
      return rs.getString("HASH");
    }
    if (certhashAlgo == HashAlgo.SHA1) {
      return rs.getString("SHA1");
    } else {
      byte[] encodedCert = Base64.decodeFast(rs.getString("CERT"));
      return certhashAlgo.base64Hash(encodedCert);
    }
  } // method getBase64HashValue
}
