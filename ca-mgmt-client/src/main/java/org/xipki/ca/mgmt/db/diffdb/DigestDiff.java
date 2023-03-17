// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.diffdb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.ProcessLog;
import org.xipki.util.StringUtil;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Compare content of two databases.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class DigestDiff {

  private static final Logger LOG = LoggerFactory.getLogger(DigestDiff.class);

  private final DataSourceWrapper refDatasource;

  private final boolean revokedOnly;

  private final DataSourceWrapper targetDatasource;

  private final DbType refDbType;

  private final DbType targetDbType;

  private final HashAlgo certhashAlgo;

  private Set<byte[]> includeCaCerts;

  private final String reportDirName;

  private final AtomicBoolean stopMe;

  private final int numPerSelect;

  private final int numTargetThreads;

  public DigestDiff(
      DataSourceWrapper refDatasource, DataSourceWrapper targetDatasource, String reportDirName,
      boolean revokedOnly, AtomicBoolean stopMe, int numPerSelect, int numThreads)
      throws DataAccessException {
    this.refDatasource = Args.notNull(refDatasource, "refDatasource");
    this.revokedOnly = revokedOnly;
    this.targetDatasource = Args.notNull(targetDatasource, "targetDatasource");
    this.reportDirName = Args.notNull(reportDirName, "reportDirName");
    this.stopMe = Args.notNull(stopMe, "stopMe");
    this.numPerSelect = Args.positive(numPerSelect, "numPerSelect");

    this.refDbType = detectDbType(refDatasource);
    this.targetDbType = detectDbType(targetDatasource);

    if (refDbType == DbType.XIPKI_OCSP_v4) {
      HashAlgo refAlgo = detectOcspDbCerthashAlgo(refDatasource);
      HashAlgo targetAlgo = detectOcspDbCerthashAlgo(targetDatasource);
      if (refAlgo != targetAlgo) {
        throw new IllegalArgumentException(StringUtil.concatObjects(
            "Could not compare OCSP datasources with different CERTHASH_ALGO: refDataSource (",
            refAlgo, ") and targetDataSource (", targetAlgo, ")"));
      }
      this.certhashAlgo = refAlgo;
    } else {
      this.certhashAlgo = HashAlgo.SHA1;
    }

    // number of threads
    this.numTargetThreads = Math.min(numThreads, targetDatasource.getMaximumPoolSize() - 1);

    if (this.numTargetThreads != numThreads) {
      LOG.info("reduce the numTargetThreads from {} to {}", numTargetThreads, this.numTargetThreads);
    }
  } // constructor

  public Set<byte[]> isIncludeCaCerts() {
    return includeCaCerts;
  }

  public void setIncludeCaCerts(Set<byte[]> includeCaCerts) {
    this.includeCaCerts = includeCaCerts;
  }

  public void diff() throws Exception {
    Map<Integer, byte[]> caIdCertMap = getCas(targetDatasource, targetDbType);

    List<Integer> refCaIds = new LinkedList<>();

    String refSql = (refDbType == DbType.XIPKI_OCSP_v4) ? "SELECT ID FROM ISSUER" : "SELECT ID FROM CA";

    Statement refStmt = null;
    try {
      refStmt = refDatasource.createStatement();
      ResultSet refRs = null;
      try {
        refRs = refStmt.executeQuery(refSql);
        while (refRs.next()) {
          int id = refRs.getInt(1);
          refCaIds.add(id);
        }
      } catch (SQLException ex) {
        throw refDatasource.translate(refSql, ex);
      } finally {
        refDatasource.releaseResources(refStmt, refRs);
      }
    } finally {
      refDatasource.releaseResources(refStmt, null);
    }

    final int numBlocksToRead = numTargetThreads * 3 / 2;
    for (Integer refCaId : refCaIds) {
      RefDigestReader refReader = RefDigestReader.getInstance(refDatasource, refDbType,
          certhashAlgo, refCaId, numBlocksToRead, numPerSelect, stopMe);
      diffSingleCa(refReader, caIdCertMap);
    }
  } // method diff

  private void diffSingleCa(RefDigestReader refReader, Map<Integer, byte[]> caIdCertBytesMap)
      throws IOException, InterruptedException {
    X509Cert caCert = refReader.getCaCert();
    byte[] caCertBytes = caCert.getEncoded();

    if (includeCaCerts != null && !includeCaCerts.isEmpty()) {
      boolean include = false;
      for (byte[] m : includeCaCerts) {
        if (Arrays.equals(m, caCertBytes)) {
          include = true;
          break;
        }
      }
      if (!include) {
        System.out.println("skipped CA " + refReader.getCaSubjectName());
      }
    }

    String commonName = caCert.getCommonName();
    File caReportDir = new File(reportDirName, "ca-" + commonName);

    int idx = 2;
    while (caReportDir.exists()) {
      caReportDir = new File(reportDirName, "ca-" + commonName + "-" + (idx++));
    }

    DigestDiffReporter reporter = new DigestDiffReporter(caReportDir.getPath(), caCertBytes);

    Integer caId = null;
    for (Entry<Integer, byte[]> entry : caIdCertBytesMap.entrySet()) {
      if (Arrays.equals(caCertBytes, entry.getValue())) {
        caId = entry.getKey();
      }
    }

    if (caId == null) {
      reporter.addNoCaMatch();
      refReader.close();
      reporter.close();
      return;
    }

    TargetDigestReader target = null;

    try {
      reporter.start();
      ProcessLog processLog = new ProcessLog(refReader.getTotalAccount());
      System.out.println("Processing certificates of CA \n\t'" + refReader.getCaSubjectName() + "'");
      processLog.printHeader();

      target = new TargetDigestReader(revokedOnly, processLog, refReader, reporter,
          targetDatasource, targetDbType, certhashAlgo, caId, numPerSelect, numTargetThreads, stopMe);

      target.awaitTerminiation();
      processLog.printTrailer();
    } catch (InterruptedException ex) {
      throw ex;
    } catch (Exception ex) {
      reporter.addError("Exception thrown: " + ex.getClass().getName() + ": " + ex.getMessage());
      LOG.error("exception in diffSingleCa", ex);
    } finally {
      reporter.close();
      refReader.close();
      if (target != null) {
        target.close();
      }
    }
  } // method diffSingleCa

  private static Map<Integer, byte[]> getCas(DataSourceWrapper datasource, DbType dbType)
      throws DataAccessException {
    // get a list of available CAs in the target database
    String sql = "SELECT ID,CERT FROM " + (dbType == DbType.XIPKI_OCSP_v4 ? "ISSUER" : "CA");

    Statement stmt = datasource.createStatement();
    Map<Integer, byte[]> caIdCertMap = new HashMap<>(5);
    ResultSet rs = null;
    try {
      rs = stmt.executeQuery(sql);
      while (rs.next()) {
        caIdCertMap.put(rs.getInt("ID"), Base64.decodeFast(rs.getString("CERT")));
      }
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }

    return caIdCertMap;
  } // method getCas

  public static DbType detectDbType(DataSourceWrapper datasource)
      throws DataAccessException {
    Connection conn = datasource.getConnection();
    try {
      String dbSchemaVersion = datasource.getFirstStringValue(
          null, "DBSCHEMA", "VALUE2", "WHERE NAME='VERSION'");

      if (datasource.tableExists(conn, "CA")) {
        if ("4".equals(dbSchemaVersion)) {
          return DbType.XIPKI_CA_v4;
        } else if ("5".equals(dbSchemaVersion)) {
          return DbType.XIPKI_CA_v5;
        } else if ("6".equals(dbSchemaVersion)) {
          return DbType.XIPKI_CA_v6;
        } else if ("7".equals(dbSchemaVersion)) {
          return DbType.XIPKI_CA_v7;
        } else {
          throw new IllegalArgumentException("unknown DBSCHEMA version " + dbSchemaVersion);
        }
      } else if (datasource.tableExists(conn, "ISSUER")) {
        if ("4".equals(dbSchemaVersion)) {
          return DbType.XIPKI_OCSP_v4;
        } else {
          throw new IllegalArgumentException("unknown DBSCHEMA version " + dbSchemaVersion);
        }
      } else {
        throw new IllegalArgumentException("unknown database schema");
      }
    } finally {
      datasource.returnConnection(conn);
    }
  } // method

  public static HashAlgo detectOcspDbCerthashAlgo(DataSourceWrapper datasource)
      throws DataAccessException {
    String str = datasource.getFirstStringValue(null, "DBSCHEMA", "VALUE2", "NAME='CERTHASH_ALGO'");
    try {
      return HashAlgo.getInstance(str);
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalArgumentException(ex);
    }
  } // method detectOcspDbCerthashAlgo

}
