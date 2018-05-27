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

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ProcessLog;
import org.xipki.common.util.Base64;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class DigestDiff {

  private static final Logger LOG = LoggerFactory.getLogger(DigestDiff.class);

  private final DataSourceWrapper refDatasource;

  private final boolean revokedOnly;

  private final DataSourceWrapper targetDatasource;

  private final DbControl refDbControl;

  private final DbControl targetDbControl;

  private final HashAlgo certhashAlgo;

  private Set<byte[]> includeCaCerts;

  private final String reportDirName;

  private final AtomicBoolean stopMe;

  private final int numPerSelect;

  private final int numTargetThreads;

  public DigestDiff(DataSourceWrapper refDatasource, DataSourceWrapper targetDatasource,
      String reportDirName, boolean revokedOnly, AtomicBoolean stopMe, int numPerSelect,
      int numThreads) throws IOException, DataAccessException {
    this.refDatasource = ParamUtil.requireNonNull("refDatasource", refDatasource);
    this.revokedOnly = revokedOnly;
    this.targetDatasource = ParamUtil.requireNonNull("targetDatasource", targetDatasource);
    this.reportDirName = ParamUtil.requireNonNull("reportDirName", reportDirName);
    this.stopMe = ParamUtil.requireNonNull("stopMe", stopMe);
    this.numPerSelect = ParamUtil.requireMin("numPerSelect", numPerSelect, 1);

    this.refDbControl = detectDbControl(refDatasource);
    this.targetDbControl = detectDbControl(targetDatasource);

    if (refDbControl == DbControl.XIPKI_OCSP_v3) {
      HashAlgo refAlgo = detectOcspDbCerthashAlgo(refDatasource);
      HashAlgo targetAlgo = detectOcspDbCerthashAlgo(targetDatasource);
      if (refAlgo != targetAlgo) {
        throw new IllegalArgumentException(StringUtil.concatObjects(
            "Could not compare OCSP datasources with different CERTHASH_ALGO: refDataSource (",
            refAlgo, ") and targetDataSource (", targetAlgo, ")"));
      }
      this.certhashAlgo = refAlgo;
    } else if (refDbControl == DbControl.XIPKI_CA_v3) {
      this.certhashAlgo = HashAlgo.SHA1;
    } else {
      throw new RuntimeException("should not reach here, unknown dbContro " + refDbControl);
    }

    // number of threads
    this.numTargetThreads = Math.min(numThreads, targetDatasource.getMaximumPoolSize() - 1);

    if (this.numTargetThreads != numThreads) {
      LOG.info("reduce the numTargetThreads from {} to {}", numTargetThreads,
          this.numTargetThreads);
    }
  } // constuctor

  public Set<byte[]> isIncludeCaCerts() {
    return includeCaCerts;
  }

  public void setIncludeCaCerts(Set<byte[]> includeCaCerts) {
    this.includeCaCerts = includeCaCerts;
  }

  public void diff() throws Exception {
    Map<Integer, byte[]> caIdCertMap = getCas(targetDatasource, targetDbControl);

    List<Integer> refCaIds = new LinkedList<>();

    String refSql;
    if (refDbControl == DbControl.XIPKI_OCSP_v3) {
      refSql = "SELECT ID FROM ISSUER";
    } else if (refDbControl == DbControl.XIPKI_CA_v3) {
      refSql = "SELECT ID FROM CA";
    } else {
      throw new RuntimeException("invalid refDbControl " + refDbControl);
    }

    Statement refStmt = null;
    try {
      refStmt = refDatasource.createStatement(refDatasource.getConnection());
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
      RefDigestReader refReader = RefDigestReader.getInstance(refDatasource, refDbControl,
          certhashAlgo, refCaId, numBlocksToRead, numPerSelect, stopMe);
      diffSingleCa(refReader, caIdCertMap);
    }
  } // method diff

  private void diffSingleCa(RefDigestReader refReader, Map<Integer, byte[]> caIdCertBytesMap)
      throws CertificateException, IOException, InterruptedException {
    X509Certificate caCert = refReader.getCaCert();
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

    String commonName = X509Util.getCommonName(caCert.getSubjectX500Principal());
    File caReportDir = new File(reportDirName, "ca-" + commonName);

    int idx = 2;
    while (caReportDir.exists()) {
      caReportDir = new File(reportDirName, "ca-" + commonName + "-" + (idx++));
    }

    DigestDiffReporter reporter = new DigestDiffReporter(caReportDir.getPath(), caCertBytes);

    Integer caId = null;
    for (Integer i : caIdCertBytesMap.keySet()) {
      if (Arrays.equals(caCertBytes, caIdCertBytesMap.get(i))) {
        caId = i;
      }
    }

    if (caId == null) {
      reporter.addNoCaMatch();
      refReader.close();
      reporter.close();
      return;
    }

    TargetDigestRetriever target = null;

    try {
      reporter.start();
      ProcessLog processLog = new ProcessLog(refReader.getTotalAccount());
      System.out.println(
          "Processing certificates of CA \n\t'" + refReader.getCaSubjectName() + "'");
      processLog.printHeader();

      target = new TargetDigestRetriever(revokedOnly, processLog, refReader, reporter,
          targetDatasource, targetDbControl, certhashAlgo, caId, numPerSelect,
          numTargetThreads, stopMe);

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

  private static Map<Integer, byte[]> getCas(DataSourceWrapper datasource, DbControl dbControl)
      throws DataAccessException {
    // get a list of available CAs in the target database
    String sql = "SELECT ID,CERT FROM ";
    if (dbControl == DbControl.XIPKI_CA_v3) {
      sql += "CA";
    } else if (dbControl == DbControl.XIPKI_OCSP_v3) {
      sql += "ISSUER";
    } else {
      throw new IllegalArgumentException("unknown dbControl " + dbControl);
    }

    Connection conn = datasource.getConnection();
    Statement stmt = datasource.createStatement(conn);
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
  }

  public static DbControl detectDbControl(DataSourceWrapper datasource) throws DataAccessException {
    Connection conn = datasource.getConnection();
    try {
      if (datasource.tableExists(conn, "CA")) {
        return DbControl.XIPKI_CA_v3;
      } else if (datasource.tableExists(conn, "ISSUER")) {
        return DbControl.XIPKI_OCSP_v3;
      } else {
        throw new IllegalArgumentException("unknown database schema");
      }
    } finally {
      datasource.returnConnection(conn);
    }
  }

  public static HashAlgo detectOcspDbCerthashAlgo(DataSourceWrapper datasource)
      throws DataAccessException {
    String str = datasource.getFirstValue(null, "DBSCHEMA", "VALUE2", "NAME='CERTHASH_ALGO'",
        String.class);
    return HashAlgo.getNonNullInstance(str);
  }

}
