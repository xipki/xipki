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
import org.xipki.ca.dbtool.StopMe;
import org.xipki.ca.dbtool.diffdb.io.DbSchemaType;
import org.xipki.ca.dbtool.diffdb.io.TargetDigestRetriever;
import org.xipki.ca.dbtool.diffdb.io.XipkiDbControl;
import org.xipki.common.ProcessLog;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbDigestDiff {

    private static final Logger LOG = LoggerFactory.getLogger(DbDigestDiff.class);

    private final String refDirname;

    private final DataSourceWrapper refDatasource;

    private final boolean revokedOnly;

    private final DataSourceWrapper targetDatasource;

    private final XipkiDbControl targetDbControl;

    private Set<byte[]> includeCaCerts;

    private final String reportDirName;

    private final AtomicBoolean stopMe;

    private final int numPerSelect;

    private final int numTargetThreads;

    private DbDigestDiff(String refDir, DataSourceWrapper refDatasource,
            DataSourceWrapper targetDatasource, String reportDirName,
            boolean revokedOnly, AtomicBoolean stopMe, int numPerSelect,
            int numThreads) throws IOException, DataAccessException {
        if (refDir == null && refDatasource == null) {
            throw new IllegalArgumentException("refDir and refDatasource must not be both null");
        } else if (refDir != null && refDatasource != null) {
            throw new IllegalArgumentException(
                    "refDir and refDatasource must not be both non-null");
        }

        this.revokedOnly = revokedOnly;
        this.refDirname = (refDir == null) ? null : IoUtil.expandFilepath(refDir);
        this.refDatasource = refDatasource;
        this.targetDatasource = ParamUtil.requireNonNull("targetDatasource", targetDatasource);
        this.reportDirName = ParamUtil.requireNonNull("reportDirName", reportDirName);
        this.stopMe = ParamUtil.requireNonNull("stopMe", stopMe);
        this.numPerSelect = ParamUtil.requireMin("numPerSelect", numPerSelect, 1);

        DbSchemaType dbSchemaType = DbDigestExportWorker.detectDbSchemaType(targetDatasource);
        this.targetDbControl = new XipkiDbControl(dbSchemaType);

        // number of threads
        this.numTargetThreads = Math.min(numThreads, targetDatasource.maximumPoolSize() - 1);

        if (this.numTargetThreads != numThreads) {
            LOG.info("reduce the numTargetThreads from {} to {}", numTargetThreads,
                    this.numTargetThreads);
        }
    } // constuctor

    public Set<byte[]> includeCaCerts() {
        return includeCaCerts;
    }

    public void setIncludeCaCerts(Set<byte[]> includeCaCerts) {
        this.includeCaCerts = includeCaCerts;
    }

    public void diff() throws Exception {
        Map<Integer, byte[]> caIdCertMap = getCas(targetDatasource, targetDbControl);

        if (refDirname != null) {
            File refDir = new File(this.refDirname);
            File[] childFiles = refDir.listFiles();
            if (childFiles != null) {
                for (File caDir : childFiles) {
                    if (!caDir.isDirectory() || !caDir.getName().startsWith("ca-")) {
                        continue;
                    }

                    String caDirPath = caDir.getPath();
                    DigestReader refReader = new FileDigestReader(caDirPath, numPerSelect);
                    diffSingleCa(refReader, caIdCertMap);
                }
            }
        } else {
            DbSchemaType refDbSchemaType = DbDigestExportWorker.detectDbSchemaType(refDatasource);
            List<Integer> refCaIds = new LinkedList<>();

            XipkiDbControl refDbControl = new XipkiDbControl(refDbSchemaType);
            String refSql = "SELECT ID FROM " + refDbControl.tblCa();

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

            final int numBlocksToRead = (numTargetThreads * 3 / 2);
            for (Integer refCaId : refCaIds) {
                DigestReader refReader = XipkiDbDigestReader.getInstance(refDatasource,
                        refDbSchemaType, refCaId, numBlocksToRead, numPerSelect,
                        new StopMe(stopMe));
                diffSingleCa(refReader, caIdCertMap);
            }
        }
    } // method diff

    private void diffSingleCa(DigestReader refReader, Map<Integer, byte[]> caIdCertBytesMap)
            throws CertificateException, IOException, InterruptedException {
        X509Certificate caCert = refReader.caCert();
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
                System.out.println("skipped CA " + refReader.caSubjectName());
            }
        }

        String commonName = X509Util.getCommonName(caCert.getSubjectX500Principal());
        File caReportDir = new File(reportDirName, "ca-" + commonName);

        int idx = 2;
        while (caReportDir.exists()) {
            caReportDir = new File(reportDirName, "ca-" + commonName + "-" + (idx++));
        }

        DbDigestReporter reporter = new DbDigestReporter(caReportDir.getPath(), caCertBytes);

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
            ProcessLog processLog = new ProcessLog(refReader.totalAccount());
            System.out.println("Processing certificates of CA \n\t'" + refReader.caSubjectName()
                + "'");
            processLog.printHeader();

            target = new TargetDigestRetriever(revokedOnly, processLog, refReader, reporter,
                    targetDatasource, targetDbControl, caId, numPerSelect, numTargetThreads,
                    new StopMe(stopMe));

            target.awaitTerminiation();
            processLog.printTrailer();
        } catch (InterruptedException ex) {
            throw ex;
        } catch (Exception ex) {
            reporter.addError("Exception thrown: " + ex.getClass().getName() + ": "
                    + ex.getMessage());
            LOG.error("exception in diffSingleCa", ex);
        } finally {
            reporter.close();
            refReader.close();
            if (target != null) {
                target.close();
            }
        }
    } // method diffSingleCa

    public static DbDigestDiff getInstanceForDirRef(String refDirname,
            DataSourceWrapper targetDatasource, String reportDirName, boolean revokedOnly,
            AtomicBoolean stopMe, int numPerSelect, int numThreads)
            throws IOException, DataAccessException {
        return new DbDigestDiff(refDirname, null, targetDatasource, reportDirName, revokedOnly,
                stopMe, numPerSelect, numThreads);
    }

    public static DbDigestDiff getInstanceForDbRef(DataSourceWrapper refDatasource,
            DataSourceWrapper targetDatasource, String reportDirName,
            boolean revokedOnly, AtomicBoolean stopMe, int numPerSelect,
            int numThreads) throws IOException, DataAccessException {
        return new DbDigestDiff(null, refDatasource, targetDatasource, reportDirName, revokedOnly,
                stopMe, numPerSelect, numThreads);
    }

    private static Map<Integer, byte[]> getCas(DataSourceWrapper datasource,
            XipkiDbControl dbControl) throws DataAccessException {
        // get a list of available CAs in the target database
        String sql = "SELECT ID,CERT FROM " + dbControl.tblCa();
        Connection conn = datasource.getConnection();
        Statement stmt = datasource.createStatement(conn);
        Map<Integer, byte[]> caIdCertMap = new HashMap<>(5);
        ResultSet rs = null;
        try {
            rs = stmt.executeQuery(sql);
            while (rs.next()) {
                int id = rs.getInt("ID");
                String b64Cert = rs.getString("CERT");
                caIdCertMap.put(id, Base64.decodeFast(b64Cert));
            }
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }

        return caIdCertMap;
    }

}
