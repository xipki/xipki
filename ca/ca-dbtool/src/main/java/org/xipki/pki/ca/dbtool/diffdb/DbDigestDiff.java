/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ProcessLog;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.diffdb.internal.CertsBundle;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbSchemaType;
import org.xipki.pki.ca.dbtool.diffdb.internal.TargetDigestRetriever;
import org.xipki.pki.ca.dbtool.diffdb.internal.XipkiDbControl;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class DbDigestDiff
{
    private static final Logger LOG = LoggerFactory.getLogger(DbDigestDiff.class);
    private final String refDirname;
    private final DataSourceWrapper refDatasource;
    private final boolean revokedOnly;

    private final DataSourceWrapper targetDatasource;
    private final XipkiDbControl targetDbControl;

    private final String reportDirName;
    private final AtomicBoolean stopMe;
    private final int numPerSelect;
    private final int numRefThreads;
    private final int numTargetThreads;

    public static DbDigestDiff getInstanceForDirRef(
            final boolean revokedOnly,
            final String refDirname,
            final DataSourceWrapper targetDatasource,
            final String reportDirName,
            final AtomicBoolean stopMe,
            final int numPerSelect,
            final int numRefThreads,
            final int numTargetThreads)
    throws IOException, DataAccessException
    {
        ParamUtil.assertNotBlank("refDirname", refDirname);
        ParamUtil.assertNotBlank("reportDirName", reportDirName);
        ParamUtil.assertNotNull("targetDatasource", targetDatasource);
        ParamUtil.assertNotNull("stopMe", stopMe);
        if (numPerSelect < 1)
        {
            throw new IllegalArgumentException("invalid numPerSelect: " + numPerSelect);
        }

        return new DbDigestDiff(revokedOnly, refDirname, null,
                targetDatasource, reportDirName, stopMe, numPerSelect,
                numRefThreads, numTargetThreads);
    }

    public static DbDigestDiff getInstanceForDbRef(
            final boolean revokedOnly,
            final DataSourceWrapper refDatasource,
            final DataSourceWrapper targetDatasource,
            final String reportDirName,
            final AtomicBoolean stopMe,
            final int numPerSelect,
            final int numRefThreads,
            final int numTargetThreads)
    throws IOException, DataAccessException
    {
        ParamUtil.assertNotNull("refDatasource", refDatasource);
        ParamUtil.assertNotBlank("reportDirName", reportDirName);
        ParamUtil.assertNotNull("targetDatasource", targetDatasource);
        ParamUtil.assertNotNull("stopMe", stopMe);
        if (numPerSelect < 1)
        {
            throw new IllegalArgumentException("invalid numPerSelect: " + numPerSelect);
        }

        return new DbDigestDiff(revokedOnly, null, refDatasource,
                targetDatasource, reportDirName, stopMe, numPerSelect,
                numRefThreads, numTargetThreads);
    }

    private DbDigestDiff(
            final boolean revokedOnly,
            final String refDir,
            final DataSourceWrapper refDatasource,
            final DataSourceWrapper targetDatasource,
            final String reportDirName,
            final AtomicBoolean stopMe,
            final int numPerSelect,
            final int numRefThreads,
            final int numTargetThreads)
    throws IOException, DataAccessException
    {
        if (numRefThreads < 1)
        {
            throw new IllegalArgumentException("invalid numRefThreads: " + numRefThreads);
        }
        if (numTargetThreads < 1)
        {
            throw new IllegalArgumentException("invalid numTargetThreads: " + numTargetThreads);
        }
        this.revokedOnly = revokedOnly;

        this.refDirname = (refDir == null)
                ? null
                : IoUtil.expandFilepath(refDir);

        this.refDatasource = refDatasource;
        this.targetDatasource = targetDatasource;
        DbSchemaType dbSchemaType = DbDigestExportWorker.detectDbSchemaType(targetDatasource);
        this.targetDbControl = new XipkiDbControl(dbSchemaType);

        this.reportDirName = reportDirName;
        this.stopMe = stopMe;
        this.numPerSelect = numPerSelect;
        this.numRefThreads = numRefThreads;
        this.numTargetThreads = numTargetThreads;
    }

    public void diff()
    throws Exception
    {
        Map<Integer, byte[]> caIdCertMap = getCAs(targetDatasource, targetDbControl);

        if (refDirname != null)
        {
            File refDir = new File(this.refDirname);
            File[] childFiles = refDir.listFiles();
            for (File caDir : childFiles)
            {
                if (!caDir.isDirectory()
                        ||  !caDir.getName().startsWith("ca-"))
                {
                    continue;
                }

                String caDirPath = caDir.getPath();
                DigestReader refReader = new FileDigestReader(caDirPath, revokedOnly);
                diffSingleCA(refReader, caIdCertMap);
            }
        } else
        {
            DbSchemaType refDbSchemaType = DbDigestExportWorker
                    .detectDbSchemaType(refDatasource);
            List<Integer> refCaIds = new LinkedList<>();

            XipkiDbControl refDbControl = null;
            String refSql;

            if (refDbSchemaType == DbSchemaType.EJBCA_CA_v3)
            {
                if (!refDatasource.tableHasColumn(null, "CertificateData", "id"))
                {
                    throw new RuntimeException(
                            "EJBCA without column 'CertificateData.id' is not supported, "
                            + "please call 'digest-db' first and then use the exported"
                            + " folder as the reference");
                }
                refSql = "SELECT cAId FROM CAData WHERE cAId != 0";
            } else
            {
                refDbControl = new XipkiDbControl(refDbSchemaType);
                refSql = "SELECT ID FROM " + refDbControl.getTblCa();
            }

            Statement refStmt = null;
            try
            {
                refStmt = refDatasource.createStatement(refDatasource.getConnection());
                ResultSet refRs = null;
                try
                {
                    refRs = refStmt.executeQuery(refSql);
                    while (refRs.next())
                    {
                        int id = refRs.getInt(1);
                        refCaIds.add(id);
                    }
                } catch (SQLException e)
                {
                    throw refDatasource.translate(refSql, e);
                } finally
                {
                    refDatasource.releaseResources(refStmt, refRs);
                }
            } finally
            {
                refDatasource.releaseResources(refStmt, null);
            }

            boolean dbContainsMultipleCAs = refCaIds.size() > 1;

            for (Integer refCaId : refCaIds)
            {
                DigestReader refReader = (refDbSchemaType == DbSchemaType.EJBCA_CA_v3)
                        ? EjbcaDbDigestReader.getInstance(refDatasource, refDbSchemaType,
                                refCaId, dbContainsMultipleCAs, revokedOnly, numRefThreads)
                        : XipkiDbDigestReader.getInstance(refDatasource, refDbSchemaType,
                                refCaId, revokedOnly, numRefThreads);
                diffSingleCA(refReader, caIdCertMap);
            }
        }
    }

    private void diffSingleCA(DigestReader refReader,
            Map<Integer, byte[]> caIdCertBytesMap)
    throws CertificateException, IOException, InterruptedException
    {
        X509Certificate caCert = refReader.getCaCert();
        byte[] caCertBytes = caCert.getEncoded();

        String commonName = X509Util.getCommonName(caCert.getSubjectX500Principal());
        File caReportDir = new File(reportDirName, "ca-" + commonName);

        int idx = 2;
        while (caReportDir.exists())
        {
            caReportDir = new File(reportDirName, "ca-" + commonName + "-" + (idx++));
        }

        DbDigestReporter reporter = new DbDigestReporter(
                caReportDir.getPath(), caCertBytes);

        Integer caId = null;
        for (Integer i : caIdCertBytesMap.keySet())
        {
            if (Arrays.equals(caCertBytes, caIdCertBytesMap.get(i)))
            {
                caId = i;
            }
        }

        if (caId == null)
        {
            reporter.addNoCAMatch();
            refReader.close();
            reporter.close();
            return;
        }

        TargetDigestRetriever target = null;

        try
        {
            target = new TargetDigestRetriever(targetDatasource, targetDbControl,
                    caId, numPerSelect, numTargetThreads);
            doDiff(refReader, target, reporter);
        } catch (InterruptedException e)
        {
            throw e;
        } catch (Exception e)
        {
            reporter.addError("Exception thrown: " + e.getClass().getName() + ": "
                    + e.getMessage());
            LOG.error("exception on doDiff", e);
        } finally
        {
            reporter.close();
            refReader.close();
            if (target != null)
            {
                target.close();
            }
        }
    }

    private void doDiff(
            final DigestReader refReader,
            final TargetDigestRetriever target,
            final DbDigestReporter reporter)
    throws Exception
    {
        ProcessLog processLog = new ProcessLog(refReader.getTotalAccount());
        System.out.println("Processing certifiates of CA \n\t'"
                + refReader.getCaSubjectName() + "'");
        processLog.printHeader();
        reporter.start();

        boolean interrupted = false;

        while (true)
        {
            if (stopMe.get())
            {
                interrupted = true;
                break;
            }

            int numBundles = 0;
            for (int i = 0; i < numTargetThreads * 2; i++)
            {
                CertsBundle myBundle = refReader.nextCerts(numPerSelect);
                if (myBundle != null
                        && !myBundle.getSerialNumbers().isEmpty())
                {
                    numBundles++;
                    target.addIn(myBundle);
                } else
                {
                    break; // break for
                }
            }

            if (numBundles == 0)
            {
                break; // break while (true)
            }

            for (int i = 0; i < numBundles; i++)
            {
                CertsBundle bundle = target.takeOut();
                Exception targetException = bundle.getTargetException();
                if (targetException != null)
                {
                    throw targetException;
                }

                List<Long> serialNumbers = bundle.getSerialNumbers();
                int n = serialNumbers.size();

                List<Long> cloneSerialNumbers = new ArrayList<>(serialNumbers);
                Map<Long, DbDigestEntry> refCerts = bundle.getCerts();

                for (Long serialNumber : serialNumbers)
                {
                    DbDigestEntry targetCert = bundle.getTargetCert(serialNumber);
                    cloneSerialNumbers.remove(serialNumber);
                    DbDigestEntry refCert = refCerts.get(serialNumber);
                    if (targetCert != null)
                    {
                        if (refCert.contentEquals(targetCert))
                        {
                            reporter.addGood(serialNumber);
                        } else
                        {
                            reporter.addDiff(refCert, targetCert);
                        }
                    } else
                    {
                        reporter.addMissing(serialNumber);
                    }
                } // end for

                cloneSerialNumbers.clear();

                processLog.addNumProcessed(n);
                processLog.printStatus();
            }
        }

        processLog.printTrailer();

        if (interrupted)
        {
            throw new InterruptedException("interrupted by the user");
        }
    }

    public static Map<Integer, byte[]> getCAs(
            DataSourceWrapper datasource, XipkiDbControl dbControl)
    throws DataAccessException
    {
        // get a list of available CAs in the target database
        String sql = "SELECT ID, CERT FROM " + dbControl.getTblCa();
        Connection conn = datasource.getConnection();
        Statement stmt = datasource.createStatement(conn);
        Map<Integer, byte[]> caIdCertMap = new HashMap<>(5);
        ResultSet rs = null;
        try
        {
            rs = stmt.executeQuery(sql);
            while (rs.next())
            {
                int id = rs.getInt("ID");
                String b64Cert = rs.getString("CERT");
                caIdCertMap.put(id, Base64.decode(b64Cert));
            }
        } catch (SQLException e)
        {
            throw datasource.translate(sql, e);
        } finally
        {
            datasource.releaseResources(stmt, rs);
        }

        return caIdCertMap;
    }

}
