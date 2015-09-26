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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.ProcessLog;
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

    private final String reportDirName;
    private final AtomicBoolean stopMe;
    private final int numPerSelect;
    private final int numThreads;

    private final TargetDigestRetriever target;

    public static DbDigestDiff getInstanceForDirRef(
            final boolean revokedOnly,
            final String refDirname,
            final DataSourceWrapper datasource,
            final String reportDirName,
            final AtomicBoolean stopMe,
            final int numPerSelect,
            final int numThreads)
    throws IOException, DataAccessException
    {
        ParamUtil.assertNotBlank("refDirname", refDirname);
        ParamUtil.assertNotBlank("reportDirName", reportDirName);
        ParamUtil.assertNotNull("datasource", datasource);
        ParamUtil.assertNotNull("stopMe", stopMe);
        if (numPerSelect < 1)
        {
            throw new IllegalArgumentException("invalid numPerSelect: " + numPerSelect);
        }

        return new DbDigestDiff(revokedOnly, refDirname, null,
                datasource, reportDirName, stopMe, numPerSelect, numThreads);
    }

    public static DbDigestDiff getInstanceForDbRef(
            final boolean revokedOnly,
            final DataSourceWrapper refDatasource,
            final DataSourceWrapper datasource,
            final String reportDirName,
            final AtomicBoolean stopMe,
            final int numPerSelect,
            final int numThreads)
    throws IOException, DataAccessException
    {
        ParamUtil.assertNotNull("refDatasource", refDatasource);
        ParamUtil.assertNotBlank("reportDirName", reportDirName);
        ParamUtil.assertNotNull("datasource", datasource);
        ParamUtil.assertNotNull("stopMe", stopMe);
        if (numPerSelect < 1)
        {
            throw new IllegalArgumentException("invalid numPerSelect: " + numPerSelect);
        }

        return new DbDigestDiff(revokedOnly, null, refDatasource,
                datasource, reportDirName, stopMe, numPerSelect, numThreads);
    }

    private DbDigestDiff(
            final boolean revokedOnly,
            final String refDir,
            final DataSourceWrapper refDatasource,
            final DataSourceWrapper datasource,
            final String reportDirName,
            final AtomicBoolean stopMe,
            final int numPerSelect,
            final int numThreads)
    throws IOException, DataAccessException
    {
        if (numThreads < 1)
        {
            throw new IllegalArgumentException("invalid numThreads: " + numThreads);
        }

        this.revokedOnly = revokedOnly;

        this.refDirname = (refDir == null)
                ? null
                : IoUtil.expandFilepath(refDir);

        this.refDatasource = refDatasource;

        this.reportDirName = reportDirName;
        this.stopMe = stopMe;
        this.numPerSelect = numPerSelect;
        this.numThreads = numThreads;
        this.target = new TargetDigestRetriever(datasource, numPerSelect, numThreads);
    }

    public void diff()
    throws Exception
    {
        try
        {
            Map<Integer, byte[]> caIdCertMap = target.getCAs();

            if (refDirname != null)
            {
                File refDir = new File(this.refDirname);
                File[] childFiles = refDir.listFiles();
                for (File caDir : childFiles)
                {
                    if (caDir.isDirectory() == false
                            ||  caDir.getName().startsWith("ca-") == false)
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
                    if (refDatasource.tableHasColumn(null, "CertificateData", "id") == false)
                    {
                        throw new RuntimeException(
                                "EJBCA without column 'CertificateData.id' is not supported, "
                                + "please call 'digest-db' first and then use the exported"
                                + " folder as reference");
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
                            ? new EjbcaDbDigestReader(refDatasource, refDbSchemaType,
                                    refCaId, dbContainsMultipleCAs, revokedOnly)
                            : new XipkiDbDigestReader(refDatasource, refDbSchemaType,
                                    refCaId, revokedOnly);
                    diffSingleCA(refReader, caIdCertMap);
                }
            }
        }finally
        {
            if (target != null)
            {
                target.close();
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
        } else
        {
            try
            {
                doDiff(refReader, caId.intValue(), reporter);
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
            }
        }
    }

    private void doDiff(
            final DigestReader readerA,
            final int caIdB,
            final DbDigestReporter reporter)
    throws Exception
    {
        target.startCA(caIdB);
        ProcessLog processLog = new ProcessLog(readerA.getTotalAccount(),
                System.currentTimeMillis(), 0);

        System.out.println("Processing certifiates of CA \n\t'"
                + readerA.getCaSubjectName() + "'");
        ProcessLog.printHeader();

        boolean interrupted = false;
        int numProcessed = 0;

        while (true)
        {
            if (stopMe.get())
            {
                interrupted = true;
                target.close();
                break;
            }

            int numBundles = 0;
            for (int i = 0; i < numThreads; i++)
            {
                CertsBundle myBundle = readerA.nextCerts(numPerSelect);
                if (myBundle != null
                        && myBundle.getSerialNumbers().isEmpty() == false)
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
                Map<Long, DbDigestEntry> certs = bundle.getCerts();

                for (Long serialNumber : serialNumbers)
                {
                    DbDigestEntry certB = bundle.getTargetCert(serialNumber);
                    cloneSerialNumbers.remove(serialNumber);
                    DbDigestEntry certA = certs.get(serialNumber);
                    if (certB != null)
                    {
                        if (certA.contentEquals(certB))
                        {
                            reporter.addGood(serialNumber);
                        } else
                        {
                            reporter.addDiff(certA, certB);
                        }
                    } else
                    {
                        reporter.addMissing(serialNumber);
                    }
                } // end for

                processLog.addNumProcessed(n);
                processLog.printStatus();

                numProcessed += n;
                reporter.setAccout(numProcessed);
            }
        }

        processLog.printStatus(true);
        ProcessLog.printTrailer();

        if (interrupted)
        {
            throw new InterruptedException("interrupted by the user");
        }
    }

}
