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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.DatabaseType;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.ProcessLog;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class DbDigestDiff
{
    private static class MyBundle
    {
        int numSkipped;
        Map<Long, DbDigestEntry> certs;
        List<Long> serialNumbers;
    }

    private final String refDirname;
    private final DataSourceWrapper refDatasource;

    private final boolean revokedOnly;

    private final XipkiDbControl dbControl;
    private final DataSourceWrapper datasource;
    private final String reportDirName;
    private final AtomicBoolean stopMe;
    private final int numPerSelect;
    private Connection conn;
    private final String singleCertSql;
    private final String inArrayCertsSql;
    private final String rangeCertsSql;

    public static DbDigestDiff getInstanceForDirRef(
            final boolean revokedOnly,
            final String refDirname,
            final DataSourceWrapper datasource,
            final String reportDirName,
            final AtomicBoolean stopMe,
            final int numPerSelect)
    throws IOException, DataAccessException
    {
        ParamUtil.assertNotBlank("refDirname", refDirname);
        ParamUtil.assertNotBlank("reportDirName", reportDirName);
        ParamUtil.assertNotNull("datasource", datasource);
        ParamUtil.assertNotNull("stopMe", stopMe);
        if(numPerSelect < 1)
        {
            throw new IllegalArgumentException("invalid numPerSelect: " + numPerSelect);
        }

        return new DbDigestDiff(revokedOnly, refDirname, null,
                datasource, reportDirName, stopMe, numPerSelect);
    }

    public static DbDigestDiff getInstanceForDbRef(
            final boolean revokedOnly,
            final DataSourceWrapper refDatasource,
            final DataSourceWrapper datasource,
            final String reportDirName,
            final AtomicBoolean stopMe,
            final int numPerSelect)
    throws IOException, DataAccessException
    {
        ParamUtil.assertNotNull("refDatasource", refDatasource);
        ParamUtil.assertNotBlank("reportDirName", reportDirName);
        ParamUtil.assertNotNull("datasource", datasource);
        ParamUtil.assertNotNull("stopMe", stopMe);
        if(numPerSelect < 1)
        {
            throw new IllegalArgumentException("invalid numPerSelect: " + numPerSelect);
        }

        return new DbDigestDiff(revokedOnly, null, refDatasource,
                datasource, reportDirName, stopMe, numPerSelect);
    }

    private DbDigestDiff(
            final boolean revokedOnly,
            final String refDir,
            final DataSourceWrapper refDatasource,
            final DataSourceWrapper datasource,
            final String reportDirName,
            final AtomicBoolean stopMe,
            final int numPerSelect)
    throws IOException, DataAccessException
    {
        this.revokedOnly = revokedOnly;

        this.refDirname = (refDir == null)
                ? null
                : IoUtil.expandFilepath(refDir);

        this.refDatasource = refDatasource;

        this.datasource = datasource;
        this.reportDirName = reportDirName;
        this.stopMe = stopMe;
        this.numPerSelect = numPerSelect;

        DbSchemaType dbSchemaType = DbDigestExportWorker.detectDbSchemaType(datasource);
        this.dbControl = new XipkiDbControl(dbSchemaType);

        String coreSql =
                dbControl.getColRevoked() + ","
                + dbControl.getColRevReason() + ","
                + dbControl.getColRevTime() + ","
                + dbControl.getColRevInvTime() + ","
                + dbControl.getColCerthash()
                + " FROM CERT INNER JOIN " + dbControl.getTblCerthash()
                + " ON CERT." + dbControl.getColCaId() + "=?"
                + " AND CERT." + dbControl.getColSerialNumber() + "=?"
                + " AND CERT.ID=" + dbControl.getTblCerthash() + "."
                + dbControl.getColCertId();
        singleCertSql = datasource.createFetchFirstSelectSQL(coreSql, 1);

        StringBuilder sb = new StringBuilder("?");
        for(int i = 1; i < numPerSelect; i++)
        {
            sb.append(",?");
        }

        coreSql =
                dbControl.getColSerialNumber() + ","
                + dbControl.getColRevoked() + ","
                + dbControl.getColRevReason() + ","
                + dbControl.getColRevTime() + ","
                + dbControl.getColRevInvTime() + ","
                + dbControl.getColCerthash()
                + " FROM CERT INNER JOIN " + dbControl.getTblCerthash()
                + " ON CERT." + dbControl.getColCaId() + "=?"
                + " AND CERT." + dbControl.getColSerialNumber() + " IN (" + sb.toString() + ")"
                + " AND CERT.ID=" + dbControl.getTblCerthash() + "." + dbControl.getColCertId();
        inArrayCertsSql = datasource.createFetchFirstSelectSQL(coreSql, numPerSelect);

        rangeCertsSql = "SELECT "
                + dbControl.getColSerialNumber() + ","
                + dbControl.getColRevoked() + ","
                + dbControl.getColRevReason() + ","
                + dbControl.getColRevTime() + ","
                + dbControl.getColRevInvTime() + ","
                + dbControl.getColCerthash()
                + " FROM CERT INNER JOIN " + dbControl.getTblCerthash()
                + " ON CERT." + dbControl.getColCaId() + "=?"
                + " AND CERT." + dbControl.getColSerialNumber() + ">=?"
                + " AND CERT." + dbControl.getColSerialNumber() + "<=?"
                + " AND CERT.ID=" + dbControl.getTblCerthash() + "."
                + dbControl.getColCertId();

        this.conn = datasource.getConnection();
    }

    public void diff()
    throws DataAccessException, IOException, InterruptedException, CertificateException
    {
        // get a list of available CAs in the target database
        String sql = "SELECT ID, CERT FROM " + dbControl.getTblCa();
        Statement stmt = datasource.createStatement(conn);
        Map<Integer, byte[]> caIdCertMap = new HashMap<>(5);
        ResultSet rs = null;
        try
        {
            rs = stmt.executeQuery(sql);
            while(rs.next())
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
            releaseResources(stmt, rs);
        }

        if(refDirname != null)
        {
            File refDir = new File(this.refDirname);
            File[] childFiles = refDir.listFiles();
            for(File caDir : childFiles)
            {
                if(caDir.isDirectory() == false
                        ||  caDir.getName().startsWith("ca-") == false)
                {
                    continue;
                }

                String caDirPath = caDir.getPath();
                DigestReader refReader = new FileDigestReader(caDirPath);
                diffSingleCA(refReader, caIdCertMap);
            }
        } else
        {
            List<Integer> refCaIds = new LinkedList<>();
            Statement refStmt = refDatasource.createStatement(refDatasource.getConnection());
            DbSchemaType refDbSchemaType = DbDigestExportWorker.detectDbSchemaType(refDatasource);
            XipkiDbControl refDbControl = new XipkiDbControl(refDbSchemaType);
            String refSql = "SELECT ID FROM " + refDbControl.getTblCa();
            ResultSet refRs = null;
            try
            {
                refRs = refStmt.executeQuery(refSql);
                while(refRs.next())
                {
                    int id = refRs.getInt("ID");
                    refCaIds.add(id);
                }
            } catch (SQLException e)
            {
                throw datasource.translate(refSql, e);
            } finally
            {
                refDatasource.releaseResources(refStmt, refRs);
            }

            for(Integer refCaId : refCaIds)
            {
                DigestReader refReader = new DbDigestReader(refDatasource, refDbSchemaType,
                        refCaId, revokedOnly);
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
        while(caReportDir.exists())
        {
            caReportDir = new File(reportDirName, "ca-" + commonName + "-" + (idx++));
        }

        DbDigestReporter reporter = new DbDigestReporter(
                caReportDir.getPath(), caCertBytes);

        Integer caId = null;
        for(Integer i : caIdCertBytesMap.keySet())
        {
            if(Arrays.equals(caCertBytes, caIdCertBytesMap.get(i)))
            {
                caId = i;
            }
        }

        if(caId == null)
        {
            reporter.addNoCAMatch();
            refReader.close();
            reporter.close();
        } else
        {
            try
            {
                doDiff(refReader, caId.intValue(), reporter);
            }catch(InterruptedException e)
            {
                throw e;
            }catch(Exception e)
            {
                reporter.addError("Exception thrown: " + e.getClass().getName() + ": "
                        + e.getMessage());
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
    throws IOException, DataAccessException, InterruptedException
    {
        PreparedStatement singleSelectStmt = null;
        PreparedStatement inArraySelectStmt = null;
        PreparedStatement rangeSelectStmt = null;

        try
        {
            singleSelectStmt = datasource.prepareStatement(conn, singleCertSql);
            singleSelectStmt.setInt(1, caIdB);

            inArraySelectStmt = datasource.prepareStatement(conn, inArrayCertsSql);
            inArraySelectStmt.setInt(1, caIdB);

            rangeSelectStmt = datasource.prepareStatement(conn, rangeCertsSql);
            rangeSelectStmt.setInt(1, caIdB);

            ProcessLog processLog = new ProcessLog(readerA.getTotalAccount(),
                    System.currentTimeMillis(), 0);
            System.out.println("Processing certifiates of CA \n\t'"
                    + readerA.getCaSubjectName() + "'");
            ProcessLog.printHeader();

            boolean interrupted = false;
            int numProcessed = 0;
            while(true)
            {
                if(stopMe.get())
                {
                    interrupted = true;
                    break;
                }

                MyBundle myBundle = readNextLines(readerA);

                int n = myBundle.serialNumbers.size();
                if(n + myBundle.numSkipped == 0)
                {
                    break;
                }

                if(n > 0)
                {
                    List<Long> cloneSerialNumbers = new ArrayList<>(myBundle.serialNumbers);
                    long minSerialNumber = 0;
                    long maxSerialNumber = 0;
                    for(Long m : cloneSerialNumbers)
                    {
                        if(minSerialNumber > m)
                        {
                            minSerialNumber = m;
                        }
                        if(maxSerialNumber < m)
                        {
                            maxSerialNumber = m;
                        }
                    }

                    Map<Long, DbDigestEntry> certsInB;

                    if((int) (maxSerialNumber - minSerialNumber) < numPerSelect * 2)
                    {
                        ResultSet rs = null;
                        try
                        {
                            rangeSelectStmt.setLong(2, minSerialNumber);
                            rangeSelectStmt.setLong(3, maxSerialNumber);
                            rs = rangeSelectStmt.executeQuery();

                            certsInB = buildResult(rs, myBundle.serialNumbers);
                        } catch(SQLException e)
                        {
                            throw datasource.translate(inArrayCertsSql, e);
                        }
                        finally
                        {
                            releaseResources(null, rs);
                        }
                    } else
                    {
                        boolean batchSupported = datasource.getDatabaseType() != DatabaseType.H2;
                        if(batchSupported && myBundle.serialNumbers.size() == numPerSelect)
                        {
                            certsInB = getCertsViaInArraySelectInB(inArraySelectStmt,
                                    myBundle.serialNumbers);
                        } else
                        {
                            certsInB = getCertsViaSingleSelectInB(
                                    singleSelectStmt, myBundle.serialNumbers);
                        }
                    }

                    for(Long serialNumber : myBundle.serialNumbers)
                    {
                        DbDigestEntry certB = certsInB.get(serialNumber);
                        cloneSerialNumbers.remove(serialNumber);
                        DbDigestEntry certA = myBundle.certs.get(serialNumber);
                        if(certB != null)
                        {
                            if(certA.contentEquals(certB))
                            {
                                reporter.addSame(serialNumber);
                            } else
                            {
                                reporter.addDiff(certA, certB);
                            }
                        } else
                        {
                            reporter.addMissing(serialNumber);
                        }
                    } // end for
                } // end if (n > 0)

                processLog.addNumProcessed(n + myBundle.numSkipped);
                processLog.printStatus();

                numProcessed += n;
                reporter.setAccout(numProcessed);
            }
            processLog.printStatus(true);
            ProcessLog.printTrailer();

            if(interrupted)
            {
                throw new InterruptedException("interrupted by the user");
            }
        } catch (SQLException e)
        {
            throw datasource.translate(singleCertSql, e);
        }finally
        {
            releaseResources(singleSelectStmt, null);
        }
    }

    private Map<Long, DbDigestEntry> getCertsViaSingleSelectInB(
            final PreparedStatement singleSelectStmt,
            final List<Long> serialNumbers)
    throws DataAccessException
    {
        Map<Long, DbDigestEntry> ret = new HashMap<>(serialNumbers.size());

        for(Long serialNumber : serialNumbers)
        {
            DbDigestEntry certB = getSingleCert(singleSelectStmt, serialNumber);
            if(certB != null)
            {
                ret.put(serialNumber, certB);
            }
        }

        return ret;
    }

    private Map<Long, DbDigestEntry> getCertsViaInArraySelectInB(
            final PreparedStatement batchSelectStmt,
            final List<Long> serialNumbers)
    throws DataAccessException
    {
        final int n = serialNumbers.size();
        if(n != numPerSelect)
        {
            throw new IllegalArgumentException("size of serialNumbers is not '" + numPerSelect
                    + "': " + n);
        }

        Collections.sort(serialNumbers);

        ResultSet rs = null;

        try
        {
            for(int i = 0; i < n; i++)
            {
                batchSelectStmt.setLong(i+2, serialNumbers.get(i));
            }

            rs = batchSelectStmt.executeQuery();
            return buildResult(rs, serialNumbers);
        } catch(SQLException e)
        {
            throw datasource.translate(inArrayCertsSql, e);
        }
        finally
        {
            releaseResources(null, rs);
        }
    }

    private Map<Long, DbDigestEntry> buildResult(
            final ResultSet rs,
            final List<Long> serialNumbers)
    throws SQLException
    {
        Map<Long, DbDigestEntry> ret = new HashMap<>(serialNumbers.size());

        while(rs.next())
        {
            long serialNumber = rs.getLong(dbControl.getColSerialNumber());
            if(serialNumbers.contains(serialNumber) == false)
            {
                continue;
            }

            boolean revoked = rs.getBoolean(dbControl.getColRevoked());
            Integer revReason = null;
            Long revTime = null;
            Long revInvTime = null;
            if(revoked)
            {
                revReason = rs.getInt(dbControl.getColRevReason());
                revTime = rs.getLong(dbControl.getColRevTime());
                revInvTime = rs.getLong(dbControl.getColRevInvTime());
                if(revInvTime == 0)
                {
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
    throws DataAccessException
    {
        ResultSet rs = null;
        try
        {
            singleSelectStmt.setLong(2, serialNumber);
            rs = singleSelectStmt.executeQuery();
            if(rs.next() == false)
            {
                return null;
            }
            boolean revoked = rs.getBoolean(dbControl.getColRevoked());
            Integer revReason = null;
            Long revTime = null;
            Long revInvTime = null;
            if(revoked)
            {
                revReason = rs.getInt(dbControl.getColRevReason());
                revTime = rs.getLong(dbControl.getColRevTime());
                revInvTime = rs.getLong(dbControl.getColRevInvTime());
                if(revInvTime == 0)
                {
                    revInvTime = null;
                }
            }
            String sha1Fp = rs.getString(dbControl.getColCerthash());
            return new DbDigestEntry(serialNumber,
                    revoked, revReason, revTime, revInvTime, sha1Fp);
        } catch(SQLException e)
        {
            throw datasource.translate(singleCertSql, e);
        } finally
        {
            releaseResources(null, rs);
        }
    }

    private MyBundle readNextLines(
            final DigestReader reader)
    throws IOException
    {
        MyBundle ret = new MyBundle();
        ret.numSkipped = 0;
        ret.serialNumbers = new ArrayList<>(numPerSelect);
        ret.certs = new HashMap<>(numPerSelect);

        int k = 0;
        while(reader.hasNext())
        {
            DbDigestEntry line = reader.nextCert();
            if(revokedOnly && line.isRevoked() == false)
            {
                ret.numSkipped++;
                continue;
            }

            ret.serialNumbers.add(line.getSerialNumber());
            ret.certs.put(line.getSerialNumber(), line);
            k++;
            if(k >= numPerSelect)
            {
                break;
            }
        }

        return ret;
    }

    private void releaseResources(
            final Statement ps,
            final ResultSet rs)
    {
        if(ps != null)
        {
            try
            {
                ps.close();
            }catch(Exception e)
            {
            }
        }

        if(rs != null)
        {
            try
            {
                rs.close();
            }catch(Exception e)
            {
            }
        }
    }

}
