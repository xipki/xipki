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
import java.io.FilenameFilter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
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

    private final String tbl_ca;
    private final String tbl_certhash;
    private final String col_caId;
    private final String col_certId;
    private final String col_certhash;
    private final String col_revoked;
    private final String col_revReason;
    private final String col_revTime;
    private final String col_revInvTime;
    private final String col_serialNumber;

    private final boolean revokedOnly;
    private final String dirnameA;
    private final DataSourceWrapper datasourceB;
    private final String reportDirName;
    private final AtomicBoolean stopMe;
    private final int numPerSelect;
    private Connection conn;
    private final String singleCertSql;
    private final String batchCertsSql;

    public DbDigestDiff(
            final boolean revokedOnly,
            final String dirnameA,
            final DataSourceWrapper datasourceB,
            final String reportDirName,
            final AtomicBoolean stopMe,
            final int numPerSelect)
    throws IOException, DataAccessException
    {
        ParamUtil.assertNotBlank("dirnameA", dirnameA);
        ParamUtil.assertNotBlank("reportDirName", reportDirName);
        ParamUtil.assertNotNull("datasourceB", datasourceB);
        ParamUtil.assertNotNull("stopMe", stopMe);
        if(numPerSelect < 1)
        {
            throw new IllegalArgumentException("invalid numPerSelect: " + numPerSelect);
        }

        this.revokedOnly = revokedOnly;
        this.dirnameA = IoUtil.expandFilepath(dirnameA);
        this.datasourceB = datasourceB;
        this.reportDirName = reportDirName;
        this.stopMe = stopMe;
        this.numPerSelect = numPerSelect;

        DbSchemaType datasourceType = DbDigestExportWorker.detectDbSchemaType(datasourceB);

        if(datasourceType == DbSchemaType.XIPKI_CA_v1
                || datasourceType == DbSchemaType.XIPKI_OCSP_v1)
        {
            if(datasourceType == DbSchemaType.XIPKI_CA_v1)
            { // CA
                tbl_ca = "CAINFO";
                tbl_certhash = "RAWCERT";
                col_caId = "CAINFO_ID";
            } else
            { // OCSP
                tbl_ca = "ISSUER";
                tbl_certhash = "CERTHASH";
                col_caId = "ISSUER_ID";
            }

            col_certhash = "SHA1_FP";
            col_certId = "CERT_ID";
            col_revInvTime = "REV_INVALIDITY_TIME";
            col_revoked = "REVOKED";
            col_revReason = "REV_REASON";
            col_revTime = "REV_TIME";
            col_serialNumber = "SERIAL";
        } else if(datasourceType == DbSchemaType.XIPKI_CA_v2
                || datasourceType == DbSchemaType.XIPKI_OCSP_v2)
        {
            if(datasourceType == DbSchemaType.XIPKI_CA_v2)
            { // CA
                tbl_ca = "CS_CA";
                tbl_certhash = "CRAW";
                col_caId = "CA_ID";
                col_certhash = "SHA1";
            } else
            { // OCSP
                tbl_ca = "ISSUER";
                tbl_certhash = "CHASH";
                col_caId = "IID";
                col_certhash = "S1";
            }

            col_certId = "CID";
            col_revInvTime = "RIT";
            col_revoked = "REV";
            col_revReason = "RR";
            col_revTime = "RT";
            col_serialNumber = "SN";
        } else
        {
            throw new RuntimeException("unsupported DbSchemaType " + datasourceType);
        }

        String coreSql =
                col_revoked + ","
                + col_revReason + ","
                + col_revTime + ","
                + col_revInvTime + ","
                + col_certhash
                + " FROM CERT INNER JOIN " + tbl_certhash
                + " ON CERT." + col_caId + "=?"
                + " AND CERT." + col_serialNumber + "=?"
                + " AND CERT.ID=" + tbl_certhash + "." + col_certId;
        singleCertSql = datasourceB.createFetchFirstSelectSQL(coreSql, 1);

        StringBuilder sb = new StringBuilder("?");
        for(int i = 1; i < numPerSelect; i++)
        {
            sb.append(",?");
        }

        coreSql =
                col_serialNumber + ","
                + col_revoked + ","
                + col_revReason + ","
                + col_revTime + ","
                + col_revInvTime + ","
                + col_certhash
                + " FROM CERT INNER JOIN " + tbl_certhash
                + " ON CERT." + col_caId + "=?"
                + " AND CERT." + col_serialNumber + " IN (" + sb.toString() + ")"
                + " AND CERT.ID=" + tbl_certhash + "." + col_certId;
        batchCertsSql = datasourceB.createFetchFirstSelectSQL(coreSql, numPerSelect);

        this.conn = datasourceB.getConnection();
    }

    public void diff()
    throws DataAccessException, IOException, InterruptedException
    {
        File dirA = new File(dirnameA);
        String[] caDirnamesA = dirA.list(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.startsWith("ca-");
            }
        });

        String sql = "SELECT ID, CERT FROM " + tbl_ca;
        Statement stmt = datasourceB.createStatement(conn);
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
            throw datasourceB.translate(sql, e);
        } finally
        {
            releaseResources(stmt, rs);
        }

        Map<String, DbDigestReader> caDigestReaderMap = new HashMap<>();
        Map<String, DbDigestReporter> caReporterMap = new HashMap<>();
        Map<String, Integer> a_b_map = new HashMap<>();
        for(String caDirnameA : caDirnamesA)
        {
            DbDigestReader reader = new DbDigestReader(dirnameA + File.separator + caDirnameA);

            byte[] caCertBytes = reader.getCaCert();
            DbDigestReporter reporter = new DbDigestReporter(
                    reportDirName + File.separator + caDirnameA, caCertBytes);

            for(Integer caId : caIdCertMap.keySet())
            {
                if(Arrays.equals(caCertBytes, caIdCertMap.get(caId)))
                {
                    a_b_map.put(caDirnameA, caId);
                    break;
                }
            }

            if(a_b_map.containsKey(caDirnameA))
            {
                caDigestReaderMap.put(caDirnameA, reader);
                caReporterMap.put(caDirnameA, reporter);
            } else
            {
                reporter.addNoCAMatch();
                reader.close();
                reporter.close();
            }
        }

        if(a_b_map.isEmpty())
        {
            return;
        }

        for(String caDirNameA : a_b_map.keySet())
        {
            DbDigestReader readerA = caDigestReaderMap.get(caDirNameA);
            int caIdB = a_b_map.get(caDirNameA);
            DbDigestReporter reporter = caReporterMap.get(caDirNameA);
            try
            {
                doDiff(readerA, caIdB, reporter);
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
                readerA.close();
            }
        }

    }

    private void doDiff(
            final DbDigestReader readerA,
            final int caIdB,
            final DbDigestReporter reporter)
    throws IOException, DataAccessException, InterruptedException
    {
        PreparedStatement singleSelectStmt = null;
        PreparedStatement batchSelectStmt = null;

        try
        {
            singleSelectStmt = datasourceB.prepareStatement(conn, singleCertSql);
            singleSelectStmt.setInt(1, caIdB);

            batchSelectStmt = datasourceB.prepareStatement(conn, batchCertsSql);
            batchSelectStmt.setInt(1, caIdB);

            ProcessLog processLog = new ProcessLog(readerA.getTotalAccount(),
                    System.currentTimeMillis(), 0);
            System.out.println("Processing certifiates of CA \n\t'" + readerA.getCaDirname() + "'");
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
                    Map<Long, DbDigestEntry> certsInB;

                    boolean batch = datasourceB.getDatabaseType() != DatabaseType.H2;
                    if(batch)
                    {
                        certsInB = getCertsViaBatchSelectInB(
                                singleSelectStmt, batchSelectStmt, myBundle.serialNumbers);
                    } else
                    {
                        certsInB = getCertsViaSingleSelectInB(
                                singleSelectStmt, myBundle.serialNumbers);
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
                            reporter.addOnlyInA(serialNumber);
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
            throw datasourceB.translate(singleCertSql, e);
        }finally
        {
            releaseResources(singleSelectStmt, null);
        }
    }

    private Map<Long, DbDigestEntry> getCertsViaBatchSelectInB(
            final PreparedStatement singleSelectStmt,
            final PreparedStatement batchSelectStmt,
            final List<Long> serialNumbers)
    throws DataAccessException
    {
        Collections.sort(serialNumbers);
        final int n = serialNumbers.size();
        final int nBlock = n / numPerSelect;

        Map<Long, DbDigestEntry> ret = new HashMap<>(n);

        int offset = 0;
        for(int i = 0; i < nBlock; i++)
        {
            retrieveBatchCertsInB(ret, batchSelectStmt, serialNumbers, offset);
            offset += numPerSelect;
        }

        if(offset < n)
        {
            for(; offset < n; offset++)
            {
                long serialNumber = serialNumbers.get(offset);
                DbDigestEntry cert = getSingleCert(singleSelectStmt, serialNumber);
                if(cert != null)
                {
                    ret.put(serialNumber, cert);
                }
            }
        }

        return ret;
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

    private void retrieveBatchCertsInB(
            final Map<Long, DbDigestEntry> result,
            final PreparedStatement batchSelectStmt,
            final List<Long> serialNumbers,
            final int offset)
    throws DataAccessException
    {
        final int n = serialNumbers.size();
        if(n != numPerSelect)
        {
            throw new IllegalArgumentException("size of serialNumbers is not '" + numPerSelect
                    + "': " + n);
        }

        ResultSet rs = null;

        try
        {
            for(int i = 0; i < n; i++)
            {
                batchSelectStmt.setLong(i+2, serialNumbers.get(i));
            }

            rs = batchSelectStmt.executeQuery();
            while(rs.next())
            {
                long serialNumber = rs.getLong(col_serialNumber);
                boolean revoked = rs.getBoolean(col_revoked);
                Integer revReason = null;
                Long revTime = null;
                Long revInvTime = null;
                if(revoked)
                {
                    revReason = rs.getInt(col_revReason);
                    revTime = rs.getLong(col_revTime);
                    revInvTime = rs.getLong(col_revInvTime);
                    if(revInvTime == 0)
                    {
                        revInvTime = null;
                    }
                }
                String sha1Fp = rs.getString(col_certhash);
                DbDigestEntry certB = new DbDigestEntry(serialNumber,
                        revoked, revReason, revTime, revInvTime, sha1Fp);
                result.put(serialNumber, certB);
            }
        } catch(SQLException e)
        {
            throw datasourceB.translate(batchCertsSql, e);
        }
        finally
        {
            releaseResources(null, rs);
        }
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
            boolean revoked = rs.getBoolean(col_revoked);
            Integer revReason = null;
            Long revTime = null;
            Long revInvTime = null;
            if(revoked)
            {
                revReason = rs.getInt(col_revReason);
                revTime = rs.getLong(col_revTime);
                revInvTime = rs.getLong(col_revInvTime);
                if(revInvTime == 0)
                {
                    revInvTime = null;
                }
            }
            String sha1Fp = rs.getString(col_certhash);
            return new DbDigestEntry(serialNumber,
                    revoked, revReason, revTime, revInvTime, sha1Fp);
        } catch(SQLException e)
        {
            throw datasourceB.translate(singleCertSql, e);
        } finally
        {
            releaseResources(null, rs);
        }
    }

    private MyBundle readNextLines(
            final DbDigestReader reader)
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
