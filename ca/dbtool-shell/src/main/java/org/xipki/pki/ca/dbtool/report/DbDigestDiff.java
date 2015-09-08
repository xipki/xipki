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

package org.xipki.pki.ca.dbtool.report;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.ProcessLog;

/**
 * @author Lijun Liao
 */

public class DbDigestDiff
{
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
    private final int numPerSelect;
    private Connection conn;
    private final String sqlCert;

    public DbDigestDiff(
            final boolean revokedOnly,
            final String dirnameA,
            final DataSourceWrapper datasourceB,
            final String reportDirName,
            final int numPerSelect)
    throws IOException, DataAccessException
    {
        ParamUtil.assertNotBlank("dirnameA", dirnameA);
        ParamUtil.assertNotBlank("reportDirName", reportDirName);
        ParamUtil.assertNotNull("datasourceB", datasourceB);
        if(numPerSelect < 1)
        {
            throw new IllegalArgumentException("invalid numPerSelect: " + numPerSelect);
        }

        this.revokedOnly = revokedOnly;
        this.dirnameA = IoUtil.expandFilepath(dirnameA);
        this.datasourceB = datasourceB;
        this.reportDirName = reportDirName;
        this.numPerSelect = numPerSelect;

        DbSchemaType datasourceType = DbDigestExportWorker.detectDbSchemaType(datasourceB);

        if(datasourceType == DbSchemaType.XIPKI_CA_v1 || datasourceType == DbSchemaType.XIPKI_OCSP_v1)
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
        } else if(datasourceType == DbSchemaType.XIPKI_CA_v2 || datasourceType == DbSchemaType.XIPKI_OCSP_v2)
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

        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("SELECT ");
        sqlBuilder.append(col_revoked).append(", ");
        sqlBuilder.append(col_revReason).append(", ");
        sqlBuilder.append(col_revTime).append(", ");
        sqlBuilder.append(col_revInvTime).append(", ");
        sqlBuilder.append(col_certhash).append(" ");
        sqlBuilder.append("FROM CERT ");
        sqlBuilder.append("INNER JOIN ");
        sqlBuilder.append(tbl_certhash).append(" ON ");
        sqlBuilder.append("CERT.").append(col_serialNumber).append("=? ");
        sqlBuilder.append("AND CERT.").append(col_caId).append("=? ");
        sqlBuilder.append("AND CERT.ID=").append(tbl_certhash).append(".").append(col_certId);
        sqlCert = sqlBuilder.toString();

        this.conn = datasourceB.getConnection();
    }

    public void diff()
    throws DataAccessException, IOException
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
            }catch(Exception e)
            {
                e.printStackTrace();
                reporter.addError("Exception thrown: " + e.getClass().getName() + ": " + e.getMessage());
            } finally
            {
                reporter.close();
                readerA.close();
            }
        }

    }

    @SuppressWarnings("unchecked")
    private void doDiff(
            final DbDigestReader readerA,
            final int caIdB,
            final DbDigestReporter reporter)
    throws IOException, DataAccessException
    {
        PreparedStatement selectStmt = null;

        try
        {
            selectStmt = datasourceB.prepareStatement(conn, sqlCert);
            selectStmt.setInt(2, caIdB);

            ProcessLog processLog = new ProcessLog(readerA.getTotalAccount(), System.currentTimeMillis(), 0);
            System.out.println("Processing certifiates of CA \n\t'" + readerA.getCaDirname() + "'");
            ProcessLog.printHeader();

            while(true)
            {
                Object[] objs = readNextLines(readerA);
                List<Long> serialNumbers = (List<Long>) objs[0];
                int n = serialNumbers.size();
                if(n == 0)
                {
                    break;
                }

                Map<Long, DbDigestEntry> certsMap = (Map<Long, DbDigestEntry>) objs[1];
                internal_diff(reporter, selectStmt, serialNumbers, certsMap, processLog);
            }
            processLog.printStatus(true);
            ProcessLog.printTrailer();
        } catch (SQLException e)
        {
            throw datasourceB.translate(sqlCert, e);
        }finally
        {
            releaseResources(selectStmt, null);
        }
    }

    private void internal_diff(
            final DbDigestReporter reporter,
            final PreparedStatement selectStmt,
            final List<Long> serialNumbers,
            final Map<Long, DbDigestEntry> certsMap,
            final ProcessLog processLog)
    throws DataAccessException, IOException
    {
        int n = serialNumbers.size();
        StringBuilder sb = new StringBuilder("(");
        for(int i = 0; i < n; i++)
        {
            if(i > 0)
            {
                sb.append(',');
            }
            sb.append(serialNumbers.get(i));
        }
        sb.append(")");

        String sql = sqlCert;
        ResultSet rs = null;

        try
        {
            for(Long serialNumber : new ArrayList<>(serialNumbers))
            {
                selectStmt.setLong(1, serialNumber);
                rs = selectStmt.executeQuery();
                if(rs.next())
                {
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
                    serialNumbers.remove(serialNumber);
                    DbDigestEntry certA = certsMap.get(serialNumber);

                    if(certA == null)
                    {
                        reporter.addError("sql error (should not happen)");
                    }
                    else if(certA.contentEquals(certB))
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
                processLog.addNumProcessed(1);
                processLog.printStatus();
            }
        } catch(SQLException e)
        {
            throw datasourceB.translate(sql, e);
        }
        finally
        {
            datasourceB.releaseResources(null, rs);
        }
    }

    private Object[] readNextLines(
            final DbDigestReader reader)
    throws IOException
    {
        List<Long> serialNumbers = new ArrayList<>(numPerSelect);
        Map<Long, DbDigestEntry> map = new HashMap<>(numPerSelect);

        int k = 0;
        while(reader.hasNext())
        {
            DbDigestEntry line = reader.nextCert();
            if(revokedOnly && line.isRevoked() == false)
            {
                continue;
            }

            k++;
            serialNumbers.add(line.getSerialNumber());
            map.put(line.getSerialNumber(), line);

            if(k >= numPerSelect)
            {
                break;
            }
        }

        return new Object[]{serialNumbers, map};
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
            }catch(SQLException e)
            {
            }
        }

        if(rs != null)
        {
            try
            {
                rs.close();
            }catch(SQLException e)
            {
            }
        }
    }

}
