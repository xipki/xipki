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
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.IoUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.ProcessLog;

/**
 * @author Lijun Liao
 */

public class OcspDbReporter extends DbReporter
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspDbReporter.class);

    public OcspDbReporter(
            final DataSourceWrapper datasource,
            final String baseDir,
            final AtomicBoolean stopMe,
            final int numCertsPerSelect)
    throws DataAccessException, IOException
    {
        super(datasource, baseDir, stopMe, numCertsPerSelect);
    }

    public void report()
    throws Exception
    {
        ProcessLog processLog;
        {
            final long total = getCount("CERT");
            processLog = new ProcessLog(total, System.currentTimeMillis(), 0);
        }

        Set<Integer> caIds = getCas();

        int sum = 0;
        Exception exception = null;
        try
        {
            for(Integer caId : caIds)
            {
                sum += doReport(caId, processLog);
            }
        }catch(Exception e)
        {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-");
            System.err.println("\nreporting process has been cancelled due to error");
            LOG.error("Exception", e);
            exception = e;
        }

        if(exception == null)
        {
            System.out.println(" reported " + sum + " certificates");
        }
        else
        {
            throw exception;
        }
    }

    private Set<Integer> getCas()
    throws DataAccessException, IOException
    {
        Set<Integer> caIds = new HashSet<>();
        final String sql = "SELECT ID, CERT FROM ISSUER";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);
            while(rs.next())
            {
                int id = rs.getInt("ID");
                File caDir = new File(baseDir, "ca-" + id);
                File caCertFile = new File(caDir, "ca.der");

                if(caCertFile.exists() == false)
                {
                    caDir.mkdirs();
                    String cert = rs.getString("CERT");
                    byte[] certBytes = Base64.decode(cert);
                    IoUtil.save(caCertFile, certBytes);
                }
                caIds.add(id);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        return caIds;
    }

    private int doReport(
            final int caId,
            final ProcessLog processLog)
    throws Exception
    {
        final String sql = "SELECT T1.ID ID, T1.SN SN, T1.REV REV, T1.RR RR, T1.RT RT, T1.RIT RIT, T2.S1 SHA1 "
                + "FROM CERT T1, CHASH T2 WHERE T1.IID=" + caId + " AND T1.ID>=? AND T1.ID<? AND T2.CID=T1.ID";

        System.out.println("reporting tables CERT and CHASH for CA " + caId);

        final int minCertId = (int) getMin("CERT", "ID", "IID=" + caId);
        final int maxCertId = (int) getMax("CERT", "ID", "IID=" + caId);

        PreparedStatement ps = prepareStatement(sql);

        int numCertsInBundle = DFLT_NUM_CERTS_IN_BUNDLE;

        List<String> certsFileNames = new LinkedList<>();

        File currentCertsZipFile = new File(new File(baseDir, "ca-" + caId), "report.zip");
        ZipOutputStream zipStream = getZipOutputStream(currentCertsZipFile);

        {
            String singleFilename = buildFilename("certs_", ".csv", minCertId);
            ZipEntry zipEntry = new ZipEntry(singleFilename);
            zipStream.putNextEntry(zipEntry);
            certsFileNames.add(singleFilename);
        }

        int sum = 0;
        int numCertInCurrentFile = 0;

        ProcessLog.printHeader();

        Integer id = null;
        try
        {
            boolean interrupted = false;
            for(int i = minCertId; i <= maxCertId; i += numCertsPerSelect)
            {
                if(stopMe.get())
                {
                    interrupted = true;
                    break;
                }

                ps.setInt(1, i);
                ps.setInt(2, i + numCertsPerSelect);

                ResultSet rs = ps.executeQuery();

                while(rs.next())
                {
                    id = rs.getInt("ID");

                    ReportEntry cert = new ReportEntry();

                    String b64Sha1 = rs.getString("SHA1");
                    cert.setBase64Sha1(b64Sha1);

                    cert.setId(id);

                    long serial = rs.getLong("SN");
                    cert.setSerialNumber(serial);

                    boolean revoked = rs.getBoolean("REV");
                    cert.setRevoked(revoked);

                    if(revoked)
                    {
                        int rev_reason = rs.getInt("RR");
                        long rev_time = rs.getLong("RT");
                        long rev_invalidity_time = rs.getLong("RIT");
                        cert.setRevReason(rev_reason);
                        cert.setRevTime(rev_time);
                        if(rev_invalidity_time != 0)
                        {
                            cert.setRevInvTime(rev_invalidity_time);
                        }
                    }

                    zipStream.write(cert.getEncoded().getBytes());
                    zipStream.write('\n');

                    numCertInCurrentFile ++;
                    sum++;

                    if(numCertInCurrentFile == numCertsInBundle)
                    {
                        zipStream.closeEntry();

                        String singleFilename = buildFilename("certs_", ".csv", id + 1);
                        ZipEntry zipEntry = new ZipEntry(singleFilename);
                        zipStream.putNextEntry(zipEntry);
                        certsFileNames.add(singleFilename);

                        processLog.addNumProcessed(numCertInCurrentFile);
                        processLog.printStatus();

                        // reset
                        numCertInCurrentFile = 0;
                    }
                }
            } // end for

            if(interrupted)
            {
                justThrowsException();
            }

            if(numCertInCurrentFile > 0)
            {
                finalizeZip(zipStream, certsFileNames, sum);

                processLog.addNumProcessed(numCertInCurrentFile);
                processLog.printStatus(true);
            }
            else
            {
                zipStream.close();
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(ps, null);
        }

        ProcessLog.printTrailer();

        System.out.println(" reported" + processLog.getNumProcessed() +
                " certificates for CA " + caId);
        return sum;
    }

    private void justThrowsException()
    throws InterruptedException
    {
        throw new InterruptedException("interrupted by the user");
    }

    private void finalizeZip(
            final ZipOutputStream zipOutStream,
            final List<String> certsFileNames,
            final int sum)
    throws JAXBException, IOException, XMLStreamException
    {
        ZipEntry entry = new ZipEntry("account");
        zipOutStream.putNextEntry(entry);
        zipOutStream.write(Integer.toString(sum).getBytes());
        zipOutStream.closeEntry();

        ZipEntry certZipEntry = new ZipEntry("certs-manifest");
        zipOutStream.putNextEntry(certZipEntry);

        for(String fn : certsFileNames)
        {
            zipOutStream.write(fn.getBytes());
            zipOutStream.write('\n');
        }

        zipOutStream.closeEntry();

        zipOutStream.close();
    }

}
