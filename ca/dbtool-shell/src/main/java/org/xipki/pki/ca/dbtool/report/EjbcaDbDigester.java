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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.DbPorter;
import org.xipki.pki.ca.dbtool.DbToolBase;
import org.xipki.pki.ca.dbtool.ProcessLog;
import org.xipki.security.api.HashCalculator;

/**
 * @author Lijun Liao
 */

public class EjbcaDbDigester extends DbToolBase
{
    private static class CaInfo
    {
        final int caId;
        final X500Name subject;
        final String hexSha1;

        public CaInfo(int caId, byte[] certBytes)
        {
            this.caId = caId;
            this.hexSha1 = HashCalculator.hexSha1(certBytes);
            this.subject = Certificate.getInstance(certBytes).getSubject();
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(EjbcaDbDigester.class);

    public static final String PROCESS_LOG_FILENAME = "digest.process";

    protected final boolean resume;
    protected final int numCertsPerSelect;

    private final boolean tblCertHasId;

    private final String sql;
    private final String certSql;

    public EjbcaDbDigester(
            final DataSourceWrapper datasource,
            final String baseDir,
            final AtomicBoolean stopMe,
            final boolean resume,
            final int numCertsPerSelect)
    throws DataAccessException, IOException
    {
        super(datasource, baseDir, stopMe);
        if(numCertsPerSelect < 1)
        {
            throw new IllegalArgumentException("numCertsPerSelect could not be less than 1: " + numCertsPerSelect);
        }

        this.resume = resume;
        this.numCertsPerSelect = numCertsPerSelect;

        File f = new File(baseDir);
        if(f.exists() == false)
        {
            f.mkdirs();
        }
        else
        {
            if(f.isDirectory() == false)
            {
                throw new IOException(baseDir + " is not a folder");
            }

            if(f.canWrite() == false)
            {
                throw new IOException(baseDir + " is not writable");
            }
        }

        if(resume == false)
        {
            String[] children = f.list();
            if(children != null && children.length > 0)
            {
                throw new IOException(baseDir + " is not empty");
            }
        }

        // detect the type of:
        int dbSchemaType = detectDbSchemaType();

        if(dbSchemaType == 1)
        {
            tblCertHasId = true;
            sql = "SELECT id, cAFingerprint, status, revocationReason, revocationDate, username " +
                    " FROM CertificateData WHERE id >= ? AND id < ? ORDER BY id ASC";
            certSql = "SELECT base64Cert FROM CertificateData WHERE id=?";
        } else if(dbSchemaType == 2)
        {
            tblCertHasId = false;
            String coreSql =
                    "FINGERPRINT, cAFingerprint, status, revocationReason, revocationDate, username, base64Cert" +
                    " FROM CertificateData WHERE FINGERPRINT > ?";
            sql = dataSource.createFetchFirstSelectSQL(coreSql, numCertsPerSelect, "FINGERPRINT ASC");
            certSql = "SELECT base64Cert FROM CertificateData WHERE FINGERPRINT=?";
        } else
        {
            throw new RuntimeException("should not reach here");
        }
    }

    /**
     *
     * @return 1 for EJBCA v3 with column id in table CertificateData,
     *   2 for EJBCA v3 without column id in table CertificateData
     */
    private int detectDbSchemaType()
    throws DataAccessException
    {
        if(dataSource.tableHasColumn(connection, "CertificateData", "id"))
        {
            return 1;
        }
        else
        {
            return 2;
        }
    }

    public void digest()
    throws Exception
    {
        File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);

        System.out.println("digesting database");

        int numProcessedBefore = 0;
        int minCertId = -1;
        if(processLogFile.exists())
        {
            byte[] content = IoUtil.read(processLogFile);
            if(content != null && content.length > 2)
            {
                String str = new String(content);
                if(str.trim().equalsIgnoreCase(DbPorter.MSG_CERTS_FINISHED))
                {
                    return;
                }

                StringTokenizer st = new StringTokenizer(str, ":");
                numProcessedBefore = Integer.parseInt(st.nextToken());
                minCertId = Integer.parseInt(st.nextToken());
                minCertId++;
            }
        }

        if(minCertId == -1)
        {
            minCertId = (int) getMin("CERT", "ID");
        }

        ProcessLog processLog;
        {
            final long total = getCount("CERT") - numProcessedBefore;
            processLog = new ProcessLog(total, System.currentTimeMillis(), numProcessedBefore);
        }

        Map<String, CaInfo> cas = getCas();
        Set<CaEntry> caEntries = new HashSet<>(cas.size());

        File fBaseDir = new File(baseDir);
        for(CaInfo caInfo : cas.values())
        {
            CaEntry caEntry = new CaEntry(caInfo.caId, fBaseDir);
            caEntries.add(caEntry);
        }

        CaEntryContainer caEntryContainer = new CaEntryContainer(caEntries);

        Exception exception = null;
        try
        {
            if(tblCertHasId)
            {
                doReportWithId(minCertId, processLogFile, processLog, caEntryContainer, cas);
            } else
            {
                // TODO doReportWithoutId(minCertId, processLogFile, processLog, caEntryContainer, cas);
            }
        }catch(Exception e)
        {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-");
            System.err.println("\ndigesting process has been cancelled due to error,\n"
                    + "please continue with the option '--resume'");
            LOG.error("Exception", e);
            exception = e;
        } finally
        {
            caEntryContainer.close();
        }

        if(exception == null)
        {
            System.out.println(" digested database");
        }
        else
        {
            throw exception;
        }
    }

    private Map<String, CaInfo> getCas()
    throws Exception
    {
        Map<String, CaInfo> cas = new HashMap<>();
        final String sql = "SELECT NAME, DATA FROM CAData";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);
            while(rs.next())
            {
                String name = rs.getString("NAME");
                String data = rs.getString("DATA");
                if(name == null || name.isEmpty())
                {
                    continue;
                }

                Element rootElement = XMLUtil.getDocumentElment(data.getBytes());
                final String XPATH_CERT = "/java/object/void[string[position()=1]='certificatechain']/object/void/string[1]";
                String cert = XMLUtil.getValueOfFirstMatch(rootElement, XPATH_CERT, null);
                if(cert == null)
                {
                    throw new Exception("Could not extract CA certificate");
                }

                byte[] certBytes = Base64.decode(cert);

                // find out the id
                File fBaseDir = new File(baseDir);
                File[] caDirs = fBaseDir.listFiles();
                int maxCurrentCaId = 0;
                int caId = 0;

                if(caDirs != null)
                {
                    Map<Integer, byte[]> caIdCertMap = new HashMap<>(caDirs.length);
                    for(File caDir : caDirs)
                    {
                        int id = Integer.parseInt(caDir.getName().substring("ca-".length()));
                        byte[] cacertBytes = IoUtil.read(new File(caDir, "ca.der"));
                        caIdCertMap.put(id, cacertBytes);

                        if(maxCurrentCaId < id)
                        {
                            maxCurrentCaId = id;
                        }
                    }

                    for(Integer id : caIdCertMap.keySet())
                    {
                        if(Arrays.equals(certBytes, caIdCertMap.get(caId)))
                        {
                            caId = id;
                        }
                    }
                }

                if(caId == 0)
                {
                    caId = maxCurrentCaId + 1;
                    File caDir = new File(baseDir, "ca-" + caId);
                    File caCertFile = new File(caDir, "ca.der");
                    IoUtil.save(caCertFile, certBytes);
                }

                CaInfo caInfo = new CaInfo(caId, certBytes);
                cas.put(caInfo.hexSha1, caInfo);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        return cas;
    }

    private void doReportWithId(
            final int minCertId,
            final File processLogFile,
            final ProcessLog processLog,
            final CaEntryContainer caEntryContainer,
            final Map<String, CaInfo> caInfos)
    throws Exception
    {
        System.out.println("digesting certificates from id " + minCertId);

        final int maxCertId = (int) getMax("CertificateData", "id");

        PreparedStatement ps = prepareStatement(sql);
        PreparedStatement certPs = prepareStatement(certSql);

        ProcessLog.printHeader();

        String sql = null;
        Integer id = null;

        try
        {
            boolean interrupted = false;
            int k = 0;

            for(int i = minCertId; i <= maxCertId; i += numCertsPerSelect)
            {
                if(stopMe.get())
                {
                    interrupted = true;
                    break;
                }

                certPs.setInt(1, i);
                certPs.setInt(2, i + numCertsPerSelect);

                ResultSet rs = ps.executeQuery();

                while(rs.next())
                {
                    id = rs.getInt("id");
                    String username = rs.getString("username");
                    String hexCaFp = rs.getString("cAFingerprint");

                    CaInfo caInfo = getCaInfo(caInfos, username, hexCaFp, id, null, certPs);
                    if(caInfo == null)
                    {
                        continue;
                    }

                    DbDigestEntry cert = buildDigestEntry(id, rs);
                    caEntryContainer.addDigestEntry(caInfo.caId, cert);

                    processLog.addNumProcessed(1);

                    k++;
                    if(k == 1000)
                    {
                        processLog.printStatus();
                        k = 0;
                    }
                }

                rs.close();
            } // end for

            if(interrupted)
            {
                justThrowsException();
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(ps, null);
            releaseResources(certPs, null);
        }

        processLog.printStatus(true);
        ProcessLog.printTrailer();
        // all successful, delete the processLogFile
        processLogFile.delete();

        System.out.println(" digested " + processLog.getNumProcessed() +
                " certificates");
    }

    private void doReportWithoutId(
            String lastProcessedHexCertFp,
            final File processLogFile,
            final ProcessLog processLog,
            final CaEntryContainer caEntryContainer,
            final Map<String, CaInfo> caInfos)
    throws Exception
    {
        System.out.println("digesting certificates from fingerprint (exclusive)\n\t" + lastProcessedHexCertFp);

        final int maxCertId = (int) getMax("CertificateData", "id");

        PreparedStatement ps = prepareStatement(sql);
        PreparedStatement certPs = prepareStatement(certSql);

        ProcessLog.printHeader();

        String sql = null;
        Integer id = null;

        try
        {
            boolean interrupted = false;
            int k = 0;

            while(true)
            {
                if(stopMe.get())
                {
                    interrupted = true;
                    break;
                }

                ps.setString(1, lastProcessedHexCertFp);

                ResultSet rs = ps.executeQuery();

                while(rs.next())
                {
                    id = rs.getInt("id");
                    String username = rs.getString("username");
                    String hexCaFp = rs.getString("cAFingerprint");

                    CaInfo caInfo = getCaInfo(caInfos, username, hexCaFp, id, null, certPs);

                    if(caInfo == null)
                    {
                        continue;
                    }

                    lastProcessedHexCertFp = rs.getString("FINGERPRINT");
                    DbDigestEntry cert = buildDigestEntry(id, rs);

                    caEntryContainer.addDigestEntry(caInfo.caId, cert);

                    processLog.addNumProcessed(1);

                    k++;
                    if(k == 1000)
                    {
                        processLog.printStatus();
                        k = 0;
                    }
                }

                rs.close();
            } // end for

            if(interrupted)
            {
                justThrowsException();
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(ps, null);
            releaseResources(certPs, null);
        }

        processLog.printStatus(true);
        ProcessLog.printTrailer();
        // all successful, delete the processLogFile
        processLogFile.delete();

        System.out.println(" reported " + processLog.getNumProcessed() +
                " certificates");
    }

    private void justThrowsException()
    throws InterruptedException
    {
        throw new InterruptedException("interrupted by the user");
    }

    private static CaInfo getCaInfo(
            final Map<String, CaInfo> caInfos,
            final String username,
            final String hexCaFp,
            final Integer id,
            final String hexFp,
            final PreparedStatement certPs)
    throws Exception
    {
        CaInfo caInfo = null;

        if(username.startsWith("systemca") == false)
        {
            caInfo = caInfos.get(hexCaFp);
        }

        if ( caInfo != null)
        {
            return caInfo;
        }

        if(id != null)
        {
            certPs.setInt(1, id);
        } else
        {
            certPs.setString(1, hexFp);
        }

        ResultSet certRs = certPs.executeQuery();

        if(certRs.next())
        {
            String b64Cert = certRs.getString("base64Cert");
            Certificate cert = Certificate.getInstance(Base64.decode(b64Cert));
            for(CaInfo entry : caInfos.values())
            {
                if(entry.subject.equals(cert.getIssuer()))
                {
                    caInfo = entry;
                    break;
                }
            }
        }
        certRs.close();

        return caInfo;
    }

    private static DbDigestEntry buildDigestEntry(int id, ResultSet rs)
    throws SQLException
    {
        DbDigestEntry cert = new DbDigestEntry();
        cert.setId(id);

        String hexHash = rs.getString("fingerprint");
        String hash = Base64.toBase64String(Hex.decode(hexHash));
        cert.setBase64Sha1(hash);

        String s = rs.getString("serialNumber");
        long serial = Long.parseLong(s);
        cert.setSerialNumber(serial);

        int status = rs.getInt("status");
        boolean revoked = (status != 20);
        cert.setRevoked(revoked);

        if(revoked)
        {
            int rev_reason = rs.getInt("revocationReason");
            cert.setRevReason(rev_reason);

            long rev_timeInMs = rs.getLong("revocationDate");
            // rev_time is milliseconds, convert it to seconds
            long rev_time = rev_timeInMs / 1000;
            cert.setRevTime(rev_time);
            cert.setRevInvTime(null);
        }

        return cert;
    }
}
