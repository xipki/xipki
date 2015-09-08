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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.IoUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.DbToolBase;
import org.xipki.pki.ca.dbtool.ProcessLog;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class XipkiDigestExporter extends DbToolBase implements DbDigestExporter
{
    private static final Logger LOG = LoggerFactory.getLogger(XipkiDigestExporter.class);

    private final int numCertsPerSelect;

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

    private final String caSql;
    private final String certSql;

    public XipkiDigestExporter(
            final DataSourceWrapper datasource,
            final String baseDir,
            final AtomicBoolean stopMe,
            final int numCertsPerSelect,
            final DbSchemaType dbSchemaType)
    throws DataAccessException, IOException
    {
        super(datasource, baseDir, stopMe);
        if(numCertsPerSelect < 1)
        {
            throw new IllegalArgumentException("numCertsPerSelect could not be less than 1: " + numCertsPerSelect);
        }

        this.numCertsPerSelect = numCertsPerSelect;

        if(dbSchemaType == DbSchemaType.XIPKI_CA_v1 || dbSchemaType == DbSchemaType.XIPKI_OCSP_v1)
        {
            if(dbSchemaType == DbSchemaType.XIPKI_CA_v1)
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
        } else if(dbSchemaType == DbSchemaType.XIPKI_CA_v2 || dbSchemaType == DbSchemaType.XIPKI_OCSP_v2)
        {
            if(dbSchemaType == DbSchemaType.XIPKI_CA_v2)
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
            throw new RuntimeException("unsupported DbSchemaType " + dbSchemaType);
        }

        // CA SQL
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT ID, CERT FROM ").append(tbl_ca);
        this.caSql = sb.toString();

        // CERT SQL
        sb.delete(0, sb.length());
        sb.append("SELECT ID,");
        sb.append(col_caId).append(",");
        sb.append(col_serialNumber).append(",");
        sb.append(col_revoked).append(",");
        sb.append(col_revReason).append(",");
        sb.append(col_revTime).append(",");
        sb.append(col_revInvTime).append(",");
        sb.append(col_certhash);
        sb.append(" FROM CERT INNER JOIN ").append(tbl_certhash);
        sb.append(" ON CERT.ID>=? AND CER.ID<? AND CERT.ID=");
        sb.append(tbl_certhash).append(".").append(col_certId);
        sb.append(" ORDER BY CERT.ID ASC");
        this.certSql = sb.toString();
    }

    @Override
    public void digest()
    throws Exception
    {
        System.out.println("digesting database");

        int minCertId = (int) getMin("CERT", "ID");

        ProcessLog processLog;
        {
            final long total = getCount("CERT");
            processLog = new ProcessLog(total, System.currentTimeMillis(), 0);
        }

        Map<Integer, String> caIdDirMap = getCaIds();
        Set<CaEntry> caEntries = new HashSet<>(caIdDirMap.size());

        for(Integer caId : caIdDirMap.keySet())
        {
            CaEntry caEntry = new CaEntry(caId, baseDir + File.separator + caIdDirMap.get(caId));
            caEntries.add(caEntry);
        }

        CaEntryContainer caEntryContainer = new CaEntryContainer(caEntries);

        Exception exception = null;
        try
        {
            doDigest(minCertId, processLog, caEntryContainer);
        }catch(Exception e)
        {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-");
            System.err.println("\ndigesting process has been cancelled due to error");
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

    private Map<Integer, String> getCaIds()
    throws DataAccessException, IOException
    {
        Map<Integer, String> caIdDirMap = new HashMap<>();
        final String sql = caSql;

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);
            while(rs.next())
            {
                int id = rs.getInt("ID");
                String b64Cert = rs.getString("CERT");
                byte[] certBytes = Base64.decode(b64Cert);

                Certificate cert = Certificate.getInstance(certBytes);
                String commonName = X509Util.getCommonName(cert.getSubject());

                String fn = toAsciiFilename("ca-" + commonName);
                File caDir = new File(baseDir, fn);
                int i = 2;
                while(caDir.exists())
                {
                    caDir = new File(baseDir, fn + "." + (i++));
                }

                File caCertFile = new File(caDir, "ca.der");
                caDir.mkdirs();
                IoUtil.save(caCertFile, certBytes);

                caIdDirMap.put(id, caDir.getName());
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        return caIdDirMap;
    }

    private void doDigest(
            final int minCertId,
            final ProcessLog processLog,
            final CaEntryContainer caEntryContainer)
    throws Exception
    {
        System.out.println("digesting certificates from ID " + minCertId);

        final int maxCertId = (int) getMax("CERT", "ID");

        PreparedStatement certPs = prepareStatement(certSql);

        ProcessLog.printHeader();

        String sql = null;

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

                sql = certSql;
                certPs.setInt(1, i);
                certPs.setInt(2, i + numCertsPerSelect);

                ResultSet rs = certPs.executeQuery();

                while(rs.next())
                {
                    int caId = rs.getInt(col_caId);
                    int id = rs.getInt("ID");
                    String hash = rs.getString(col_certhash);
                    long serial = rs.getLong(col_serialNumber);
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

                    DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime, revInvTime, hash);
                    caEntryContainer.addDigestEntry(caId, id, cert);

                    processLog.addNumProcessed(1);
                    processLog.printStatus();
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
            releaseResources(certPs, null);
        }

        processLog.printStatus(true);
        ProcessLog.printTrailer();

        System.out.println(" digested " + processLog.getNumProcessed() +
                " certificates");
    }

    private void justThrowsException()
    throws InterruptedException
    {
        throw new InterruptedException("interrupted by the user");
    }

    static String toAsciiFilename(String filename)
    {
        final int n = filename.length();
        StringBuilder sb = new StringBuilder(n);
        for(int i = 0; i < n; i++)
        {
            char c = filename.charAt(i);
            if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '-' || c == ' ')
            {
                sb.append(c);
            } else
            {
                sb.append('_');
            }
        }
        return sb.toString();
    }

}
