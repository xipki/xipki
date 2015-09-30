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
import org.xipki.common.ProcessLog;
import org.xipki.common.util.IoUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.DbToolBase;
import org.xipki.pki.ca.dbtool.diffdb.internal.CaEntry;
import org.xipki.pki.ca.dbtool.diffdb.internal.CaEntryContainer;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbSchemaType;
import org.xipki.pki.ca.dbtool.diffdb.internal.XipkiDbControl;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class XipkiDigestExporter extends DbToolBase implements DbDigestExporter
{
    private static final Logger LOG = LoggerFactory.getLogger(XipkiDigestExporter.class);

    private final int numCertsPerSelect;

    private final XipkiDbControl dbControl;

    public XipkiDigestExporter(
            final DataSourceWrapper datasource,
            final String baseDir,
            final AtomicBoolean stopMe,
            final int numCertsPerSelect,
            final DbSchemaType dbSchemaType)
    throws DataAccessException, IOException
    {
        super(datasource, baseDir, stopMe);
        if (numCertsPerSelect < 1)
        {
            throw new IllegalArgumentException("numCertsPerSelect could not be less than 1: "
                    + numCertsPerSelect);
        }

        this.numCertsPerSelect = numCertsPerSelect;
        this.dbControl = new XipkiDbControl(dbSchemaType);
    }

    @Override
    public void digest()
    throws Exception
    {
        System.out.println("digesting database");

        int minCertId = (int) getMin("CERT", "ID");

        final long total = getCount("CERT");
        ProcessLog processLog = new ProcessLog(total);

        Map<Integer, String> caIdDirMap = getCaIds();
        Set<CaEntry> caEntries = new HashSet<>(caIdDirMap.size());

        for (Integer caId : caIdDirMap.keySet())
        {
            CaEntry caEntry = new CaEntry(caId, baseDir + File.separator + caIdDirMap.get(caId));
            caEntries.add(caEntry);
        }

        CaEntryContainer caEntryContainer = new CaEntryContainer(caEntries);

        Exception exception = null;
        try
        {
            doDigest(minCertId, processLog, caEntryContainer);
        } catch (Exception e)
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

        if (exception == null)
        {
            System.out.println(" digested database");
        } else
        {
            throw exception;
        }
    }

    private Map<Integer, String> getCaIds()
    throws DataAccessException, IOException
    {
        Map<Integer, String> caIdDirMap = new HashMap<>();
        final String sql = dbControl.getCaSql();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);
            while (rs.next())
            {
                int id = rs.getInt("ID");
                String b64Cert = rs.getString("CERT");
                byte[] certBytes = Base64.decode(b64Cert);

                Certificate cert = Certificate.getInstance(certBytes);
                String commonName = X509Util.getCommonName(cert.getSubject());

                String fn = toAsciiFilename("ca-" + commonName);
                File caDir = new File(baseDir, fn);
                int i = 2;
                while (caDir.exists())
                {
                    caDir = new File(baseDir, fn + "." + (i++));
                }

                File caCertFile = new File(caDir, "ca.der");
                caDir.mkdirs();
                IoUtil.save(caCertFile, certBytes);

                caIdDirMap.put(id, caDir.getName());
            }
        } catch (SQLException e)
        {
            throw translate(sql, e);
        } finally
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

        PreparedStatement certPs = prepareStatement(dbControl.getCertSql());

        processLog.printHeader();

        try
        {
            boolean interrupted = false;

            for (int i = minCertId; i <= maxCertId; i += numCertsPerSelect)
            {
                if (stopMe.get())
                {
                    interrupted = true;
                    break;
                }

                certPs.setInt(1, i);
                certPs.setInt(2, i + numCertsPerSelect);

                ResultSet rs = certPs.executeQuery();

                while (rs.next())
                {
                    int caId = rs.getInt(dbControl.getColCaId());
                    int id = rs.getInt("ID");
                    String hash = rs.getString(dbControl.getColCerthash());
                    long serial = rs.getLong(dbControl.getColSerialNumber());
                    boolean revoked = rs.getBoolean(dbControl.getColRevoked());

                    Integer revReason = null;
                    Long revTime = null;
                    Long revInvTime = null;

                    if (revoked)
                    {
                        revReason = rs.getInt(dbControl.getColRevReason());
                        revTime = rs.getLong(dbControl.getColRevTime());
                        revInvTime = rs.getLong(dbControl.getColRevInvTime());
                        if (revInvTime == 0)
                        {
                            revInvTime = null;
                        }
                    }

                    DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                            revInvTime, hash);
                    caEntryContainer.addDigestEntry(caId, id, cert);

                    processLog.addNumProcessed(1);
                    processLog.printStatus();
                }
                rs.close();
            } // end for

            if (interrupted)
            {
                throw new InterruptedException("interrupted by the user");
            }
        } catch (SQLException e)
        {
            throw translate(dbControl.getCertSql(), e);
        } finally
        {
            releaseResources(certPs, null);
        }

        processLog.printTrailer();

        System.out.println(" digested " + processLog.getNumProcessed() + " certificates");
    }

    static String toAsciiFilename(
            final String filename)
    {
        final int n = filename.length();
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++)
        {
            char c = filename.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-' || c == ' ')
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
