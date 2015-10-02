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

package org.xipki.pki.ca.dbtool.diffdb.internal;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.DbToolBase;
import org.xipki.pki.ca.dbtool.IDRange;

/**
 * @author Lijun Liao
 */

public class EjbcaDigestExportReader
{
    private static final Logger LOG = LoggerFactory.getLogger(EjbcaDigestExportReader.class);

    private class Retriever
    implements Runnable
    {
        private Connection conn;
        private PreparedStatement selectCertStmt;
        private PreparedStatement selectRawCertStmt;

        public Retriever()
        throws DataAccessException
        {
            this.conn = datasource.getConnection();
            try
            {
                selectCertStmt = datasource.prepareStatement(conn, selectCertSql);
                selectRawCertStmt = datasource.prepareStatement(conn, selectRawCertSql);
            } catch (DataAccessException e)
            {
                DbToolBase.releaseResources(selectCertStmt, null);
                DbToolBase.releaseResources(selectRawCertStmt, null);
                datasource.returnConnection(conn);
                throw e;
            }
        }

        @Override
        public void run()
        {
            while (!stop.get())
            {
                try
                {
                    IDRange idRange = inQueue.take();
                    query(idRange);
                } catch (InterruptedException e)
                {
                    LOG.error("InterruptedException", e);
                }
            }

            DbToolBase.releaseResources(selectCertStmt, null);
            datasource.returnConnection(conn);
            selectCertStmt = null;
        }

        private void query(
                final IDRange idRange)
        {
            DigestDBEntrySet result = new DigestDBEntrySet(idRange.getFrom());

            ResultSet rs = null;
            try
            {
                selectCertStmt.setInt(1, idRange.getFrom());
                selectCertStmt.setInt(2, idRange.getTo() + 1);

                rs = selectCertStmt.executeQuery();

                int id;
                String hexCaFp;
                String hexCertFp;

                while (rs.next())
                {
                    id = rs.getInt("id");
                    hexCaFp = rs.getString("cAFingerprint");
                    hexCertFp = rs.getString("fingerprint");

                    EjbcaCaInfo caInfo = null;

                    if (!hexCaFp.equals(hexCertFp))
                    {
                        caInfo = fpCaInfoMap.get(hexCaFp);
                    }

                    if (caInfo == null)
                    {
                        LOG.debug("Found no CA by caFingerprint, try to resolve by issuer");
                        selectRawCertStmt.setInt(1, id);

                        ResultSet certRs = selectRawCertStmt.executeQuery();

                        if (certRs.next())
                        {
                            String b64Cert = certRs.getString("base64Cert");
                            Certificate cert = Certificate.getInstance(Base64.decode(b64Cert));
                            for (EjbcaCaInfo entry : fpCaInfoMap.values())
                            {
                                if (entry.getSubject().equals(cert.getIssuer()))
                                {
                                    caInfo = entry;
                                    break;
                                }
                            }
                        }
                        certRs.close();
                    }

                    if (caInfo == null)
                    {
                        LOG.error("FOUND no CA for Cert with id '{}'", id);
                        numSkippedCerts.incrementAndGet();
                        continue;
                    }

                    String hash = Base64.toBase64String(Hex.decode(hexCertFp));

                    String s = rs.getString("serialNumber");
                    long serial = Long.parseLong(s);

                    int status = rs.getInt("status");
                    boolean revoked = (status == 40);

                    Integer revReason = null;
                    Long revTime = null;
                    Long revInvTime = null;

                    if (revoked)
                    {
                        revReason = rs.getInt("revocationReason");
                        long rev_timeInMs = rs.getLong("revocationDate");
                        // rev_time is milliseconds, convert it to seconds
                        revTime = rev_timeInMs / 1000;
                    }

                    DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                            revInvTime, hash);

                    IdentifiedDbDigestEntry idCert = new IdentifiedDbDigestEntry(cert, id);
                    idCert.setCaId(caInfo.getCaId());

                    result.addEntry(idCert);
                }
            } catch (Exception e)
            {
                if (e instanceof SQLException)
                {
                    e = datasource.translate(selectCertSql, (SQLException) e);
                }
                result.setException(e);
            }
            finally
            {
                outQueue.add(result);
                DbToolBase.releaseResources(null, rs);
            }
        }
    }

    protected final AtomicBoolean stop = new AtomicBoolean(false);
    protected final BlockingDeque<IDRange> inQueue = new LinkedBlockingDeque<>();
    protected final BlockingDeque<DigestDBEntrySet> outQueue = new LinkedBlockingDeque<>();
    private final int numThreads;
    private ExecutorService executor;
    private final List<Retriever> retrievers;
    private final DataSourceWrapper datasource;
    private final Map<String, EjbcaCaInfo> fpCaInfoMap;

    private final String selectCertSql;
    private final String selectRawCertSql;
    private final AtomicInteger numSkippedCerts = new AtomicInteger(0);

    public EjbcaDigestExportReader(
            final DataSourceWrapper datasource,
            final Map<String, EjbcaCaInfo> fpCaInfoMap,
            final int numThreads)
    throws Exception
    {
        this.datasource = datasource;
        this.numThreads = numThreads;
        this.fpCaInfoMap = fpCaInfoMap;

        selectCertSql =
                "SELECT id, fingerprint, serialNumber, cAFingerprint, status, revocationReason,"
                + " revocationDate"
                + " FROM CertificateData WHERE id >= ? AND id < ? ORDER BY id ASC";

        selectRawCertSql = "SELECT base64Cert FROM CertificateData WHERE id=?";

        retrievers = new ArrayList<>(numThreads);

        for (int i = 0; i < numThreads; i++)
        {
            Retriever retriever = new Retriever();
            retrievers.add(retriever);
        }

        executor = Executors.newFixedThreadPool(numThreads);
        for (Runnable runnable : retrievers)
        {
            executor.execute(runnable);
        }
    }

    public List<IdentifiedDbDigestEntry> readCerts(List<IDRange> idRanges)
    throws DataAccessException
    {
        int n = idRanges.size();
        for (IDRange range : idRanges)
        {
            inQueue.add(range);
        }

        List<DigestDBEntrySet> results = new ArrayList<>(n);
        int numCerts = 0;
        for (int i = 0; i < n; i++)
        {
            try
            {
                DigestDBEntrySet result = outQueue.take();
                numCerts += result.getEntries().size();
                results.add(result);
            } catch (InterruptedException e)
            {
                throw new DataAccessException("InterruptedException " + e.getMessage(), e);
            }
        }

        Collections.sort(results);
        List<IdentifiedDbDigestEntry> ret = new ArrayList<>(numCerts);

        for (DigestDBEntrySet result : results)
        {
            if (result.getException() != null)
            {
                throw new DataAccessException(
                        "error while reading from ID " + result.getStartId()
                            + ": " + result.getException().getMessage(),
                        result.getException());
            }

            ret.addAll(result.getEntries());
        }

        return ret;
    }

    public int getNumThreads()
    {
        return numThreads;
    }

    public int getNumSkippedCerts()
    {
        return numSkippedCerts.get();
    }

    public void stop()
    {
        stop.set(true);
        executor.shutdownNow();
    }
}
