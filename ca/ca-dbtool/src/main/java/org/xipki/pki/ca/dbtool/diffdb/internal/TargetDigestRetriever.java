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
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.atomic.AtomicBoolean;

import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.DatabaseType;
import org.xipki.datasource.api.exception.DataAccessException;

/**
 * @author Lijun Liao
 */

public class TargetDigestRetriever
{
    private class Retriever
    implements Runnable
    {
        private Connection conn;
        private PreparedStatement singleSelectStmt = null;
        private PreparedStatement inArraySelectStmt = null;
        private PreparedStatement rangeSelectStmt = null;

        public Retriever()
        throws DataAccessException
        {
            conn = datasource.getConnection();

            try
            {
                singleSelectStmt = datasource.prepareStatement(conn, singleCertSql);
                inArraySelectStmt = datasource.prepareStatement(conn, inArrayCertsSql);
                rangeSelectStmt = datasource.prepareStatement(conn, rangeCertsSql);
            } catch (DataAccessException e)
            {
                releaseResources(singleSelectStmt, null);
                releaseResources(inArraySelectStmt, null);
                releaseResources(rangeSelectStmt, null);
                datasource.returnConnection(conn);
                throw e;
            }
        }

        @Override
        public void run()
        {
            while (!stop.get())
            {
                CertsBundle bundle = null;
                try
                {
                    bundle = inQueue.take();
                } catch (InterruptedException e)
                {
                    continue;
                }

                try
                {
                    Map<Long, DbDigestEntry> resp = query(bundle);
                    for (Long serialNumber : resp.keySet())
                    {
                        bundle.addTargetCert(serialNumber, resp.get(serialNumber));
                    }
                } catch (Exception e)
                {
                    bundle.setTargetException(e);
                } finally
                {
                    outQueue.add(bundle);
                }
            }

            releaseResources(singleSelectStmt, null);
            releaseResources(inArraySelectStmt, null);
            releaseResources(rangeSelectStmt, null);
            datasource.returnConnection(conn);
        }

        private Map<Long, DbDigestEntry> query(CertsBundle bundle)
        throws DataAccessException
        {
            List<Long> serialNumbers = bundle.getSerialNumbers();
            int n = serialNumbers.size();

            int numSkipped = bundle.getNumSkipped();
            long minSerialNumber = serialNumbers.get(0);
            long maxSerialNumber = serialNumbers.get(0);
            for (Long m : serialNumbers)
            {
                if (minSerialNumber > m)
                {
                    minSerialNumber = m;
                }
                if (maxSerialNumber < m)
                {
                    maxSerialNumber = m;
                }
            }

            Map<Long, DbDigestEntry> certsInB;
            long serialDiff = maxSerialNumber - minSerialNumber;

            if (serialDiff < (numSkipped + numPerSelect) * 2)
            {
                ResultSet rs = null;
                try
                {
                    rangeSelectStmt.setLong(1, minSerialNumber);
                    rangeSelectStmt.setLong(2, maxSerialNumber);
                    rs = rangeSelectStmt.executeQuery();

                    certsInB = buildResult(rs, serialNumbers);
                } catch (SQLException e)
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
                if (batchSupported && n == numPerSelect)
                {
                    certsInB = getCertsViaInArraySelectInB(inArraySelectStmt,
                            serialNumbers);
                } else
                {
                    certsInB = getCertsViaSingleSelectInB(
                            singleSelectStmt, serialNumbers);
                }
            }

            return certsInB;
        }
    }

    private final XipkiDbControl dbControl;
    private final DataSourceWrapper datasource;

    private final BlockingDeque<CertsBundle> inQueue = new LinkedBlockingDeque<>();
    private final BlockingDeque<CertsBundle> outQueue = new LinkedBlockingDeque<>();

    private final int numPerSelect;

    private final String singleCertSql;
    private final String inArrayCertsSql;
    private final String rangeCertsSql;
    private final AtomicBoolean stop = new AtomicBoolean(false);

    private ExecutorService executor;

    private final List<Retriever> retrievers;

    public TargetDigestRetriever(
            final DataSourceWrapper datasource,
            final XipkiDbControl dbControl,
            final int caId,
            final int numPerSelect,
            final int numThreads)
    throws DataAccessException
    {
        try
        {

        } catch (Exception e)
        {
            throw e;
        }

        this.numPerSelect = numPerSelect;
        this.datasource = datasource;
        this.dbControl = dbControl;

        String coreSql =
                dbControl.getColRevoked() + ","
                + dbControl.getColRevReason() + ","
                + dbControl.getColRevTime() + ","
                + dbControl.getColRevInvTime() + ","
                + dbControl.getColCerthash()
                + " FROM CERT INNER JOIN " + dbControl.getTblCerthash()
                + " ON CERT." + dbControl.getColCaId() + "=" + caId
                + " AND CERT." + dbControl.getColSerialNumber() + "=?"
                + " AND CERT.ID=" + dbControl.getTblCerthash() + "."
                + dbControl.getColCertId();
        singleCertSql = datasource.createFetchFirstSelectSQL(coreSql, 1);

        StringBuilder sb = new StringBuilder("?");
        for (int i = 1; i < numPerSelect; i++)
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
                + " ON CERT." + dbControl.getColCaId() + "=" + caId
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
                + " ON CERT." + dbControl.getColCaId() + "=" + caId
                + " AND CERT." + dbControl.getColSerialNumber() + ">=?"
                + " AND CERT." + dbControl.getColSerialNumber() + "<=?"
                + " AND CERT.ID=" + dbControl.getTblCerthash() + "."
                + dbControl.getColCertId();

        retrievers = new ArrayList<>(numThreads);

        try
        {
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
        } catch (Exception e)
        {
            close();
            throw e;
        }
    }

    public void addIn(CertsBundle certsBundle)
    {
        inQueue.add(certsBundle);
    }

    public CertsBundle takeOut()
    throws InterruptedException
    {
        return outQueue.take();
    }

    public boolean hasTasks()
    {
        return inQueue.isEmpty() && outQueue.isEmpty();
    }

    public void close()
    {
        stop.set(true);
        if (executor != null)
        {
            executor.shutdownNow();
        }
    }

    private Map<Long, DbDigestEntry> getCertsViaSingleSelectInB(
            final PreparedStatement singleSelectStmt,
            final List<Long> serialNumbers)
    throws DataAccessException
    {
        Map<Long, DbDigestEntry> ret = new HashMap<>(serialNumbers.size());

        for (Long serialNumber : serialNumbers)
        {
            DbDigestEntry certB = getSingleCert(singleSelectStmt, serialNumber);
            if (certB != null)
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
        if (n != numPerSelect)
        {
            throw new IllegalArgumentException("size of serialNumbers is not '" + numPerSelect
                    + "': " + n);
        }

        Collections.sort(serialNumbers);

        ResultSet rs = null;

        try
        {
            for (int i = 0; i < n; i++)
            {
                batchSelectStmt.setLong(i + 1, serialNumbers.get(i));
            }

            rs = batchSelectStmt.executeQuery();
            return buildResult(rs, serialNumbers);
        } catch (SQLException e)
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

        while (rs.next())
        {
            long serialNumber = rs.getLong(dbControl.getColSerialNumber());
            if (!serialNumbers.contains(serialNumber))
            {
                continue;
            }

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
            singleSelectStmt.setLong(1, serialNumber);
            rs = singleSelectStmt.executeQuery();
            if (!rs.next())
            {
                return null;
            }
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
            String sha1Fp = rs.getString(dbControl.getColCerthash());
            return new DbDigestEntry(serialNumber,
                    revoked, revReason, revTime, revInvTime, sha1Fp);
        } catch (SQLException e)
        {
            throw datasource.translate(singleCertSql, e);
        } finally
        {
            releaseResources(null, rs);
        }
    }

    private void releaseResources(
            final Statement ps,
            final ResultSet rs)
    {
        if (ps != null)
        {
            try
            {
                ps.close();
            } catch (Exception e)
            {
            }
        }

        if (rs != null)
        {
            try
            {
                rs.close();
            } catch (Exception e)
            {
            }
        }
    }

}
