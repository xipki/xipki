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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.DbToolBase;
import org.xipki.pki.ca.dbtool.IDRange;
import org.xipki.pki.ca.dbtool.diffdb.internal.CertsBundle;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.internal.DigestDBEntrySet;
import org.xipki.pki.ca.dbtool.diffdb.internal.IdentifiedDbDigestEntry;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

abstract class DbDigestReader implements DigestReader
{
    interface Retriever extends Runnable
    {
    }

    private static Logger LOG = LoggerFactory.getLogger(DbDigestReader.class);

    protected final AtomicBoolean stop = new AtomicBoolean(false);
    protected final BlockingDeque<IDRange> inQueue = new LinkedBlockingDeque<>();
    protected final BlockingDeque<DigestDBEntrySet> outQueue = new LinkedBlockingDeque<>();
    private final int numThreads;
    private ExecutorService executor;
    private List<Retriever> retrievers;

    protected final DataSourceWrapper datasource;
    protected final X509Certificate caCert;
    private final boolean revokedOnly;
    private final int totalAccount;
    private final String caSubjectName;
    private final int minId;
    private final int maxId;

    protected final Deque<IdentifiedDbDigestEntry> certs = new LinkedList<>();
    private int nextId;

    public DbDigestReader(
            final DataSourceWrapper datasource,
            final X509Certificate caCert,
            final boolean revokedOnly,
            final int totalAccount,
            final int minId,
            final int maxId,
            final int numThreads)
    throws DataAccessException, CertificateException, IOException
    {
        ParamUtil.assertNotNull("datasource", datasource);
        this.datasource = datasource;
        this.totalAccount = totalAccount;
        this.revokedOnly = revokedOnly;
        this.numThreads = numThreads;
        this.caCert = caCert;
        this.caSubjectName = X509Util.getRFC4519Name(caCert.getSubjectX500Principal());
        this.minId = minId;
        this.maxId = maxId;
        this.nextId = minId;
    }

    boolean init()
    {
        retrievers = new ArrayList<>(numThreads);

        try
        {
            for (int i = 0; i < numThreads; i++)
            {
                Retriever retriever = getRetriever(datasource);
                retrievers.add(retriever);
            }

            executor = Executors.newFixedThreadPool(numThreads);
            for (Runnable runnable : retrievers)
            {
                executor.execute(runnable);
            }
            return true;
        } catch (Exception e)
        {
            LOG.error("could not initialize DbDigestReader", e);
            close();
            return false;
        }
    }

    protected abstract Retriever getRetriever(
            DataSourceWrapper dataSource)
    throws DataAccessException;

    protected abstract int getNumSkippedCerts(
            final int fromId,
            final int toId,
            final int numCerts)
    throws DataAccessException;

    @Override
    public X509Certificate getCaCert()
    {
        return caCert;
    }

    @Override
    public String getCaSubjectName()
    {
        return caSubjectName;
    }

    @Override
    public int getTotalAccount()
    {
        return totalAccount;
    }

    @Override
    public CertsBundle nextCerts(
            final int n)
    throws DataAccessException
    {
        if (nextId > maxId && certs.isEmpty())
        {
            return null;
        }

        List<IdentifiedDbDigestEntry> entries = new ArrayList<>(n);
        int k = 0;
        while (true)
        {
            if (certs.isEmpty())
            {
                readNextCerts();
            }

            IdentifiedDbDigestEntry next = certs.poll();
            if (next == null)
            {
                break;
            }

            entries.add(next);
            k++;
            if (k >= n)
            {
                break;
            }
        }

        if (k == 0)
        {
            return null;
        }

        int numSkipped = 0;
        if (revokedOnly)
        {
            numSkipped = getNumSkippedCerts(entries.get(0).getId(),
                    entries.get(k - 1).getId(), k);
        }

        List<Long> serialNumbers = new ArrayList<>(k);
        Map<Long, DbDigestEntry> certsMap = new HashMap<>(k);
        for (IdentifiedDbDigestEntry m : entries)
        {
            long sn = m.getContent().getSerialNumber();
            serialNumbers.add(sn);
            certsMap.put(sn, m.getContent());
        }

        return new CertsBundle(numSkipped, certsMap, serialNumbers);
    }

    private void readNextCerts()
    throws DataAccessException
    {
        while (certs.isEmpty() && nextId <= maxId)
        {
            int n = 0;
            for (int i = 0; i < numThreads; i++)
            {
                if (nextId <= maxId)
                {
                    n++;
                    inQueue.add(new IDRange(nextId, nextId + 999));
                    nextId += 1000;
                } else
                {
                    break;
                }
            }

            List<DigestDBEntrySet> results = new ArrayList<>(n);
            for (int i = 0; i < n; i++)
            {
                try
                {
                    results.add(outQueue.take());
                } catch (InterruptedException e)
                {
                    throw new DataAccessException("InterruptedException " + e.getMessage(), e);
                }
            }

            for (DigestDBEntrySet result : results)
            {
                if (result.getException() != null)
                {
                    throw new DataAccessException(
                            "error while reading from ID " + result.getStartId()
                                + ": " + result.getException().getMessage(),
                            result.getException());
                }
            }

            Collections.sort(results);
            for (DigestDBEntrySet result : results)
            {
                for (IdentifiedDbDigestEntry entry : result.getEntries())
                {
                    certs.addLast(entry);
                }
            }
        }
    }

    public void close()
    {
        stop.set(true);
        executor.shutdownNow();
    }

    protected static void releaseResources(
            final Statement ps,
            final ResultSet rs)
    {
        DbToolBase.releaseResources(ps, rs);
    }

    public int getMinId()
    {
        return minId;
    }

}
