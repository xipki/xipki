/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.dbtool.DbToolBase;
import org.xipki.pki.ca.dbtool.EndOfQueue;
import org.xipki.pki.ca.dbtool.IdRange;
import org.xipki.pki.ca.dbtool.QueueEntry;
import org.xipki.pki.ca.dbtool.StopMe;
import org.xipki.pki.ca.dbtool.diffdb.io.CertsBundle;
import org.xipki.pki.ca.dbtool.diffdb.io.DbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.io.DigestDbEntrySet;
import org.xipki.pki.ca.dbtool.diffdb.io.IdentifiedDbDigestEntry;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class DbDigestReader implements DigestReader {

    private static final Logger LOG = LoggerFactory.getLogger(DbDigestReader.class);

    protected final BlockingQueue<IdRange> inQueue;

    protected final BlockingQueue<DigestDbEntrySet> outQueue;

    protected final DataSourceWrapper datasource;

    protected final X509Certificate caCert;

    protected final ArrayBlockingQueue<QueueEntry> fixedSizedCerts;

    protected final StopMe stopMe;

    protected final boolean revokedOnly;

    private final int numThreads;

    private ExecutorService executor;

    private List<Retriever> retrievers;

    private final int totalAccount;

    private final String caSubjectName;

    private final int minId;

    private final int maxId;

    private final AtomicBoolean endReached = new AtomicBoolean(false);

    private Exception exception;

    private int nextId;

    DbDigestReader(
            final DataSourceWrapper datasource,
            final X509Certificate caCert,
            final boolean revokedOnly,
            final int totalAccount,
            final int minId,
            final int maxId,
            final int numThreads,
            final int numCertsToPredicate,
            final StopMe stopMe)
    throws DataAccessException, CertificateException, IOException {
        ParamUtil.assertNotNull("datasource", datasource);

        this.datasource = datasource;
        this.totalAccount = totalAccount;
        this.revokedOnly = revokedOnly;
        this.numThreads = numThreads;
        this.caCert = caCert;
        this.caSubjectName = X509Util.getRfc4519Name(caCert.getSubjectX500Principal());
        this.minId = minId;
        this.maxId = maxId;
        this.nextId = minId;

        this.stopMe = stopMe;
        this.inQueue = new LinkedBlockingDeque<>();
        this.outQueue = new LinkedBlockingDeque<>();
        this.fixedSizedCerts = new ArrayBlockingQueue<>(numCertsToPredicate);
    }

    interface Retriever extends Runnable {
    } // interface Retriever

    private class Dispatcher implements Runnable {

        @Override
        public void run() {
            while (nextId <= maxId && !stopMe.stopMe()) {
                int n = 0;
                for (int i = 0; i < numThreads; i++) {
                    if (nextId <= maxId) {
                        n++;
                        inQueue.add(new IdRange(nextId, nextId + 999));
                        nextId += 1000;
                    } else {
                        break;
                    }
                }

                List<DigestDbEntrySet> results = new ArrayList<>(n);
                for (int i = 0; i < n; i++) {
                    try {
                        results.add(outQueue.take());
                    } catch (InterruptedException e) {
                        exception = e;
                        return;
                    }
                }

                for (DigestDbEntrySet result : results) {
                    if (result.getException() != null) {
                        exception = new DataAccessException(
                                String.format(
                                        "error while reading from ID %d: %s",
                                        result.getStartId(), result.getException().getMessage()),
                                result.getException());
                        return;
                    }
                }

                Collections.sort(results);
                for (DigestDbEntrySet result : results) {
                    for (IdentifiedDbDigestEntry entry : result.getEntries()) {
                        try {
                            fixedSizedCerts.offer(entry, Integer.MAX_VALUE, TimeUnit.MILLISECONDS);
                        } catch (InterruptedException e) {
                            exception = e;
                            return;
                        }
                    }
                }
            } // method run

            endReached.set(true);
            try {
                fixedSizedCerts.offer(EndOfQueue.INSTANCE, Integer.MAX_VALUE,
                        TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                exception = e;
                return;
            }
        }

    } // class Dispatcher

    boolean init() {
        retrievers = new ArrayList<>(numThreads);

        try {
            for (int i = 0; i < numThreads; i++) {
                Retriever retriever = getRetriever();
                retrievers.add(retriever);
            }

            executor = Executors.newFixedThreadPool(numThreads + 1);
            for (Runnable runnable : retrievers) {
                executor.execute(runnable);
            }

            executor.execute(new Dispatcher());
            return true;
        } catch (Exception e) {
            LOG.error("could not initialize DbDigestReader", e);
            close();
            return false;
        }
    }

    protected abstract Retriever getRetriever()
    throws DataAccessException;

    protected abstract int getNumSkippedCerts(
            final int fromId,
            final int toId,
            final int numCerts)
    throws DataAccessException;

    @Override
    public X509Certificate getCaCert() {
        return caCert;
    }

    @Override
    public String getCaSubjectName() {
        return caSubjectName;
    }

    @Override
    public int getTotalAccount() {
        return totalAccount;
    }

    @Override
    public synchronized CertsBundle nextCerts(
            final int n)
    throws Exception {
        if (endReached.get() && fixedSizedCerts.isEmpty()) {
            return null;
        }

        if (exception != null) {
            throw exception;
        }

        List<IdentifiedDbDigestEntry> entries = new ArrayList<>(n);
        int k = 0;
        while (true) {
            QueueEntry next = null;
            while (next == null) {
                next = fixedSizedCerts.poll(1, TimeUnit.SECONDS);
                if (exception != null) {
                    throw exception;
                }
            }

            if (next instanceof EndOfQueue) {
                break;
            }

            entries.add((IdentifiedDbDigestEntry) next);
            k++;
            if (k >= n) {
                break;
            }
        }

        if (k == 0) {
            return null;
        }

        int numSkipped = 0;
        if (revokedOnly) {
            numSkipped = getNumSkippedCerts(entries.get(0).getId(), entries.get(k - 1).getId(), k);
        }

        List<Long> serialNumbers = new ArrayList<>(k);
        Map<Long, DbDigestEntry> certsMap = new HashMap<>(k);
        for (IdentifiedDbDigestEntry m : entries) {
            long sn = m.getContent().getSerialNumber();
            serialNumbers.add(sn);
            certsMap.put(sn, m.getContent());
        }

        return new CertsBundle(numSkipped, certsMap, serialNumbers);
    } // method nextCerts

    public void close() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    public int getMinId() {
        return minId;
    }

    protected static void releaseResources(
            final Statement ps,
            final ResultSet rs) {
        DbToolBase.releaseResources(ps, rs);
    }

}
