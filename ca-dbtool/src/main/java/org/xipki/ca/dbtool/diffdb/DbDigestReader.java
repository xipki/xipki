/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.dbtool.diffdb;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.DbToolBase;
import org.xipki.ca.dbtool.StopMe;
import org.xipki.ca.dbtool.diffdb.io.CertsBundle;
import org.xipki.ca.dbtool.diffdb.io.DbDigestEntry;
import org.xipki.ca.dbtool.diffdb.io.DigestDbEntrySet;
import org.xipki.ca.dbtool.diffdb.io.IdentifiedDbDigestEntry;
import org.xipki.common.EndOfQueue;
import org.xipki.common.QueueEntry;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class DbDigestReader implements DigestReader {

    private static final Logger LOG = LoggerFactory.getLogger(DbDigestReader.class);

    protected final BlockingQueue<QueueEntry> outQueue;

    protected final DataSourceWrapper datasource;

    protected final X509Certificate caCert;

    protected final StopMe stopMe;

    private ExecutorService executor;

    private Retriever retriever;

    private final int totalAccount;

    private final String caSubjectName;

    private final AtomicBoolean endReached = new AtomicBoolean(false);

    protected long lastProcessedId;

    DbDigestReader(final DataSourceWrapper datasource, final X509Certificate caCert,
            final int totalAccount, final long minId, final int numBlocksToRead,
            final StopMe stopMe) throws DataAccessException, CertificateException, IOException {
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);
        this.caCert = ParamUtil.requireNonNull("caCert", caCert);
        this.stopMe = ParamUtil.requireNonNull("stopMe", stopMe);
        this.totalAccount = totalAccount;
        this.caSubjectName = X509Util.getRfc4519Name(caCert.getSubjectX500Principal());
        this.lastProcessedId = minId - 1;
        this.outQueue = new ArrayBlockingQueue<>(numBlocksToRead);
    }

    interface Retriever extends Runnable {
    } // interface Retriever

    boolean init() {
        try {
            retriever = retriever();
            executor = Executors.newFixedThreadPool(1);
            executor.execute(retriever);
            return true;
        } catch (Exception ex) {
            LOG.error("could not initialize DbDigestReader", ex);
            close();
            return false;
        }
    }

    protected abstract Retriever retriever() throws DataAccessException;

    @Override
    public X509Certificate caCert() {
        return caCert;
    }

    @Override
    public String caSubjectName() {
        return caSubjectName;
    }

    @Override
    public int totalAccount() {
        return totalAccount;
    }

    @Override
    public synchronized CertsBundle nextCerts() throws Exception {
        if (endReached.get() && outQueue.isEmpty()) {
            return null;
        }

        DigestDbEntrySet certSet;

        QueueEntry next = null;
        while (next == null) {
            if (stopMe.stopMe()) {
                return null;
            }
            next = outQueue.poll(1, TimeUnit.SECONDS);
        }

        if (next instanceof EndOfQueue) {
            endReached.set(true);
            return null;
        } else if (!(next instanceof DigestDbEntrySet)) {
            throw new RuntimeException("unknown QueueEntry type: " + next.getClass().getName());
        }

        certSet = (DigestDbEntrySet) next;
        if (certSet.exception() != null) {
            throw certSet.exception();
        }

        List<BigInteger> serialNumbers = new LinkedList<>();
        Map<BigInteger, DbDigestEntry> certsMap = new HashMap<>();
        for (IdentifiedDbDigestEntry m : certSet.entries()) {
            BigInteger sn = m.content().serialNumber();
            serialNumbers.add(sn);
            certsMap.put(sn, m.content());
        }

        return new CertsBundle(certsMap, serialNumbers);
    } // method nextCerts

    public void close() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    protected void releaseResources(final Statement ps, final ResultSet rs) {
        DbToolBase.releaseResources(datasource, ps, rs);
    }

}
