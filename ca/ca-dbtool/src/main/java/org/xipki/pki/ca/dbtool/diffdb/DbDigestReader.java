/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
import org.xipki.commons.common.EndOfQueue;
import org.xipki.commons.common.QueueEntry;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.DataSourceWrapper;
import org.xipki.commons.datasource.springframework.dao.DataAccessException;
import org.xipki.commons.security.util.X509Util;
import org.xipki.pki.ca.dbtool.DbToolBase;
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
            retriever = getRetriever();
            executor = Executors.newFixedThreadPool(1);
            executor.execute(retriever);
            return true;
        } catch (Exception ex) {
            LOG.error("could not initialize DbDigestReader", ex);
            close();
            return false;
        }
    }

    protected abstract Retriever getRetriever() throws DataAccessException;

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
        if (certSet.getException() != null) {
            throw certSet.getException();
        }

        List<BigInteger> serialNumbers = new LinkedList<>();
        Map<BigInteger, DbDigestEntry> certsMap = new HashMap<>();
        for (IdentifiedDbDigestEntry m : certSet.getEntries()) {
            BigInteger sn = m.getContent().getSerialNumber();
            serialNumbers.add(sn);
            certsMap.put(sn, m.getContent());
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
