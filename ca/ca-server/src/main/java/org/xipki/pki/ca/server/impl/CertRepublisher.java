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

package org.xipki.pki.ca.server.impl;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.EndOfQueue;
import org.xipki.common.ProcessLog;
import org.xipki.common.QueueEntry;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ca.api.NameId;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.publisher.x509.X509CertificateInfo;
import org.xipki.pki.ca.server.impl.store.CertificateStore;
import org.xipki.security.X509Cert;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

class CertRepublisher {

    private class SerialWithIdQueueEntry implements QueueEntry {

        private final SerialWithId serialWithId;

        public SerialWithIdQueueEntry(final SerialWithId serialWithId) {
            this.serialWithId = ParamUtil.requireNonNull("serialWithId", serialWithId);
        }

        public SerialWithId serialWithId() {
            return serialWithId;
        }

    }

    private class CertRepublishProducer implements Runnable {

        private boolean failed;

        private CertRepublishProducer() {
        }

        @Override
        public void run() {
            final int numEntries = 100;
            long startId = 1;

            try {
                List<SerialWithId> serials;
                do {
                    serials = certstore.getCertSerials(ca, startId, numEntries,
                            onlyRevokedCerts);
                    long maxId = 1;
                    for (SerialWithId sid : serials) {
                        if (sid.id() > maxId) {
                            maxId = sid.id();
                        }
                        queue.put(new SerialWithIdQueueEntry(sid));
                    }

                    startId = maxId + 1;
                }
                while (serials.size() >= numEntries && !failed && !stopMe.get());

                queue.put(EndOfQueue.INSTANCE);
            } catch (OperationException ex) {
                LogUtil.error(LOG, ex, "error in RepublishProducer");
                failed = true;
            } catch (InterruptedException ex) {
                LogUtil.error(LOG, ex, "error in RepublishProducer");
                failed = true;
            }

            if (!queue.contains(EndOfQueue.INSTANCE)) {
                try {
                    queue.put(EndOfQueue.INSTANCE);
                } catch (InterruptedException ex) {
                    LogUtil.error(LOG, ex, "error in RepublishProducer");
                    failed = true;
                }
            }
        }
    }

    private class CertRepublishConsumer implements Runnable {

        private boolean failed;

        private CertRepublishConsumer() {
        }

        @Override
        public void run() {
            while (!failed) {
                QueueEntry entry;
                try {
                    entry = queue.take();
                } catch (InterruptedException ex) {
                    LogUtil.error(LOG, ex, "could not take from queue");
                    failed = true;
                    break;
                }

                if (entry instanceof EndOfQueue) {
                    // re-add it to queue so that other consumers know it
                    try {
                        queue.put(entry);
                    } catch (InterruptedException ex) {
                        LogUtil.warn(LOG, ex, "could not re-add EndOfQueue to queue");
                    }
                    break;
                }

                SerialWithId sid = ((SerialWithIdQueueEntry) entry).serialWithId();

                X509CertificateInfo certInfo;

                try {
                    certInfo = certstore.getCertificateInfoForId(ca, caCert, sid.id(),
                            caIdNameMap);
                } catch (OperationException | CertificateException ex) {
                    LogUtil.error(LOG, ex);
                    failed = true;
                    break;
                }

                boolean allSucc = true;
                for (IdentifiedX509CertPublisher publisher : publishers) {
                    if (!certInfo.isRevoked() && !publisher.publishsGoodCert()) {
                        continue;
                    }

                    boolean successful = publisher.certificateAdded(certInfo);
                    if (!successful) {
                        LOG.error("republish certificate serial={} to publisher {} failed",
                                LogUtil.formatCsn(sid.serial()), publisher.ident());
                        allSucc = false;
                    }
                }

                if (!allSucc) {
                    break;
                }
                processLog.addNumProcessed(1);
            }
        }

    }

    private static final Logger LOG = LoggerFactory.getLogger(CertRepublisher.class);

    private final NameId ca;

    private final X509Cert caCert;

    private final CaIdNameMap caIdNameMap;

    private final CertificateStore certstore;

    private final List<IdentifiedX509CertPublisher> publishers;

    private final boolean onlyRevokedCerts;

    private final int numThreads;

    private final BlockingQueue<QueueEntry> queue = new ArrayBlockingQueue<>(1000);

    private final AtomicBoolean stopMe = new AtomicBoolean(false);

    private ProcessLog processLog;

    CertRepublisher(final NameId ca, final X509Cert caCert, final CaIdNameMap caIdNameMap,
            final CertificateStore certstore, final List<IdentifiedX509CertPublisher> publishers,
            final boolean onlyRevokedCerts, final int numThreads) {
        this.ca = ParamUtil.requireNonNull("ca", ca);
        this.caCert = ParamUtil.requireNonNull("caCert", caCert);
        this.caIdNameMap = ParamUtil.requireNonNull("caIdNameMap", caIdNameMap);
        this.certstore = ParamUtil.requireNonNull("certstore", certstore);
        this.publishers = ParamUtil.requireNonEmpty("publishers", publishers);
        this.onlyRevokedCerts = onlyRevokedCerts;
        this.numThreads = ParamUtil.requireMin("numThreads", numThreads, 1);
    }

    boolean republish() {
        try {
            return doRepublish();
        } finally {
            if (processLog != null) {
                processLog.finish();
                processLog.printTrailer();
            }
        }
    }

    private boolean doRepublish() {
        long total;
        try {
            total = certstore.getCountOfCerts(ca, onlyRevokedCerts);
        } catch (OperationException ex) {
            LogUtil.error(LOG, ex, "could not getCountOfCerts");
            return false;
        }
        processLog = new ProcessLog(total);
        processLog.printHeader();

        ExecutorService executor = Executors.newFixedThreadPool(numThreads + 1);
        List<CertRepublishConsumer> consumers = new ArrayList<>(numThreads);
        AtomicBoolean stopMe = new AtomicBoolean(false);
        for (int i = 0; i < numThreads; i++) {
            CertRepublishConsumer consumer = new CertRepublishConsumer();
            consumers.add(consumer);
        }

        CertRepublishProducer producer = new CertRepublishProducer();

        executor.execute(producer);
        for (CertRepublishConsumer consumer : consumers) {
            executor.execute(consumer);
        }

        executor.shutdown();
        boolean successful = true;

        while (true) {
            processLog.printStatus();

            if (successful) {
                if (producer.failed) {
                    successful = false;
                }

                if (successful) {
                    for (CertRepublishConsumer consumer : consumers) {
                        if (consumer.failed) {
                            successful = false;
                            break;
                        }
                    }
                }

                if (!successful) {
                    stopMe.set(true);
                    LOG.warn("failed");
                }
            }

            try {
                boolean terminated = executor.awaitTermination(1, TimeUnit.SECONDS);
                if (terminated) {
                    break;
                }
            } catch (InterruptedException ex) {
                stopMe.set(true);
                LogUtil.warn(LOG, ex, "interrupted: " + ex.getMessage());
            }
        }

        if (successful) {
            if (producer.failed) {
                successful = false;
            }

            if (successful) {
                for (CertRepublishConsumer consumer : consumers) {
                    if (consumer.failed) {
                        successful = false;
                        break;
                    }
                }
            }

            if (!successful) {
                LOG.warn("failed");
            }
        }

        return successful;
    }

}
