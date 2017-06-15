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

package org.xipki.pki.ocsp.qa.benchmark;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.LoadExecutor;
import org.xipki.common.concurrent.CountLatch;
import org.xipki.common.util.ParamUtil;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

class OcspResponseHandler {

    private static final Logger LOG = LoggerFactory.getLogger(OcspResponseHandler.class);

    private final AtomicInteger numPendingRequests = new AtomicInteger(0);

    private final LoadExecutor loadTestAccount;

    private final int maxPendingRequests;

    private final CountLatch finishLatch;

    private final CountLatch freeSourceLatch;

    public OcspResponseHandler(LoadExecutor loadTestAccount, int maxPendingRequests) {
        this.loadTestAccount = ParamUtil.requireNonNull("loadTestAccount",
                loadTestAccount);
        this.maxPendingRequests = ParamUtil.requireMin("maxPendingRequests",
                maxPendingRequests, 1);
        this.finishLatch = new CountLatch(0, 0);
        this.freeSourceLatch = new CountLatch(0, 0);
    }

    public synchronized void incrementNumPendingRequests() {
        numPendingRequests.incrementAndGet();
        manageLatches();
    }

    public void onComplete(FullHttpResponse response) {
        boolean success;
        try {
            success = onComplete0(response);
        } catch (Throwable th) {
            LOG.warn("unexpected exception", th);
            success = false;
        }

        synchronized (this) {
            numPendingRequests.decrementAndGet();
            loadTestAccount.account(1, success ? 0 : 1);
            manageLatches();
        }
    }

    public synchronized void onError() {
        numPendingRequests.decrementAndGet();
        loadTestAccount.account(1, 1);
        manageLatches();
    }

    private boolean onComplete0(FullHttpResponse response) {
        if (response == null) {
            LOG.warn("bad response: response is null");
            return false;
        }

        if (response.decoderResult().isFailure()) {
            LOG.warn("failed: {}", response.decoderResult());
            return false;
        }

        if (response.status().code() != HttpResponseStatus.OK.code()) {
            LOG.warn("bad response: {}", response.status());
            return false;
        }

        String responseContentType = response.headers().get("Content-Type");
        if (responseContentType == null) {
            LOG.warn("bad response: mandatory Content-Type not specified");
            return false;
        } else if (!responseContentType.equalsIgnoreCase(OcspBenchmark.CT_RESPONSE)) {
            LOG.warn("bad response: Content-Type {} unsupported", responseContentType);
            return false;
        }

        ByteBuf buf = response.content();
        if (buf == null || buf.readableBytes() == 0) {
            LOG.warn("no body in response");
            return false;
        }
        byte[] respBytes = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), respBytes);

        OCSPResp ocspResp;
        try {
            ocspResp = new OCSPResp(respBytes);
        } catch (IOException ex) {
            LOG.warn("could not parse OCSP response", ex);
            return false;
        }

        Object respObject;
        try {
            respObject = ocspResp.getResponseObject();
        } catch (OCSPException ex) {
            LOG.warn("responseObject is invalid", ex);
            return false;
        }

        if (ocspResp.getStatus() != 0) {
            return false;
        }

        if (!(respObject instanceof BasicOCSPResp)) {
            return false;
        }

        return true;
    }

    public int getMaxPendingRequests() {
        return maxPendingRequests;
    }

    public void waitForResource() throws InterruptedException {
        freeSourceLatch.await();
    }

    public void waitForFinish(int timeout, TimeUnit timeUnit)
            throws InterruptedException {
        finishLatch.await();
    }

    private synchronized void manageLatches() {
        // freeSourceLatch have either count value 1 (not finished) or 0 (finished).
        boolean isFinish = finishLatch.getCount() == 0;
        boolean expectedFinish = numPendingRequests.get() == 0;
        if (isFinish != expectedFinish) {
            if (expectedFinish) {
                finishLatch.countDown();
            } else {
                finishLatch.countUp();
            }
        }

        // freeSourceLatch have either count value 1 (no free source) or 0 (with free source).
        boolean isWithFreeSource = freeSourceLatch.getCount() == 0;
        boolean expectedWithFreeSource = numPendingRequests.get() < maxPendingRequests;
        if (isWithFreeSource != expectedWithFreeSource) {
            if (expectedWithFreeSource) {
                freeSourceLatch.countDown();
            } else {
                freeSourceLatch.countUp();
            }
        }
    }

}
