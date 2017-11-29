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

package org.xipki.ocsp.qa.benchmark;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.LoadExecutor;
import org.xipki.common.util.ParamUtil;
import org.xipki.ocsp.client.api.OcspRequestorException;
import org.xipki.ocsp.client.api.RequestOptions;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspBenchmark extends LoadExecutor {

    final class Testor implements Runnable {

        private OcspBenchRequestor requestor;

        Testor() throws Exception {
            this.requestor = new OcspBenchRequestor();
            this.requestor.init(OcspBenchmark.this, responderUrl, issuerCert, requestOptions,
                    queueSize);
        }

        @Override
        public void run() {
            while (!stop()) {
                BigInteger sn = nextSerialNumber();
                if (sn == null) {
                    break;
                }
                testNext(sn);
            }

            try {
                requestor.shutdown();
            } catch (Exception ex) {
                LOG.warn("got IOException in requestor.stop()");
            }
        }

        private void testNext(final BigInteger sn) {
            try {
                requestor.ask(new BigInteger[]{sn});
            } catch (OcspRequestorException ex) {
                LOG.warn("OCSPRequestorException: {}", ex.getMessage());
                account(1, 1);
            } catch (Throwable th) {
                LOG.warn("{}: {}", th.getClass().getName(), th.getMessage());
                account(1, 1);
            }
        } // method testNext

    } // class Testor

    private static final Logger LOG = LoggerFactory.getLogger(OcspBenchmark.class);

    private final Certificate issuerCert;

    private final String responderUrl;

    private final RequestOptions requestOptions;

    private final Iterator<BigInteger> serials;

    private final int maxRequests;

    private final boolean parseResponse;

    private final int queueSize;

    private AtomicInteger processedRequests = new AtomicInteger(0);

    public OcspBenchmark(final Certificate issuerCert, final String responderUrl,
            final RequestOptions requestOptions, final Iterator<BigInteger> serials,
            final int maxRequests, final boolean parseResponse, int queueSize,
            final String description) {
        super(description);

        this.issuerCert = ParamUtil.requireNonNull("issuerCert", issuerCert);
        this.responderUrl = ParamUtil.requireNonNull("responderUrl", responderUrl);
        this.requestOptions = ParamUtil.requireNonNull("requestOptions", requestOptions);
        this.maxRequests = maxRequests;
        this.serials = ParamUtil.requireNonNull("serials", serials);
        this.parseResponse = parseResponse;
        this.queueSize = queueSize;
    }

    @Override
    protected Runnable getTestor() throws Exception {
        return new Testor();
    }

    private BigInteger nextSerialNumber() {
        if (maxRequests > 0) {
            int num = processedRequests.getAndAdd(1);
            if (num >= maxRequests) {
                return null;
            }
        }

        try {
            return this.serials.next();
        } catch (NoSuchElementException ex) {
            return null;
        }
    }

    public void onComplete(FullHttpResponse response) {
        boolean success;
        try {
            success = onComplete0(response);
        } catch (Throwable th) {
            LOG.warn("unexpected exception", th);
            success = false;
        }

        account(1, success ? 0 : 1);
    }

    public synchronized void onError() {
        account(1, 1);
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
        } else if (!responseContentType.equalsIgnoreCase("application/ocsp-response")) {
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

        if (!parseResponse) {
            // a valid response should at least of size 10.
            if (respBytes.length < 10) {
                LOG.warn("bad response: response too short");
                return false;
            } else {
                return true;
            }
        }

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
            LOG.warn("bad response: response status is other than OK");
            return false;
        }

        if (!(respObject instanceof BasicOCSPResp)) {
            LOG.warn("bad response: response is not BasiOCSPResp");
            return false;
        }

        return true;
    }

}
