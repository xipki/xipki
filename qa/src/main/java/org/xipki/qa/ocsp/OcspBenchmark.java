/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.qa.ocsp;

import static org.xipki.util.Args.notNull;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.client.RequestOptions;
import org.xipki.qa.BenchmarkHttpClient.ResponseHandler;
import org.xipki.security.X509Cert;
import org.xipki.util.BenchmarkExecutor;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;

/**
 * OCSP benchmark.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspBenchmark extends BenchmarkExecutor implements ResponseHandler {

  final class Testor implements Runnable {

    private OcspBenchRequestor requestor;

    Testor()
        throws Exception {
      this.requestor = new OcspBenchRequestor();
      this.requestor.init(OcspBenchmark.this, responderUrl, issuerCert, requestOptions, queueSize);
    }

    @Override
    public void run() {
      while (!stop()) {
        BigInteger sn = nextSerialNumber();
        if (sn == null) {
          break;
        }

        try {
          requestor.ask(new BigInteger[]{sn});
        } catch (Throwable th) {
          LOG.warn("{}: {}", th.getClass().getName(), th.getMessage());
          account(1, 1);
        }
      }

      try {
        requestor.shutdown();
      } catch (Exception ex) {
        LOG.warn("got IOException in requestor.stop()");
      }
    }

  } // class Testor

  private static final Logger LOG = LoggerFactory.getLogger(OcspBenchmark.class);

  private final X509Cert issuerCert;

  private final String responderUrl;

  private final RequestOptions requestOptions;

  private final Iterator<BigInteger> serials;

  private final int maxRequests;

  private final int queueSize;

  private AtomicInteger processedRequests = new AtomicInteger(0);

  public OcspBenchmark(X509Cert issuerCert, String responderUrl, RequestOptions requestOptions,
      Iterator<BigInteger> serials, int maxRequests, int queueSize, String description) {
    super(description);

    this.issuerCert = notNull(issuerCert, "issuerCert");
    this.responderUrl = notNull(responderUrl, "responderUrl");
    this.requestOptions = notNull(requestOptions, "requestOptions");
    this.maxRequests = maxRequests;
    this.serials = notNull(serials, "serials");
    this.queueSize = queueSize;
  }

  @Override
  protected Runnable getTestor()
      throws Exception {
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

  @Override
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

  @Override
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
  } // method onComplete0

}
