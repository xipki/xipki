/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.qa.ocsp.benchmark;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.client.api.OcspRequestorException;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspBenchmark extends BenchmarkExecutor {

  final class Testor implements Runnable {

    private OcspBenchRequestor requestor;

    Testor() throws Exception {
      this.requestor = new OcspBenchRequestor();
      this.requestor.init(responderUrl, issuerCert, requestOptions, parseResponse);
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
        requestor.close();
      } catch (Exception ex) {
        LOG.warn("got IOException in requestor.stop()");
      }
    }

    private void testNext(BigInteger sn) {
      try {
        requestor.ask(new BigInteger[]{sn});
        account(1, 0);
      } catch (IOException ex) {
        LOG.warn("IOException: {}", ex.getMessage());
        account(1, 1);
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

  private AtomicInteger processedRequests = new AtomicInteger(0);

  public OcspBenchmark(Certificate issuerCert, String responderUrl, RequestOptions requestOptions,
      Iterator<BigInteger> serials, int maxRequests, boolean parseResponse, String description) {
    super(description);

    this.issuerCert = Args.notNull(issuerCert, "issuerCert");
    this.responderUrl = Args.notNull(responderUrl, "responderUrl");
    this.requestOptions = Args.notNull(requestOptions, "requestOptions");
    this.maxRequests = maxRequests;
    this.serials = Args.notNull(serials, "serials");
    this.parseResponse = parseResponse;
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

}
