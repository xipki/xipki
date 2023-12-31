// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ocsp;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.client.HttpOcspRequestor;
import org.xipki.ocsp.client.OcspRequestor;
import org.xipki.ocsp.client.RequestOptions;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.BenchmarkExecutor;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * OCSP benchmark.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class OcspBenchmark extends BenchmarkExecutor {

  final class Tester implements Runnable {

    Tester() {
    }

    @Override
    public void run() {
      while (!stop()) {
        BigInteger sn = nextSerialNumber();
        if (sn == null) {
          break;
        }

        try {
          boolean valid = ask(new BigInteger[]{sn});
          account(1, valid ? 0 : 1);
        } catch (Throwable th) {
          LOG.warn("{}: {}", th.getClass().getName(), th.getMessage());
          account(1, 1);
        }
      }
    }

  } // class Tester

  private static final Logger LOG = LoggerFactory.getLogger(OcspBenchmark.class);

  private final OcspRequestor client;

  private final X509Cert issuerCert;

  private final URL responderUrl;

  private final RequestOptions requestOptions;

  private final Iterator<BigInteger> serials;

  private final int maxRequests;

  private final AtomicInteger processedRequests = new AtomicInteger(0);

  public OcspBenchmark(X509Cert issuerCert, String responderUrl, RequestOptions requestOptions,
      Iterator<BigInteger> serials, int maxRequests, String description)
      throws MalformedURLException {
    super(description);

    this.client = new HttpOcspRequestor();
    this.issuerCert = Args.notNull(issuerCert, "issuerCert");
    this.responderUrl = new URL(Args.notNull(responderUrl, "responderUrl"));
    this.requestOptions = Args.notNull(requestOptions, "requestOptions");
    this.maxRequests = maxRequests;
    this.serials = Args.notNull(serials, "serials");
  }

  @Override
  protected Runnable getTester() {
    return new Tester();
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

  public boolean ask(BigInteger[] serialNumbers) {
    OCSPResp ocspResp;
    try {
      ocspResp = client.ask(issuerCert, serialNumbers, responderUrl, requestOptions, null);
    } catch (Exception e) {
      LOG.warn("error client.ask", e);
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
      LOG.warn("bad response: response status is other than OK: {}", ocspResp.getStatus());
      return false;
    }

    if (!(respObject instanceof BasicOCSPResp)) {
      LOG.warn("bad response: response is not BasicOCSPResp");
      return false;
    }

    return true;
  } // method ask

}
