// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.sdk.*;
import org.xipki.util.BenchmarkExecutor;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;

/**
 * CA enrollment benchmark.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CaEnrollBenchmark extends BenchmarkExecutor {

  class Tester implements Runnable {

    public Tester() {
    }

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        try {
          EnrollCertsRequest certReq = nextCertRequest();
          if (certReq == null) {
            break;
          }

          testNext(certReq);
          account(1, 0);
        } catch (Exception ex) {
          LOG.warn("exception", ex);
          account(1, 1);
        } catch (Error ex) {
          LOG.warn("unexpected exception", ex);
          account(1, 1);
        }
      }
    }

    private void testNext(EnrollCertsRequest request) throws Exception {
      EnrollOrPollCertsResponse sdkResponse = client.enrollCerts(caName, request);
      parseEnrollCertResult(sdkResponse, num);
    } // method testNext

  } // class Tester

  private static final String CONf_FILE = "xipki/ca-qa/qa-benchmark-conf.json";

  private static final Logger LOG = LoggerFactory.getLogger(CaEnrollBenchmark.class);

  private final CaEnrollBenchEntry benchmarkEntry;

  private final AtomicLong index;

  private final SecureRandom random = new SecureRandom();

  private final int num;

  private final AtomicInteger processedRequests = new AtomicInteger(0);

  private final int maxRequests;

  private final SdkClient client;

  private final String caName;

  private final boolean caGenKeyPair;

  public CaEnrollBenchmark(
      String caName, CaEnrollBenchEntry benchmarkEntry, int maxRequests, int num, String description)
      throws Exception {
    super(description);
    this.caName = caName;
    this.maxRequests = maxRequests;
    this.num = positive(num, "num");
    this.benchmarkEntry = notNull(benchmarkEntry, "benchmarkEntry");
    this.index = new AtomicLong(getSecureIndex());
    this.caGenKeyPair = benchmarkEntry.getSubjectPublicKeyInfo() == null;
    this.client = new SdkClient(SdkClientConf.readConfFromFile(CONf_FILE));
  } // constructor

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

  @Override
  protected long getRealAccount(long account) {
    return num * account;
  }

  public EnrollCertsRequest nextCertRequest() throws Exception {
    if (maxRequests > 0) {
      int num = processedRequests.getAndAdd(1);
      if (num >= maxRequests) {
        return null;
      }
    }

    List<EnrollCertRequestEntry> entries = new ArrayList<>(num);

    for (int i = 0; i < num; i++) {
      long thisIndex = index.getAndIncrement();
      EnrollCertRequestEntry entry = new EnrollCertRequestEntry();
      entry.setSubject(new X500NameType(benchmarkEntry.getX500Name(thisIndex)));
      if (!caGenKeyPair) {
        entry.setSubjectPublicKey(benchmarkEntry.getSubjectPublicKeyInfo().getEncoded());
      }
      entry.setCertprofile(benchmarkEntry.getCertprofile());
      entry.setCertReqId(BigInteger.valueOf(i + 1));
      entries.add(entry);
    }

    EnrollCertsRequest req = new EnrollCertsRequest();
    req.setTransactionId(Hex.toHexString(randomBytes(8)));
    req.setEntries(entries);
    return req;
  } // method nextCertRequest

  private void parseEnrollCertResult(EnrollOrPollCertsResponse response, int numCerts)
      throws Exception {
    List<EnrollOrPullCertResponseEntry> entries = response.getEntries();
    int n = entries == null ? 0 : entries.size();
    if (n != numCerts) {
      throw new Exception("expected " + numCerts + " CertResponse, but returned " + n);
    }

    for (int i = 0; i < numCerts; i++) {
      EnrollOrPullCertResponseEntry certResp = entries.get(i);
      if (certResp.getError() != null) {
        throw new Exception("CertReqId " + certResp.getId() + ": server returned PKIStatus: " + certResp.getError());
      }
    }
  } // method parseEnrollCertResult

  private byte[] randomBytes(int size) {
    byte[] bytes = new byte[size];
    random.nextBytes(bytes);
    return bytes;
  }

}
