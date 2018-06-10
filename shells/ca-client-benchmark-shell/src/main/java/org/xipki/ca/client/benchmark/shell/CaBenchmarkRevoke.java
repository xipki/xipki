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

package org.xipki.ca.client.benchmark.shell;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.client.api.CaClient;
import org.xipki.ca.client.api.CaClientException;
import org.xipki.ca.client.api.CertIdOrError;
import org.xipki.ca.client.api.PkiErrorException;
import org.xipki.ca.client.api.dto.RevokeCertRequest;
import org.xipki.ca.client.api.dto.RevokeCertRequestEntry;
import org.xipki.common.qa.BenchmarkExecutor;
import org.xipki.datasource.DataAccessException;
import org.xipki.security.CrlReason;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaBenchmarkRevoke extends BenchmarkExecutor {

  private static final Logger LOG = LoggerFactory.getLogger(CaBenchmarkRevoke.class);

  private static final List<CrlReason> REASONS = CrlReason.PERMITTED_CLIENT_CRLREASONS;

  private final CaClient caClient;

  private final X500Name caSubject;

  private final int num;

  private final int maxCerts;

  private final Iterator<BigInteger> serialNumberIterator;

  private AtomicInteger processedCerts = new AtomicInteger(0);

  public CaBenchmarkRevoke(CaClient caClient, Certificate caCert,
      Iterator<BigInteger> serialNumberIterator, int maxCerts, int num, String description) {
    super(description);
    ParamUtil.requireNonNull("caCert", caCert);
    this.num = ParamUtil.requireMin("num", num, 1);
    this.caClient = ParamUtil.requireNonNull("caClient", caClient);
    this.serialNumberIterator = ParamUtil.requireNonNull("serialNumberIterator",
        serialNumberIterator);
    this.caSubject = caCert.getSubject();
    this.maxCerts = maxCerts;
  } // constructor

  class Testor implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        List<BigInteger> serialNumbers;
        try {
          serialNumbers = nextSerials();
        } catch (DataAccessException ex) {
          account(1, 1);
          break;
        }

        if (CollectionUtil.isEmpty(serialNumbers)) {
          break;
        }

        boolean successful = testNext(serialNumbers);
        int numFailed = successful ? 0 : 1;
        account(1, numFailed);
      }
    }

    private boolean testNext(List<BigInteger> serialNumbers) {
      RevokeCertRequest request = new RevokeCertRequest();
      int id = 1;
      for (BigInteger serialNumber : serialNumbers) {
        CrlReason reason = REASONS.get(Math.abs(serialNumber.intValue()) % REASONS.size());
        RevokeCertRequestEntry entry = new RevokeCertRequestEntry(Integer.toString(id++),
                caSubject, serialNumber, reason.getCode(), null);
        request.addRequestEntry(entry);
      }

      Map<String, CertIdOrError> result;
      try {
        result = caClient.revokeCerts(request, null);
      } catch (CaClientException | PkiErrorException ex) {
        LOG.warn("{}: {}", ex.getClass().getName(), ex.getMessage());
        return false;
      } catch (Throwable th) {
        LOG.warn("{}: {}", th.getClass().getName(), th.getMessage());
        return false;
      }

      if (result == null) {
        return false;
      }

      int numSuccess = 0;
      for (CertIdOrError entry : result.values()) {
        if (entry.getCertId() != null) {
          numSuccess++;
        }
      }
      return numSuccess == serialNumbers.size();
    } // method testNext

  } // class Testor

  @Override
  protected Runnable getTestor() throws Exception {
    return new Testor();
  }

  private List<BigInteger> nextSerials() throws DataAccessException {
    List<BigInteger> ret = new ArrayList<>(num);
    for (int i = 0; i < num; i++) {
      if (maxCerts > 0) {
        int num = processedCerts.getAndAdd(1);
        if (num >= maxCerts) {
          break;
        }
      }

      if (serialNumberIterator.hasNext()) {
        BigInteger serial = serialNumberIterator.next();
        ret.add(serial);
      } else {
        break;
      }
    }
    return ret;
  }

}
