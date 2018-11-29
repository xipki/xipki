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

package org.xipki.qa.ca.benchmark;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.cmpclient.CmpClient;
import org.xipki.cmpclient.CmpClientException;
import org.xipki.cmpclient.EnrollCertRequest;
import org.xipki.cmpclient.EnrollCertRequest.EnrollType;
import org.xipki.cmpclient.EnrollCertResult;
import org.xipki.cmpclient.EnrollCertResult.CertifiedKeyPairOrError;
import org.xipki.cmpclient.PkiErrorException;
import org.xipki.qa.ca.benchmark.BenchmarkEntry.RandomDn;
import org.xipki.qa.ca.benchmark.EnrollTemplateType.EnrollCertType;
import org.xipki.util.Args;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.conf.InvalidConfException;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaBenchmarkTemplateEnroll extends BenchmarkExecutor {

  private static final class CertRequestWithProfile {

    private final String certprofile;

    private final CertRequest certRequest;

    CertRequestWithProfile(String certprofile, CertRequest certRequest) {
      this.certprofile = certprofile;
      this.certRequest = certRequest;
    }

  } // class CertRequestWithProfile

  class Testor implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        Map<Integer, CertRequestWithProfile> certReqs = nextCertRequests();
        if (certReqs == null) {
          break;
        }

        boolean successful = testNext(certReqs);
        int numFailed = successful ? 0 : 1;
        account(1, numFailed);
      }
    }

    private boolean testNext(Map<Integer, CertRequestWithProfile> certRequests) {
      EnrollCertResult result;
      try {
        EnrollCertRequest request = new EnrollCertRequest(EnrollType.CERT_REQ);
        for (Integer certId : certRequests.keySet()) {
          CertRequestWithProfile certRequest = certRequests.get(certId);
          EnrollCertRequest.Entry requestEntry = new EnrollCertRequest.Entry("id-" + certId,
                  certRequest.certprofile, certRequest.certRequest, RA_VERIFIED);
          request.addRequestEntry(requestEntry);
        }

        result = client.enrollCerts(null, request, null);
      } catch (CmpClientException | PkiErrorException ex) {
        LOG.warn("{}: {}", ex.getClass().getName(), ex.getMessage());
        return false;
      } catch (Throwable th) {
        LOG.warn("{}: {}", th.getClass().getName(), th.getMessage());
        return false;
      }

      if (result == null) {
        return false;
      }

      Set<String> ids = result.getAllIds();
      if (ids.size() < certRequests.size()) {
        return false;
      }

      for (String id : ids) {
        CertifiedKeyPairOrError certOrError = result.getCertOrError(id);
        X509Certificate cert = (X509Certificate) certOrError.getCertificate();

        if (cert == null) {
          return false;
        }
      }

      return true;
    } // method testNext

  } // class Testor

  private static final Logger LOG = LoggerFactory.getLogger(CaBenchmarkTemplateEnroll.class);

  private static final ProofOfPossession RA_VERIFIED = new ProofOfPossession();

  private final CmpClient client;

  private final List<BenchmarkEntry> benchmarkEntries;

  private final int num;

  private final int maxRequests;

  private AtomicInteger processedRequests = new AtomicInteger(0);

  private final AtomicLong index;

  public CaBenchmarkTemplateEnroll(CmpClient client, EnrollTemplateType template,
      int maxRequests, String description) throws Exception {
    super(description);

    Args.notNull(template, "template");
    this.maxRequests = maxRequests;
    this.client = Args.notNull(client, "client");

    Calendar baseTime = Calendar.getInstance(Locale.UK);
    baseTime.set(Calendar.YEAR, 2014);
    baseTime.set(Calendar.MONTH, 0);
    baseTime.set(Calendar.DAY_OF_MONTH, 1);

    this.index = new AtomicLong(getSecureIndex());

    List<EnrollCertType> list = template.getEnrollCerts();
    benchmarkEntries = new ArrayList<>(list.size());

    for (EnrollCertType m : list) {
      String keyspec = m.getKeyspec().toUpperCase();
      KeyEntry keyEntry;
      if (keyspec.startsWith("EC:")) {
        String curve = keyspec.substring("EC:".length());
        keyEntry = new KeyEntry.ECKeyEntry(curve);
      } else if (keyspec.startsWith("RSA:")) {
        int modulusLength = Integer.parseInt(keyspec.substring("RSA:".length()));
        keyEntry = new KeyEntry.RSAKeyEntry(modulusLength);
      } else if (keyspec.startsWith("DSA:")) {
        int pLength = Integer.parseInt(keyspec.substring("DSA:".length()));
        keyEntry = new KeyEntry.DSAKeyEntry(pLength);
      } else {
        throw new IllegalStateException("should not reach here, unknown child of KeyEntry");
      }

      RandomDn randomDn = m.getRandomDn();
      if (randomDn == null) {
        throw new InvalidConfException("randomDn unspecified");
      }

      benchmarkEntries.add(
          new BenchmarkEntry(m.getCertprofile(), keyEntry, m.getSubject(), randomDn));
    }

    num = benchmarkEntries.size();
  } // constructor

  @Override
  protected int getRealAccount(int account) {
    return num * account;
  }

  @Override
  protected Runnable getTestor() throws Exception {
    return new Testor();
  }

  public int getNumberOfCertsInOneRequest() {
    return benchmarkEntries.size();
  }

  private Map<Integer, CertRequestWithProfile> nextCertRequests() {
    if (maxRequests > 0) {
      int num = processedRequests.getAndAdd(1);
      if (num >= maxRequests) {
        return null;
      }
    }

    Map<Integer, CertRequestWithProfile> certRequests = new HashMap<>();
    final int n = benchmarkEntries.size();
    for (int i = 0; i < n; i++) {
      BenchmarkEntry benchmarkEntry = benchmarkEntries.get(i);
      final int certId = i + 1;
      CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();

      long thisIndex = index.getAndIncrement();
      certTempBuilder.setSubject(benchmarkEntry.getX500Name(thisIndex));

      SubjectPublicKeyInfo spki = benchmarkEntry.getSubjectPublicKeyInfo();
      certTempBuilder.setPublicKey(spki);

      CertTemplate certTemplate = certTempBuilder.build();
      CertRequest certRequest = new CertRequest(certId, certTemplate, null);
      CertRequestWithProfile requestWithCertprofile = new CertRequestWithProfile(
              benchmarkEntry.getCertprofile(), certRequest);
      certRequests.put(certId, requestWithCertprofile);
    }
    return certRequests;
  } // method nextCertRequests

  public static EnrollTemplateType parse(InputStream confStream)
      throws InvalidConfException, IOException {
    Args.notNull(confStream, "confStream");

    try {
      EnrollTemplateType root = JSON.parseObject(confStream, EnrollTemplateType.class);
      root.validate();
      return root;
    } finally {
      try {
        confStream.close();
      } catch (IOException ex) {
        LOG.warn("could not close confStream: {}", ex.getMessage());
      }
    }
  } // method parse

}
