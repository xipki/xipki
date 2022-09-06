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

package org.xipki.qa.ca;

import com.alibaba.fastjson.JSON;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslContext;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.sdk.*;
import org.xipki.qa.BenchmarkHttpClient;
import org.xipki.qa.BenchmarkHttpClient.HttpClientException;
import org.xipki.qa.BenchmarkHttpClient.ResponseHandler;
import org.xipki.qa.BenchmarkHttpClient.SslConf;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
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
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaEnrollBenchmark extends BenchmarkExecutor implements ResponseHandler {

  public static class Conf extends ValidatableConf {

    private String caUrl;

    private SslConf ssl;

    public String getCaUrl() {
      return caUrl;
    }

    public void setCaUrl(String caUrl) {
      this.caUrl = caUrl.endsWith("/") ? caUrl : caUrl + "/";
    }

    public SslConf getSsl() {
      return ssl;
    }

    public void setSsl(SslConf ssl) {
      this.ssl = ssl;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(caUrl, "caUrl");
      notNull(ssl, "ssl");
      validate(ssl);
    }

  } // classConf

  class Testor implements Runnable {

    private final BenchmarkHttpClient httpClient;

    public Testor() {
      this.httpClient = new BenchmarkHttpClient(caHost, caPort, sslContext,
                      CaEnrollBenchmark.this, queueSize);
      this.httpClient.start();
    }

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        try {
          SdkRequest certReq = nextCertRequest();
          if (certReq == null) {
            break;
          }

          testNext(certReq);
        } catch (Exception ex) {
          LOG.warn("exception", ex);
          account(1, 1);
        } catch (Error ex) {
          LOG.warn("unexpected exception", ex);
          account(1, 1);
        }
      }

      try {
        httpClient.shutdown();
      } catch (Exception ex) {
        LOG.warn("got IOException in requestor.stop()", ex);
      }
    }

    private void testNext(SdkRequest request) throws HttpClientException, IOException {
      SdkClient client = null;
      byte[] encoded = request.encode();
      ByteBuf content = Unpooled.wrappedBuffer(encoded);
      FullHttpRequest httpReq = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST,
          conf.caUrl + "enroll", content);
      httpReq.headers().addInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes())
        .add(HttpHeaderNames.CONTENT_TYPE, REQUEST_MIMETYPE);
      httpClient.send(httpReq);
    } // method testNext

  } // class Testor

  private static final String CONf_FILE = "xipki/ca-qa/qa-benchmark-conf.json";

  private static final String REQUEST_MIMETYPE = "application/json";

  private static final String RESPONSE_MIMETYPE = "application/json";

  private static final Logger LOG = LoggerFactory.getLogger(CaEnrollBenchmark.class);

  private final CaEnrollBenchEntry benchmarkEntry;

  private final AtomicLong index;

  private final SecureRandom random = new SecureRandom();

  private final int num;

  private final int queueSize;

  private final AtomicInteger processedRequests = new AtomicInteger(0);

  private final Conf conf;

  private final String caHost;

  private final int caPort;

  private final int maxRequests;

  private SslContext sslContext;

  private final boolean caGenKeyPair;

  public CaEnrollBenchmark(
      CaEnrollBenchEntry benchmarkEntry, int maxRequests, int num, int queueSize, String description)
      throws Exception {
    super(description);
    this.maxRequests = maxRequests;
    this.num = positive(num, "num");
    this.benchmarkEntry = notNull(benchmarkEntry, "benchmarkEntry");
    this.index = new AtomicLong(getSecureIndex());
    this.queueSize = queueSize;
    this.caGenKeyPair = benchmarkEntry.getSubjectPublicKeyInfo() == null;

    try (InputStream is = Files.newInputStream(Paths.get(CONf_FILE))) {
      Conf tmpConf = JSON.parseObject(is, Conf.class);
      tmpConf.validate();
      this.conf = tmpConf;
      if (tmpConf.getSsl() != null) {
        try {
          this.sslContext = tmpConf.getSsl().buildSslContext();
        } catch (GeneralSecurityException ex) {
          throw new InvalidConfException(ex.getMessage(), ex);
        }
      }

      URI uri;
      try {
        uri = new URI(conf.getCaUrl());
      } catch (URISyntaxException ex) {
        throw new InvalidConfException(ex.getMessage(), ex);
      }
      int port = uri.getPort();
      if (port == -1) {
        port = uri.getScheme().equalsIgnoreCase("https") ? 443 : 80;
      }

      this.caHost = uri.getHost();
      this.caPort = port;
    }

  } // constructor

  @Override
  protected Runnable getTestor()
      throws Exception {
    return new Testor();
  }

  @Override
  protected long getRealAccount(long account) {
    return num * account;
  }

  public SdkRequest nextCertRequest() throws Exception {
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
  } // method onComplete

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
    } else if (!responseContentType.equalsIgnoreCase(RESPONSE_MIMETYPE)) {
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

    EnrollOrPollCertsResponse sdkResponse = EnrollOrPollCertsResponse.decode(respBytes);
    try {
      parseEnrollCertResult(sdkResponse, num);
      return true;
    } catch (Throwable th) {
      LOG.warn("exception while parsing response", th);
      return false;
    }
  } // method onComplete0

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

  @Override
  public void onError() {
    account(1, 1);
  }

  private byte[] randomBytes(int size) {
    byte[] bytes = new byte[size];
    random.nextBytes(bytes);
    return bytes;
  }

}
