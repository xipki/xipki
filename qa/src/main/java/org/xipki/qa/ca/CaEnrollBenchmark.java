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
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.qa.BenchmarkHttpClient;
import org.xipki.qa.BenchmarkHttpClient.HttpClientException;
import org.xipki.qa.BenchmarkHttpClient.ResponseHandler;
import org.xipki.qa.BenchmarkHttpClient.SslConf;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.cmp.CmpUtf8Pairs;
import org.xipki.security.util.X509Util;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Date;
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

    private String requestorCert;

    private String responderCert;

    private SslConf ssl;

    private GeneralName requestor;

    private GeneralName responder;

    public String getCaUrl() {
      return caUrl;
    }

    public void setCaUrl(String caUrl) {
      this.caUrl = caUrl;
    }

    public String getRequestorCert() {
      return requestorCert;
    }

    public void setRequestorCert(String requestorCert) {
      this.requestorCert = requestorCert;
    }

    public String getResponderCert() {
      return responderCert;
    }

    public void setResponderCert(String responderCert) {
      this.responderCert = responderCert;
    }

    public SslConf getSsl() {
      return ssl;
    }

    public void setSsl(SslConf ssl) {
      this.ssl = ssl;
    }

    public GeneralName requestor()
        throws CertificateException, IOException {
      if (requestor == null && requestorCert != null) {
        X500Name subject = X509Util.parseCert(new File(requestorCert)).getSubject();
        requestor = new GeneralName(subject);
      }
      return requestor;
    }

    public GeneralName responder()
        throws CertificateException, IOException {
      if (responder == null && responderCert != null) {
        X500Name subject = X509Util.parseCert(new File(responderCert)).getSubject();
        responder = new GeneralName(subject);
      }
      return responder;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notBlank(requestorCert, "requestorCert");
      notBlank(responderCert, "responderCert");
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
          PKIMessage certReq = nextCertRequest();
          if (certReq == null) {
            break;
          }

          testNext(certReq);
        } catch (HttpClientException | CertificateException | IOException ex) {
          LOG.warn("exception", ex);
          account(1, 1);
        } catch (RuntimeException | Error ex) {
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

    private void testNext(PKIMessage certReq)
        throws HttpClientException, IOException {
      byte[] encoded = certReq.getEncoded();
      ByteBuf content = Unpooled.wrappedBuffer(encoded);
      FullHttpRequest httpReq = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
          HttpMethod.POST, conf.caUrl, content);
      httpReq.headers().addInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes())
        .add(HttpHeaderNames.CONTENT_TYPE, REQUEST_MIMETYPE);
      httpClient.send(httpReq);
    } // method testNext

  } // class Testor

  private static final String CONf_FILE = "xipki/ca-qa/qa-benchmark-conf.json";

  private static final String REQUEST_MIMETYPE = "application/pkixcmp";

  private static final String RESPONSE_MIMETYPE = "application/pkixcmp";

  private static final ProofOfPossession RA_VERIFIED = new ProofOfPossession();

  private static final InfoTypeAndValue IMPLICIT_CONFIRM =
      new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE);

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

  private final SslContext sslContext;

  private final boolean caGenKeyPair;

  public CaEnrollBenchmark(
          CaEnrollBenchEntry benchmarkEntry,
          int maxRequests,
          int num,
          int queueSize,
          String description)
          throws IOException, InvalidConfException {
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
      try {
        this.sslContext = tmpConf.getSsl().buildSslContext();
      } catch (GeneralSecurityException ex) {
        throw new InvalidConfException(ex.getMessage(), ex);
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

  public PKIMessage nextCertRequest()
      throws IOException, CertificateException {
    if (maxRequests > 0) {
      int num = processedRequests.getAndAdd(1);
      if (num >= maxRequests) {
        return null;
      }
    }

    CertReqMsg[] certReqMsgs = new CertReqMsg[num];

    for (int i = 0; i < num; i++) {
      CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();

      long thisIndex = index.getAndIncrement();
      certTempBuilder.setSubject(benchmarkEntry.getX500Name(thisIndex));

      if (!caGenKeyPair) {
        SubjectPublicKeyInfo spki = benchmarkEntry.getSubjectPublicKeyInfo();
        certTempBuilder.setPublicKey(spki);
      }

      CertTemplate certTemplate = certTempBuilder.build();
      CertRequest certRequest = new CertRequest(new ASN1Integer(i + 1), certTemplate, null);
      certReqMsgs[i] = new CertReqMsg(certRequest, RA_VERIFIED, null);
    }

    PKIHeaderBuilder builder = new PKIHeaderBuilder(
        PKIHeader.CMP_2000, conf.requestor(), conf.responder());
    builder.setMessageTime(new ASN1GeneralizedTime(new Date()));
    builder.setTransactionID(randomBytes(8));
    builder.setSenderNonce(randomBytes(8));

    InfoTypeAndValue certprofileInfo =
            new InfoTypeAndValue(ObjectIdentifiers.CMP.id_it_certProfile,
                    new DERSequence(new DERUTF8String(benchmarkEntry.getCertprofile())));
    builder.setGeneralInfo(new InfoTypeAndValue[]{IMPLICIT_CONFIRM, certprofileInfo});

    PKIBody body = new PKIBody(PKIBody.TYPE_CERT_REQ, new CertReqMessages(certReqMsgs));
    return new PKIMessage(builder.build(), body);
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

    PKIMessage cmpResponse = PKIMessage.getInstance(respBytes);
    try {
      parseEnrollCertResult(cmpResponse, PKIBody.TYPE_CERT_REP, num);
      return true;
    } catch (Throwable th) {
      LOG.warn("exception while parsing response", th);
      return false;
    }
  } // method onComplete0

  private void parseEnrollCertResult(PKIMessage response, int resonseBodyType, int numCerts)
      throws Exception {
    PKIBody respBody = response.getBody();
    final int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new Exception("Server returned PKIStatus: " + buildText(content.getPKIStatusInfo()));
    } else if (resonseBodyType != bodyType) {
      throw new Exception(String.format("unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, resonseBodyType, PKIBody.TYPE_ERROR));
    }

    CertRepMessage certRep = CertRepMessage.getInstance(respBody.getContent());
    CertResponse[] certResponses = certRep.getResponse();

    if (certResponses.length != numCerts) {
      throw new Exception("expected " + numCerts + " CertResponse, but returned "
          + certResponses.length);
    }

    for (int i = 0; i < numCerts; i++) {
      CertResponse certResp = certResponses[i];
      PKIStatusInfo statusInfo = certResp.getStatus();
      int status = statusInfo.getStatus().intValue();
      BigInteger certReqId = certResp.getCertReqId().getValue();

      if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
        throw new Exception("CertReqId " + certReqId
            + ": server returned PKIStatus: " + buildText(statusInfo));
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

  private static String buildText(PKIStatusInfo pkiStatusInfo) {
    final int status = pkiStatusInfo.getStatus().intValue();
    switch (status) {
      case 0:
        return "accepted (0)";
      case 1:
        return "grantedWithMods (1)";
      case 2:
        return "rejection (2)";
      case 3:
        return "waiting (3)";
      case 4:
        return "revocationWarning (4)";
      case 5:
        return "revocationNotification (5)";
      case 6:
        return "keyUpdateWarning (6)";
      default:
        return Integer.toString(status);
    }
  } // method buildText

}
