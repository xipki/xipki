/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ca.server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.security.CtLog.DigitallySigned;
import org.xipki.security.CtLog.SerializedSCT;
import org.xipki.security.CtLog.SignedCertificateTimestamp;
import org.xipki.security.CtLog.SignedCertificateTimestampList;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.Curl;
import org.xipki.util.Curl.CurlResult;
import org.xipki.util.DefaultCurl;
import org.xipki.util.StringUtil;
import org.xipki.util.http.SslContextConf;

import com.alibaba.fastjson.JSON;

/**
 * Certificate transparency (CT) log client.
 *
 * @author Lijun Liao
 */
public class CtLogClient {

  private static Logger LOG = LoggerFactory.getLogger(CtLogClient.class);

  // Do not change the variable name, and the get- and set-methods.
  public static class AddPreChainRequest {
    private List<byte[]> chain;

    public List<byte[]> getChain() {
      return chain;
    }

    public void setChain(List<byte[]> chain) {
      this.chain = chain;
    }

  } // class AddPreChainRequest

  // Do not change the variable name, and the get- and set-methods.
  public static class AddPreChainResponse {

    // CHECKSTYLE:SKIP
    private byte sct_version;

    private byte[] id;

    private long timestamp;

    private byte[] extensions;

    private byte[] signature;

    public byte getSct_version() {
      return sct_version;
    }

    // CHECKSTYLE:SKIP
    public void setSct_version(byte sct_version) {
      this.sct_version = sct_version;
    }

    public byte[] getId() {
      return id;
    }

    public void setId(byte[] id) {
      this.id = id;
    }

    public long getTimestamp() {
      return timestamp;
    }

    public void setTimestamp(long timestamp) {
      this.timestamp = timestamp;
    }

    public byte[] getExtensions() {
      return extensions;
    }

    public void setExtensions(byte[] extensions) {
      this.extensions = extensions;
    }

    public byte[] getSignature() {
      return signature;
    }

    public void setSignature(byte[] signature) {
      this.signature = signature;
    }

  } // class AddPreChainResponse

  private final Curl curl;

  private final List<String> addPreChainUrls;

  public CtLogClient(List<String> serverUrls, SslContextConf sslContextConf) {
    Args.notEmpty(serverUrls, "serverUrls");

    DefaultCurl dfltCurl  = new DefaultCurl();
    dfltCurl.setSslContextConf(sslContextConf);
    this.curl = dfltCurl;
    this.addPreChainUrls = new ArrayList<>(serverUrls.size());
    for (String m : serverUrls) {
      String addPreChainUrl = m.endsWith("/")
          ? m + "ct/v1/add-pre-chain" : m + "/ct/v1/add-pre-chain";
      this.addPreChainUrls.add(addPreChainUrl);
    }
  } // constructor

  public SignedCertificateTimestampList getCtLogScts(
      byte[] precert, X509Cert caCert, List<X509Cert> certchain) throws OperationException {
    AddPreChainRequest request = new AddPreChainRequest();
    List<byte[]> chain = new LinkedList<>();
    request.setChain(chain);

    chain.add(precert);
    chain.add(caCert.getEncodedCert());
    if (certchain != null) {
      for (X509Cert m : certchain) {
        chain.add(m.getEncodedCert());
      }
    }

    byte[] content = JSON.toJSONBytes(request);
    if (LOG.isDebugEnabled()) {
      LOG.debug("CTLog Request: {}", StringUtil.toUtf8String(content));
    }

    List<SignedCertificateTimestamp> scts = new ArrayList<>(addPreChainUrls.size());
    Map<String, String> headers = new HashMap<>();
    headers.put("content-type", "application/json");
    for (String url : addPreChainUrls) {
      CurlResult res;
      try {
        res = curl.curlPost(url, false, headers, null, content);
      } catch (Exception ex) {
        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
            "error while calling " + url + ": " + ex.getMessage());
      }

      byte[] respContent = res.getContent();
      if (respContent == null) {
        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
            "server does not return any content while responding " + url);
      }

      if (LOG.isDebugEnabled()) {
        LOG.debug("CTLog Response: {}", StringUtil.toUtf8String(respContent));
      }

      AddPreChainResponse resp = JSON.parseObject(respContent, AddPreChainResponse.class);

      DigitallySigned ds = DigitallySigned.getInstance(resp.getSignature(), new AtomicInteger(0));
      SignedCertificateTimestamp sct = new SignedCertificateTimestamp(resp.getSct_version(),
          resp.getId(), resp.getTimestamp(), resp.getExtensions(), ds);
      scts.add(sct);
    }

    return new SignedCertificateTimestampList(new SerializedSCT(scts));
  } // method getCtLogScts

}
