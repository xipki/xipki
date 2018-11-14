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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.xipki.ocsp.client.api.OcspRequestorException;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HttpClient {

  // result in maximal 254 Base-64 encoded octets
  private static final int MAX_LEN_GET = 190;

  private static final String CT_REQUEST = "application/ocsp-request";

  private static final String CT_RESPONSE = "application/ocsp-response";

  private URL responderUrl;

  private boolean viaHttpGetIfPossible;

  private boolean parseResponse;

  public HttpClient(URL responderUrl, boolean viaHttpGetIfPossible, boolean parseResponse) {
    this.responderUrl = responderUrl;
    this.viaHttpGetIfPossible = viaHttpGetIfPossible;
    this.parseResponse = parseResponse;
  }

  public void send(byte[] request) throws IOException, OcspRequestorException {
    Args.notNull(request, "request");
    Args.notNull(responderUrl, "responderUrl");

    int size = request.length;
    HttpURLConnection httpUrlConnection;
    if (viaHttpGetIfPossible && size <= MAX_LEN_GET) {
      String b64Request = Base64.encodeToString(request);
      String urlEncodedReq = URLEncoder.encode(b64Request, "UTF-8");
      String baseUrl = responderUrl.toString();
      String url = StringUtil.concat(baseUrl, (baseUrl.endsWith("/") ? "" : "/"), urlEncodedReq);

      URL newUrl = new URL(url);
      httpUrlConnection = IoUtil.openHttpConn(newUrl);
      httpUrlConnection.setRequestMethod("GET");
    } else {
      httpUrlConnection = IoUtil.openHttpConn(responderUrl);
      httpUrlConnection.setDoOutput(true);
      httpUrlConnection.setUseCaches(false);

      httpUrlConnection.setRequestMethod("POST");
      httpUrlConnection.setRequestProperty("Content-Type", CT_REQUEST);
      httpUrlConnection.setRequestProperty("Content-Length", Integer.toString(size));
      OutputStream outputstream = httpUrlConnection.getOutputStream();
      outputstream.write(request);
      outputstream.flush();
    }

    InputStream inputstream = httpUrlConnection.getInputStream();
    if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
      inputstream.close();
      throw new IOException("bad response: " + httpUrlConnection.getResponseCode() + "    "
          + httpUrlConnection.getResponseMessage());
    }

    String responseContentType = httpUrlConnection.getContentType();
    boolean isValidContentType = false;
    if (responseContentType != null) {
      if (responseContentType.equalsIgnoreCase(CT_RESPONSE)) {
        isValidContentType = true;
      }
    }

    if (!isValidContentType) {
      inputstream.close();
      throw new IOException("bad response: mime type " + responseContentType + " not supported!");
    }

    byte[] respBytes = IoUtil.read(inputstream);
    if (respBytes == null || respBytes.length == 0) {
      throw new IOException("no body in response");
    }

    if (!parseResponse) {
      // a valid response should at least of size 10.
      if (respBytes.length < 10) {
        throw new OcspRequestorException("bad response: response too short");
      }
      return;
    }

    OCSPResp ocspResp;
    try {
      ocspResp = new OCSPResp(respBytes);
    } catch (IOException ex) {
      throw new OcspRequestorException("could not parse OCSP response", ex);
    }

    Object respObject;
    try {
      respObject = ocspResp.getResponseObject();
    } catch (OCSPException ex) {
      throw new OcspRequestorException("responseObject is invalid", ex);
    }

    if (ocspResp.getStatus() != 0) {
      throw new OcspRequestorException("bad response: response status is other than OK");
    }

    if (!(respObject instanceof BasicOCSPResp)) {
      throw new OcspRequestorException("bad response: response is not BasiOCSPResp");
    }
  } // method send

}
