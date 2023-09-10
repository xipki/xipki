// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import static org.xipki.util.Args.notNull;

/**
 * HTTP OCSP requestor.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class HttpOcspRequestor extends AbstractOcspRequestor {

  // result in maximal 254 Base-64 encoded octets
  private static final int MAX_LEN_GET = 190;

  private static final String CT_REQUEST = "application/ocsp-request";

  private static final String CT_RESPONSE = "application/ocsp-response";

  public HttpOcspRequestor() {
  }

  @Override
  protected byte[] send(byte[] request, URL responderUrl, RequestOptions requestOptions)
      throws IOException {
    notNull(request, "request");
    notNull(responderUrl, "responderUrl");
    notNull(requestOptions, "requestOptions");

    int size = request.length;
    HttpURLConnection httpUrlConnection;
    if (size <= MAX_LEN_GET && requestOptions.isUseHttpGetForRequest()) {
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

    return IoUtil.readAllBytesAndClose(inputstream);
  } // method send

}
