// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.xipki.security.SecurityFactory;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.extra.http.Curl;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Dictionary;
import java.util.Enumeration;

/**
 * HTTP OCSP requestor.
 *
 * @author Lijun Liao (xipki)
 */
@Component(service = OcspRequestor.class, immediate = true,
    configurationPid = "org.xipki.pki.client")
public class HttpOcspRequestor extends AbstractOcspRequestor {

  // result in maximal 254 Base-64 encoded octets
  private static final int MAX_LEN_GET = 190;

  private static final String CT_REQUEST = "application/ocsp-request";

  private static final String CT_RESPONSE = "application/ocsp-response";

  @Reference
  private SecurityFactory securityFactory;

  public HttpOcspRequestor() {
  }

  public SecurityFactory securityFactory() {
    return securityFactory;
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  @Activate
  public void activate(ComponentContext context) {
    Dictionary<String, Object> properties = context.getProperties();
    Enumeration<String> keys = properties.keys();
    while (keys.hasMoreElements()) {
      String key = keys.nextElement();
      Object value = properties.get(key);
      if (!(value instanceof String)) {
        continue;
      }

      String sValue = (String) value;
      if (key.equals("confFile")) {
        setConfFile(sValue);
      }
    }

    init();
  }

  @Override
  protected byte[] send(byte[] request, URL responderUrl, RequestOptions requestOptions)
      throws IOException {
    Args.notNull(responderUrl, "responderUrl");

    int size = Args.notNull(request, "request").length;
    HttpURLConnection httpUrlConnection;
    if (size <= MAX_LEN_GET &&
        Args.notNull(requestOptions, "requestOptions").isUseHttpGetForRequest()) {
      String b64Request = Base64.getEncoder().encodeToString(request);
      String urlEncodedReq = URLEncoder.encode(b64Request, StandardCharsets.UTF_8);
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

    httpUrlConnection.setConnectTimeout(Curl.DEFAULT_CONNECT_TIMEOUT_MS);
    httpUrlConnection.setReadTimeout(Curl.DEFAULT_READ_TIMEOUT_MS);

    InputStream inputstream = httpUrlConnection.getInputStream();
    if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
      inputstream.close();
      throw new IOException("bad response: "
          + httpUrlConnection.getResponseCode() + "    "
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
