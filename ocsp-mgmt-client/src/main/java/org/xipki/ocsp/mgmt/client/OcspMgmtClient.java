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

package org.xipki.ocsp.mgmt.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.xipki.ocsp.server.mgmt.api.OcspManager;
import org.xipki.ocsp.server.mgmt.api.OcspMgmtException;
import org.xipki.ocsp.server.mgmt.msg.CommAction;
import org.xipki.ocsp.server.mgmt.msg.CommRequest;
import org.xipki.ocsp.server.mgmt.msg.CommResponse;
import org.xipki.ocsp.server.mgmt.msg.NameRequest;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.http.ssl.SslContextConf;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 */

public class OcspMgmtClient implements OcspManager {

  private static final String REQUEST_CT = "application/json";

  private static final String RESPONSE_CT = "application/json";

  private final Map<CommAction, URL> actionUrlMap = new HashMap<>(50);

  private String serverUrl;

  private SslContextConf sslContextConf;

  private SSLSocketFactory sslSocketFactory;

  private HostnameVerifier hostnameVerifier;

  private boolean initialized;

  private OcspMgmtException initException;

  public OcspMgmtClient() {
  }

  public void setServerUrl(String serverUrl) throws MalformedURLException {
    ParamUtil.requireNonBlank("serverUrl", serverUrl);
    this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";

    for (CommAction action : CommAction.values()) {
      actionUrlMap.put(action, new URL(this.serverUrl + action));
    }
  }

  public void setSslContextConf(SslContextConf sslContextConf) {
    this.sslContextConf = sslContextConf;
  }

  public synchronized void initIfNotDone() throws OcspMgmtException {
    if (initException != null) {
      throw initException;
    }

    if (initialized) {
      return;
    }

    if (sslContextConf != null && sslContextConf.isUseSslConf()) {
      try {
        sslSocketFactory = sslContextConf.getSslSocketFactory();
        hostnameVerifier = sslContextConf.buildHostnameVerifier();
      } catch (ObjectCreationException ex) {
        initException = new OcspMgmtException(
            "could not initialize CaMgmtClient: " + ex.getMessage(), ex);
        throw initException;
      }
    }

    initialized = true;
  }

  @Override
  public void restartOcspServer() throws OcspMgmtException {
    voidTransmit(CommAction.restartServer, null);
  }

  @Override
  public void refreshTokenForSignerType(String signerType) throws OcspMgmtException {
    NameRequest req = new NameRequest(signerType);
    voidTransmit(CommAction.refreshTokenForSignerType, req);
  }

  private void voidTransmit(CommAction action, CommRequest req) throws OcspMgmtException {
    transmit(action, req, true);
  }

  @SuppressWarnings("unused")
  private byte[] transmit(CommAction action, CommRequest req) throws OcspMgmtException {
    return transmit(action, req, false);
  }

  private byte[] transmit(CommAction action, CommRequest req, boolean voidReturn)
      throws OcspMgmtException {
    initIfNotDone();

    byte[] reqBytes = req == null ? null : JSON.toJSONBytes(req);
    int size = reqBytes == null ? 0 : reqBytes.length;

    URL url = actionUrlMap.get(action);

    try {
      HttpURLConnection httpUrlConnection = IoUtil.openHttpConn(url);
      if (httpUrlConnection instanceof HttpsURLConnection) {
        if (sslSocketFactory != null) {
          ((HttpsURLConnection) httpUrlConnection).setSSLSocketFactory(sslSocketFactory);
        }
        if (hostnameVerifier != null) {
          ((HttpsURLConnection) httpUrlConnection).setHostnameVerifier(hostnameVerifier);
        }
      }

      httpUrlConnection.setDoOutput(true);
      httpUrlConnection.setUseCaches(false);

      httpUrlConnection.setRequestMethod("POST");
      httpUrlConnection.setRequestProperty("Content-Type", REQUEST_CT);
      httpUrlConnection.setRequestProperty("Content-Length", java.lang.Integer.toString(size));
      OutputStream outputstream = httpUrlConnection.getOutputStream();
      if (size != 0) {
        outputstream.write(reqBytes);
      }
      outputstream.flush();

      if (httpUrlConnection.getResponseCode() == HttpURLConnection.HTTP_OK) {
        InputStream in = httpUrlConnection.getInputStream();

        boolean inClosed = false;
        try {
          String responseContentType = httpUrlConnection.getContentType();
          if (!RESPONSE_CT.equals(responseContentType)) {
            throw new OcspMgmtException(
                "bad response: mime type " + responseContentType + " not supported!");
          }

          if (voidReturn) {
            return null;
          } else {
            inClosed = true;
            return IoUtil.read(httpUrlConnection.getInputStream());
          }
        } finally {
          if (in != null & !inClosed) {
            in.close();
          }
        }
      } else {
        String errorMessage = httpUrlConnection.getHeaderField(HttpConstants.HEADER_XIPKI_ERROR);
        if (errorMessage == null) {
          StringBuilder sb = new StringBuilder(100);
          sb.append("server returns ").append(httpUrlConnection.getResponseCode());
          String respMsg = httpUrlConnection.getResponseMessage();
          if (StringUtil.isNotBlank(respMsg)) {
            sb.append(" ").append(respMsg);
          }
          throw new OcspMgmtException(sb.toString());
        } else {
          throw new OcspMgmtException(errorMessage);
        }
      }
    } catch (IOException ex) {
      throw new OcspMgmtException(
          "IOException while sending message to the server: " + ex.getMessage(), ex);
    }
  }

  @SuppressWarnings("unused")
  private static <T extends CommResponse> T parse(byte[] bytes, Class<?> clazz)
      throws OcspMgmtException {
    try {
      return JSON.parseObject(bytes, clazz);
    } catch (RuntimeException ex) {
      throw new OcspMgmtException("cannot parse response " + clazz + " from byte[]", ex);
    }
  }

}
