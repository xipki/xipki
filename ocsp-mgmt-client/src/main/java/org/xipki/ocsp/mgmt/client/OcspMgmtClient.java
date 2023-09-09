// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.mgmt.client;

import org.xipki.ocsp.api.mgmt.MgmtMessage.MgmtAction;
import org.xipki.ocsp.api.mgmt.MgmtRequest;
import org.xipki.ocsp.api.mgmt.OcspManager;
import org.xipki.ocsp.api.mgmt.OcspMgmtException;
import org.xipki.security.util.JSON;
import org.xipki.util.Args;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.http.SslContextConf;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * OCSP Management client. It communicates with the server via REST API.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspMgmtClient implements OcspManager {

  private static final String REQUEST_CT = "application/json";

  private static final String RESPONSE_CT = "application/json";

  private final Map<MgmtAction, URL> actionUrlMap = new HashMap<>(50);

  private final SslContextConf sslContextConf;

  private SSLSocketFactory sslSocketFactory;

  private HostnameVerifier hostnameVerifier;

  private boolean initialized;

  private OcspMgmtException initException;

  public OcspMgmtClient(SslContextConf sslContextConf) {
    this.sslContextConf = sslContextConf;
  }

  public void setServerUrl(String serverUrl) throws MalformedURLException {
    Args.notBlank(serverUrl, "serverUrl");
    if (!serverUrl.endsWith("/")) {
      serverUrl += "/";
    }

    for (MgmtAction action : MgmtAction.values()) {
      actionUrlMap.put(action, new URL(serverUrl + action));
    }
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
        initException = new OcspMgmtException("could not initialize CaMgmtClient: " + ex.getMessage(), ex);
        throw initException;
      }
    }

    initialized = true;
  } // method initIfNotDone

  @Override
  public void restartOcspServer() throws OcspMgmtException {
    voidTransmit(MgmtAction.restartServer, null);
  }

  private void voidTransmit(MgmtAction action, MgmtRequest req) throws OcspMgmtException {
    transmit(action, req, true);
  }

  @SuppressWarnings("unused")
  private byte[] transmit(MgmtAction action, MgmtRequest req) throws OcspMgmtException {
    return transmit(action, req, false);
  }

  private byte[] transmit(MgmtAction action, MgmtRequest req, boolean voidReturn)
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
            throw new OcspMgmtException("bad response: mime type " + responseContentType + " not supported!");
          }

          if (voidReturn) {
            return null;
          } else {
            inClosed = true;
            return IoUtil.readAndClose(httpUrlConnection.getInputStream());
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
      throw new OcspMgmtException("IOException while sending message to the server: " + ex.getMessage(), ex);
    }
  } // method transmit

}
