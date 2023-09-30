// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.api.mgmt.MgmtMessage.MgmtAction;
import org.xipki.ocsp.server.OcspServerImpl;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.X509Cert;
import org.xipki.security.util.HttpRequestMetadataRetriever;
import org.xipki.util.HttpConstants;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.RestResponse;

import java.io.InputStream;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.xipki.util.Args.notEmpty;
import static org.xipki.util.Args.notNull;

/**
 * REST management servlet of OCSP server.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class HttpMgmtServlet0 {

  private static final class MyException extends Exception {

    private final int status;

    public MyException(int status, String message) {
      super(message);
      this.status = status;
    }

    public int getStatus() {
      return status;
    }

  } // class MyException

  private static final Logger LOG = LoggerFactory.getLogger(HttpMgmtServlet0.class);

  private static final String CT_RESPONSE = "application/json";

  private Set<X509Cert> mgmtCerts;

  private OcspServerImpl ocspServer;

  public void setMgmtCerts(Set<X509Cert> mgmtCerts) {
    this.mgmtCerts = new HashSet<>(notEmpty(mgmtCerts, "mgmtCerts"));
  }

  public void setOcspServer(OcspServerImpl ocspServer) {
    this.ocspServer = notNull(ocspServer, "ocspServer");
  }

  public RestResponse doPost(HttpRequestMetadataRetriever req, InputStream reqStream) {
    try {
      X509Cert clientCert = req.getTlsClientCert();
      if (clientCert == null) {
        throw new MyException(HttpStatusCode.SC_UNAUTHORIZED,
            "remote management is not permitted if TLS client certificate is not present");
      }

      if (!mgmtCerts.contains(clientCert)) {
        throw new MyException(HttpStatusCode.SC_UNAUTHORIZED,
            "remote management is not permitted to the client without valid certificate");
      }

      String path = (String) req.getAttribute(HttpConstants.ATTR_XIPKI_PATH);

      if (path == null || path.length() < 2) {
        throw new MyException(HttpStatusCode.SC_NOT_FOUND, "no action is specified");
      }

      String actionStr = path.substring(1);
      MgmtAction action = MgmtAction.ofName(actionStr);
      if (action == null) {
        throw new MyException(HttpStatusCode.SC_NOT_FOUND, "unknown action '" + actionStr + "'");
      }

      if (action == MgmtAction.restartServer) {
        try {
          ocspServer.init(true);
        } catch (InvalidConfException | PasswordResolverException ex) {
          LOG.warn(action + ": could not restart OCSP server", ex);
          throw new MyException(HttpStatusCode.SC_INTERNAL_SERVER_ERROR,
              "could not restart OCSP server: " + ex.getMessage());
        }
      } else {
          throw new MyException(HttpStatusCode.SC_NOT_FOUND, "unsupported action " + action);
      }

      return new RestResponse(HttpStatusCode.SC_OK, CT_RESPONSE, null, new byte[0]);
    } catch (MyException ex) {
      Map<String, String> headers = Collections.singletonMap(HttpConstants.HEADER_XIPKI_ERROR, ex.getMessage());
      return new RestResponse(ex.getStatus(), null, headers, null);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      return new RestResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    }
  } // method doPost

}
