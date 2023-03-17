// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.api.mgmt.MgmtMessage.MgmtAction;
import org.xipki.ocsp.server.OcspServerImpl;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.X509Cert;
import org.xipki.util.HttpConstants;
import org.xipki.util.exception.InvalidConfException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import static org.xipki.util.Args.notEmpty;
import static org.xipki.util.Args.notNull;

/**
 * REST management servlet of OCSP server.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class HttpMgmtServlet extends HttpServlet {

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

  private static final Logger LOG = LoggerFactory.getLogger(HttpMgmtServlet.class);

  private static final String CT_RESPONSE = "application/json";

  private Set<X509Cert> mgmtCerts;

  private OcspServerImpl ocspServer;

  public void setMgmtCerts(Set<X509Cert> mgmtCerts) {
    this.mgmtCerts = new HashSet<>(notEmpty(mgmtCerts, "mgmtCerts"));
  }

  public void setOcspServer(OcspServerImpl ocspServer) {
    this.ocspServer = notNull(ocspServer, "ocspServer");
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    try {
      X509Cert clientCert = TlsHelper.getTlsClientCert(request);
      if (clientCert == null) {
        throw new MyException(HttpServletResponse.SC_UNAUTHORIZED,
            "remote management is not permitted if TLS client certificate is not present");
      }

      if (!mgmtCerts.contains(clientCert)) {
        throw new MyException(HttpServletResponse.SC_UNAUTHORIZED,
            "remote management is not permitted to the client without valid certificate");
      }

      String path = (String) request.getAttribute(HttpConstants.ATTR_XIPKI_PATH);

      if (path == null || path.length() < 2) {
        throw new MyException(HttpServletResponse.SC_NOT_FOUND, "no action is specified");
      }

      String actionStr = path.substring(1);
      MgmtAction action = MgmtAction.ofName(actionStr);
      if (action == null) {
        throw new MyException(HttpServletResponse.SC_NOT_FOUND, "unknown action '" + actionStr + "'");
      }

      if (action == MgmtAction.restartServer) {
        try {
          ocspServer.init(true);
        } catch (InvalidConfException | PasswordResolverException ex) {
          LOG.warn(action + ": could not restart OCSP server", ex);
          throw new MyException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
              "could not build the CaEntry: " + ex.getMessage());
        }
      } else {
          throw new MyException(HttpServletResponse.SC_NOT_FOUND, "unsupported action " + action);
      }

      response.setContentType(CT_RESPONSE);
      response.setStatus(HttpServletResponse.SC_OK);
      response.setContentLength(0);
    } catch (MyException ex) {
      response.setHeader(HttpConstants.HEADER_XIPKI_ERROR, ex.getMessage());
      response.sendError(ex.getStatus());
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      response.flushBuffer();
    }
  } // method doPost

}
