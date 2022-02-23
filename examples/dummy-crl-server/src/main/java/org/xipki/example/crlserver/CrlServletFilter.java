/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.example.crlserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.*;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Dummy CRL ServletFilter.
 *
 * @author Lijun Liao
 */
public class CrlServletFilter implements Filter {

  private static class CrlWrapper {
    String caName;
    long crlNo;
    byte[] sha1Fp;
    byte[] crl;
  }

  private static final Logger LOG = LoggerFactory.getLogger(CrlServletFilter.class);

  private static final String RESP_CONTENT_TYPE = "application/pkix-crl";

  private static final String DFLT_CA_SERVER_CFG = "xipki/etc/ca/database/ca-db.properties";

  private DataSourceWrapper dataSource;

  private final ConcurrentLinkedQueue<CrlWrapper> crls = new ConcurrentLinkedQueue<>();

  @Override
  public void init(FilterConfig filterConfig)
          throws ServletException {
    XipkiBaseDir.init();
    try {
      this.dataSource = new DataSourceFactory().createDataSourceForFile(
              "ca", DFLT_CA_SERVER_CFG, null);
    } catch (PasswordResolverException | IOException ex) {
      LOG.error("error initializing datasource", ex);
    }
  } // method init

  @Override
  public void destroy() {
    if (dataSource != null) {
      dataSource.close();
    }
  } // method destroy

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
          throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest & response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse resp = (HttpServletResponse) response;

    String hashalgo = req.getParameter("hashalgo");
    String caName = req.getParameter("name");
    String type = req.getParameter("type");
    if (!("crl".equalsIgnoreCase(type) || "deltacrl".equalsIgnoreCase(type))) {
      LOG.warn("Type {} is not in the supported types [crl, deltacrl]", type);
      sendError(resp, HttpServletResponse.SC_NOT_FOUND);
      return;
    }

    if (hashalgo == null) {
      LOG.info("GET CRL for CA {}", caName);
    } else {
      if ("sha1".equalsIgnoreCase(hashalgo) || "sha-1".equalsIgnoreCase(hashalgo)) {
        LOG.info("Get {} hash value for CA {}", hashalgo, caName);
      } else {
        LOG.warn("Unknown hashalgo  {}", hashalgo);
        sendError(resp, HttpServletResponse.SC_NOT_FOUND);
        return;
      }
    }

    Connection conn = null;
    try {
      conn = dataSource.getConnection();
      String sql = dataSource.buildSelectFirstSql(1, "ID FROM CA WHERE NAME='" + caName + "'");
      ResultSet rs = dataSource.createStatement(conn).executeQuery(sql);

      int id;
      try {
        if (!rs.next()) {
          LOG.warn("Unknown CA {}", caName);
          sendError(resp, HttpServletResponse.SC_NOT_FOUND);
          return;
        }
        id = rs.getInt("ID");
      } finally {
        dataSource.releaseResources(null, rs);
      }

      long crlNo = dataSource.getMax(conn, "CRL", "CRL_NO",
              "CA_ID=" + id + " AND DELTACRL=" + ("deltacrl".equalsIgnoreCase(type) ? 1 : 0));
      if (crlNo == 0) {
        LOG.warn("No CRL for CA {}", caName);
        sendError(resp, HttpServletResponse.SC_NOT_FOUND);
        return;
      }

      // Get the cached CRL
      CrlWrapper cachedCrl = null;
      for (CrlWrapper crl : crls) {
        if (crl.caName.equals(caName)) {
          cachedCrl = crl;
          break;
        }
      }

      if (cachedCrl != null) {
        // the cached CRL is not the latest, remove it from cache
        if (cachedCrl.crlNo != crlNo) {
          crls.remove(cachedCrl);
          cachedCrl = null;
        }
      }

      if (cachedCrl == null) {
        // retrieve the CRL from the database
        sql = dataSource.buildSelectFirstSql(1,
                "CRL FROM CRL WHERE CA_ID=" + id + " AND CRL_NO=" + crlNo);
        rs = dataSource.prepareStatement(sql).executeQuery();
        try {
          if (rs.next()) {
            String b64Crl = rs.getString("CRL");
            byte[] encodedCrl = Base64.decodeFast(b64Crl);
            cachedCrl = new CrlWrapper();
            cachedCrl.crlNo = crlNo;
            cachedCrl.caName = caName;
            cachedCrl.crl = encodedCrl;
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            cachedCrl.sha1Fp = sha1.digest(encodedCrl);
            crls.add(cachedCrl);
          }
        } finally {
          dataSource.releaseResources(null, rs);
        }
      }

      byte[] respContent = hashalgo == null ? cachedCrl.crl : cachedCrl.sha1Fp;
      resp.setContentType(hashalgo == null ? RESP_CONTENT_TYPE : "application/octet-stream");
      resp.setContentLengthLong(respContent.length);
      resp.getOutputStream().write(respContent);
      resp.setStatus(HttpServletResponse.SC_OK);
    } catch (Throwable th) {
      LogUtil.error(LOG, th);
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      if (conn != null) {
        dataSource.returnConnection(conn);
      }
    }
  } // method doFilter

  private static void sendError(HttpServletResponse resp, int status) {
    resp.setStatus(status);
    resp.setContentLength(0);
  } // method sendError

}
