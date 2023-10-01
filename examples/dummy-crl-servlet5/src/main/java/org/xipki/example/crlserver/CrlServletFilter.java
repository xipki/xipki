// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.example.crlserver;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolverException;
import org.xipki.password.Passwords;
import org.xipki.util.Base64;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.XipkiBaseDir;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;

/**
 * Dummy CRL ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CrlServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(CrlServletFilter.class);

  private static final String RESP_CONTENT_TYPE = "application/pkix-crl";

  private static final String DFLT_CA_DB_CFG = "xipki/etc/ca/database/ca-db.properties";

  private static final String DFLT_CA_SERVER_CFG = "xipki/etc/ca/ca.json";

  private DataSourceWrapper dataSource;

  private boolean hasSha1Column;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    XipkiBaseDir.init();
    try {
      String masterPasswordCallback = null;
      // read the password resolver configuration
      try (BufferedReader reader = new BufferedReader(new FileReader(DFLT_CA_SERVER_CFG))) {
        String name = "\"masterPasswordCallback\"";
        String line;
        while ((line = reader.readLine()) != null) {
          if (line.contains(name)) {
            line = line.trim();
            if (line.startsWith(name)) {
              masterPasswordCallback = line.substring(name.length() + 2, line.length() - 1); // 2=":\"".length
              break;
            }
          }
        }
      }

      Passwords passwords = new Passwords();
      Passwords.PasswordConf conf = new Passwords.PasswordConf();
      conf.setMasterPasswordCallback(masterPasswordCallback);
      passwords.init(conf);

      this.dataSource = new DataSourceFactory().createDataSourceForFile("ca", DFLT_CA_DB_CFG,
          passwords.getPasswordResolver());
      this.hasSha1Column = dataSource.tableHasColumn(null, "CRL", "SHA1");
    } catch (PasswordResolverException | IOException | DataAccessException ex) {
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
    if (!StringUtil.orEqualsIgnoreCase(type, "crl", "deltacrl")) {
      LOG.warn("Type {} is not in the supported types [crl, deltacrl]", type);
      sendError(resp, HttpServletResponse.SC_NOT_FOUND);
      return;
    }

    if (hashalgo == null) {
      LOG.info("GET CRL for CA {}", caName);
    } else {
      if (StringUtil.orEqualsIgnoreCase(hashalgo, "sha1", "sha-1")) {
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

      // retrieve the CRL from the database
      String columnName = "CRL";
      if (hasSha1Column && hashalgo != null) {
        columnName = "SHA1";
      }
      sql = dataSource.buildSelectFirstSql(1,
          columnName + " FROM CRL WHERE CA_ID=" + id + " AND CRL_NO=" + crlNo);
      rs = dataSource.prepareStatement(sql).executeQuery();

      byte[] dbContent;
      try {
        rs.next();
        String b64 = rs.getString(columnName);
        dbContent = Base64.decodeFast(b64);
      } finally {
        dataSource.releaseResources(null, rs);
      }

      byte[] respContent;
      if (hashalgo != null && columnName.equals("CRL")) {
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        respContent = sha1.digest(dbContent);
      } else {
        respContent = dbContent;
      }

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
