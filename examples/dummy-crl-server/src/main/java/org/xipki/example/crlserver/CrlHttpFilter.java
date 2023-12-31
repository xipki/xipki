// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.example.crlserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.Base64;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.XipkiBaseDir;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;

/**
 * Dummy CRL ServletFilter.
 *
 * @author Lijun Liao (xipki)
 */
public class CrlHttpFilter implements XiHttpFilter {

  private static final Logger LOG = LoggerFactory.getLogger(CrlHttpFilter.class);

  private static final String RESP_CONTENT_TYPE = "application/pkix-crl";

  private static final String DFLT_CA_DB_CFG = "${sys:catalina.home}/xipki/etc/ca/database/ca-db.properties";

  private final DataSourceWrapper dataSource;

  private final boolean hasSha1Column;

  public CrlHttpFilter() throws Exception {
    XipkiBaseDir.init();
    try {
      this.dataSource = new DataSourceFactory().createDataSourceForFile("ca",
          StringUtil.resolveVariables(DFLT_CA_DB_CFG));
      this.hasSha1Column = dataSource.tableHasColumn(null, "CRL", "SHA1");
    } catch (InvalidConfException | IOException | DataAccessException ex) {
      LOG.error("error initializing datasource", ex);
      throw ex;
    }
  }

  @Override
  public void destroy() {
    if (dataSource != null) {
      dataSource.close();
    }
  }

  @Override
  public void doFilter(XiHttpRequest req, XiHttpResponse resp) throws IOException {
    String hashalgo = req.getParameter("hashalgo");
    String caName = req.getParameter("name");
    String type = req.getParameter("type");
    if (!StringUtil.orEqualsIgnoreCase(type, "crl", "deltacrl")) {
      LOG.warn("Type {} is not in the supported types [crl, deltacrl]", type);
      resp.sendError(HttpStatusCode.SC_NOT_FOUND);
      return;
    }

    if (hashalgo == null) {
      LOG.info("GET CRL for CA {}", caName);
    } else {
      if (StringUtil.orEqualsIgnoreCase(hashalgo, "sha1", "sha-1")) {
        LOG.info("Get {} hash value for CA {}", hashalgo, caName);
      } else {
        LOG.warn("Unknown hashalgo  {}", hashalgo);
        resp.sendError(HttpStatusCode.SC_NOT_FOUND);
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
          resp.sendError(HttpStatusCode.SC_NOT_FOUND);
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
        resp.sendError(HttpStatusCode.SC_NOT_FOUND);
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

      String contentType = hashalgo == null ? RESP_CONTENT_TYPE : "application/octet-stream";
      new HttpResponse(HttpStatusCode.SC_OK, contentType, null, respContent)
          .fillResponse(resp);
    } catch (Throwable th) {
      LogUtil.error(LOG, th);
      resp.sendError(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    } finally {
      if (conn != null) {
        dataSource.returnConnection(conn);
      }
    }
  } // method doFilter

}
