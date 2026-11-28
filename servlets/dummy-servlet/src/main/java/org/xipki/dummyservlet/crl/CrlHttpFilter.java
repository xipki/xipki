// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.dummyservlet.crl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.Base64;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.codec.util.StringUtil;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;
import org.xipki.util.misc.LogUtil;

import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * Crl Http Filter.
 *
 * @author Lijun Liao (xipki)
 */
public class CrlHttpFilter implements XiHttpFilter {

  private static final Logger LOG = LoggerFactory.getLogger(CrlHttpFilter.class);

  private static final String RESP_CONTENT_TYPE = "application/pkix-crl";

  private static final String DFLT_CA_DB_CFG = "etc/ca/database/ca-db.properties";

  private final DataSourceWrapper dataSource;

  private final boolean hasSha1Column;

  public CrlHttpFilter(String basedir) throws Exception {
    try {
      this.dataSource = new DataSourceFactory().createDataSourceForFile(
          "ca", DFLT_CA_DB_CFG, basedir);
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
      String sql = dataSource.buildSelectFirstSql(1, "ID FROM CA WHERE NAME=?");

      int id;
      PreparedStatement ps = dataSource.prepareStatement(conn, sql);
      ResultSet rs = null;
      try {
        ps.setString(1, caName);
        rs = ps.executeQuery();
        if (!rs.next()) {
          LOG.warn("Unknown CA {}", caName);
          resp.sendError(HttpStatusCode.SC_NOT_FOUND);
          return;
        }
        id = rs.getInt("ID");
      } finally {
        // close ps and rs, but keep conn; it is returned in the outer finally block
        dataSource.releaseResources(ps, rs, false);
      }

      long crlNo = dataSource.getMax(conn, "CRL", "CRL_NO", "CA_ID=" + id + " AND DELTACRL=" +
              ("deltacrl".equalsIgnoreCase(type) ? 1 : 0));
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
      sql = dataSource.buildSelectFirstSql(1, columnName +
          " FROM CRL WHERE CA_ID=? AND CRL_NO=?");

      byte[] dbContent;
      // use the same connection, do not borrow a second one from the pool
      ps = dataSource.prepareStatement(conn, sql);
      rs = null;
      try {
        ps.setInt(1, id);
        ps.setLong(2, crlNo);
        rs = ps.executeQuery();
        if (!rs.next()) {
          LOG.warn("CRL {} of CA {} not found", crlNo, caName);
          resp.sendError(HttpStatusCode.SC_NOT_FOUND);
          return;
        }
        String b64 = rs.getString(columnName);
        dbContent = Base64.decodeFast(b64);
      } finally {
        dataSource.releaseResources(ps, rs, false);
      }

      byte[] respContent;
      if (hashalgo != null && columnName.equals("CRL")) {
        MessageDigest sha1 = CryptoApiFactory.get().newMessageDigest("SHA1");
        respContent = sha1.digest(dbContent);
      } else {
        respContent = dbContent;
      }

      String contentType = hashalgo == null ? RESP_CONTENT_TYPE : "application/octet-stream";
      new HttpResponse(HttpStatusCode.SC_OK, contentType, null, respContent).fillResponse(resp);
    } catch (Throwable th) {
      LogUtil.error(LOG, th);
      resp.sendError(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    } finally {
      dataSource.returnConnection(conn);
    }
  } // method doFilter

}
