// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit.extra;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.services.FileMacAuditService;
import org.xipki.audit.services.MacAuditService;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.*;
import java.time.Instant;

/**
 * Database-based MAC protected audit service.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class DatabaseMacAuditService extends MacAuditService {

  private static final Logger LOG = LoggerFactory.getLogger(FileMacAuditService.class);

  public static final String KEY_DATASOURCE = "datasource";

  private static final String SQL_ADD_AUDIT =
      SqlUtil.buildInsertSql("AUDIT", "SHARD_ID,ID,TIME,LEVEL,EVENT_TYPE,PREVIOUS_ID,MESSAGE,TAG");

  private static final String SQL_UPDATE_INTEGRITY = "UPDATE INTEGRITY SET TEXT=? WHERE ID=1";

  private int maxMessageLength = 1000;

  private DataSourceWrapper datasource;

  public DatabaseMacAuditService() {
  }

  @Override
  protected void storeIntegrity(String integrityText) {
    PreparedStatement ps = null;
    try {
      ps = datasource.prepareStatement(SQL_UPDATE_INTEGRITY);
      ps.setString(1, integrityText);
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw new IllegalStateException(datasource.translate(SQL_UPDATE_INTEGRITY, ex));
    } catch (DataAccessException ex) {
      throw new IllegalStateException(ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  }

  @Override
  protected void doClose() {
  }

  @Override
  protected void storeLog(
          Instant date, long thisId, int eventType, String levelText,
          long previousId, String message, String thisTag) {
    String logMessage = message.length() <= maxMessageLength
        ? message : message.substring(0, maxMessageLength - 4) + " ...";

    try {
      PreparedStatement ps = datasource.prepareStatement(SQL_ADD_AUDIT);
      try {
        int idx = 1;
        ps.setInt   (idx++, shardId);
        ps.setLong  (idx++, thisId);
        ps.setString(idx++, formatDate(date));
        ps.setString(idx++, levelText);
        ps.setInt   (idx++, eventType);
        ps.setLong  (idx++, previousId);
        ps.setString(idx++, logMessage);
        ps.setString(idx, thisTag);
        ps.executeUpdate();
      } catch (SQLException ex) {
        throw datasource.translate(SQL_ADD_AUDIT, ex);
      } finally {
        datasource.releaseResources(ps, null);
      }
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
    }
  }

  @Override
  protected void doExtraInit(ConfPairs confPairs, PasswordResolver passwordResolver)
          throws PasswordResolverException {
    String dataSourceFile = confPairs.value(KEY_DATASOURCE);
    if (StringUtil.isBlank(dataSourceFile)) {
      throw new IllegalArgumentException("property " + KEY_DATASOURCE + " not defined");
    }

    Connection conn = null;
    try {
      try (InputStream is = Files.newInputStream(Paths.get(IoUtil.expandFilepath(dataSourceFile, true)))) {
        datasource = new DataSourceFactory().createDataSource("audit", is, passwordResolver);
      }

      conn = datasource.getConnection();
      String str = datasource.getFirstStringValue(conn, "DBSCHEMA", "VALUE2", "NAME='MAX_MESSAGE_LEN'");
      this.maxMessageLength = str == null ? 1000: Integer.parseInt(str);

      long maxId = datasource.getMax(conn, "AUDIT", "ID", "SHARD_ID=" + shardId);
      if (maxId < 1) {
        id.set(0);
        previousTag = null;
      } else {
        String sql = datasource.buildSelectFirstSql(1,
                "TAG FROM AUDIT WHERE SHARD_ID=" + shardId + " AND ID=" + maxId);
        ResultSet rs = null;
        Statement stmt = null;

        try {
          stmt = datasource.createStatement(conn);
          rs = stmt.executeQuery(sql);
          rs.next();

          id.set(maxId);
          previousTag = rs.getString("TAG");
        } catch (SQLException ex) {
          throw datasource.translate(sql, ex);
        } finally {
          datasource.releaseResources(stmt, rs, false);
        }
      }

      String integrityText = datasource.getFirstStringValue(conn, "INTEGRITY", "TEXT", "ID=1");
      if (integrityText == null) {
        String sql = "INSERT INTO INTEGRITY (ID,TEXT) VALUES(1,'')";
        try {
          datasource.createStatement(conn).executeUpdate(sql);
        } catch (SQLException ex) {
          throw datasource.translate(sql, ex);
        }
      }

      verify(id.get(), previousTag, integrityText, confPairs);
    } catch (IOException | DataAccessException ex) {
      throw new IllegalStateException(ex);
    } finally {
      if (conn != null) {
        datasource.returnConnection(conn);
      }
    }
  }

}
