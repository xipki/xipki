// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.audit.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceFactory;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.SqlUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;

/**
 * Database Mac Audit Service.
 *
 * @author Lijun Liao (xipki)
 */
public class DatabaseMacAuditService extends MacAuditService {

  private static final Logger LOG = LoggerFactory.getLogger(DatabaseMacAuditService.class);

  public static final String KEY_DATASOURCE = "datasource";

  private static final String SQL_ADD_AUDIT = SqlUtil.buildInsertSql("AUDIT",
          "SHARD_ID,ID,TIME,LEVEL,EVENT_TYPE,PREVIOUS_ID,MESSAGE,TAG");

  // one row per shard: ID = shard-id + 1, the shard 0 uses the row 1.
  private static final String SQL_UPDATE_INTEGRITY = "UPDATE INTEGRITY SET TEXT=? WHERE ID=?";

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
      ps.setInt(2, integrityRowId());
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw new IllegalStateException(datasource.translate(SQL_UPDATE_INTEGRITY, ex));
    } catch (DataAccessException ex) {
      throw new IllegalStateException(ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  }

  private int integrityRowId() {
    return shardId + 1;
  }

  @Override
  protected String prepareMessage(String message) {
    // shortened before the MAC is computed: the MAC covers the stored message
    return message.length() <= maxMessageLength
        ? message : message.substring(0, maxMessageLength - 4) + " ...";
  }

  @Override
  protected void doClose() {
    if (datasource != null) {
      datasource.close();
      datasource = null;
    }
  }

  @Override
  protected void storeLog(Instant date, long thisId, int eventType, String levelText,
                          long previousId, String message, String thisTag) {
    // the message has been shortened in prepareMessage(), before the MAC is computed
    try {
      PreparedStatement ps = datasource.prepareStatement(SQL_ADD_AUDIT);
      try {
        int idx = 1;
        ps.setInt   (idx++, shardId);
        ps.setLong  (idx++, thisId);
        // stored without the ending 'Z' to fit into the column TIME CHAR(23), it is always UTC.
        // The MAC covers the time with 'Z', see formatDate().
        String time = formatDate(date);
        ps.setString(idx++, time.substring(0, time.length() - 1));
        ps.setString(idx++, levelText);
        ps.setInt   (idx++, eventType);
        ps.setLong  (idx++, previousId);
        ps.setString(idx++, message);
        ps.setString(idx, thisTag);
        ps.executeUpdate();
      } catch (SQLException ex) {
        throw datasource.translate(SQL_ADD_AUDIT, ex);
      } finally {
        datasource.releaseResources(ps, null);
      }
    } catch (Exception ex) {
      LogUtil.error(LOG, ex, "could not store the audit entry " + thisId);
      throw new IllegalStateException("could not store the audit entry " + thisId, ex);
    }
  }

  @Override
  protected void doExtraInit(ConfPairs confPairs) throws InvalidConfException {
    String dataSourceFile = confPairs.value(KEY_DATASOURCE);
    if (StringUtil.isBlank(dataSourceFile)) {
      throw new IllegalArgumentException("property " + KEY_DATASOURCE + " not defined");
    }

    Connection conn = null;
    try {
      try (InputStream is = Files.newInputStream(
          Paths.get(IoUtil.expandFilepath(dataSourceFile, true)))) {
        datasource = new DataSourceFactory().createDataSource("audit", is);
      }

      conn = datasource.getConnection();
      String str = datasource.getDbSchemaEntry(conn, "MAX_MESSAGE_LEN");
      this.maxMessageLength = str == null ? 1000: Integer.parseInt(str);

      long maxId = datasource.getMax(conn, "AUDIT", "ID", "SHARD_ID=" + shardId);
      if (maxId < 1) {
        id.set(0);
        previousTag = null;
      } else {
        String sql = datasource.buildSelectFirstSql(1,
            "TAG FROM AUDIT WHERE SHARD_ID=" + shardId + " AND ID=" + maxId);
        ResultSet rs = null;
        PreparedStatement stmt = null;

        try {
          stmt = datasource.prepareStatement(conn, sql);
          rs = stmt.executeQuery();
          rs.next();

          id.set(maxId);
          previousTag = rs.getString("TAG");
        } catch (SQLException ex) {
          throw datasource.translate(sql, ex);
        } finally {
          datasource.releaseResources(stmt, rs, false);
        }
      }

      String integrityText = datasource.getFirstStringValue(conn, "INTEGRITY", "TEXT",
          "ID=" + integrityRowId());
      if (integrityText == null) {
        String sql = "INSERT INTO INTEGRITY (ID,TEXT) VALUES(" + integrityRowId() + ",'')";

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
