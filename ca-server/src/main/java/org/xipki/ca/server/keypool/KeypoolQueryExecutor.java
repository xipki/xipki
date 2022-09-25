/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.server.keypool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.Base64;
import org.xipki.util.LogUtil;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static org.xipki.util.Args.notNull;

/**
 * XiPKI Keypool database query executor.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

class KeypoolQueryExecutor {

  private static final Logger LOG = LoggerFactory.getLogger(KeypoolQueryExecutor.class);

  private final DataSourceWrapper datasource;

  private final String sqlGetKeyData;

  private final String sqlDeleteKeyData = "DELETE FROM KEYPOOL WHERE ID=?";

  KeypoolQueryExecutor(DataSourceWrapper datasource, int shardId) throws DataAccessException {
    this.datasource = notNull(datasource, "datasource");
    this.sqlGetKeyData = datasource.buildSelectFirstSql(1,
        "ID,ENC_ALG,ENC_META,DATA FROM KEYPOOL WHERE SHARD_ID=" + shardId + " AND KID=?");
  } // constructor

  void close() {
    if (datasource != null) {
      datasource.close();
    }
  }

  Map<String, Integer> getKeyspecs() throws DataAccessException {
    final String sql = "SELECT ID,KEYSPEC FROM KEYSPEC";
    Statement ps = datasource.createStatement();
    ResultSet rs = null;

    Map<String, Integer> rv = new HashMap<>();

    try {
      rs = ps.executeQuery(sql);
      while (rs.next()) {
        rv.put(rs.getString("KEYSPEC").toUpperCase(Locale.ROOT), rs.getInt("ID"));
      }

      return rv;
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method initIssuerStore

  KeypoolKeypairGenerator.CipherData nextKeyData(int keyspecId) throws DataAccessException {
    final String sql = sqlGetKeyData;
    PreparedStatement ps = datasource.prepareStatement(sql);

    ResultSet rs = null;
    try {
      ps.setInt(1, keyspecId);
      rs = ps.executeQuery();
      if (!rs.next()) {
        return null;
      }

      int id = rs.getInt("ID");
      KeypoolKeypairGenerator.CipherData cd = new KeypoolKeypairGenerator.CipherData();
      cd.encAlg = rs.getInt("ENC_ALG");
      cd.encMeta = Base64.decodeFast(rs.getString("ENC_META"));
      cd.cipherText = Base64.decodeFast(rs.getString("DATA"));
      datasource.releaseResources(ps, rs);
      ps = null;
      rs = null;

      ps = datasource.prepareStatement(sqlDeleteKeyData);
      ps.setInt(1, id);
      ps.executeUpdate();
      return cd;
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method nextKeyData

  boolean isHealthy() {
    final String sql = "SELECT ID FROM KEYSPEC";

    try {
      ResultSet rs = null;
      PreparedStatement ps = datasource.prepareStatement(sql);

      try {
        rs = ps.executeQuery();
      } finally {
        datasource.releaseResources(ps, rs);
      }
      return true;
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
      return false;
    }
  } // method isHealthy

  private static void setBoolean(PreparedStatement ps, int index, boolean value) throws SQLException {
    ps.setInt(index, value ? 1 : 0);
  }

}
