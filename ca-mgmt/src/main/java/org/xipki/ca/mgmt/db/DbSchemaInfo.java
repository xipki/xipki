// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db;

import org.xipki.util.codec.Args;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceWrapper;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Database Schema Information. It contains the content of the table DBSCHEMA.
 *
 * @author Lijun Liao (xipki)
 */

public class DbSchemaInfo {

  private final Map<String, String> variables = new HashMap<>();

  public DbSchemaInfo(DataSourceWrapper datasource) throws DataAccessException {
    Args.notNull(datasource, "datasource");

    final String sql = "SELECT NAME,VALUE2 FROM DBSCHEMA";

    PreparedStatement stmt = null;
    ResultSet rs = null;

    try {
      stmt = Optional.ofNullable(datasource.prepareStatement(sql))
          .orElseThrow(() -> new DataAccessException(
              "could not create statement"));

      rs = stmt.executeQuery();
      while (rs.next()) {
        variables.put(rs.getString("NAME"), rs.getString("VALUE2"));
      }
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  } // constructor

  public Set<String> getVariableNames() {
    return Collections.unmodifiableSet(variables.keySet());
  }

  public String getVariableValue(String variableName) {
    return variables.get(Args.notNull(variableName, "variableName"));
  }

  public void setVariable(String name, String value) {
    variables.put(name, value);
  }

}
