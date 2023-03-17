// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db;

import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.Args;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Database Schema Information. It contains the content of the table DBSCHEMA.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbSchemaInfo {

  private final Map<String, String> variables = new HashMap<>();

  public DbSchemaInfo(DataSourceWrapper datasource) throws DataAccessException {
    Args.notNull(datasource, "datasource");

    final String sql = "SELECT NAME,VALUE2 FROM DBSCHEMA";

    Statement stmt = null;
    ResultSet rs = null;

    try {
      stmt = datasource.createStatement();
      if (stmt == null) {
        throw new DataAccessException("could not create statement");
      }

      rs = stmt.executeQuery(sql);
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
