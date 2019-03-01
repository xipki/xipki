/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ca.mgmt.db;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.Args;

/**
 * TODO.
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
