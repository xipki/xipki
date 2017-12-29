/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.dbtool;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbSchemaInfo {

    private final Map<String, String> variables = new HashMap<>();

    public DbSchemaInfo(DataSourceWrapper datasource) throws DataAccessException {
        ParamUtil.requireNonNull("datasource", datasource);

        final String sql = "SELECT NAME,VALUE2 FROM DBSCHEMA";
        Connection connection = datasource.getConnection();
        if (connection == null) {
            throw new DataAccessException("could not get connection");
        }

        Statement stmt = null;
        ResultSet rs = null;

        try {
            stmt = datasource.createStatement(connection);
            if (stmt == null) {
                throw new DataAccessException("could not create statement");
            }

            rs = stmt.executeQuery(sql);
            while (rs.next()) {
                String name = rs.getString("NAME");
                String value = rs.getString("VALUE2");
                variables.put(name, value);
            }
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            datasource.releaseResources(stmt, rs);
        }
    } // constructor

    public Set<String> variableNames() {
        return Collections.unmodifiableSet(variables.keySet());
    }

    public String variableValue(String variableName) {
        ParamUtil.requireNonNull("variableName", variableName);
        return variables.get(variableName);
    }

}
