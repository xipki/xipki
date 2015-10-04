/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.impl;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;

/**
 * @author Lijun Liao
 */

public class DbSchemaInfo {
    private final Map<String, String> variables = new HashMap<>();

    public DbSchemaInfo(DataSourceWrapper dataSource)
    throws DataAccessException {
        final String sql = "SELECT NAME, VALUE2 FROM DBSCHEMA";
        Connection c = dataSource.getConnection();
        if (c == null) {
            throw new DataAccessException("could not get connection");
        }

        Statement stmt = null;
        ResultSet rs = null;

        try {
            stmt = dataSource.createStatement(c);
            if (stmt == null) {
                throw new DataAccessException("could not create statement");
            }

            rs = stmt.executeQuery(sql);
            while (rs.next()) {
                String name = rs.getString("NAME");
                String value = rs.getString("VALUE2");
                variables.put(name, value);
            }
        } catch (SQLException e) {
            throw dataSource.translate(sql, e);
        } finally {
            dataSource.releaseResources(stmt, rs);
        }
    }

    public Set<String> getVariableNames() {
        return Collections.unmodifiableSet(variables.keySet());
    }

    public String getVariableValue(String variableName) {
        return variables.get(variableName);
    }

}
