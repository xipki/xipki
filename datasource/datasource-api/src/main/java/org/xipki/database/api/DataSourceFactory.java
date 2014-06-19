/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.database.api;

import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;

import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public interface DataSourceFactory
{
    DataSource createDataSource(InputStream conf, PasswordResolver passwordResolver)
    throws SQLException, PasswordResolverException, IOException;

    DataSource createDataSourceForFile(String confFile, PasswordResolver passwordResolver)
    throws SQLException, PasswordResolverException, IOException;

}
