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

package org.xipki.dbi;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

import org.xipki.database.api.DataSource;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class DbPorter
{
    public static final String FILENAME_CA_Configuration = "CA-Configuration.xml";
    public static final String FILENAME_CA_CertStore = "CA-CertStore.xml";
    public static final String FILENAME_OCSP_CertStore = "OCSP-CertStore.xml";
    public static final String DIRNAME_CRL = "CRL";
    public static final String DIRNAME_CERT = "CERT";
    public static final String PREFIX_FILENAME_CERTS = "certs-";

    public static final int VERSION = 1;

    protected final DataSource dataSource;
    protected final String baseDir;

    public DbPorter(DataSource dataSource, String baseDir)
    {
        super();
        ParamChecker.assertNotNull("dataSource", dataSource);
        ParamChecker.assertNotEmpty("baseDir", baseDir);

        this.dataSource = dataSource;
        this.baseDir = baseDir;
    }

    protected Statement createStatement()
    throws SQLException
    {
        Connection dsConnection = dataSource.getConnection();
        return dataSource.createStatement(dsConnection);
    }

    protected PreparedStatement prepareStatement(String sql)
    throws SQLException
    {
        Connection dsConnection = dataSource.getConnection();
        return dataSource.prepareStatement(dsConnection, sql);
    }

    protected void closeStatement(Statement ps)
    {
        dataSource.releaseResources(ps, null);
    }
}
