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

import java.io.IOException;
import java.sql.SQLException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class CaDbImporter
{

    private final DataSource dataSource;
    private final Unmarshaller unmarshaller;

    public CaDbImporter(DataSourceFactory dataSourceFactory,
            PasswordResolver passwordResolver, String dbConfFile)
    throws SQLException, PasswordResolverException, IOException, JAXBException
    {
        this.dataSource = dataSourceFactory.createDataSourceForFile(dbConfFile, passwordResolver);
        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        unmarshaller = jaxbContext.createUnmarshaller();
    }

    public void importDatabase(String srcFolder)
    throws Exception
    {
        // CAConfiguration
        CaConfigurationDbImporter caConfImporter = new CaConfigurationDbImporter(
                dataSource, unmarshaller, srcFolder);
        caConfImporter.importToDB();

        // CertStore
        CaCertStoreDbImporter certStoreImporter = new CaCertStoreDbImporter(dataSource, unmarshaller, srcFolder);
        certStoreImporter.importToDB();
    }

}
