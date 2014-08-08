/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

public class CaDbImporter
{
    private static final Logger LOG = LoggerFactory.getLogger(CaDbImporter.class);
    private final DataSourceWrapper dataSource;
    private final Unmarshaller unmarshaller;

    public CaDbImporter(DataSourceFactory dataSourceFactory,
            PasswordResolver passwordResolver, String dbConfFile)
    throws SQLException, PasswordResolverException, IOException, JAXBException
    {
        Properties props = DbPorter.getDbConfProperties(
                new FileInputStream(IoCertUtil.expandFilepath(dbConfFile)));
        this.dataSource = dataSourceFactory.createDataSource(props, passwordResolver);
        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        unmarshaller = jaxbContext.createUnmarshaller();
        unmarshaller.setSchema(DbPorter.retrieveSchema("/xsd/dbi-ca.xsd"));
    }

    public void importDatabase(String srcFolder)
    throws Exception
    {
        try
        {
            // CAConfiguration
            CaConfigurationDbImporter caConfImporter = new CaConfigurationDbImporter(
                    dataSource, unmarshaller, srcFolder);
            caConfImporter.importToDB();
            caConfImporter.shutdown();

            // CertStore
            CaCertStoreDbImporter certStoreImporter = new CaCertStoreDbImporter(dataSource, unmarshaller, srcFolder);
            certStoreImporter.importToDB();
            certStoreImporter.shutdown();
        } finally
        {
            try
            {
                dataSource.shutdown();
            }catch(Throwable e)
            {
                LOG.error("dataSource.shutdown()", e);
            }
        }
    }

}
