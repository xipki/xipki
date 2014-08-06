/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi;

import java.io.IOException;
import java.sql.SQLException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.xipki.database.api.DataSourceFactory;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.dbi.ocsp.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class OcspDbImporter
{

    private final DataSourceWrapper dataSource;
    private final Unmarshaller unmarshaller;

    public OcspDbImporter(DataSourceFactory dataSourceFactory,
            PasswordResolver passwordResolver, String dbConfFile)
    throws SQLException, PasswordResolverException, IOException, JAXBException
    {
        this.dataSource = dataSourceFactory.createDataSourceForFile(dbConfFile, passwordResolver);
        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        unmarshaller = jaxbContext.createUnmarshaller();
        unmarshaller.setSchema(DbPorter.retrieveSchema("/xsd/dbi-ocsp.xsd"));
    }

    public void importDatabase(String srcFolder)
    throws Exception
    {
        // CertStore
        try
        {
            OcspCertStoreDbImporter certStoreImporter = new OcspCertStoreDbImporter(dataSource, unmarshaller, srcFolder);
            certStoreImporter.importToDB();
            certStoreImporter.shutdown();
        } finally
        {
            dataSource.shutdown();
        }
    }

}
