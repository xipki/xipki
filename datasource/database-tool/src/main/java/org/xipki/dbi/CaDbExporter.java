/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CaDbExporter
{
    private static final Logger LOG = LoggerFactory.getLogger(CaDbExporter.class);

    protected final DataSourceWrapper dataSource;
    protected final Marshaller marshaller;
    protected final String destFolder;

    public CaDbExporter(DataSourceFactory dataSourceFactory,
            PasswordResolver passwordResolver, InputStream dbConfStream, String destFolder)
    throws SQLException, PasswordResolverException, IOException, JAXBException
    {
        ParamChecker.assertNotEmpty("destFolder", destFolder);
        this.dataSource = dataSourceFactory.createDataSource(dbConfStream, passwordResolver);
        this.marshaller = getMarshaller();
        this.destFolder = destFolder;
        checkDestFolder();
    }

    public CaDbExporter(DataSourceFactory dataSourceFactory,
            PasswordResolver passwordResolver, String dbConfFile, String destFolder)
    throws SQLException, PasswordResolverException, IOException, JAXBException
    {
        ParamChecker.assertNotEmpty("destFolder", destFolder);
        this.dataSource = dataSourceFactory.createDataSourceForFile(dbConfFile, passwordResolver);
        this.marshaller = getMarshaller();
        this.destFolder = destFolder;
        checkDestFolder();
    }

    private static Marshaller getMarshaller()
    throws JAXBException
    {
        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        marshaller.setSchema(DbPorter.retrieveSchema("/xsd/dbi-ca.xsd"));
        return marshaller;
    }

    private void checkDestFolder()
    throws IOException
    {
        File f = new File(destFolder);
        if(f.exists() == false)
        {
            f.mkdirs();
        }
        else
        {
            if(f.isDirectory() == false)
            {
                throw new IOException(destFolder + " is not a folder");
            }

            if(f.canWrite() == false)
            {
                throw new IOException(destFolder + " is not writable");
            }
        }

        String[] children = f.list();
        if(children != null && children.length > 0)
        {
            throw new IOException(destFolder + " is not empty");
        }
    }
    public void exportDatabase(int numCertsInBundle, int numCrls)
    throws Exception
    {
        try
        {
            // CAConfiguration
            CaConfigurationDbExporter caConfExporter = new CaConfigurationDbExporter(dataSource, marshaller, destFolder);
               caConfExporter.export();

            // CertStore
            CaCertStoreDbExporter certStoreExporter = new CaCertStoreDbExporter(
                    dataSource, marshaller, destFolder, numCertsInBundle, numCrls);
            certStoreExporter.export();
            certStoreExporter.shutdown();
        }finally
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
