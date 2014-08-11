/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.dbi.ocsp.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

public class OcspDbExporter
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspDbImporter.class);
    protected final DataSourceWrapper dataSource;
    protected final Marshaller marshaller;
    protected final String destFolder;

    public OcspDbExporter(DataSourceFactory dataSourceFactory,
            PasswordResolver passwordResolver, String dbConfFile, String destFolder)
    throws SQLException, PasswordResolverException, IOException, JAXBException
    {
        Properties props = DbPorter.getDbConfProperties(
                new FileInputStream(IoCertUtil.expandFilepath(dbConfFile)));
        this.dataSource = dataSourceFactory.createDataSource(props, passwordResolver);

        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        marshaller.setSchema(DbPorter.retrieveSchema("/xsd/dbi-ocsp.xsd"));

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
        this.destFolder = destFolder;
    }

    public void exportDatabase(int numCertsInBundle)
    throws Exception
    {
        try
        {
            // CertStore
            OcspCertStoreDbExporter certStoreExporter = new OcspCertStoreDbExporter(
                    dataSource, marshaller, destFolder, numCertsInBundle);
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
