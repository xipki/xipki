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
import java.io.InputStream;
import java.sql.SQLException;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.AbstractLoadTest;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CaDbExporter
{
    private static final Logger LOG = LoggerFactory.getLogger(CaDbExporter.class);

    protected final DataSourceWrapper dataSource;
    protected final Marshaller marshaller;
    protected final Unmarshaller unmarshaller;
    protected final String destFolder;
    protected final boolean resume;

    public CaDbExporter(DataSourceFactory dataSourceFactory,
            PasswordResolver passwordResolver, InputStream dbConfStream,
            String destFolder, boolean resume)
    throws SQLException, PasswordResolverException, IOException, JAXBException
    {
        ParamChecker.assertNotEmpty("destFolder", destFolder);
        Properties props = DbPorter.getDbConfProperties(dbConfStream);
        this.dataSource = dataSourceFactory.createDataSource(props, passwordResolver);
        this.marshaller = getMarshaller();
        this.unmarshaller = getUnmarshaller();
        this.destFolder = IoCertUtil.expandFilepath(destFolder);
        this.resume = resume;
        checkDestFolder();
    }

    public CaDbExporter(DataSourceFactory dataSourceFactory,
            PasswordResolver passwordResolver, String dbConfFile, String destFolder,
            boolean destFolderEmpty)
    throws SQLException, PasswordResolverException, IOException, JAXBException
    {
        this(dataSourceFactory, passwordResolver,
                new FileInputStream(IoCertUtil.expandFilepath(dbConfFile)), destFolder, destFolderEmpty);
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

    private static Unmarshaller getUnmarshaller()
    throws JAXBException
    {
        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        unmarshaller.setSchema(DbPorter.retrieveSchema("/xsd/dbi-ca.xsd"));
        return unmarshaller;
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

        File processLogFile = new File(destFolder, DbPorter.EXPORT_PROCESS_LOG_FILENAME);
        if(resume)
        {
            if(processLogFile.exists() == false)
            {
                throw new IOException("Could not process with '-resume' option");
            }
        }
        else
        {
            String[] children = f.list();
            if(children != null && children.length > 0)
            {
                throw new IOException(destFolder + " is not empty");
            }
        }
    }
    public void exportDatabase(int numCertsInBundle, int numCrls)
    throws Exception
    {
        long start = System.currentTimeMillis();
        try
        {
            if(resume == false)
            {
                // CAConfiguration
                CaConfigurationDbExporter caConfExporter = new CaConfigurationDbExporter(dataSource, marshaller, destFolder);
                caConfExporter.export();
                caConfExporter.shutdown();
            }

            // CertStore
            CaCertStoreDbExporter certStoreExporter = new CaCertStoreDbExporter(
                    dataSource, marshaller, unmarshaller, destFolder, numCertsInBundle, numCrls, resume);
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
            long end = System.currentTimeMillis();
            System.out.println("Finished in " + AbstractLoadTest.formatTime((end - start) / 1000).trim());
        }
    }

}
