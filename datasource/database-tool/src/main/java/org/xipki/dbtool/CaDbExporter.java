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

package org.xipki.dbtool;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.AbstractLoadTest;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.IoUtil;
import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

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
    throws DataAccessException, PasswordResolverException, IOException, JAXBException
    {
        ParamChecker.assertNotEmpty("destFolder", destFolder);
        Properties props = DbPorter.getDbConfProperties(dbConfStream);
        this.dataSource = dataSourceFactory.createDataSource(null, props, passwordResolver);
        this.marshaller = getMarshaller();
        this.unmarshaller = getUnmarshaller();
        this.destFolder = IoUtil.expandFilepath(destFolder);
        this.resume = resume;
        checkDestFolder();
    }

    public CaDbExporter(DataSourceFactory dataSourceFactory,
            PasswordResolver passwordResolver, String dbConfFile, String destFolder,
            boolean destFolderEmpty)
    throws DataAccessException, PasswordResolverException, IOException, JAXBException
    {
        this(dataSourceFactory, passwordResolver,
                new FileInputStream(IoUtil.expandFilepath(dbConfFile)), destFolder, destFolderEmpty);
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
