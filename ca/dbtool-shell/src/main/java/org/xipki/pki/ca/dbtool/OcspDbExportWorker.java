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

package org.xipki.pki.ca.dbtool;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.qa.AbstractLoadTest;
import org.xipki.common.util.IoUtil;
import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.jaxb.ocsp.ObjectFactory;
import org.xipki.password.api.PasswordResolver;
import org.xipki.password.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class OcspDbExportWorker extends DbPorterWorker
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspDbImportWorker.class);
    private final DataSourceWrapper dataSource;
    private final Marshaller marshaller;
    private final Unmarshaller unmarshaller;
    private final String destFolder;
    private final boolean resume;
    private final int numCertsInBundle;
    private final int numCertsPerSelect;
    private final boolean evaluateOnly;

    public OcspDbExportWorker(
            final DataSourceFactory dataSourceFactory,
            final PasswordResolver passwordResolver,
            final String dbConfFile,
            final String destFolder,
            final boolean resume,
            final int numCertsInBundle,
            final int numCertsPerSelect,
            final boolean evaluateOnly)
    throws DataAccessException, PasswordResolverException, IOException, JAXBException
    {
        Properties props = DbPorter.getDbConfProperties(
                new FileInputStream(IoUtil.expandFilepath(dbConfFile)));
        this.dataSource = dataSourceFactory.createDataSource(null, props, passwordResolver);

        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

        Schema schema = DbPorter.retrieveSchema("/xsd/dbi-ocsp.xsd");
        marshaller.setSchema(schema);

        unmarshaller = jaxbContext.createUnmarshaller();
        unmarshaller.setSchema(schema);
        this.evaluateOnly = evaluateOnly;

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

        if(resume == false)
        {
            String[] children = f.list();
            if(children != null && children.length > 0)
            {
                throw new IOException(destFolder + " is not empty");
            }
        }
        this.resume = resume;
        this.destFolder = destFolder;
        this.numCertsInBundle = numCertsInBundle;
        this.numCertsPerSelect = numCertsPerSelect;
    }

    @Override
    public void doRun(AtomicBoolean stopMe)
    throws Exception
    {
        long start = System.currentTimeMillis();
        try
        {
            // CertStore
            OcspCertStoreDbExporter certStoreExporter = new OcspCertStoreDbExporter(
                    dataSource, marshaller, unmarshaller, destFolder,
                    numCertsInBundle, numCertsPerSelect, resume, stopMe, evaluateOnly);
            certStoreExporter.export();
            certStoreExporter.shutdown();
        } finally
        {
            try
            {
                dataSource.shutdown();
            }catch(Throwable e)
            {
                LOG.error("dataSource.shutdown()", e);
            }
            long end = System.currentTimeMillis();
            System.out.println("inished in " + AbstractLoadTest.formatTime((end - start) / 1000).trim());
        }
    }

}
