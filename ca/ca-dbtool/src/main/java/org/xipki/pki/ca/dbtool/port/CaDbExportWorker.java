/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.pki.ca.dbtool.port;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.springframework.dao.DataAccessException;
import org.xipki.password.api.PasswordResolver;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.pki.ca.dbtool.jaxb.ca.ObjectFactory;

/**
 * @author Lijun Liao
 */

public class CaDbExportWorker extends DbPortWorker {

    private static final Logger LOG = LoggerFactory.getLogger(CaDbExportWorker.class);

    private final DataSourceWrapper dataSource;

    private final Marshaller marshaller;

    private final Unmarshaller unmarshaller;

    private final String destFolder;

    private final boolean resume;

    private final int numCertsInBundle;

    private final int numCertsPerSelect;

    private final boolean evaluateOnly;

    public CaDbExportWorker(
            final DataSourceFactory dataSourceFactory,
            final PasswordResolver passwordResolver,
            final InputStream dbConfStream,
            final String destFolder,
            final boolean resume,
            final int numCertsInBundle,
            final int numCertsPerSelect,
            final boolean evaluateOnly)
    throws DataAccessException, PasswordResolverException, IOException, JAXBException {
        ParamUtil.assertNotBlank("destFolder", destFolder);
        Properties props = DbPorter.getDbConfProperties(dbConfStream);
        this.dataSource = dataSourceFactory.createDataSource(null, props, passwordResolver);
        this.marshaller = getMarshaller();
        this.unmarshaller = getUnmarshaller();
        this.destFolder = IoUtil.expandFilepath(destFolder);
        this.resume = resume;
        this.numCertsInBundle = numCertsInBundle;
        this.numCertsPerSelect = numCertsPerSelect;
        this.evaluateOnly = evaluateOnly;
        checkDestFolder();
    }

    public CaDbExportWorker(
            final DataSourceFactory dataSourceFactory,
            final PasswordResolver passwordResolver,
            final String dbConfFile,
            final String destFolder,
            final boolean destFolderEmpty,
            final int numCertsInBundle,
            final int numCertsPerSelect,
            final boolean evaluateOnly)
    throws DataAccessException, PasswordResolverException, IOException, JAXBException {
        this(dataSourceFactory, passwordResolver,
                new FileInputStream(IoUtil.expandFilepath(dbConfFile)), destFolder, destFolderEmpty,
                    numCertsInBundle, numCertsPerSelect, evaluateOnly);
    }

    private void checkDestFolder()
    throws IOException {
        File f = new File(destFolder);
        if (!f.exists()) {
            f.mkdirs();
        } else {
            if (!f.isDirectory()) {
                throw new IOException(destFolder + " is not a folder");
            }

            if (!f.canWrite()) {
                throw new IOException(destFolder + " is not writable");
            }
        }

        File processLogFile = new File(destFolder, DbPorter.EXPORT_PROCESS_LOG_FILENAME);
        if (resume) {
            if (!processLogFile.exists()) {
                throw new IOException("could not process with '--resume' option");
            }
        } else {
            String[] children = f.list();
            if (children != null && children.length > 0) {
                throw new IOException(destFolder + " is not empty");
            }
        }
    } // method checkDestFolder

    @Override
    public void doRun(
            final AtomicBoolean stopMe)
    throws Exception {
        long start = System.currentTimeMillis();
        try {
            if (!resume) {
                // CAConfiguration
                CaConfigurationDbExporter caConfExporter = new CaConfigurationDbExporter(
                        dataSource, marshaller, destFolder, stopMe, evaluateOnly);
                caConfExporter.export();
                caConfExporter.shutdown();
            }

            // CertStore
            CaCertStoreDbExporter certStoreExporter = new CaCertStoreDbExporter(
                    dataSource, marshaller, unmarshaller, destFolder,
                    numCertsInBundle, numCertsPerSelect, resume, stopMe, evaluateOnly);
            certStoreExporter.export();
            certStoreExporter.shutdown();
        } finally {
            try {
                dataSource.shutdown();
            } catch (Throwable e) {
                LOG.error("dataSource.shutdown()", e);
            }
            long end = System.currentTimeMillis();
            System.out.println("Finished in " + StringUtil.formatTime((end - start) / 1000, false));
        }
    } // method doRun

    private static Marshaller getMarshaller()
    throws JAXBException {
        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        marshaller.setSchema(DbPorter.retrieveSchema("/xsd/dbi-ca.xsd"));
        return marshaller;
    }

    private static Unmarshaller getUnmarshaller()
    throws JAXBException {
        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        unmarshaller.setSchema(DbPorter.retrieveSchema("/xsd/dbi-ca.xsd"));
        return unmarshaller;
    }

}
