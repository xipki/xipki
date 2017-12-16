/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.dbtool.port.ocsp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.jaxb.ocsp.ObjectFactory;
import org.xipki.ca.dbtool.port.DbPortWorker;
import org.xipki.ca.dbtool.port.DbPorter;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspDbExportWorker extends DbPortWorker {

    private static final Logger LOG = LoggerFactory.getLogger(OcspDbImportWorker.class);

    private final DataSourceWrapper datasource;

    private final Marshaller marshaller;

    private final Unmarshaller unmarshaller;

    private final String destFolder;

    private final boolean resume;

    private final int numCertsInBundle;

    private final int numCertsPerSelect;

    private final boolean evaluateOnly;

    public OcspDbExportWorker(final DataSourceFactory datasourceFactory,
            final PasswordResolver passwordResolver, final String dbConfFile,
            final String destFolder, final boolean resume, final int numCertsInBundle,
            final int numCertsPerSelect, final boolean evaluateOnly)
            throws DataAccessException, PasswordResolverException, IOException, JAXBException {
        ParamUtil.requireNonNull("datasourceFactory", datasourceFactory);
        ParamUtil.requireNonNull("dbConfFile", dbConfFile);
        this.destFolder = ParamUtil.requireNonNull(destFolder, destFolder);

        Properties props = DbPorter.getDbConfProperties(
                new FileInputStream(IoUtil.expandFilepath(dbConfFile)));
        this.datasource = datasourceFactory.createDataSource("ds-" + dbConfFile, props,
                passwordResolver);

        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

        Schema schema = DbPorter.retrieveSchema("/xsd/dbi-ocsp.xsd");
        marshaller.setSchema(schema);

        unmarshaller = jaxbContext.createUnmarshaller();
        unmarshaller.setSchema(schema);
        this.evaluateOnly = evaluateOnly;

        File file = new File(destFolder);
        if (!file.exists()) {
            file.mkdirs();
        } else {
            if (!file.isDirectory()) {
                throw new IOException(destFolder + " is not a folder");
            }

            if (!file.canWrite()) {
                throw new IOException(destFolder + " is not writable");
            }
        }

        if (!resume) {
            String[] children = file.list();
            if (children != null && children.length > 0) {
                throw new IOException(destFolder + " is not empty");
            }
        }
        this.resume = resume;
        this.numCertsInBundle = numCertsInBundle;
        this.numCertsPerSelect = numCertsPerSelect;
    } // constructor

    @Override
    protected void run0() throws Exception {
        long start = System.currentTimeMillis();
        try {
            // CertStore
            OcspCertStoreDbExporter certStoreExporter = new OcspCertStoreDbExporter(datasource,
                    marshaller, unmarshaller, destFolder, numCertsInBundle, numCertsPerSelect,
                    resume, stopMe, evaluateOnly);
            certStoreExporter.export();
            certStoreExporter.shutdown();
        } finally {
            try {
                datasource.close();
            } catch (Throwable th) {
                LOG.error("datasource.close()", th);
            }
            long end = System.currentTimeMillis();
            System.out.println("finished in " + StringUtil.formatTime((end - start) / 1000, false));
        }
    }

}
