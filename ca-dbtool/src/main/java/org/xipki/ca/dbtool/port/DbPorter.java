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

package org.xipki.ca.dbtool.port;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xipki.ca.dbtool.DbSchemaInfo;
import org.xipki.ca.dbtool.DbToolBase;
import org.xipki.ca.dbtool.jaxb.ca.FileOrBinaryType;
import org.xipki.ca.dbtool.jaxb.ca.FileOrValueType;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbPorter extends DbToolBase {

    public enum OcspDbEntryType {
        CERT("certs", "CERT", 1);

        private final String dirName;

        private final String tableName;

        private final float sqlBatchFactor;

        private OcspDbEntryType(final String dirName, final String tableName,
                final float sqlBatchFactor) {
            this.dirName = dirName;
            this.tableName = tableName;
            this.sqlBatchFactor = sqlBatchFactor;
        }

        public String dirName() {
            return dirName;
        }

        public String tableName() {
            return tableName;
        }

        public float sqlBatchFactor() {
            return sqlBatchFactor;
        }

    }

    public enum CaDbEntryType {
        CERT("certs", "CERT", 1),
        CRL("crls", "CRL", 0.1f),
        USER("users", "TUSER", 10),
        CAUSER("causers", "CA_HAS_USER", 10),
        REQUEST("requests", "REQUEST", 0.1f),
        REQCERT("reqcerts", "REQCERT", 50);

        private final String dirName;

        private final String tableName;

        private final float sqlBatchFactor;

        private CaDbEntryType(final String dirName, final String tableName,
                final float sqlBatchFactor) {
            this.dirName = dirName;
            this.tableName = tableName;
            this.sqlBatchFactor = sqlBatchFactor;
        }

        public String dirName() {
            return dirName;
        }

        public String tableName() {
            return tableName;
        }

        public float sqlBatchFactor() {
            return sqlBatchFactor;
        }

    }

    public static final String FILENAME_CA_CONFIGURATION = "ca-configuration.xml";

    public static final String FILENAME_CA_CERTSTORE = "ca-certstore.xml";

    public static final String FILENAME_OCSP_CERTSTORE = "ocsp-certstore.xml";

    public static final String DIRNAME_CRL = "crl";

    public static final String DIRNAME_CERT = "cert";

    public static final String PREFIX_FILENAME_CERTS = "certs-";

    public static final String EXPORT_PROCESS_LOG_FILENAME = "export.process";

    public static final String IMPORT_PROCESS_LOG_FILENAME = "import.process";

    public static final String IMPORT_TO_OCSP_PROCESS_LOG_FILENAME = "import-to-ocsp.process";

    public static final int VERSION = 1;

    protected final boolean evaulateOnly;

    protected final int dbSchemaVersion;

    protected final int maxX500nameLen;

    public DbPorter(final DataSourceWrapper datasource, final String baseDir,
            final AtomicBoolean stopMe, final boolean evaluateOnly) throws DataAccessException {
        super(datasource, baseDir, stopMe);

        this.evaulateOnly = evaluateOnly;

        DbSchemaInfo dbSchemaInfo = new DbSchemaInfo(datasource);
        String str = dbSchemaInfo.variableValue("VERSION");
        this.dbSchemaVersion = Integer.parseInt(str);
        str = dbSchemaInfo.variableValue("X500NAME_MAXLEN");
        this.maxX500nameLen = Integer.parseInt(str);
    }

    protected FileOrValueType buildFileOrValue(final String content, final String fileName)
            throws IOException {
        if (content == null) {
            return null;
        }

        ParamUtil.requireNonNull("fileName", fileName);

        FileOrValueType ret = new FileOrValueType();
        if (content.length() < 256) {
            ret.setValue(content);
            return ret;
        }

        File file = new File(baseDir, fileName);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        IoUtil.save(file, content.getBytes("UTF-8"));

        ret.setFile(fileName);
        return ret;
    }

    protected String value(final FileOrValueType fileOrValue) throws IOException {
        if (fileOrValue == null) {
            return null;
        }

        if (fileOrValue.getValue() != null) {
            return fileOrValue.getValue();
        }

        File file = new File(baseDir, fileOrValue.getFile());
        return new String(IoUtil.read(file), "UTF-8");
    }

    protected FileOrBinaryType buildFileOrBase64Binary(final String base64Content,
            final String fileName) throws IOException {
        if (base64Content == null) {
            return null;
        }
        return buildFileOrBinary(Base64.decode(base64Content), fileName);
    }

    protected FileOrBinaryType buildFileOrBinary(final byte[] content, final String fileName)
            throws IOException {
        if (content == null) {
            return null;
        }

        ParamUtil.requireNonNull("fileName", fileName);

        FileOrBinaryType ret = new FileOrBinaryType();
        if (content.length < 256) {
            ret.setBinary(content);
            return ret;
        }

        File file = new File(baseDir, fileName);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        IoUtil.save(file, content);

        ret.setFile(fileName);
        return ret;
    }

    protected byte[] binary(final FileOrBinaryType fileOrValue) throws IOException {
        if (fileOrValue == null) {
            return null;
        }

        if (fileOrValue.getBinary() != null) {
            return fileOrValue.getBinary();
        }

        File file = new File(baseDir, fileOrValue.getFile());
        return IoUtil.read(file);
    }

    protected String importingText() {
        return evaulateOnly ? "evaluating import " : "importing ";
    }

    protected String importedText() {
        return evaulateOnly ? " evaluated import " : " imported ";
    }

    protected String exportingText() {
        return evaulateOnly ? "evaluating export " : "exporting ";
    }

    protected String exportedText() {
        return evaulateOnly ? " evaluated export " : " exported ";
    }

    public static final Schema retrieveSchema(final String schemaPath) throws JAXBException {
        ParamUtil.requireNonNull("schemaPath", schemaPath);

        URL schemaUrl = DbPorter.class.getResource(schemaPath);
        final SchemaFactory schemaFact = SchemaFactory.newInstance(
                javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try {
            return schemaFact.newSchema(schemaUrl);
        } catch (SAXException ex) {
            throw new JAXBException("could not load schemas for the specified classes\nDetails:\n"
                    + ex.getMessage());
        }
    }

    public static void echoToFile(final String content, final File file) throws IOException {
        ParamUtil.requireNonNull("content", content);
        ParamUtil.requireNonNull("file", file);

        FileOutputStream out = null;
        try {
            out = new FileOutputStream(file);
            out.write(content.getBytes());
        } finally {
            if (out != null) {
                out.flush();
                out.close();
            }
        }
    }

}
