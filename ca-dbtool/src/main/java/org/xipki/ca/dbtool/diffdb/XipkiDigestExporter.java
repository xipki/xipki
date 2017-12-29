/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.dbtool.diffdb;

import java.io.File;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.DbToolBase;
import org.xipki.ca.dbtool.diffdb.io.CaEntry;
import org.xipki.ca.dbtool.diffdb.io.CaEntryContainer;
import org.xipki.ca.dbtool.diffdb.io.DbSchemaType;
import org.xipki.ca.dbtool.diffdb.io.IdentifiedDbDigestEntry;
import org.xipki.ca.dbtool.diffdb.io.XipkiDbControl;
import org.xipki.ca.dbtool.diffdb.io.XipkiDigestExportReader;
import org.xipki.common.ProcessLog;
import org.xipki.common.util.Base64;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XipkiDigestExporter extends DbToolBase implements DbDigestExporter {

    private static final Logger LOG = LoggerFactory.getLogger(XipkiDigestExporter.class);

    private final int numCertsPerSelect;

    private final XipkiDbControl dbControl;

    public XipkiDigestExporter(DataSourceWrapper datasource, String baseDir, AtomicBoolean stopMe,
            int numCertsPerSelect, DbSchemaType dbSchemaType)
            throws DataAccessException, IOException {
        super(datasource, baseDir, stopMe);
        this.numCertsPerSelect = ParamUtil.requireMin("numCertsPerSelect", numCertsPerSelect, 1);
        this.dbControl = new XipkiDbControl(dbSchemaType);
    }

    @Override
    public void digest() throws Exception {
        System.out.println("digesting database");

        final long total = count("CERT");
        ProcessLog processLog = new ProcessLog(total);

        Map<Integer, String> caIdDirMap = getCaIds();
        Set<CaEntry> caEntries = new HashSet<>(caIdDirMap.size());

        for (Integer caId : caIdDirMap.keySet()) {
            CaEntry caEntry = new CaEntry(caId, baseDir + File.separator + caIdDirMap.get(caId));
            caEntries.add(caEntry);
        }

        CaEntryContainer caEntryContainer = new CaEntryContainer(caEntries);
        XipkiDigestExportReader certsReader = new XipkiDigestExportReader(datasource, dbControl,
                numCertsPerSelect);

        Exception exception = null;
        try {
            digest0(certsReader, processLog, caEntryContainer);
        } catch (Exception ex) {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-");
            System.err.println("\ndigesting process has been cancelled due to error");
            LOG.error("Exception", ex);
            exception = ex;
        } finally {
            caEntryContainer.close();
            certsReader.stop();
        }

        if (exception == null) {
            System.out.println(" digested database");
        } else {
            throw exception;
        }
    } // method digest

    private Map<Integer, String> getCaIds() throws DataAccessException, IOException {
        Map<Integer, String> caIdDirMap = new HashMap<>();
        final String sql = dbControl.caSql();

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);
            while (rs.next()) {
                String b64Cert = rs.getString("CERT");
                byte[] certBytes = Base64.decodeFast(b64Cert);

                Certificate cert = Certificate.getInstance(certBytes);
                String commonName = X509Util.getCommonName(cert.getSubject());

                String fn = toAsciiFilename("ca-" + commonName);
                File caDir = new File(baseDir, fn);
                int idx = 2;
                while (caDir.exists()) {
                    caDir = new File(baseDir, fn + "." + (idx++));
                }

                File caCertFile = new File(caDir, "ca.der");
                caDir.mkdirs();
                IoUtil.save(caCertFile, certBytes);

                int id = rs.getInt("ID");
                caIdDirMap.put(id, caDir.getName());
            }
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            releaseResources(stmt, rs);
        }

        return caIdDirMap;
    } // method getCaIds

    private void digest0(XipkiDigestExportReader certsReader, ProcessLog processLog,
            CaEntryContainer caEntryContainer) throws Exception {
        long lastProcessedId = 0;
        System.out.println("digesting certificates from ID " + (lastProcessedId + 1));
        processLog.printHeader();

        boolean interrupted = false;

        while (true) {
            if (stopMe.get()) {
                interrupted = true;
                break;
            }

            List<IdentifiedDbDigestEntry> certs = certsReader.readCerts(lastProcessedId + 1);
            if (CollectionUtil.isEmpty(certs)) {
                break;
            }

            for (IdentifiedDbDigestEntry cert : certs) {
                long id = cert.id();
                if (lastProcessedId < id) {
                    lastProcessedId = id;
                }
                caEntryContainer.addDigestEntry(cert.caId().intValue(), id, cert.content());
            }
            processLog.addNumProcessed(certs.size());
            processLog.printStatus();

            if (interrupted) {
                throw new InterruptedException("interrupted by the user");
            }
        }

        processLog.printTrailer();

        System.out.println(" digested " + processLog.numProcessed() + " certificates");
    } // method digest0

    static String toAsciiFilename(String filename) {
        final int n = filename.length();
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            char ch = filename.charAt(i);
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
                    || ch == '.' || ch == '_' || ch == '-' || ch == ' ') {
                sb.append(ch);
            } else {
                sb.append('_');
            }
        }
        return sb.toString();
    }

}
