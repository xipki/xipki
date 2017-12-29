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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.diffdb.io.CaEntry;
import org.xipki.ca.dbtool.diffdb.io.CertsBundle;
import org.xipki.ca.dbtool.diffdb.io.DbDigestEntry;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class FileDigestReader implements DigestReader {

    private static final Logger LOG = LoggerFactory.getLogger(FileDigestReader.class);

    private final int totalAccount;

    private final String caDirname;

    private final String caSubjectName;

    private final X509Certificate caCert;

    private final BufferedReader certsFilesReader;

    private BufferedReader certsReader;

    private DbDigestEntry next;

    private final int numCertsInOneBlock;

    public FileDigestReader(String caDirname, int numCertsInOneBlock)
            throws IOException, CertificateException {
        this.caDirname = ParamUtil.requireNonBlank("caDirname", caDirname);
        this.numCertsInOneBlock = ParamUtil.requireMin("numCertsInOneBlock", numCertsInOneBlock, 1);

        this.caCert = X509Util.parseCert(new File(caDirname, "ca.der"));
        Properties props = new Properties();
        props.load(new FileInputStream(new File(caDirname, CaEntry.FILENAME_OVERVIEW)));
        String accoutPropKey = CaEntry.PROPKEY_ACCOUNT;
        String accoutS = props.getProperty(accoutPropKey);
        this.totalAccount = Integer.parseInt(accoutS);

        this.certsFilesReader = new BufferedReader(
                new FileReader(new File(caDirname, "certs.mf")));
        this.caSubjectName = X509Util.getRfc4519Name(this.caCert.getSubjectX500Principal());
        this.next = retrieveNext(true);
    }

    @Override
    public X509Certificate caCert() {
        return caCert;
    }

    @Override
    public String caSubjectName() {
        return this.caSubjectName;
    }

    @Override
    public int totalAccount() {
        return totalAccount;
    }

    @Override
    public synchronized CertsBundle nextCerts()
            throws DataAccessException, InterruptedException {
        if (!hasNext()) {
            return null;
        }

        List<BigInteger> serialNumbers = new ArrayList<>(numCertsInOneBlock);
        Map<BigInteger, DbDigestEntry> certs = new HashMap<>(numCertsInOneBlock);

        int ik = 0;
        while (hasNext()) {
            DbDigestEntry line;
            try {
                line = nextCert();
            } catch (IOException ex) {
                throw new DataAccessException("IOException: " + ex.getMessage());
            }

            serialNumbers.add(line.serialNumber());
            certs.put(line.serialNumber(), line);
            ik++;
            if (ik >= numCertsInOneBlock) {
                break;
            }
        }

        return (ik == 0) ? null : new CertsBundle(certs, serialNumbers);
    } // method nextCerts

    private DbDigestEntry nextCert() throws IOException {
        if (next == null) {
            throw new IllegalStateException("reach end of the stream");
        }

        DbDigestEntry ret = next;
        next = null;
        next = retrieveNext(false);
        return ret;
    }

    private DbDigestEntry retrieveNext(boolean firstTime) throws IOException {
        String line = firstTime ? null : certsReader.readLine();
        if (line == null) {
            closeReader(certsReader);
            String nextFileName = certsFilesReader.readLine();
            if (nextFileName == null) {
                return null;
            }
            String filePath = "certs" + File.separator + nextFileName;
            certsReader = new BufferedReader(new FileReader(new File(caDirname, filePath)));
            line = certsReader.readLine();
        }

        return (line == null) ? null : DbDigestEntry.decode(line);
    }

    @Override
    public void close() {
        closeReader(certsFilesReader);
        closeReader(certsReader);
    }

    private boolean hasNext() {
        return next != null;
    }

    private static void closeReader(Reader reader) {
        if (reader == null) {
            return;
        }

        try {
            reader.close();
        } catch (Exception ex) {
            LOG.warn("could not close reader: {}", ex.getMessage());
            LOG.debug("could not close reader", ex);
        }
    }

}
