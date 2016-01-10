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

package org.xipki.pki.ca.dbtool.diffdb;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.diffdb.internal.CaEntry;
import org.xipki.pki.ca.dbtool.diffdb.internal.CertsBundle;
import org.xipki.pki.ca.dbtool.diffdb.internal.DbDigestEntry;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public class FileDigestReader implements DigestReader {

    private final int totalAccount;

    private final String caDirname;

    private final String caSubjectName;

    private final X509Certificate caCert;

    private final BufferedReader certsFilesReader;

    private final boolean revokedOnly;

    private BufferedReader certsReader;

    private DbDigestEntry next;

    public FileDigestReader(
            final String caDirname,
            final boolean revokedOnly)
    throws IOException, CertificateException {
        ParamUtil.assertNotBlank("caDirname", caDirname);
        this.caDirname = caDirname;
        this.revokedOnly = revokedOnly;

        this.caCert = X509Util.parseCert(
                new File(caDirname, "ca.der"));
        Properties props = new Properties();
        props.load(new FileInputStream(new File(caDirname, CaEntry.FILENAME_OVERVIEW)));
        String accoutPropKey = revokedOnly
                ? CaEntry.PROPKEY_ACCOUNT_REVOKED
                : CaEntry.PROPKEY_ACCOUNT;
        String accoutS = props.getProperty(accoutPropKey);
        this.totalAccount = Integer.parseInt(accoutS);

        this.certsFilesReader = new BufferedReader(
                new FileReader(
                        new File(caDirname, "certs-manifest")));
        this.caSubjectName = X509Util.getRFC4519Name(this.caCert.getSubjectX500Principal());
        this.next = retrieveNext(true);
    }

    @Override
    public X509Certificate getCaCert() {
        return caCert;
    }

    @Override
    public String getCaSubjectName() {
        return this.caSubjectName;
    }

    @Override
    public int getTotalAccount() {
        return totalAccount;
    }

    @Override
    public synchronized CertsBundle nextCerts(
            final int n)
    throws DataAccessException, InterruptedException {
        if (!hasNext()) {
            return null;
        }

        int numSkipped = 0;
        List<Long> serialNumbers = new ArrayList<>(n);
        Map<Long, DbDigestEntry> certs = new HashMap<>(n);

        int k = 0;
        while (hasNext()) {
            DbDigestEntry line;
            try {
                line = nextCert();
            } catch (IOException e) {
                throw new DataAccessException("IOException: " + e.getMessage());
            }
            if (revokedOnly && !line.isRevoked()) {
                numSkipped++;
                continue;
            }

            serialNumbers.add(line.getSerialNumber());
            certs.put(line.getSerialNumber(), line);
            k++;
            if (k >= n) {
                break;
            }
        }

        return (k == 0)
                ? null
                : new CertsBundle(numSkipped, certs, serialNumbers);
    }

    private DbDigestEntry nextCert()
    throws IOException {
        if (next == null) {
            throw new IllegalStateException("reach end of the stream");
        }

        DbDigestEntry ret = next;
        next = null;
        next = retrieveNext(false);
        return ret;
    }

    private DbDigestEntry retrieveNext(
            final boolean firstTime)
    throws IOException {
        String line = firstTime
                ? null
                : certsReader.readLine();
        if (line == null) {
            close(certsReader);
            String nextFileName = certsFilesReader.readLine();
            if (nextFileName == null) {
                return null;
            }
            String filePath = "certs" + File.separator + nextFileName;
            certsReader = new BufferedReader(
                    new FileReader(new File(caDirname, filePath)));
            line = certsReader.readLine();
        }

        return (line == null)
                ? null
                : DbDigestEntry.decode(line);
    }

    @Override
    public void close() {
        close(certsFilesReader);
        close(certsReader);
    }

    private boolean hasNext() {
        return next != null;
    }

    private static void close(
            final Reader reader) {
        if (reader == null) {
            return;
        }

        try {
            reader.close();
        } catch (Exception e) {
        }
    }

}
