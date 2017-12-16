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

package org.xipki.ca.dbtool.diffdb.io;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.xipki.ca.dbtool.DbToolBase;
import org.xipki.ca.dbtool.xmlio.InvalidDataObjectException;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaEntry {

    public static final String FILENAME_OVERVIEW = "overview.properties";

    public static final String PROPKEY_ACCOUNT = "account";

    public static final String PROPKEY_ACCOUNT_REVOKED = "account-revoked";

    public static final int DFLT_NUM_CERTS_IN_BUNDLE = 100000;

    public static final int STREAM_BUFFERSIZE = 1024 * 1024; // 1M

    private final int caId;

    private final FileOutputStream certsManifestOs;

    private final File caDir;

    private final File certsDir;

    private int numProcessed;

    private int numProcessedRevoked;

    private File csvFile;

    private BufferedOutputStream csvOutputStream;

    private long minIdInCsvFile;

    private long maxIdInCsvFile;

    private int numInCsvFile;

    public CaEntry(final int caId, final String caDir) throws IOException {
        ParamUtil.requireNonNull("caDir", caDir);

        this.caId = caId;
        this.caDir = new File(caDir);
        this.certsDir = new File(caDir, "certs");
        this.certsDir.mkdirs();

        this.certsManifestOs = new FileOutputStream(new File(caDir, "certs.mf"), true);

        createNewCsvFile();
    }

    public int caId() {
        return caId;
    }

    public void addDigestEntry(final long id, final DbDigestEntry reportEntry)
            throws IOException, InvalidDataObjectException {
        ParamUtil.requireNonNull("reportEntry", reportEntry);

        if (minIdInCsvFile == 0) {
            minIdInCsvFile = id;
        } else if (minIdInCsvFile > id) {
            minIdInCsvFile = id;
        }

        if (maxIdInCsvFile == 0) {
            maxIdInCsvFile = id;
        } else if (maxIdInCsvFile < id) {
            maxIdInCsvFile = id;
        }
        numInCsvFile++;

        csvOutputStream.write(reportEntry.encoded().getBytes());
        csvOutputStream.write('\n');

        if (numInCsvFile == DFLT_NUM_CERTS_IN_BUNDLE) {
            closeCurrentCsvFile();
            numInCsvFile = 0;
            minIdInCsvFile = 0;
            maxIdInCsvFile = 0;
            createNewCsvFile();
        }
        numProcessed++;
        if (reportEntry.isRevoked()) {
            numProcessedRevoked++;
        }
    }

    public void close() throws IOException {
        // write the account
        StringBuilder sb = new StringBuilder(50);
        sb.append(PROPKEY_ACCOUNT).append("=").append(numProcessed).append("\n");
        sb.append(PROPKEY_ACCOUNT_REVOKED).append("=").append(numProcessedRevoked).append("\n");
        IoUtil.save(new File(caDir, FILENAME_OVERVIEW), sb.toString().getBytes());

        closeCurrentCsvFile();
        IoUtil.closeStream(certsManifestOs);
    }

    private void closeCurrentCsvFile() throws IOException {
        csvOutputStream.close();

        String zipFilename = DbToolBase.buildFilename("certs_", ".csv", minIdInCsvFile,
                maxIdInCsvFile, Integer.MAX_VALUE);
        csvFile.renameTo(new File(caDir, "certs" + File.separator + zipFilename));
        certsManifestOs.write((zipFilename + "\n").getBytes());
        certsManifestOs.flush();
    }

    private void createNewCsvFile() throws IOException {
        this.csvFile = new File(caDir.getParentFile(),
                "tmp-ca-" + caId + "-" + System.currentTimeMillis() + ".csv");
        csvOutputStream = new BufferedOutputStream(
                new FileOutputStream(this.csvFile), STREAM_BUFFERSIZE);
    }

}
