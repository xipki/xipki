/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

import java.io.File;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ProcessLog;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.dbtool.DbToolBase;
import org.xipki.pki.ca.dbtool.IDRange;
import org.xipki.pki.ca.dbtool.diffdb.io.CaEntry;
import org.xipki.pki.ca.dbtool.diffdb.io.CaEntryContainer;
import org.xipki.pki.ca.dbtool.diffdb.io.DbDigestEntry;
import org.xipki.pki.ca.dbtool.diffdb.io.DbSchemaType;
import org.xipki.pki.ca.dbtool.diffdb.io.EjbcaCACertExtractor;
import org.xipki.pki.ca.dbtool.diffdb.io.EjbcaCaInfo;
import org.xipki.pki.ca.dbtool.diffdb.io.EjbcaDigestExportReader;
import org.xipki.pki.ca.dbtool.diffdb.io.IdentifiedDbDigestEntry;

/**
 * @author Lijun Liao
 */

public class EjbcaDigestExporter extends DbToolBase implements DbDigestExporter {

    private static final Logger LOG = LoggerFactory.getLogger(EjbcaDigestExporter.class);

    private final int numCertsPerSelect;

    private final boolean tblCertHasId;

    private final String sql;

    private final String certSql;

    private final int numThreads;

    public EjbcaDigestExporter(
            final DataSourceWrapper datasource,
            final String baseDir,
            final AtomicBoolean stopMe,
            final int numCertsPerSelect,
            final DbSchemaType dbSchemaType,
            final int numThreads)
    throws Exception {
        super(datasource, baseDir, stopMe);
        if (numCertsPerSelect < 1) {
            throw new IllegalArgumentException("numCertsPerSelect could not be less than 1: "
                    + numCertsPerSelect);
        }

        if (dbSchemaType != DbSchemaType.EJBCA_CA_v3) {
            throw new RuntimeException("unsupported DbSchemaType " + dbSchemaType);
        }
        this.numCertsPerSelect = numCertsPerSelect;

        // detect whether the table CertificateData has the column id
        if (dataSource.tableHasColumn(connection, "CertificateData", "id")) {
            tblCertHasId = true;
            sql = null;
            certSql = null;
            this.numThreads = Math.min(numThreads, datasource.getMaximumPoolSize() - 1);
        } else {
            String lang = System.getenv("LANG");
            if (lang == null) {
                throw new Exception("no environment LANG is set");
            }

            String lLang = lang.toLowerCase();
            if (!lLang.startsWith("en_") || !lLang.endsWith(".utf-8")) {
                throw new Exception(
                        "The environment LANG does not satisfy the pattern  'en_*.UTF-8': '"
                        + lang + "'");
            }

            String osName = System.getProperty("os.name");
            if (!osName.toLowerCase().contains("linux")) {
                throw new Exception("Exporting EJBCA database is only possible in Linux, but not '"
                        + osName + "'");
            }

            tblCertHasId = false;
            String coreSql =
                    "fingerprint, serialNumber, cAFingerprint, status, revocationReason, "
                    + "revocationDate FROM CertificateData WHERE fingerprint > ?";
            sql = dataSource.createFetchFirstSelectSQL(coreSql, numCertsPerSelect,
                    "fingerprint ASC");
            certSql = "SELECT base64Cert FROM CertificateData WHERE fingerprint=?";

            this.numThreads = 1;
        }

        if (this.numThreads != numThreads) {
            LOG.info("adapted the numThreads from {} to {}", numThreads, this.numThreads);
        }
    } // constructor

    @Override
    public void digest()
    throws Exception {
        System.out.println("digesting database");

        final long total = getCount("CertificateData");
        ProcessLog processLog = new ProcessLog(total);

        Map<String, EjbcaCaInfo> cas = getCas();
        Set<CaEntry> caEntries = new HashSet<>(cas.size());

        for (EjbcaCaInfo caInfo : cas.values()) {
            CaEntry caEntry = new CaEntry(caInfo.getCaId(),
                    baseDir + File.separator + caInfo.getCaDirname());
            caEntries.add(caEntry);
        }

        CaEntryContainer caEntryContainer = new CaEntryContainer(caEntries);

        Exception exception = null;
        try {
            if (tblCertHasId) {
                EjbcaDigestExportReader certsReader = new EjbcaDigestExportReader(dataSource,
                        cas, numThreads);
                doDigest_withTableId(certsReader, processLog, caEntryContainer, cas);
            } else {
                doDigest_noTableId(processLog, caEntryContainer, cas);
            }
        } catch (Exception e) {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-");
            System.err.println("\ndigesting process has been cancelled due to error");
            LOG.error("Exception", e);
            exception = e;
        } finally {
            caEntryContainer.close();
        }

        if (exception == null) {
            System.out.println(" digested database");
        } else {
            throw exception;
        }
    } // method digest

    private Map<String, EjbcaCaInfo> getCas()
    throws Exception {
        Map<String, EjbcaCaInfo> cas = new HashMap<>();
        final String sql = "SELECT NAME, DATA FROM CAData";

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);
            int caId = 0;

            while (rs.next()) {
                String name = rs.getString("NAME");
                String data = rs.getString("DATA");
                if (name == null || name.isEmpty()) {
                    continue;
                }

                X509Certificate cert = EjbcaCACertExtractor.extractCACert(data);
                byte[] certBytes = cert.getEncoded();

                String commonName = X509Util.getCommonName(cert.getSubjectX500Principal());
                String fn = XipkiDigestExporter.toAsciiFilename("ca-" + commonName);
                File caDir = new File(baseDir, fn);
                int i = 2;
                while (caDir.exists()) {
                    caDir = new File(baseDir, fn + "." + (i++));
                }

                // find out the id
                caId++;
                File caCertFile = new File(caDir, "ca.der");
                caDir.mkdirs();
                IoUtil.save(caCertFile, certBytes);

                EjbcaCaInfo caInfo = new EjbcaCaInfo(caId, certBytes, caDir.getName());
                cas.put(caInfo.getHexSha1(), caInfo);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        return cas;
    } // method getCas

    private void doDigest_noTableId(
            final ProcessLog processLog,
            final CaEntryContainer caEntryContainer,
            final Map<String, EjbcaCaInfo> caInfos)
    throws Exception {
        int skippedAccount = 0;
        String lastProcessedHexCertFp;

        lastProcessedHexCertFp = Hex.toHexString(new byte[20]); // 40 zeros
        System.out.println("digesting certificates from fingerprint (exclusive)\n\t"
                + lastProcessedHexCertFp);

        PreparedStatement ps = prepareStatement(sql);
        PreparedStatement rawCertPs = prepareStatement(certSql);

        processLog.printHeader();

        String sql = null;
        int id = 0;

        try {
            boolean interrupted = false;
            String hexCertFp = lastProcessedHexCertFp;

            while (true) {
                if (stopMe.get()) {
                    interrupted = true;
                    break;
                }

                ps.setString(1, hexCertFp);
                ResultSet rs = ps.executeQuery();

                int countEntriesInResultSet = 0;
                while (rs.next()) {
                    id++;
                    countEntriesInResultSet++;
                    String hexCaFp = rs.getString("cAFingerprint");
                    hexCertFp = rs.getString("fingerprint");

                    EjbcaCaInfo caInfo = null;

                    if (!hexCaFp.equals(hexCertFp)) {
                        caInfo = caInfos.get(hexCaFp);
                    }

                    if (caInfo == null) {
                        LOG.debug("Found no CA by caFingerprint, try to resolve by issuer");
                        rawCertPs.setString(1, hexCertFp);

                        ResultSet certRs = rawCertPs.executeQuery();

                        if (certRs.next()) {
                            String b64Cert = certRs.getString("base64Cert");
                            Certificate cert = Certificate.getInstance(Base64.decode(b64Cert));
                            for (EjbcaCaInfo entry : caInfos.values()) {
                                if (entry.getSubject().equals(cert.getIssuer())) {
                                    caInfo = entry;
                                    break;
                                }
                            }
                        }
                        certRs.close();
                    }

                    if (caInfo == null) {
                        LOG.error("FOUND no CA for Cert with fingerprint '{}'", hexCertFp);
                        skippedAccount++;
                        processLog.addNumProcessed(1);
                        continue;
                    }

                    String hash = Base64.toBase64String(Hex.decode(hexCertFp));

                    String s = rs.getString("serialNumber");
                    long serial = Long.parseLong(s);

                    int status = rs.getInt("status");
                    boolean revoked = (status == 40);

                    Integer revReason = null;
                    Long revTime = null;
                    Long revInvTime = null;

                    if (revoked) {
                        revReason = rs.getInt("revocationReason");
                        long rev_timeInMs = rs.getLong("revocationDate");
                        // rev_time is milliseconds, convert it to seconds
                        revTime = rev_timeInMs / 1000;
                    }

                    DbDigestEntry cert = new DbDigestEntry(serial, revoked, revReason, revTime,
                            revInvTime, hash);

                    caEntryContainer.addDigestEntry(caInfo.getCaId(), id, cert);

                    processLog.addNumProcessed(1);
                    processLog.printStatus();
                } // end while (rs.next())
                rs.close();

                if (countEntriesInResultSet == 0) {
                    break;
                }
            } // end while (true)

            if (interrupted) {
                throw new InterruptedException("interrupted by the user");
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(ps, null);
            releaseResources(rawCertPs, null);
        }

        processLog.printTrailer();

        StringBuilder sb = new StringBuilder(200);
        sb.append(" digested ")
            .append((processLog.getNumProcessed() - skippedAccount))
            .append(" certificates");
        if (skippedAccount > 0) {
            sb.append(", ignored ")
                .append(skippedAccount)
                .append(" certificates (see log for details)");
        }
        System.out.println(sb.toString());
    } // method doDigest_noTableId

    private void doDigest_withTableId(
            final EjbcaDigestExportReader certsReader,
            final ProcessLog processLog,
            final CaEntryContainer caEntryContainer,
            final Map<String, EjbcaCaInfo> caInfos)
    throws Exception {
        final int minCertId = (int) getMin("CertificateData", "id");
        final int maxCertId = (int) getMax("CertificateData", "id");
        System.out.println("digesting certificates from id " + minCertId);

        processLog.printHeader();

        List<IDRange> idRanges = new ArrayList<>(numThreads);

        boolean interrupted = false;

        for (int i = minCertId; i <= maxCertId;) {

            if (stopMe.get()) {
                interrupted = true;
                break;
            }

            idRanges.clear();
            for (int j = 0; j < numThreads; j++) {
                int to = i + numCertsPerSelect - 1;
                idRanges.add(new IDRange(i, to));
                i = to + 1;
                if (i > maxCertId) {
                    break; // break for (int j; ...)
                }
            }

            List<IdentifiedDbDigestEntry> certs = certsReader.readCerts(idRanges);
            for (IdentifiedDbDigestEntry cert : certs) {
                caEntryContainer.addDigestEntry(cert.getCaId().intValue(),
                        cert.getId(), cert.getContent());
            }
            processLog.addNumProcessed(certs.size());
            processLog.printStatus();

            if (interrupted) {
                throw new InterruptedException("interrupted by the user");
            }
        }

        processLog.printTrailer();

        StringBuilder sb = new StringBuilder(200);
        sb.append(" digested ")
            .append((processLog.getNumProcessed()))
            .append(" certificates");

        int skippedAccount = certsReader.getNumSkippedCerts();
        if (skippedAccount > 0) {
            sb.append(", ignored ")
                .append(skippedAccount)
                .append(" certificates (see log for details)");
        }
        System.out.println(sb.toString());
    } // method doDigest_withTableId

}
