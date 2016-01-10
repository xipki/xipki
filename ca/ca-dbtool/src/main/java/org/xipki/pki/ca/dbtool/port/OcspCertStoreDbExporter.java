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
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLStreamException;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ProcessLog;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.jaxb.ocsp.CertStoreType;
import org.xipki.pki.ca.dbtool.jaxb.ocsp.CertStoreType.Issuers;
import org.xipki.pki.ca.dbtool.jaxb.ocsp.IssuerType;
import org.xipki.pki.ca.dbtool.jaxb.ocsp.ObjectFactory;
import org.xipki.pki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.pki.ca.dbtool.xmlio.OcspCertType;
import org.xipki.pki.ca.dbtool.xmlio.OcspCertsWriter;
import org.xipki.security.api.HashCalculator;

/**
 * @author Lijun Liao
 */

class OcspCertStoreDbExporter extends DbPorter {

    public static final String PROCESS_LOG_FILENAME = "export.process";

    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreDbExporter.class);

    private final Marshaller marshaller;

    private final Unmarshaller unmarshaller;

    private final int numCertsInBundle;

    private final int numCertsPerSelect;

    private final boolean resume;

    OcspCertStoreDbExporter(
            final DataSourceWrapper dataSource,
            final Marshaller marshaller,
            final Unmarshaller unmarshaller,
            final String baseDir,
            final int numCertsInBundle,
            final int numCertsPerSelect,
            final boolean resume,
            final AtomicBoolean stopMe,
            final boolean evaluateOnly)
    throws Exception {
        super(dataSource, baseDir, stopMe, evaluateOnly);
        ParamUtil.assertNotNull("marshaller", marshaller);
        ParamUtil.assertNotNull("unmarshaller", unmarshaller);
        if (numCertsInBundle < 1) {
            throw new IllegalArgumentException("numCertsInBundle could not be less than 1: "
                    + numCertsInBundle);
        }
        if (numCertsPerSelect < 1) {
            throw new IllegalArgumentException("numCertsPerSelect could not be less than 1: "
                    + numCertsPerSelect);
        }

        this.numCertsInBundle = numCertsInBundle;
        this.numCertsPerSelect = numCertsInBundle;

        this.marshaller = marshaller;
        this.unmarshaller = unmarshaller;
        if (resume) {
            File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);
            if (!processLogFile.exists()) {
                throw new Exception("could not process with '--resume' option");
            }
        }
        this.resume = resume;
    }

    public void export()
    throws Exception {
        File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);

        CertStoreType certstore;
        if (resume) {
            try {
                @SuppressWarnings("unchecked")
                JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                        unmarshaller.unmarshal(new File(baseDir, FILENAME_OCSP_CertStore));
                certstore = root.getValue();
            } catch (JAXBException e) {
                throw XMLUtil.convert(e);
            }

            if (certstore.getVersion() > VERSION) {
                throw new Exception("could not continue with CertStore greater than " + VERSION
                        + ": " + certstore.getVersion());
            }
        } else {
            certstore = new CertStoreType();
            certstore.setVersion(VERSION);
        }
        System.out.println("exporting OCSP certstore from database");

        if (!resume) {
            export_issuer(certstore);
        }
        Exception exception = export_cert(certstore, processLogFile);

        JAXBElement<CertStoreType> root = new ObjectFactory().createCertStore(certstore);
        try {
            marshaller.marshal(root, new File(baseDir, FILENAME_OCSP_CertStore));
        } catch (JAXBException e) {
            throw XMLUtil.convert(e);
        }

        if (exception == null) {
            System.out.println(" exported OCSP certstore from database");
        } else {
            throw exception;
        }
    }

    private void export_issuer(
            final CertStoreType certstore)
    throws DataAccessException, IOException {
        System.out.println("exporting table ISSUER");
        Issuers issuers = new Issuers();
        certstore.setIssuers(issuers);
        final String sql = "SELECT ID,CERT,REV,RR,RT,RIT FROM ISSUER";

        Statement stmt = null;
        ResultSet rs = null;

        try {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            String issuerCertsDir = "issuer-conf";
            new File(issuerCertsDir).mkdirs();

            while (rs.next()) {
                int id = rs.getInt("ID");
                String cert = rs.getString("CERT");

                IssuerType issuer = new IssuerType();
                issuer.setId(id);

                String certFileName = issuerCertsDir + "/cert-issuer-" + id;
                IoUtil.save(new File(baseDir, certFileName), cert.getBytes("UTF-8"));
                issuer.setCertFile(certFileName);

                boolean revoked = rs.getBoolean("REV");
                issuer.setRevoked(revoked);
                if (revoked) {
                    int rev_reason = rs.getInt("RR");
                    long rev_time = rs.getLong("RT");
                    long rev_invalidity_time = rs.getLong("RIT");
                    issuer.setRevReason(rev_reason);
                    issuer.setRevTime(rev_time);
                    if (rev_invalidity_time != 0) {
                        issuer.setRevInvTime(rev_invalidity_time);
                    }
                }

                issuers.getIssuer().add(issuer);
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, rs);
        }

        System.out.println(" exported table ISSUER");
    }

    private Exception export_cert(
            final CertStoreType certstore,
            final File processLogFile) {
        File fCertsDir = new File(certsDir);
        fCertsDir.mkdirs();

        FileOutputStream certsFileOs = null;

        try {
            certsFileOs = new FileOutputStream(certsListFile, true);
            do_export_cert(certstore, processLogFile, certsFileOs);
            return null;
        } catch (Exception e) {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-certs-");
            System.err.println("\nexporting table CERT and CRAW has been cancelled due to error,\n"
                    + "please continue with the option '--resume'");
            LOG.error("Exception", e);
            return e;
        } finally {
            IoUtil.closeStream(certsFileOs);
        }
    }

    private void do_export_cert(
            final CertStoreType certstore,
            final File processLogFile,
            final FileOutputStream certsFileOs)
    throws Exception {
        int numProcessedBefore = certstore.getCountCerts();

        Integer minCertId = null;
        if (processLogFile.exists()) {
            byte[] content = IoUtil.read(processLogFile);
            if (content != null && content.length > 0) {
                minCertId = Integer.parseInt(new String(content).trim());
                minCertId++;
            }
        }

        if (minCertId == null) {
            minCertId = (int) getMin("CERT", "ID");
        }

        System.out.println(getExportingText() + "tables CERT, CHASH and CRAW from ID " + minCertId);

        final String certSql = "SELECT ID,SN,IID,LUPDATE,REV,RR,RT,RIT,PN,CERT "
                + "FROM CERT INNER JOIN CRAW ON "
                + "CERT.ID>=? AND CERT.ID<? AND CERT.ID=CRAW.CID ORDER BY CERT.ID ASC";

        final int maxCertId = (int) getMax("CERT", "ID");

        final long total = getCount("CERT") - numProcessedBefore;
        ProcessLog processLog = new ProcessLog(total);

        PreparedStatement certPs = prepareStatement(certSql);

        int sum = 0;
        int numCertInCurrentFile = 0;

        OcspCertsWriter certsInCurrentFile = new OcspCertsWriter();

        final int n = numCertsPerSelect;

        File currentCertsZipFile = new File(baseDir,
                "tmp-certs-" + System.currentTimeMillis() + ".zip");
        ZipOutputStream currentCertsZip = getZipOutputStream(currentCertsZipFile);

        int minCertIdOfCurrentFile = -1;
        int maxCertIdOfCurrentFile = -1;

        processLog.printHeader();

        String sql = null;

        Integer id = null;
        try {
            boolean interrupted = false;
            for (int i = minCertId; i <= maxCertId; i += n) {
                if (stopMe.get()) {
                    interrupted = true;
                    break;
                }

                sql = certSql;
                certPs.setInt(1, i);
                certPs.setInt(2, i + n);

                ResultSet rs = certPs.executeQuery();

                while (rs.next()) {
                    id = rs.getInt("ID");

                    if (minCertIdOfCurrentFile == -1) {
                        minCertIdOfCurrentFile = id;
                    } else if (minCertIdOfCurrentFile > id) {
                        minCertIdOfCurrentFile = id;
                    }

                    if (maxCertIdOfCurrentFile == -1) {
                        maxCertIdOfCurrentFile = id;
                    } else if (maxCertIdOfCurrentFile < id) {
                        maxCertIdOfCurrentFile = id;
                    }

                    String b64Cert = rs.getString("CERT");
                    byte[] certBytes = Base64.decode(b64Cert);

                    String sha1_cert = HashCalculator.hexSha1(certBytes);

                    if (!evaulateOnly) {
                        ZipEntry certZipEntry = new ZipEntry(sha1_cert + ".der");
                        currentCertsZip.putNextEntry(certZipEntry);
                        try {
                            currentCertsZip.write(certBytes);
                        } finally {
                            currentCertsZip.closeEntry();
                        }
                    }

                    OcspCertType cert = new OcspCertType();

                    cert.setId(id);

                    int issuer_id = rs.getInt("IID");
                    cert.setIid(issuer_id);

                    long serial = rs.getLong("SN");
                    cert.setSn(Long.toHexString(serial));

                    long update = rs.getLong("LUPDATE");
                    cert.setUpdate(update);

                    boolean revoked = rs.getBoolean("REV");
                    cert.setRev(revoked);

                    if (revoked) {
                        int rev_reason = rs.getInt("RR");
                        long rev_time = rs.getLong("RT");
                        long rev_invalidity_time = rs.getLong("RIT");
                        cert.setRr(rev_reason);
                        cert.setRt(rev_time);
                        if (rev_invalidity_time != 0) {
                            cert.setRit(rev_invalidity_time);
                        }
                    }
                    cert.setFile(sha1_cert + ".der");

                    String profile = rs.getString("PN");
                    cert.setProfile(profile);

                    certsInCurrentFile.add(cert);
                    numCertInCurrentFile++;
                    sum++;

                    if (numCertInCurrentFile == numCertsInBundle) {
                        finalizeZip(currentCertsZip, certsInCurrentFile);

                        String currentCertsFilename = buildFilename("certs_", ".zip",
                                minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxCertId);
                        currentCertsZipFile.renameTo(new File(certsDir, currentCertsFilename));

                        writeLine(certsFileOs, currentCertsFilename);
                        certstore.setCountCerts(numProcessedBefore + sum);
                        echoToFile(Integer.toString(id), processLogFile);

                        processLog.addNumProcessed(numCertInCurrentFile);
                        processLog.printStatus();

                        // reset
                        certsInCurrentFile = new OcspCertsWriter();
                        numCertInCurrentFile = 0;
                        minCertIdOfCurrentFile = -1;
                        maxCertIdOfCurrentFile = -1;
                        currentCertsZipFile = new File(baseDir,
                                "tmp-certs-" + System.currentTimeMillis() + ".zip");
                        currentCertsZip = getZipOutputStream(currentCertsZipFile);
                    } // end if
                } // end while (rs.next))

                rs.close();
            } // end for

            if (interrupted) {
                throw new InterruptedException("interrupted by the user");
            }

            if (numCertInCurrentFile > 0) {
                finalizeZip(currentCertsZip, certsInCurrentFile);

                String currentCertsFilename = buildFilename("certs_", ".zip",
                        minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxCertId);
                currentCertsZipFile.renameTo(new File(certsDir, currentCertsFilename));

                writeLine(certsFileOs, currentCertsFilename);
                certstore.setCountCerts(numProcessedBefore + sum);
                echoToFile(Integer.toString(id), processLogFile);

                processLog.addNumProcessed(numCertInCurrentFile);
            } else {
                currentCertsZip.close();
                currentCertsZipFile.delete();
            }
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(certPs, null);
        }

        processLog.printTrailer();
        // all successful, delete the processLogFile
        processLogFile.delete();

        System.out.println(getExportedText() + processLog.getNumProcessed()
                + " certificates from tables CERT, CHASH and CRAW");
    }

    private void finalizeZip(
            final ZipOutputStream zipOutStream,
            final DbiXmlWriter certsType)
    throws JAXBException, IOException, XMLStreamException {
        ZipEntry certZipEntry = new ZipEntry("certs.xml");
        zipOutStream.putNextEntry(certZipEntry);
        try {
            certsType.rewriteToZipStream(zipOutStream);
        } finally {
            zipOutStream.closeEntry();
        }

        zipOutStream.close();
    }

}
