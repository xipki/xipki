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

package org.xipki.ca.dbtool.port.ocsp;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.jaxb.ocsp.CertStoreType;
import org.xipki.ca.dbtool.jaxb.ocsp.CertStoreType.Issuers;
import org.xipki.ca.dbtool.jaxb.ocsp.IssuerType;
import org.xipki.ca.dbtool.jaxb.ocsp.ObjectFactory;
import org.xipki.ca.dbtool.port.DbPorter;
import org.xipki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.ca.dbtool.xmlio.ocsp.OcspCertType;
import org.xipki.ca.dbtool.xmlio.ocsp.OcspCertsWriter;
import org.xipki.common.ProcessLog;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.XmlUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class OcspCertStoreDbExporter extends DbPorter {

    public static final String PROCESS_LOG_FILENAME = "export.process";

    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreDbExporter.class);

    private final Marshaller marshaller;

    private final Unmarshaller unmarshaller;

    private final int numCertsInBundle;

    private final int numCertsPerSelect;

    private final boolean resume;

    OcspCertStoreDbExporter(DataSourceWrapper datasource, Marshaller marshaller,
            Unmarshaller unmarshaller, String baseDir, int numCertsInBundle, int numCertsPerSelect,
            boolean resume, AtomicBoolean stopMe, boolean evaluateOnly) throws Exception {
        super(datasource, baseDir, stopMe, evaluateOnly);

        this.numCertsInBundle = ParamUtil.requireMin("numCertsInBundle", numCertsInBundle, 1);
        this.numCertsPerSelect = ParamUtil.requireMin("numCertsPerSelect", numCertsPerSelect, 1);
        this.marshaller = ParamUtil.requireNonNull("marshaller", marshaller);
        this.unmarshaller = ParamUtil.requireNonNull("unmarshaller", unmarshaller);
        if (resume) {
            File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);
            if (!processLogFile.exists()) {
                throw new Exception("could not process with '--resume' option");
            }
        }
        this.resume = resume;
    } // constructor

    public void export() throws Exception {
        CertStoreType certstore;
        if (resume) {
            try {
                @SuppressWarnings("unchecked")
                JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                        unmarshaller.unmarshal(new File(baseDir, FILENAME_OCSP_CERTSTORE));
                certstore = root.getValue();
            } catch (JAXBException ex) {
                throw XmlUtil.convert(ex);
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
            exportIssuer(certstore);
        }

        File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);
        Exception exception = exportCert(certstore, processLogFile);

        JAXBElement<CertStoreType> root = new ObjectFactory().createCertStore(certstore);
        try {
            marshaller.marshal(root, new File(baseDir, FILENAME_OCSP_CERTSTORE));
        } catch (JAXBException ex) {
            throw XmlUtil.convert(ex);
        }

        if (exception == null) {
            System.out.println(" exported OCSP certstore from database");
        } else {
            throw exception;
        }
    } // method export

    private void exportIssuer(CertStoreType certstore) throws DataAccessException, IOException {
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
                    int revReason = rs.getInt("RR");
                    long revTime = rs.getLong("RT");
                    long revInvalidityTime = rs.getLong("RIT");
                    issuer.setRevReason(revReason);
                    issuer.setRevTime(revTime);
                    if (revInvalidityTime != 0) {
                        issuer.setRevInvTime(revInvalidityTime);
                    }
                }

                issuers.getIssuer().add(issuer);
            }
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            releaseResources(stmt, rs);
        }

        System.out.println(" exported table ISSUER");
    } // method exportIssuer

    private Exception exportCert(CertStoreType certstore, File processLogFile) {
        final File entriesDir = new File(baseDir, OcspDbEntryType.CERT.dirName());
        entriesDir.mkdirs();

        FileOutputStream certsFileOs = null;

        try {
            certsFileOs = new FileOutputStream(
                    new File(baseDir, OcspDbEntryType.CERT.dirName() + ".mf"), true);
            exportCert0(certstore, processLogFile, certsFileOs);
            return null;
        } catch (Exception ex) {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-certs-");
            System.err.println("\nexporting table CERT and CRAW has been cancelled due to error,\n"
                    + "please continue with the option '--resume'");
            LOG.error("Exception", ex);
            return ex;
        } finally {
            IoUtil.closeStream(certsFileOs);
        }
    } // method exportCert

    private void exportCert0(CertStoreType certstore, File processLogFile,
            FileOutputStream certsFileOs) throws Exception {
        File certsDir = new File(baseDir, OcspDbEntryType.CERT.dirName());
        Long minId = null;
        if (processLogFile.exists()) {
            byte[] content = IoUtil.read(processLogFile);
            if (content != null && content.length > 0) {
                minId = Long.parseLong(new String(content).trim());
                minId++;
            }
        }

        if (minId == null) {
            minId = min("CERT", "ID");
        }

        System.out.println(exportingText() + "tables CERT, CHASH and CRAW from ID " + minId);

        final String coreSql = "ID,SN,IID,LUPDATE,REV,RR,RT,RIT,PN,CERT "
                + "FROM CERT INNER JOIN CRAW ON CERT.ID>=? AND CERT.ID=CRAW.CID";
        final String certSql = datasource.buildSelectFirstSql(numCertsPerSelect, "ID ASC", coreSql);

        final long maxId = max("CERT", "ID");

        int numProcessedBefore = certstore.getCountCerts();
        final long total = count("CERT") - numProcessedBefore;
        ProcessLog processLog = new ProcessLog(total);

        PreparedStatement certPs = prepareStatement(certSql);

        int sum = 0;
        int numCertInCurrentFile = 0;

        OcspCertsWriter certsInCurrentFile = new OcspCertsWriter();

        File currentCertsZipFile = new File(baseDir,
                "tmp-certs-" + System.currentTimeMillis() + ".zip");
        ZipOutputStream currentCertsZip = getZipOutputStream(currentCertsZipFile);

        long minCertIdOfCurrentFile = -1;
        long maxCertIdOfCurrentFile = -1;

        processLog.printHeader();

        String sql = null;
        Long id = null;

        try {
            boolean interrupted = false;

            long lastMaxId = minId - 1;

            while (true) {
                if (stopMe.get()) {
                    interrupted = true;
                    break;
                }

                sql = certSql;
                certPs.setLong(1, lastMaxId + 1);

                ResultSet rs = certPs.executeQuery();

                if (!rs.next()) {
                    break;
                }

                do {
                    id = rs.getLong("ID");
                    if (lastMaxId < id) {
                        lastMaxId = id;
                    }

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
                    byte[] certBytes = Base64.decodeFast(b64Cert);

                    String sha1Cert = HashAlgoType.SHA1.hexHash(certBytes);

                    if (!evaulateOnly) {
                        ZipEntry certZipEntry = new ZipEntry(sha1Cert + ".der");
                        currentCertsZip.putNextEntry(certZipEntry);
                        try {
                            currentCertsZip.write(certBytes);
                        } finally {
                            currentCertsZip.closeEntry();
                        }
                    }

                    OcspCertType cert = new OcspCertType();

                    cert.setId(id);

                    int issuerId = rs.getInt("IID");
                    cert.setIid(issuerId);

                    String serial = rs.getString("SN");
                    cert.setSn(serial);

                    long update = rs.getLong("LUPDATE");
                    cert.setUpdate(update);

                    boolean revoked = rs.getBoolean("REV");
                    cert.setRev(revoked);

                    if (revoked) {
                        int revReason = rs.getInt("RR");
                        long revTime = rs.getLong("RT");
                        long revInvalidityTime = rs.getLong("RIT");
                        cert.setRr(revReason);
                        cert.setRt(revTime);
                        if (revInvalidityTime != 0) {
                            cert.setRit(revInvalidityTime);
                        }
                    }
                    cert.setFile(sha1Cert + ".der");

                    String profile = rs.getString("PN");
                    cert.setProfile(profile);

                    certsInCurrentFile.add(cert);
                    numCertInCurrentFile++;
                    sum++;

                    if (numCertInCurrentFile == numCertsInBundle) {
                        finalizeZip(currentCertsZip, certsInCurrentFile);

                        String currentCertsFilename = buildFilename("certs_", ".zip",
                                minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxId);
                        currentCertsZipFile.renameTo(new File(certsDir, currentCertsFilename));

                        writeLine(certsFileOs, currentCertsFilename);
                        certstore.setCountCerts(numProcessedBefore + sum);
                        echoToFile(Long.toString(id), processLogFile);

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
                }
                while (rs.next());

                rs.close();
            } // end for

            if (interrupted) {
                throw new InterruptedException("interrupted by the user");
            }

            if (numCertInCurrentFile > 0) {
                finalizeZip(currentCertsZip, certsInCurrentFile);

                String currentCertsFilename = buildFilename("certs_", ".zip",
                        minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxId);
                currentCertsZipFile.renameTo(new File(certsDir, currentCertsFilename));

                writeLine(certsFileOs, currentCertsFilename);
                certstore.setCountCerts(numProcessedBefore + sum);
                if (id != null) {
                    echoToFile(Long.toString(id), processLogFile);
                }

                processLog.addNumProcessed(numCertInCurrentFile);
            } else {
                currentCertsZip.close();
                currentCertsZipFile.delete();
            }
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            releaseResources(certPs, null);
        }

        processLog.printTrailer();
        // all successful, delete the processLogFile
        processLogFile.delete();

        System.out.println(exportedText() + processLog.numProcessed()
                + " certificates from tables CERT, CHASH and CRAW");
    } // method exportCert0

    private void finalizeZip(ZipOutputStream zipOutStream, DbiXmlWriter certsType)
            throws IOException, XMLStreamException {
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
