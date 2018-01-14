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
import java.io.IOException;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.jaxb.ca.CAConfigurationType;
import org.xipki.ca.dbtool.jaxb.ca.CaHasPublisherType;
import org.xipki.ca.dbtool.jaxb.ca.CaType;
import org.xipki.ca.dbtool.jaxb.ca.CertStoreType;
import org.xipki.ca.dbtool.jaxb.ca.ProfileType;
import org.xipki.ca.dbtool.jaxb.ca.PublisherType;
import org.xipki.ca.dbtool.port.DbPortFileNameIterator;
import org.xipki.ca.dbtool.port.DbPorter;
import org.xipki.ca.dbtool.xmlio.ca.CertType;
import org.xipki.ca.dbtool.xmlio.ca.CertsReader;
import org.xipki.common.ConfPairs;
import org.xipki.common.ProcessLog;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.XmlUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.dbtool.InvalidInputException;
import org.xipki.security.HashAlgoType;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class OcspCertStoreFromCaDbImporter extends AbstractOcspCertStoreDbImporter {

    private static final class ImportStatements {
        final PreparedStatement psCert;
        final PreparedStatement psCerthash;
        final PreparedStatement psRawCert;

        ImportStatements(PreparedStatement psCert, PreparedStatement psCerthash,
                PreparedStatement psRawCert) {
            this.psCert = psCert;
            this.psCerthash = psCerthash;
            this.psRawCert = psRawCert;
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreFromCaDbImporter.class);

    private final Unmarshaller unmarshaller;

    private final String publisherName;

    private final boolean resume;

    private final int numCertsPerCommit;

    OcspCertStoreFromCaDbImporter(DataSourceWrapper datasource, Unmarshaller unmarshaller,
            String srcDir, String publisherName, int numCertsPerCommit, boolean resume,
            AtomicBoolean stopMe, boolean evaluateOnly) throws Exception {
        super(datasource, srcDir, stopMe, evaluateOnly);

        this.unmarshaller = ParamUtil.requireNonNull("unmarshaller", unmarshaller);
        ParamUtil.requireNonBlank("publisherName", publisherName);
        this.publisherName = publisherName.toUpperCase();
        this.numCertsPerCommit = ParamUtil.requireMin("numCertsPerCommit", numCertsPerCommit, 1);

        File processLogFile = new File(baseDir, DbPorter.IMPORT_TO_OCSP_PROCESS_LOG_FILENAME);
        if (resume) {
            if (!processLogFile.exists()) {
                throw new InvalidInputException("could not process with '--resume' option");
            }
        } else {
            if (processLogFile.exists()) {
                throw new InvalidInputException(
                        "please either specify '--resume' option or delete the file "
                        + processLogFile.getPath() + " first");
            }
        }
        this.resume = resume;
    }

    public void importToDb() throws Exception {
        CertStoreType certstore;
        try {
            @SuppressWarnings("unchecked")
            JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                    unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_CERTSTORE));
            certstore = root.getValue();
        } catch (JAXBException ex) {
            throw XmlUtil.convert(ex);
        }

        if (certstore.getVersion() > VERSION) {
            throw new InvalidInputException(
                    "could not import CertStore greater than " + VERSION + ": "
                    + certstore.getVersion());
        }

        CAConfigurationType caConf;
        try {
            File file = new File(baseDir + File.separator + FILENAME_CA_CONFIGURATION);
            @SuppressWarnings("unchecked")
            JAXBElement<CAConfigurationType> rootCaConf = (JAXBElement<CAConfigurationType>)
                    unmarshaller.unmarshal(file);
            caConf = rootCaConf.getValue();
        } catch (JAXBException ex) {
            throw XmlUtil.convert(ex);
        }

        if (caConf.getVersion() > VERSION) {
            throw new InvalidInputException("could not import CA Configuration greater than "
                    + VERSION + ": " + certstore.getVersion());
        }

        System.out.println("importing CA certstore to OCSP database");
        try {
            if (!resume) {
                dropIndexes();
            }

            PublisherType publisherType = null;
            for (PublisherType type : caConf.getPublishers().getPublisher()) {
                if (publisherName.equals(type.getName())) {
                    publisherType = type;
                    break;
                }
            }

            if (publisherType == null) {
                throw new InvalidInputException("unknown publisher " + publisherName);
            }

            String type = publisherType.getType();
            if (!"ocsp".equalsIgnoreCase(type)) {
                throw new InvalidInputException("Unkwown publisher type " + type);
            }

            ConfPairs confPairs = new ConfPairs(value(publisherType.getConf()));
            String str = confPairs.value("publish.goodcerts");
            boolean revokedOnly = false;
            if (str != null) {
                revokedOnly = !Boolean.parseBoolean(str);
            }

            Set<Integer> relatedCaIds = new HashSet<>();
            for (CaHasPublisherType ctype : caConf.getCaHasPublishers().getCaHasPublisher()) {
                if (ctype.getPublisherId() == publisherType.getId()) {
                    relatedCaIds.add(ctype.getCaId());
                }
            }

            List<CaType> relatedCas = new LinkedList<>();
            for (CaType m : caConf.getCas().getCa()) {
                if (relatedCaIds.contains(m.getId())) {
                    relatedCas.add(m);
                }
            }

            if (relatedCas.isEmpty()) {
                System.out.println("No CA has publisher " + publisherName);
                return;
            }

            Map<Integer, String> profileMap = new HashMap<Integer, String>();
            for (ProfileType ni : caConf.getProfiles().getProfile()) {
                profileMap.put(ni.getId(), ni.getName());
            }

            List<Integer> relatedCertStoreCaIds = resume
                ? getIssuerIds(relatedCas)
                : importIssuer(relatedCas);

            File processLogFile = new File(baseDir, DbPorter.IMPORT_TO_OCSP_PROCESS_LOG_FILENAME);
            importCert(certstore, profileMap, revokedOnly, relatedCertStoreCaIds, processLogFile);
            recoverIndexes();
            processLogFile.delete();
        } catch (Exception ex) {
            System.err.println("could not import OCSP certstore to database");
            throw ex;
        }
        System.out.println(" imported OCSP certstore to database");
    } // method importToDb

    private List<Integer> getIssuerIds(List<CaType> cas) throws IOException {
        List<Integer> relatedCaIds = new LinkedList<>();
        for (CaType issuer : cas) {
            byte[] encodedCert = binary(issuer.getCert());

            // retrieve the revocation information of the CA, if possible
            CaType ca = null;
            for (CaType caType : cas) {
                if (Arrays.equals(encodedCert, binary(caType.getCert()))) {
                    ca = caType;
                    break;
                }
            }

            if (ca == null) {
                continue;
            }
            relatedCaIds.add(issuer.getId());
        }
        return relatedCaIds;
    }

    private List<Integer> importIssuer(List<CaType> cas)
            throws DataAccessException, CertificateException, IOException {
        System.out.println("importing table ISSUER");
        final String sql = SQL_ADD_ISSUER;
        PreparedStatement ps = prepareStatement(sql);

        List<Integer> relatedCaIds = new LinkedList<>();

        try {
            for (CaType issuer : cas) {
                importIssuer0(issuer, sql, ps, cas, relatedCaIds);
            }
        } finally {
            releaseResources(ps, null);
        }

        System.out.println(" imported table ISSUER");
        return relatedCaIds;
    }

    private void importIssuer0(CaType issuer, String sql, PreparedStatement ps, List<CaType> cas,
            List<Integer> relatedCaIds)
            throws IOException, DataAccessException, CertificateException {
        try {
            byte[] encodedCert = binary(issuer.getCert());

            // retrieve the revocation information of the CA, if possible
            CaType ca = null;
            for (CaType caType : cas) {
                if (Arrays.equals(encodedCert, binary(caType.getCert()))) {
                    ca = caType;
                    break;
                }
            }

            if (ca == null) {
                return;
            }

            relatedCaIds.add(issuer.getId());

            Certificate cert;
            try {
                cert = Certificate.getInstance(encodedCert);
            } catch (Exception ex) {
                String msg = "could not parse certificate of issuer " + issuer.getId();
                LogUtil.error(LOG, ex, msg);
                if (ex instanceof CertificateException) {
                    throw (CertificateException) ex;
                } else {
                    throw new CertificateException(ex.getMessage(), ex);
                }
            }

            int idx = 1;
            ps.setInt(idx++, issuer.getId());
            ps.setString(idx++, X509Util.cutX500Name(cert.getSubject(), maxX500nameLen));
            ps.setLong(idx++, cert.getTBSCertificate().getStartDate().getDate().getTime() / 1000);
            ps.setLong(idx++, cert.getTBSCertificate().getEndDate().getDate().getTime() / 1000);
            ps.setString(idx++, HashAlgoType.SHA1.base64Hash(encodedCert));
            setBoolean(ps, idx++, ca.isRevoked());
            setInt(ps, idx++, ca.getRevReason());
            setLong(ps, idx++, ca.getRevTime());
            setLong(ps, idx++, ca.getRevInvTime());
            ps.setString(idx++, Base64.encodeToString(encodedCert));

            ps.execute();
        } catch (SQLException ex) {
            System.err.println("could not import issuer with id=" + issuer.getId());
            throw translate(sql, ex);
        } catch (CertificateException ex) {
            System.err.println("could not import issuer with id=" + issuer.getId());
            throw ex;
        }
    } // method importIssuer0

    private void importCert(CertStoreType certstore, Map<Integer, String> profileMap,
            boolean revokedOnly, List<Integer> caIds, File processLogFile) throws Exception {
        int numProcessedBefore = 0;
        long minId = 1;
        if (processLogFile.exists()) {
            byte[] content = IoUtil.read(processLogFile);
            if (content != null && content.length > 2) {
                String str = new String(content);
                if (str.trim().equalsIgnoreCase(MSG_CERTS_FINISHED)) {
                    return;
                }

                StringTokenizer st = new StringTokenizer(str, ":");
                numProcessedBefore = Integer.parseInt(st.nextToken());
                minId = Long.parseLong(st.nextToken());
                minId++;
            }
        }

        deleteCertGreatherThan(minId - 1, LOG);

        final long total = certstore.getCountCerts() - numProcessedBefore;
        final ProcessLog processLog = new ProcessLog(total);
        // all initial values for importLog will be not evaluated, so just any number
        final ProcessLog importLog = new ProcessLog(total);

        System.out.println(importingText() + "certificates from ID " + minId);
        processLog.printHeader();

        PreparedStatement psCert = prepareStatement(SQL_ADD_CERT);
        PreparedStatement psCerthash = prepareStatement(SQL_ADD_CHASH);
        PreparedStatement psRawCert = prepareStatement(SQL_ADD_CRAW);
        ImportStatements statments = new ImportStatements(psCert, psCerthash, psRawCert);

        CaDbEntryType type = CaDbEntryType.CERT;

        DbPortFileNameIterator certsFileIterator = new DbPortFileNameIterator(
                baseDir + File.separator + type.dirName() + ".mf");
        try {
            while (certsFileIterator.hasNext()) {
                String certsFile = baseDir + File.separator + type.dirName() + File.separator
                        + certsFileIterator.next();
                // extract the toId from the filename
                int fromIdx = certsFile.indexOf('-');
                int toIdx = certsFile.indexOf(".zip");
                if (fromIdx != -1 && toIdx != -1) {
                    try {
                        long toId = Integer.parseInt(certsFile.substring(fromIdx + 1, toIdx));
                        if (toId < minId) {
                            // try next file
                            continue;
                        }
                    } catch (Exception ex) {
                        LOG.warn("invalid file name '{}', but will still be processed", certsFile);
                    }
                } else {
                    LOG.warn("invalid file name '{}', but will still be processed", certsFile);
                }

                try {
                    long lastId = importCert0(statments, certsFile, profileMap, revokedOnly, caIds,
                            minId, processLogFile, processLog, numProcessedBefore, importLog);
                    minId = lastId + 1;
                } catch (Exception ex) {
                    System.err.println("\ncould not import certificates from file " + certsFile
                            + ".\nplease continue with the option '--resume'");
                    LOG.error("Exception", ex);
                    throw ex;
                }
            }
        } finally {
            releaseResources(psCert, null);
            releaseResources(psCerthash, null);
            releaseResources(psRawCert, null);
            certsFileIterator.close();
        }

        processLog.printTrailer();
        DbPorter.echoToFile(MSG_CERTS_FINISHED, processLogFile);
        System.out.println("processed " + processLog.numProcessed() + " and "
                + importedText() + importLog.numProcessed() + " certificates");
    } // method importCert

    private long importCert0(ImportStatements statments, String certsZipFile,
            Map<Integer, String> profileMap, boolean revokedOnly, List<Integer> caIds, long minId,
            File processLogFile,ProcessLog processLog, int numProcessedInLastProcess,
            ProcessLog importLog) throws Exception {
        ZipFile zipFile = new ZipFile(new File(certsZipFile));
        ZipEntry certsXmlEntry = zipFile.getEntry("overview.xml");

        CertsReader certs;
        try {
            certs = new CertsReader(zipFile.getInputStream(certsXmlEntry));
        } catch (Exception ex) {
            try {
                zipFile.close();
            } catch (Exception ex2) {
                LOG.error("could not close ZIP file {}: {}", certsZipFile, ex2.getMessage());
                LOG.debug("could not close ZIP file " + certsZipFile, ex2);
            }
            throw ex;
        }

        disableAutoCommit();

        PreparedStatement psCert = statments.psCert;
        PreparedStatement psCerthash = statments.psCerthash;
        PreparedStatement psRawCert = statments.psRawCert;

        try {
            int numProcessedEntriesInBatch = 0;
            int numImportedEntriesInBatch = 0;
            long lastSuccessfulCertId = 0;

            while (certs.hasNext()) {
                if (stopMe.get()) {
                    throw new InterruptedException("interrupted by the user");
                }

                CertType cert = (CertType) certs.next();

                long id = cert.id();
                lastSuccessfulCertId = id;
                if (id < minId) {
                    continue;
                }

                numProcessedEntriesInBatch++;

                if (!revokedOnly || cert.rev().booleanValue()) {
                    int caId = cert.caId();
                    if (caIds.contains(caId)) {
                        numImportedEntriesInBatch++;

                        String filename = cert.file();

                        // rawcert
                        ZipEntry certZipEnty = zipFile.getEntry(filename);
                        // rawcert
                        byte[] encodedCert = IoUtil.read(zipFile.getInputStream(certZipEnty));

                        TBSCertificate tbsCert;
                        try {
                            Certificate cc = Certificate.getInstance(encodedCert);
                            tbsCert = cc.getTBSCertificate();
                        } catch (RuntimeException ex) {
                            LOG.error("could not parse certificate in file {}", filename);
                            LOG.debug("could not parse certificate in file " + filename, ex);
                            throw new CertificateException(ex.getMessage(), ex);
                        }

                        // cert
                        try {
                            int idx = 1;
                            psCert.setLong(idx++, id);
                            psCert.setInt(idx++, caId);
                            psCert.setString(idx++,
                                    tbsCert.getSerialNumber().getPositiveValue().toString(16));
                            psCert.setLong(idx++, cert.update());
                            psCert.setLong(idx++,
                                    tbsCert.getStartDate().getDate().getTime() / 1000);
                            psCert.setLong(idx++, tbsCert.getEndDate().getDate().getTime() / 1000);
                            setBoolean(psCert, idx++, cert.rev());
                            setInt(psCert, idx++, cert.rr());
                            setLong(psCert, idx++, cert.rt());
                            setLong(psCert, idx++, cert.rit());

                            int certprofileId = cert.pid();
                            String certprofileName = profileMap.get(certprofileId);
                            psCert.setString(idx++, certprofileName);
                            psCert.addBatch();
                        } catch (SQLException ex) {
                            throw translate(SQL_ADD_CERT, ex);
                        }

                        // certhash
                        try {
                            int idx = 1;
                            psCerthash.setLong(idx++, id);
                            psCerthash.setString(idx++, sha1(encodedCert));
                            psCerthash.setString(idx++, sha256(encodedCert));
                            psCerthash.setString(idx++, sha3_256(encodedCert));
                            psCerthash.addBatch();
                        } catch (SQLException ex) {
                            throw translate(SQL_ADD_CHASH, ex);
                        }

                        // rawcert
                        try {
                            int idx = 1;
                            psRawCert.setLong(idx++, id);
                            psRawCert.setString(idx++,
                                    X509Util.cutX500Name(tbsCert.getSubject(), maxX500nameLen));
                            psRawCert.setString(idx++, Base64.encodeToString(encodedCert));
                            psRawCert.addBatch();
                        } catch (SQLException ex) {
                            throw translate(SQL_ADD_CRAW, ex);
                        }
                    } // end if (caIds.contains(caId))
                } // end if (revokedOnly

                boolean isLastBlock = !certs.hasNext();

                if (numImportedEntriesInBatch > 0
                        && (numImportedEntriesInBatch % this.numCertsPerCommit == 0
                                || isLastBlock)) {
                    if (evaulateOnly) {
                        psCert.clearBatch();
                        psCerthash.clearBatch();
                        psRawCert.clearBatch();
                    } else {
                        String sql = null;
                        try {
                            sql = SQL_ADD_CERT;
                            psCert.executeBatch();

                            sql = SQL_ADD_CHASH;
                            psCerthash.executeBatch();

                            sql = SQL_ADD_CRAW;
                            psRawCert.executeBatch();

                            sql = null;
                            commit("(commit import cert to OCSP)");
                        } catch (Throwable th) {
                            rollback();
                            deleteCertGreatherThan(lastSuccessfulCertId, LOG);
                            if (th instanceof SQLException) {
                                throw translate(sql, (SQLException) th);
                            } else if (th instanceof Exception) {
                                throw (Exception) th;
                            } else {
                                throw new Exception(th);
                            }
                        }
                    }

                    lastSuccessfulCertId = id;
                    processLog.addNumProcessed(numProcessedEntriesInBatch);
                    importLog.addNumProcessed(numImportedEntriesInBatch);
                    numProcessedEntriesInBatch = 0;
                    numImportedEntriesInBatch = 0;
                    String filename = (numProcessedInLastProcess + processLog.numProcessed())
                            + ":" + lastSuccessfulCertId;
                    echoToFile(filename, processLogFile);
                    processLog.printStatus();
                } else if (isLastBlock) {
                    lastSuccessfulCertId = id;
                    processLog.addNumProcessed(numProcessedEntriesInBatch);
                    importLog.addNumProcessed(numImportedEntriesInBatch);
                    numProcessedEntriesInBatch = 0;
                    numImportedEntriesInBatch = 0;
                    String filename = (numProcessedInLastProcess + processLog.numProcessed())
                            + ":" + lastSuccessfulCertId;
                    echoToFile(filename, processLogFile);
                    processLog.printStatus();
                }
                // if (numImportedEntriesInBatch)
            } // end for

            return lastSuccessfulCertId;
        } finally {
            recoverAutoCommit();
            zipFile.close();
        }
    } // method importCert0

}
