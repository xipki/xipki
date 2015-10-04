/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ConfPairs;
import org.xipki.common.ProcessLog;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.dbtool.InvalidInputException;
import org.xipki.pki.ca.dbtool.jaxb.ca.CAConfigurationType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CaHasPublisherType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CaType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Cas;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertstoreCaType;
import org.xipki.pki.ca.dbtool.jaxb.ca.NameIdType;
import org.xipki.pki.ca.dbtool.jaxb.ca.PublisherType;
import org.xipki.pki.ca.dbtool.xmlio.CaCertType;
import org.xipki.pki.ca.dbtool.xmlio.CaCertsReader;
import org.xipki.security.api.HashAlgoType;
import org.xipki.security.api.HashCalculator;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

class OcspCertStoreFromCaDbImporter extends AbstractOcspCertStoreDbImporter {
    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreFromCaDbImporter.class);

    private final Unmarshaller unmarshaller;
    private final String publisherName;
    private final boolean resume;
    private final int numCertsPerCommit;

    OcspCertStoreFromCaDbImporter(
            final DataSourceWrapper dataSource,
            final Unmarshaller unmarshaller,
            final String srcDir,
            final String publisherName,
            final int numCertsPerCommit,
            final boolean resume,
            final AtomicBoolean stopMe,
            final boolean evaluateOnly)
    throws Exception {
        super(dataSource, srcDir, stopMe, evaluateOnly);
        if (numCertsPerCommit < 1) {
            throw new IllegalArgumentException(
                    "numCertsPerCommit could not be less than 1: " + numCertsPerCommit);
        }
        ParamUtil.assertNotNull("unmarshaller", unmarshaller);
        ParamUtil.assertNotBlank("publisherName", publisherName);
        this.unmarshaller = unmarshaller;
        this.publisherName = publisherName;
        this.numCertsPerCommit = numCertsPerCommit;

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

    public void importToDB()
    throws Exception {
        CertStoreType certstore;
        try {
            @SuppressWarnings("unchecked")
            JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                    unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_CertStore));
            certstore = root.getValue();
        } catch (JAXBException e) {
            throw XMLUtil.convert(e);
        }

        if (certstore.getVersion() > VERSION) {
            throw new InvalidInputException(
                    "could not import CertStore greater than " + VERSION + ": "
                    + certstore.getVersion());
        }

        CAConfigurationType caConf;
        try {
            @SuppressWarnings("unchecked")
            JAXBElement<CAConfigurationType> rootCaConf = (JAXBElement<CAConfigurationType>)
                    unmarshaller.unmarshal(
                            new File(baseDir + File.separator + FILENAME_CA_Configuration));
            caConf = rootCaConf.getValue();
        } catch (JAXBException e) {
            throw XMLUtil.convert(e);
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

            ConfPairs confPairs = new ConfPairs(getValue(publisherType.getConf()));
            String v = confPairs.getValue("publish.goodcerts");
            boolean revokedOnly = false;
            if (v != null) {
                revokedOnly = !Boolean.parseBoolean(v);
            }

            Set<String> relatedCaNames = new HashSet<>();
            for (CaHasPublisherType ctype : caConf.getCaHasPublishers().getCaHasPublisher()) {
                if (ctype.getPublisherName().equals(publisherName)) {
                    relatedCaNames.add(ctype.getCaName());
                }
            }

            List<CaType> relatedCas = new LinkedList<>();
            for (CaType cType : caConf.getCas().getCa()) {
                if (relatedCaNames.contains(cType.getName())) {
                    relatedCas.add(cType);
                }
            }

            if (relatedCas.isEmpty()) {
                System.out.println("No CA has publisher " + publisherName);
                return;
            }

            Map<Integer, String> profileMap = new HashMap<Integer, String>();
            for (NameIdType ni : certstore.getProfiles().getProfile()) {
                profileMap.put(ni.getId(), ni.getName());
            }

            List<Integer> relatedCaIds;
            if (resume) {
                relatedCaIds = getIssuerIds(certstore.getCas(), relatedCas);
            } else {
                relatedCaIds = import_issuer(certstore.getCas(), relatedCas);
            }

            File processLogFile = new File(baseDir, DbPorter.IMPORT_TO_OCSP_PROCESS_LOG_FILENAME);
            import_cert(certstore, profileMap, revokedOnly, relatedCaIds, processLogFile);
            recoverIndexes();
            processLogFile.delete();
        } catch (Exception e) {
            System.err.println("error while importing OCSP certstore to database");
            throw e;
        }
        System.out.println(" imported OCSP certstore to database");
    }

    private List<Integer> getIssuerIds(
            final Cas issuers,
            final List<CaType> cas)
    throws IOException {
        List<Integer> relatedCaIds = new LinkedList<>();
        for (CertstoreCaType issuer : issuers.getCa()) {
            String b64Cert = getValue(issuer.getCert());
            byte[] encodedCert = Base64.decode(b64Cert);

            // retrieve the revocation information of the CA, if possible
            CaType ca = null;
            for (CaType caType : cas) {
                if (Arrays.equals(encodedCert, Base64.decode(getValue(caType.getCert())))) {
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

    private List<Integer> import_issuer(
            final Cas issuers,
            final List<CaType> cas)
    throws DataAccessException, CertificateException, IOException {
        System.out.println("importing table ISSUER");
        final String sql = SQL_ADD_ISSUER;
        PreparedStatement ps = prepareStatement(sql);

        List<Integer> relatedCaIds = new LinkedList<>();

        try {
            for (CertstoreCaType issuer : issuers.getCa()) {
                try {
                    String b64Cert = getValue(issuer.getCert());
                    byte[] encodedCert = Base64.decode(b64Cert);

                    // retrieve the revocation information of the CA, if possible
                    CaType ca = null;
                    for (CaType caType : cas) {
                        if (Arrays.equals(encodedCert, Base64.decode(getValue(caType.getCert())))) {
                            ca = caType;
                            break;
                        }
                    }

                    if (ca == null) {
                        continue;
                    }

                    relatedCaIds.add(issuer.getId());

                    Certificate c;
                    byte[] encodedName;
                    try {
                        c = Certificate.getInstance(encodedCert);
                        encodedName = c.getSubject().getEncoded("DER");
                    } catch (Exception e) {
                        LOG.error("could not parse certificate of issuer {}", issuer.getId());
                        LOG.debug("could not parse certificate of issuer " + issuer.getId(), e);
                        if (e instanceof CertificateException) {
                            throw (CertificateException) e;
                        } else {
                            throw new CertificateException(e.getMessage(), e);
                        }
                    }
                    byte[] encodedKey = c.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

                    int idx = 1;
                    ps.setInt(idx++, issuer.getId());
                    ps.setString(idx++,
                            X509Util.cutX500Name(c.getSubject(), maxX500nameLen));
                    ps.setLong(idx++,
                            c.getTBSCertificate().getStartDate().getDate().getTime() / 1000);
                    ps.setLong(idx++,
                            c.getTBSCertificate().getEndDate().getDate().getTime() / 1000);
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA1, encodedName));
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA1, encodedKey));
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA224, encodedName));
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA224, encodedKey));
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA256, encodedName));
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA256, encodedKey));
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA384, encodedName));
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA384, encodedKey));
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA512, encodedName));
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA512, encodedKey));
                    ps.setString(idx++,
                            HashCalculator.base64Hash(HashAlgoType.SHA1, encodedCert));
                    ps.setString(idx++, b64Cert);

                    setBoolean(ps, idx++, ca.isRevoked());
                    setInt(ps, idx++, ca.getRevReason());
                    setLong(ps, idx++, ca.getRevTime());
                    setLong(ps, idx++, ca.getRevInvTime());

                    ps.execute();
                } catch (SQLException e) {
                    System.err.println("error while importing issuer with id=" + issuer.getId());
                    throw translate(sql, e);
                } catch (CertificateException e) {
                    System.err.println("error while importing issuer with id=" + issuer.getId());
                    throw e;
                }
            }
        } finally {
            releaseResources(ps, null);
        }

        System.out.println(" imported table ISSUER");
        return relatedCaIds;
    }

    private void import_cert(
            final CertStoreType certstore,
            final Map<Integer, String> profileMap,
            final boolean revokedOnly,
            final List<Integer> caIds,
            final File processLogFile)
    throws Exception {
        int numProcessedBefore = 0;
        int minId = 1;
        if (processLogFile.exists()) {
            byte[] content = IoUtil.read(processLogFile);
            if (content != null && content.length > 2) {
                String str = new String(content);
                if (str.trim().equalsIgnoreCase(MSG_CERTS_FINISHED)) {
                    return;
                }

                StringTokenizer st = new StringTokenizer(str, ":");
                numProcessedBefore = Integer.parseInt(st.nextToken());
                minId = Integer.parseInt(st.nextToken());
                minId++;
            }
        }

        deleteCertGreatherThan(minId - 1, LOG);

        final long total = certstore.getCountCerts() - numProcessedBefore;
        final ProcessLog processLog = new ProcessLog(total);
        // all initial values for importLog will be not evaluated, so just any number
        final ProcessLog importLog = new ProcessLog(total);

        System.out.println(getImportingText() + "certificates from ID " + minId);
        processLog.printHeader();

        PreparedStatement ps_cert = prepareStatement(SQL_ADD_CERT);
        PreparedStatement ps_certhash = prepareStatement(SQL_ADD_CHASH);
        PreparedStatement ps_rawcert = prepareStatement(SQL_ADD_CRAW);

        DbPortFileNameIterator certsFileIterator = new DbPortFileNameIterator(certsListFile);
        try {
            while (certsFileIterator.hasNext()) {
                String certsFile = certsDir + File.separator + certsFileIterator.next();
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
                    } catch (Exception e) {
                        LOG.warn("invalid file name '{}', but will still be processed", certsFile);
                    }
                } else {
                    LOG.warn("invalid file name '{}', but will still be processed", certsFile);
                }

                try {
                    int lastId = do_import_cert(ps_cert, ps_certhash, ps_rawcert,
                            certsFile, profileMap, revokedOnly, caIds, minId,
                            processLogFile, processLog, numProcessedBefore, importLog);
                    minId = lastId + 1;
                } catch (Exception e) {
                    System.err.println("\nerror while importing certificates from file "
                            + certsFile + ".\nplease continue with the option '--resume'");
                    LOG.error("Exception", e);
                    throw e;
                }
            }
        } finally {
            releaseResources(ps_cert, null);
            releaseResources(ps_certhash, null);
            releaseResources(ps_rawcert, null);
            certsFileIterator.close();
        }

        processLog.printTrailer();
        DbPorter.echoToFile(MSG_CERTS_FINISHED, processLogFile);
        System.out.println("processed " + processLog.getNumProcessed() + " and "
                + getImportedText() + importLog.getNumProcessed() + " certificates");
    }

    private int do_import_cert(
            final PreparedStatement ps_cert,
            final PreparedStatement ps_certhash,
            final PreparedStatement ps_rawcert,
            final String certsZipFile,
            final Map<Integer, String> profileMap,
            final boolean revokedOnly,
            final List<Integer> caIds,
            final int minId,
            final File processLogFile,
            final ProcessLog processLog,
            final int numProcessedInLastProcess,
            final ProcessLog importLog)
    throws Exception {
        ZipFile zipFile = new ZipFile(new File(certsZipFile));
        ZipEntry certsXmlEntry = zipFile.getEntry("certs.xml");

        CaCertsReader certs;
        try {
            certs = new CaCertsReader(zipFile.getInputStream(certsXmlEntry));
        } catch (Exception e) {
            try {
                zipFile.close();
            } catch (Exception e2) {
            }
            throw e;
        }

        disableAutoCommit();

        try {
            int numProcessedEntriesInBatch = 0;
            int numImportedEntriesInBatch = 0;
            int lastSuccessfulCertId = 0;

            while (certs.hasNext()) {
                if (stopMe.get()) {
                    throw new InterruptedException("interrupted by the user");
                }

                CaCertType cert = (CaCertType) certs.next();

                int id = cert.getId();
                lastSuccessfulCertId = id;
                if (id < minId) {
                    continue;
                }

                numProcessedEntriesInBatch++;

                if (!revokedOnly || cert.getRev().booleanValue()) {
                    int caId = cert.getCaId();
                    if (caIds.contains(caId)) {
                        numImportedEntriesInBatch++;

                        String filename = cert.getFile();

                        // rawcert
                        ZipEntry certZipEnty = zipFile.getEntry(filename);
                        // rawcert
                        byte[] encodedCert = IoUtil.read(zipFile.getInputStream(certZipEnty));

                        TBSCertificate c;
                        try {
                            Certificate cc = Certificate.getInstance(encodedCert);
                            c = cc.getTBSCertificate();
                        } catch (Exception e) {
                            LOG.error("could not parse certificate in file {}", filename);
                            LOG.debug("could not parse certificate in file " + filename, e);
                            if (e instanceof CertificateException) {
                                throw (CertificateException) e;
                            } else {
                                throw new CertificateException(e.getMessage(), e);
                            }
                        }

                        // cert
                        String seqName = "CID";
                        int currentId = (int) dataSource.nextSeqValue(null, seqName);

                        try {
                            int idx = 1;
                            ps_cert.setInt(idx++, currentId);
                            ps_cert.setInt(idx++, caId);
                            ps_cert.setLong(idx++,
                                    c.getSerialNumber().getPositiveValue().longValue());
                            ps_cert.setLong(idx++, cert.getUpdate());
                            ps_cert.setLong(idx++, c.getStartDate().getDate().getTime() / 1000);
                            ps_cert.setLong(idx++, c.getEndDate().getDate().getTime() / 1000);
                            setBoolean(ps_cert, idx++, cert.getRev());
                            setInt(ps_cert, idx++, cert.getRr());
                            setLong(ps_cert, idx++, cert.getRt());
                            setLong(ps_cert, idx++, cert.getRit());

                            int certprofileId = cert.getPid();
                            String certprofileName = profileMap.get(certprofileId);
                            ps_cert.setString(idx++, certprofileName);
                            ps_cert.addBatch();
                        } catch (SQLException e) {
                            throw translate(SQL_ADD_CERT, e);
                        }

                        // certhash
                        try {
                            int idx = 1;
                            ps_certhash.setInt(idx++, currentId);
                            ps_certhash.setString(idx++,
                                    HashCalculator.base64Hash(HashAlgoType.SHA1, encodedCert));
                            ps_certhash.setString(idx++,
                                    HashCalculator.base64Hash(HashAlgoType.SHA224, encodedCert));
                            ps_certhash.setString(idx++,
                                    HashCalculator.base64Hash(HashAlgoType.SHA256, encodedCert));
                            ps_certhash.setString(idx++,
                                    HashCalculator.base64Hash(HashAlgoType.SHA384, encodedCert));
                            ps_certhash.setString(idx++,
                                    HashCalculator.base64Hash(HashAlgoType.SHA512, encodedCert));
                            ps_certhash.addBatch();
                        } catch (SQLException e) {
                            throw translate(SQL_ADD_CHASH, e);
                        }

                        // rawcert
                        try {
                            int idx = 1;
                            ps_rawcert.setInt(idx++, currentId);
                            ps_rawcert.setString(idx++,
                                    X509Util.cutX500Name(c.getSubject(), maxX500nameLen));
                            ps_rawcert.setString(idx++, Base64.toBase64String(encodedCert));
                            ps_rawcert.addBatch();
                        } catch (SQLException e) {
                            throw translate(SQL_ADD_CRAW, e);
                        }
                    } // end if (caIds.contains(caId))
                } // end if (revokedOnly

                boolean isLastBlock = !certs.hasNext();

                if (numImportedEntriesInBatch > 0
                        && (numImportedEntriesInBatch % this.numCertsPerCommit == 0
                                || isLastBlock)) {
                    if (evaulateOnly) {
                        ps_cert.clearBatch();
                        ps_certhash.clearBatch();
                        ps_rawcert.clearBatch();
                    } else {
                        String sql = null;
                        try {
                            sql = SQL_ADD_CERT;
                            ps_cert.executeBatch();

                            sql = SQL_ADD_CHASH;
                            ps_certhash.executeBatch();

                            sql = SQL_ADD_CRAW;
                            ps_rawcert.executeBatch();

                            sql = null;
                            commit("(commit import cert to OCSP)");
                        } catch (Throwable t) {
                            rollback();
                            deleteCertGreatherThan(lastSuccessfulCertId, LOG);
                            if (t instanceof SQLException) {
                                throw translate(sql, (SQLException) t);
                            } else if (t instanceof Exception) {
                                throw (Exception) t;
                            } else {
                                throw new Exception(t);
                            }
                        }
                    }

                    lastSuccessfulCertId = id;
                    processLog.addNumProcessed(numProcessedEntriesInBatch);
                    importLog.addNumProcessed(numImportedEntriesInBatch);
                    numProcessedEntriesInBatch = 0;
                    numImportedEntriesInBatch = 0;
                    echoToFile(
                            (numProcessedInLastProcess + processLog.getNumProcessed())
                            + ":" + lastSuccessfulCertId,
                            processLogFile);
                    processLog.printStatus();
                } else if (isLastBlock) {
                    lastSuccessfulCertId = id;
                    processLog.addNumProcessed(numProcessedEntriesInBatch);
                    importLog.addNumProcessed(numImportedEntriesInBatch);
                    numProcessedEntriesInBatch = 0;
                    numImportedEntriesInBatch = 0;
                    echoToFile(
                            (numProcessedInLastProcess + processLog.getNumProcessed())
                            + ":" + lastSuccessfulCertId,
                            processLogFile);
                    processLog.printStatus();
                }
                // if (numImportedEntriesInBatch
            } // end for

            return lastSuccessfulCertId;
        }
        finally {
            try {
                recoverAutoCommit();
            } catch (DataAccessException e) {
            }
            zipFile.close();
        }
    }

}
