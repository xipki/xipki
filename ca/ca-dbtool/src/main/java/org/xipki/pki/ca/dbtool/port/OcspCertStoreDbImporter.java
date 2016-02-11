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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
import org.xipki.commons.common.ProcessLog;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.XmlUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.dbtool.jaxb.ocsp.CertStoreType;
import org.xipki.pki.ca.dbtool.jaxb.ocsp.CertStoreType.Issuers;
import org.xipki.pki.ca.dbtool.jaxb.ocsp.IssuerType;
import org.xipki.pki.ca.dbtool.xmlio.OcspCertType;
import org.xipki.pki.ca.dbtool.xmlio.OcspCertsReader;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class OcspCertStoreDbImporter extends AbstractOcspCertStoreDbImporter {

    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreDbImporter.class);

    private final Unmarshaller unmarshaller;

    private final boolean resume;

    private final int numCertsPerCommit;

    OcspCertStoreDbImporter(
            final DataSourceWrapper dataSource,
            final Unmarshaller unmarshaller,
            final String srcDir,
            final int numCertsPerCommit,
            final boolean resume,
            final AtomicBoolean stopMe,
            final boolean evaluateOnly)
    throws Exception {
        super(dataSource, srcDir, stopMe, evaluateOnly);
        if (numCertsPerCommit < 1) {
            throw new IllegalArgumentException("numCertsPerCommit could not be less than 1: "
                    + numCertsPerCommit);
        }
        ParamUtil.assertNotNull("unmarshaller", unmarshaller);
        this.unmarshaller = unmarshaller;
        this.numCertsPerCommit = numCertsPerCommit;
        File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
        if (resume) {
            if (!processLogFile.exists()) {
                throw new Exception("could not process with '--resume' option");
            }
        } else {
            if (processLogFile.exists()) {
                throw new Exception("please either specify '--resume' option or delete the file "
                        + processLogFile.getPath() + " first");
            }
        }
        this.resume = resume;
    }

    public void importToDb()
    throws Exception {
        CertStoreType certstore;
        try {
            @SuppressWarnings("unchecked")
            JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                    unmarshaller.unmarshal(
                            new File(baseDir + File.separator + FILENAME_OCSP_CERTSTORE));
            certstore = root.getValue();
        } catch (JAXBException e) {
            throw XmlUtil.convert(e);
        }

        if (certstore.getVersion() > VERSION) {
            throw new Exception("could not import CertStore greater than " + VERSION + ": "
                    + certstore.getVersion());
        }

        File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
        System.out.println("importing OCSP certstore to database");
        try {
            if (!resume) {
                dropIndexes();
                importIssuer(certstore.getIssuers());
            }
            importCert(certstore, processLogFile);
            recoverIndexes();
            processLogFile.delete();
        } catch (Exception e) {
            System.err.println("error while importing OCSP certstore to database");
            throw e;
        }
        System.out.println(" imported OCSP certstore to database");
    } // method importToDB

    private void importIssuer(
            final Issuers issuers)
    throws DataAccessException, CertificateException, IOException {
        System.out.println("importing table ISSUER");
        PreparedStatement ps = prepareStatement(SQL_ADD_ISSUER);

        try {
            for (IssuerType issuer : issuers.getIssuer()) {
                doImportIssuer(issuer, ps);
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table ISSUER");
    }

    private void doImportIssuer(
            final IssuerType issuer,
            final PreparedStatement ps)
    throws DataAccessException, CertificateException, IOException {
        try {
            String certFilename = issuer.getCertFile();
            String b64Cert = new String(
                    IoUtil.read(new File(baseDir, certFilename)));
            byte[] encodedCert = Base64.decode(b64Cert);

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
            ps.setString(idx++, X509Util.cutX500Name(c.getSubject(), maxX500nameLen));
            ps.setLong(idx++,
                    c.getTBSCertificate().getStartDate().getDate().getTime() / 1000);
            ps.setLong(idx++,
                    c.getTBSCertificate().getEndDate().getDate().getTime() / 1000);
            ps.setString(idx++, sha1(encodedName));
            ps.setString(idx++, sha1(encodedKey));
            ps.setString(idx++, sha224(encodedName));
            ps.setString(idx++, sha224(encodedKey));
            ps.setString(idx++, sha256(encodedName));
            ps.setString(idx++, sha256(encodedKey));
            ps.setString(idx++, sha384(encodedName));
            ps.setString(idx++, sha384(encodedKey));
            ps.setString(idx++, sha512(encodedName));
            ps.setString(idx++, sha512(encodedKey));
            ps.setString(idx++, sha1(encodedCert));
            ps.setString(idx++, b64Cert);
            setBoolean(ps, idx++, issuer.isRevoked());
            setInt(ps, idx++, issuer.getRevReason());
            setLong(ps, idx++, issuer.getRevTime());
            setLong(ps, idx++, issuer.getRevInvTime());

            ps.execute();
        } catch (SQLException e) {
            System.err.println("error while importing issuer with id=" + issuer.getId());
            throw translate(SQL_ADD_ISSUER, e);
        } catch (CertificateException e) {
            System.err.println("error while importing issuer with id=" + issuer.getId());
            throw e;
        }
    }  // method doImportIssuer

    private void importCert(
            final CertStoreType certstore,
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

        System.out.println(getImportingText() + "certificates from ID " + minId);
        processLog.printHeader();

        PreparedStatement psCert = prepareStatement(SQL_ADD_CERT);
        PreparedStatement psCerthash = prepareStatement(SQL_ADD_CHASH);
        PreparedStatement psRawcert = prepareStatement(SQL_ADD_CRAW);

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
                    int lastId = doImportCert(psCert, psCerthash, psRawcert, certsFile, minId,
                            processLogFile, processLog, numProcessedBefore);
                    minId = lastId + 1;
                } catch (Exception e) {
                    System.err.println("\nerror while importing certificates from file "
                            + certsFile + ".\nplease continue with the option '--resume'");
                    LOG.error("Exception", e);
                    throw e;
                }
            } // end for
        } finally {
            releaseResources(psCert, null);
            releaseResources(psCerthash, null);
            releaseResources(psRawcert, null);
            certsFileIterator.close();
        }

        long maxId = getMax("CERT", "ID");
        String seqName = "CID";
        dataSource.dropAndCreateSequence(seqName, maxId + 1);

        processLog.printTrailer();
        echoToFile(MSG_CERTS_FINISHED, processLogFile);
        System.out.println(getImportedText() + processLog.getNumProcessed() + " certificates");
    } // method importCert

    private int doImportCert(
            final PreparedStatement psCert,
            final PreparedStatement psCerthash,
            final PreparedStatement psRawcert,
            final String certsZipFile,
            final int minId,
            final File processLogFile,
            final ProcessLog processLog,
            final int numProcessedInLastProcess)
    throws Exception {
        ZipFile zipFile = new ZipFile(new File(certsZipFile));
        ZipEntry certsXmlEntry = zipFile.getEntry("certs.xml");

        OcspCertsReader certs;
        try {
            certs = new OcspCertsReader(zipFile.getInputStream(certsXmlEntry));
        } catch (Exception e) {
            try {
                zipFile.close();
            } catch (Exception e2) {
            }
            throw e;
        }

        disableAutoCommit();

        try {
            int numEntriesInBatch = 0;
            int lastSuccessfulCertId = 0;

            while (certs.hasNext()) {
                if (stopMe.get()) {
                    throw new InterruptedException("interrupted by the user");
                }

                OcspCertType cert = (OcspCertType) certs.next();

                int id = cert.getId();
                if (id < minId) {
                    continue;
                }

                numEntriesInBatch++;

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
                try {
                    int idx = 1;
                    psCert.setInt(idx++, id);
                    psCert.setInt(idx++, cert.getIid());
                    psCert.setLong(idx++, c.getSerialNumber().getPositiveValue().longValue());
                    psCert.setLong(idx++, cert.getUpdate());
                    psCert.setLong(idx++, c.getStartDate().getDate().getTime() / 1000);
                    psCert.setLong(idx++, c.getEndDate().getDate().getTime() / 1000);
                    setBoolean(psCert, idx++, cert.getRev().booleanValue());
                    setInt(psCert, idx++, cert.getRr());
                    setLong(psCert, idx++, cert.getRt());
                    setLong(psCert, idx++, cert.getRit());
                    psCert.setString(idx++, cert.getProfile());
                    psCert.addBatch();
                } catch (SQLException e) {
                    throw translate(SQL_ADD_CERT, e);
                }

                // certhash
                try {
                    int idx = 1;
                    psCerthash.setInt(idx++, cert.getId());
                    psCerthash.setString(idx++, sha1(encodedCert));
                    psCerthash.setString(idx++, sha224(encodedCert));
                    psCerthash.setString(idx++, sha256(encodedCert));
                    psCerthash.setString(idx++, sha384(encodedCert));
                    psCerthash.setString(idx++, sha512(encodedCert));
                    psCerthash.addBatch();
                } catch (SQLException e) {
                    throw translate(SQL_ADD_CHASH, e);
                }

                // rawcert
                try {
                    int idx = 1;
                    psRawcert.setInt(idx++, cert.getId());
                    psRawcert.setString(idx++,
                            X509Util.cutX500Name(c.getSubject(), maxX500nameLen));
                    psRawcert.setString(idx++, Base64.toBase64String(encodedCert));
                    psRawcert.addBatch();
                } catch (SQLException e) {
                    throw translate(SQL_ADD_CRAW, e);
                }

                boolean isLastBlock = !certs.hasNext();

                if (numEntriesInBatch > 0
                        && (numEntriesInBatch % this.numCertsPerCommit == 0 || isLastBlock)) {
                    if (evaulateOnly) {
                        psCert.clearBatch();
                        psCerthash.clearBatch();
                        psRawcert.clearBatch();
                    } else {
                        String sql = null;
                        try {
                            sql = SQL_ADD_CERT;
                            psCert.executeBatch();

                            sql = SQL_ADD_CHASH;
                            psCerthash.executeBatch();

                            sql = SQL_ADD_CRAW;
                            psRawcert.executeBatch();

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
                    processLog.addNumProcessed(numEntriesInBatch);
                    numEntriesInBatch = 0;
                    echoToFile((numProcessedInLastProcess + processLog.getNumProcessed())
                            + ":" + lastSuccessfulCertId,
                            processLogFile);
                    processLog.printStatus();
                }
            } // end for

            return lastSuccessfulCertId;
        } finally {
            try {
                recoverAutoCommit();
            } catch (DataAccessException e) {
            }
            zipFile.close();
        }
    } // method doImportCert

}
