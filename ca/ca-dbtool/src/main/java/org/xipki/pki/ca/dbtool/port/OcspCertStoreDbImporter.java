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
import org.xipki.commons.common.util.XMLUtil;
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

    public void importToDB()
    throws Exception {
        CertStoreType certstore;
        try {
            @SuppressWarnings("unchecked")
            JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                    unmarshaller.unmarshal(
                            new File(baseDir + File.separator + FILENAME_OCSP_CertStore));
            certstore = root.getValue();
        } catch (JAXBException e) {
            throw XMLUtil.convert(e);
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
                import_issuer(certstore.getIssuers());
            }
            import_cert(certstore, processLogFile);
            recoverIndexes();
            processLogFile.delete();
        } catch (Exception e) {
            System.err.println("error while importing OCSP certstore to database");
            throw e;
        }
        System.out.println(" imported OCSP certstore to database");
    } // method importToDB

    private void import_issuer(
            final Issuers issuers)
    throws DataAccessException, CertificateException, IOException {
        System.out.println("importing table ISSUER");
        PreparedStatement ps = prepareStatement(SQL_ADD_ISSUER);

        try {
            for (IssuerType issuer : issuers.getIssuer()) {
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
            }
        } finally {
            releaseResources(ps, null);
        }
        System.out.println(" imported table ISSUER");
    } // method import_issuer

    private void import_cert(
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
                    int lastId = do_import_cert(ps_cert, ps_certhash, ps_rawcert, certsFile, minId,
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
            releaseResources(ps_cert, null);
            releaseResources(ps_certhash, null);
            releaseResources(ps_rawcert, null);
            certsFileIterator.close();
        }

        long maxId = getMax("CERT", "ID");
        String seqName = "CID";
        dataSource.dropAndCreateSequence(seqName, maxId + 1);

        processLog.printTrailer();
        echoToFile(MSG_CERTS_FINISHED, processLogFile);
        System.out.println(getImportedText() + processLog.getNumProcessed() + " certificates");
    } // method import_cert

    private int do_import_cert(
            final PreparedStatement ps_cert,
            final PreparedStatement ps_certhash,
            final PreparedStatement ps_rawcert,
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
                    ps_cert.setInt(idx++, id);
                    ps_cert.setInt(idx++, cert.getIid());
                    ps_cert.setLong(idx++, c.getSerialNumber().getPositiveValue().longValue());
                    ps_cert.setLong(idx++, cert.getUpdate());
                    ps_cert.setLong(idx++, c.getStartDate().getDate().getTime() / 1000);
                    ps_cert.setLong(idx++, c.getEndDate().getDate().getTime() / 1000);
                    setBoolean(ps_cert, idx++, cert.getRev().booleanValue());
                    setInt(ps_cert, idx++, cert.getRr());
                    setLong(ps_cert, idx++, cert.getRt());
                    setLong(ps_cert, idx++, cert.getRit());
                    ps_cert.setString(idx++, cert.getProfile());
                    ps_cert.addBatch();
                } catch (SQLException e) {
                    throw translate(SQL_ADD_CERT, e);
                }

                // certhash
                try {
                    int idx = 1;
                    ps_certhash.setInt(idx++, cert.getId());
                    ps_certhash.setString(idx++, sha1(encodedCert));
                    ps_certhash.setString(idx++, sha224(encodedCert));
                    ps_certhash.setString(idx++, sha256(encodedCert));
                    ps_certhash.setString(idx++, sha384(encodedCert));
                    ps_certhash.setString(idx++, sha512(encodedCert));
                    ps_certhash.addBatch();
                } catch (SQLException e) {
                    throw translate(SQL_ADD_CHASH, e);
                }

                // rawcert
                try {
                    int idx = 1;
                    ps_rawcert.setInt(idx++, cert.getId());
                    ps_rawcert.setString(idx++,
                            X509Util.cutX500Name(c.getSubject(), maxX500nameLen));
                    ps_rawcert.setString(idx++, Base64.toBase64String(encodedCert));
                    ps_rawcert.addBatch();
                } catch (SQLException e) {
                    throw translate(SQL_ADD_CRAW, e);
                }

                boolean isLastBlock = !certs.hasNext();

                if (numEntriesInBatch > 0
                        && (numEntriesInBatch % this.numCertsPerCommit == 0 || isLastBlock)) {
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
    } // method do_import_cert

}
