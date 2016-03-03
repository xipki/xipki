/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ProcessLog;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.common.util.XmlUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;
import org.xipki.commons.security.api.FpIdCalculator;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Cas;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.DeltaCRLCache;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Profiles;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.PublishQueue;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Publishers;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Requestors;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertstoreCaType;
import org.xipki.pki.ca.dbtool.jaxb.ca.DeltaCRLCacheEntryType;
import org.xipki.pki.ca.dbtool.jaxb.ca.NameIdType;
import org.xipki.pki.ca.dbtool.jaxb.ca.ToPublishType;
import org.xipki.pki.ca.dbtool.xmlio.CaCertType;
import org.xipki.pki.ca.dbtool.xmlio.CaCertsReader;
import org.xipki.pki.ca.dbtool.xmlio.CaCrlType;
import org.xipki.pki.ca.dbtool.xmlio.CaCrlsReader;
import org.xipki.pki.ca.dbtool.xmlio.CaUserType;
import org.xipki.pki.ca.dbtool.xmlio.CaUsersReader;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaCertStoreDbImporter extends AbstractCaCertStoreDbPorter {

    private static final Logger LOG = LoggerFactory.getLogger(CaConfigurationDbImporter.class);

    private static final String SQL_ADD_CERT =
            "INSERT INTO CERT "
            + "(ID, ART, LUPDATE, SN, SUBJECT, FP_S, FP_RS," // 8
            + " NBEFORE, NAFTER, REV, RR, RT, RIT, PID, CA_ID," // 8
            + " RID, UNAME, FP_K, EE, RTYPE, TID)" + // 6
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SQL_ADD_CRAW =
            "INSERT INTO CRAW (CID, SHA1, REQ_SUBJECT, CERT) VALUES (?, ?, ?, ?)";

    private static final String SQL_ADD_CRL =
            "INSERT INTO CRL (ID, CA_ID, CRL_NO, THISUPDATE, NEXTUPDATE, DELTACRL, BASECRL_NO, CRL)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SQL_ADD_USER =
            "INSERT INTO USERNAME (ID, NAME, PASSWORD,CN_REGEX) VALUES (?, ?, ?, ?)";

    private final Unmarshaller unmarshaller;

    private final boolean resume;

    private final int numCertsPerCommit;

    private final int numUsersPerCommit;

    private final int numCrlsPerCommit;

    CaCertStoreDbImporter(
            final DataSourceWrapper dataSource,
            final Unmarshaller unmarshaller,
            final String srcDir,
            final int numCertsPerCommit,
            final boolean resume,
            final AtomicBoolean stopMe,
            final boolean evaluateOnly)
    throws Exception {
        super(dataSource, srcDir, stopMe, evaluateOnly);

        this.unmarshaller = ParamUtil.requireNonNull("unmarshaller", unmarshaller);
        this.numCertsPerCommit = ParamUtil.requireMin("numCertsPerCommit", numCertsPerCommit, 1);
        this.numUsersPerCommit = numCertsPerCommit * 10;
        this.numCrlsPerCommit = Math.max(1, numCertsPerCommit / 10);
        this.resume = resume;

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
    }

    public void importToDb()
    throws Exception {
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
            throw new Exception("could not import CertStore greater than " + VERSION + ": "
                    + certstore.getVersion());
        }

        File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
        System.out.println("importing CA certstore to database");
        try {
            if (!resume) {
                dropIndexes();

                importCa(certstore.getCas());
                importRequestor(certstore.getRequestors());
                importPublisher(certstore.getPublishers());
                importProfile(certstore.getProfiles());
                importUser(certstore);
                importCrl(certstore);
            }

            importCert(certstore, processLogFile);

            importPublishQueue(certstore.getPublishQueue());
            importDeltaCrlCache(certstore.getDeltaCRLCache());

            recoverIndexes();
            processLogFile.delete();
        } catch (Exception ex) {
            System.err.println("error while importing CA certstore to database");
            throw ex;
        }
        System.out.println(" imported CA certstore to database");
    } // method importToDb

    private void importCa(
            final Cas cas)
    throws DataAccessException, CertificateException, IOException {
        final String sql = "INSERT INTO CS_CA (ID, SUBJECT, SHA1_CERT, CERT) VALUES (?, ?, ?, ?)";
        System.out.println("importing table CS_CA");
        PreparedStatement ps = prepareStatement(sql);

        try {
            for (CertstoreCaType m : cas.getCa()) {
                try {
                    String b64Cert = getValue(m.getCert());
                    byte[] encodedCert = Base64.decode(b64Cert);
                    Certificate c = Certificate.getInstance(encodedCert);
                    String b64Sha1FpCert = HashCalculator.base64Sha1(encodedCert);

                    int idx = 1;
                    ps.setInt(idx++, m.getId());
                    ps.setString(idx++, X509Util.cutX500Name(c.getSubject(), maxX500nameLen));
                    ps.setString(idx++, b64Sha1FpCert);
                    ps.setString(idx++, b64Cert);

                    ps.execute();
                } catch (SQLException ex) {
                    System.err.println("error while importing CS_CA with ID=" + m.getId()
                        + ", message: " + ex.getMessage());
                    throw translate(sql, ex);
                } catch (IllegalArgumentException | IOException ex) {
                    System.err.println("error while importing CS_CA with ID=" + m.getId()
                        + ", message: " + ex.getMessage());
                    throw ex;
                }
            }
        } finally {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CS_CA");
    } // method importCa

    private void importRequestor(
            final Requestors requestors)
    throws DataAccessException {
        final String sql = "INSERT INTO CS_REQUESTOR (ID, NAME) VALUES (?, ?)";
        System.out.println("importing table CS_REQUESTOR");

        PreparedStatement ps = prepareStatement(sql);

        try {
            for (NameIdType m : requestors.getRequestor()) {
                try {
                    String name = m.getName();

                    int idx = 1;
                    ps.setInt(idx++, m.getId());
                    ps.setString(idx++, name);

                    ps.execute();
                } catch (SQLException ex) {
                    System.err.println("error while importing CS_REQUESTOR with ID=" + m.getId()
                            + ", message: " + ex.getMessage());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CS_REQUESTOR");
    } // method importRequestor

    private void importPublisher(
            final Publishers publishers)
    throws DataAccessException {
        final String sql = "INSERT INTO CS_PUBLISHER (ID, NAME) VALUES (?, ?)";

        System.out.println("importing table CS_PUBLISHER");

        PreparedStatement ps = prepareStatement(sql);

        try {
            for (NameIdType m : publishers.getPublisher()) {
                try {
                    String name = m.getName();

                    int idx = 1;
                    ps.setInt(idx++, m.getId());
                    ps.setString(idx++, name);

                    ps.execute();
                } catch (SQLException ex) {
                    System.err.println("error while importing CS_PUBLISHER with ID=" + m.getId()
                            + ", message: " + ex.getMessage());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CS_PUBLISHER");
    } // method importPublisher

    private void importProfile(
            final Profiles profiles)
    throws DataAccessException {
        final String sql = "INSERT INTO CS_PROFILE (ID, NAME) VALUES (?, ?)";
        System.out.println("importing table CS_PROFILE");

        PreparedStatement ps = prepareStatement(sql);

        try {
            for (NameIdType m : profiles.getProfile()) {
                try {
                    int idx = 1;
                    ps.setInt(idx++, m.getId());
                    ps.setString(idx++, m.getName());

                    ps.execute();
                } catch (SQLException ex) {
                    System.err.println("error while importing CS_PROFILE with ID=" + m.getId()
                            + ", message: " + ex.getMessage());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CS_PROFILE");
    } // method importProfile

    private void importUser(
            final CertStoreType certstore)
    throws Exception {
        System.out.println(getImportingText() + "table USERNAME");

        PreparedStatement ps = prepareStatement(SQL_ADD_USER);

        ProcessLog processLog = new ProcessLog(certstore.getCountUsers());
        System.out.println(getImportingText() + "users from ID 1");
        processLog.printHeader();

        DbPortFileNameIterator usersFileIterator = new DbPortFileNameIterator(usersListFile);

        int sum = 0;
        try {
            while (usersFileIterator.hasNext()) {
                String file = usersDir + File.separator + usersFileIterator.next();

                try {
                    sum += doImportUser(ps, file, processLog);
                } catch (SQLException ex) {
                    System.err.println("error while importing users from file " + file);
                    throw translate(SQL_ADD_USER, ex);
                } catch (Exception ex) {
                    System.err.println("error while importing users from file " + file);
                    throw ex;
                }
            }
        } finally {
            releaseResources(ps, null);
            usersFileIterator.close();
        }

        processLog.printTrailer();
        System.out.println(getImportedText() + sum + " users");
        System.out.println(getImportedText() + "table USERNAME");
    } // method importUser

    private int doImportUser(
            final PreparedStatement psAdduser,
            final String usersZipFile,
            final ProcessLog processLog)
    throws Exception {
        final int numEntriesPerCommit = numUsersPerCommit;

        ZipFile zipFile = new ZipFile(new File(usersZipFile));
        ZipEntry usersXmlEntry = zipFile.getEntry("users.xml");

        CaUsersReader users;
        try {
            users = new CaUsersReader(zipFile.getInputStream(usersXmlEntry));
        } catch (Exception ex) {
            try {
                zipFile.close();
            } catch (Exception e2) {
            }
            throw ex;
        }

        int numProcessed = 0;
        int numEntriesInBatch = 0;

        disableAutoCommit();

        try {
            while (users.hasNext()) {
                if (stopMe.get()) {
                    throw new InterruptedException("interrupted by the user");
                }

                CaUserType user = (CaUserType) users.next();

                numEntriesInBatch++;
                try {
                    int idx = 1;
                    psAdduser.setInt(idx++, user.getId());
                    psAdduser.setString(idx++, user.getName());
                    psAdduser.setString(idx++, user.getPassword());
                    psAdduser.setString(idx++, user.getCnRegex());
                    psAdduser.addBatch();
                } catch (SQLException ex) {
                    System.err.println("error while importing USERNAME with ID="
                            + user.getId() + ", message: " + ex.getMessage());
                    throw ex;
                }

                boolean isLastBlock = !users.hasNext();

                if (numEntriesInBatch > 0
                        && (numEntriesInBatch % numEntriesPerCommit == 0 || isLastBlock)) {
                    if (evaulateOnly) {
                        psAdduser.clearBatch();
                    } else {
                        String sql = null;
                        try {
                            sql = SQL_ADD_USER;
                            psAdduser.executeBatch();

                            sql = null;
                            commit("(commit import user to CA)");
                        } catch (SQLException ex) {
                            rollback();
                            throw translate(sql, ex);
                        } catch (DataAccessException ex) {
                            rollback();
                            throw ex;
                        }
                    }

                    processLog.addNumProcessed(numEntriesInBatch);
                    numProcessed += numEntriesInBatch;
                    numEntriesInBatch = 0;
                    processLog.printStatus();
                }
            }
            return numProcessed;
        } finally {
            try {
                recoverAutoCommit();
            } catch (DataAccessException ex) {
            }
            zipFile.close();
        }
    } // method doImportUser

    private void importPublishQueue(
            final PublishQueue publishQueue)
    throws DataAccessException {
        final String sql = "INSERT INTO PUBLISHQUEUE (CID, PID, CA_ID) VALUES (?, ?, ?)";
        System.out.println("importing table PUBLISHQUEUE");
        PreparedStatement ps = prepareStatement(sql);

        try {
            for (ToPublishType tbp : publishQueue.getTop()) {
                try {
                    int idx = 1;
                    ps.setInt(idx++, tbp.getCertId());
                    ps.setInt(idx++, tbp.getPubId());
                    ps.setInt(idx++, tbp.getCaId());
                    ps.execute();
                } catch (SQLException ex) {
                    System.err.println("error while importing PUBLISHQUEUE with CID="
                            + tbp.getCertId()
                            + " and PID=" + tbp.getPubId() + ", message: " + ex.getMessage());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }

        System.out.println(" imported table PUBLISHQUEUE");
    } // method importPublishQueue

    private void importDeltaCrlCache(
            final DeltaCRLCache deltaCRLCache)
    throws DataAccessException {
        final String sql = "INSERT INTO DELTACRL_CACHE (ID, SN, CA_ID) VALUES (?, ?, ?)";
        System.out.println("importing table DELTACRL_CACHE");
        PreparedStatement ps = prepareStatement(sql);

        try {
            long id = 1;
            for (DeltaCRLCacheEntryType entry : deltaCRLCache.getEntry()) {
                try {
                    int idx = 1;
                    ps.setLong(idx++, id++);
                    ps.setLong(idx++, entry.getSerial());
                    ps.setInt(idx++, entry.getCaId());
                    ps.execute();
                } catch (SQLException ex) {
                    System.err.println("error while importing DELTACRL_CACHE with caId="
                            + entry.getCaId() + " and serial=" + entry.getSerial()
                            + ", message: " + ex.getMessage());
                    throw translate(sql, ex);
                }
            }
        } finally {
            releaseResources(ps, null);
        }

        long maxId = getMax("DELTACRL_CACHE", "ID");
        dataSource.dropAndCreateSequence("DCC_ID", maxId + 1);

        System.out.println(" imported table DELTACRL_CACHE");
    } // method importDeltaCRLCache

    private void importCrl(
            final CertStoreType certstore)
    throws Exception {
        System.out.println(getImportingText() + "table CRL");

        PreparedStatement ps = prepareStatement(SQL_ADD_CRL);

        ProcessLog processLog = new ProcessLog(certstore.getCountCrls());
        System.out.println(getImportingText() + "CRLs from ID 1");
        processLog.printHeader();

        DbPortFileNameIterator crlsFileIterator = new DbPortFileNameIterator(crlsListFile);

        int sum = 0;
        try {
            while (crlsFileIterator.hasNext()) {
                String file = crlsDir + File.separator + crlsFileIterator.next();

                try {
                    sum += doImportCrl(ps, file, processLog);
                } catch (SQLException ex) {
                    System.err.println("error while importing CRLs from file " + file);
                    throw translate(SQL_ADD_USER, ex);
                } catch (JAXBException ex) {
                    System.err.println("error while importing CRLs from file " + file);
                    throw ex;
                }
            }
        } finally {
            releaseResources(ps, null);
            crlsFileIterator.close();
        }

        processLog.printTrailer();
        System.out.println(getImportedText() + sum + " CRLs");
        System.out.println(getImportedText() + "table CRL");
    } // method importCrl

    @SuppressWarnings("resource")
    private int doImportCrl(
            final PreparedStatement psAddCrl,
            final String crlsZipFile,
            final ProcessLog processLog)
    throws Exception {
        final int numEntriesPerCommit = numCrlsPerCommit;

        ZipFile zipFile = new ZipFile(new File(crlsZipFile));
        ZipEntry certsXmlEntry = zipFile.getEntry("crls.xml");

        CaCrlsReader crls;
        try {
            crls = new CaCrlsReader(zipFile.getInputStream(certsXmlEntry));
        } catch (Exception ex) {
            try {
                zipFile.close();
            } catch (Exception e2) {
            }
            throw ex;
        }

        int numProcessed = 0;
        int numEntriesInBatch = 0;

        disableAutoCommit();

        try {
            while (crls.hasNext()) {
                if (stopMe.get()) {
                    throw new InterruptedException("interrupted by the user");
                }

                CaCrlType crl = (CaCrlType) crls.next();

                numEntriesInBatch++;
                String filename = crl.getFile();

                // CRL
                ZipEntry zipEnty = zipFile.getEntry(filename);

                // rawcert
                byte[] encodedCrl = IoUtil.read(zipFile.getInputStream(zipEnty));

                X509CRL c = null;
                try {
                    c = X509Util.parseCrl(new ByteArrayInputStream(encodedCrl));
                } catch (Exception ex) {
                    LOG.error("could not parse CRL in file {}", filename);
                    LOG.debug("could not parse CRL in file " + filename, ex);
                    if (ex instanceof CRLException) {
                        throw (CRLException) ex;
                    } else {
                        throw new CRLException(ex.getMessage(), ex);
                    }
                }

                try {
                    byte[] octetString = c.getExtensionValue(Extension.cRLNumber.getId());
                    if (octetString == null) {
                        LOG.warn("CRL without CRL number, ignore it");
                        continue;
                    }
                    byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
                    BigInteger crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

                    BigInteger baseCrlNumber = null;
                    octetString = c.getExtensionValue(Extension.deltaCRLIndicator.getId());
                    if (octetString != null) {
                        extnValue = DEROctetString.getInstance(octetString).getOctets();
                        baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
                    }

                    int idx = 1;
                    psAddCrl.setInt(idx++, crl.getId());
                    psAddCrl.setInt(idx++, crl.getCaId());
                    psAddCrl.setLong(idx++, crlNumber.longValue());
                    psAddCrl.setLong(idx++, c.getThisUpdate().getTime() / 1000);
                    if (c.getNextUpdate() != null) {
                        psAddCrl.setLong(idx++, c.getNextUpdate().getTime() / 1000);
                    } else {
                        psAddCrl.setNull(idx++, Types.INTEGER);
                    }

                    if (baseCrlNumber == null) {
                        setBoolean(psAddCrl, idx++, false);
                        psAddCrl.setNull(idx++, Types.BIGINT);
                    } else {
                        setBoolean(psAddCrl, idx++, true);
                        psAddCrl.setLong(idx++, baseCrlNumber.longValue());
                    }

                    String s = Base64.toBase64String(encodedCrl);
                    psAddCrl.setString(idx++, s);

                    psAddCrl.addBatch();
                } catch (SQLException ex) {
                    System.err.println("error while importing CRL with ID="
                            + crl.getId() + ", message: " + ex.getMessage());
                    throw ex;
                }

                boolean isLastBlock = !crls.hasNext();

                if (numEntriesInBatch > 0
                        && (numEntriesInBatch % numEntriesPerCommit == 0 || isLastBlock)) {
                    if (evaulateOnly) {
                        psAddCrl.clearBatch();
                    } else {
                        String sql = null;
                        try {
                            sql = SQL_ADD_CRL;
                            psAddCrl.executeBatch();

                            sql = null;
                            commit("(commit import CRL to CA)");
                        } catch (SQLException ex) {
                            rollback();
                            throw translate(sql, ex);
                        } catch (DataAccessException ex) {
                            rollback();
                            throw ex;
                        }
                    }

                    processLog.addNumProcessed(numEntriesInBatch);
                    numProcessed += numEntriesInBatch;
                    numEntriesInBatch = 0;
                    processLog.printStatus();

                }
            }
            return numProcessed;
        } finally {
            try {
                recoverAutoCommit();
            } catch (DataAccessException ex) {
            }
        }
    } // method doImportCrl

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
                if (str.trim().equalsIgnoreCase(DbPorter.MSG_CERTS_FINISHED)) {
                    return;
                }

                StringTokenizer st = new StringTokenizer(str, ":");
                numProcessedBefore = Integer.parseInt(st.nextToken());
                minId = Integer.parseInt(st.nextToken());
                minId++;
            }
        }

        deleteCertGreatherThan(minId - 1);

        final long total = certstore.getCountCerts() - numProcessedBefore;
        final ProcessLog processLog = new ProcessLog(total);

        System.out.println(getImportingText() + "certificates from ID " + minId);
        processLog.printHeader();

        PreparedStatement psCert = prepareStatement(SQL_ADD_CERT);
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
                    } catch (Exception ex) {
                        LOG.warn("invalid file name '{}', but will still be processed", certsFile);
                    }
                } else {
                    LOG.warn("invalid file name '{}', but will still be processed", certsFile);
                }

                try {
                    int lastId = doImportCert(psCert, psRawcert, certsFile, minId,
                            processLogFile, processLog, numProcessedBefore);
                    minId = lastId + 1;
                } catch (Exception ex) {
                    System.err.println("\nerror while importing certificates from file "
                            + certsFile + ".\nplease continue with the option '--resume'");
                    LOG.error("Exception", ex);
                    throw ex;
                }
            } // end for
        } finally {
            releaseResources(psCert, null);
            releaseResources(psRawcert, null);
            certsFileIterator.close();
        }

        long maxId = getMax("CERT", "ID");
        dataSource.dropAndCreateSequence("CID", maxId + 1);

        processLog.printTrailer();
        echoToFile(MSG_CERTS_FINISHED, processLogFile);
        System.out.println(getImportedText() + processLog.getNumProcessed() + " certificates");
    } // method importCert

    private int doImportCert(
            final PreparedStatement psCert,
            final PreparedStatement psRawcert,
            final String certsZipFile,
            final int minId,
            final File processLogFile,
            final ProcessLog processLog,
            final int numProcessedInLastProcess)
    throws Exception {
        final int numEntriesPerCommit = numCertsPerCommit;

        ZipFile zipFile = new ZipFile(new File(certsZipFile));
        ZipEntry certsXmlEntry = zipFile.getEntry("certs.xml");

        CaCertsReader certs;
        try {
            certs = new CaCertsReader(zipFile.getInputStream(certsXmlEntry));
        } catch (Exception ex) {
            try {
                zipFile.close();
            } catch (Exception e2) {
            }
            throw ex;
        }

        disableAutoCommit();

        try {
            int numEntriesInBatch = 0;
            int lastSuccessfulCertId = 0;

            while (certs.hasNext()) {
                if (stopMe.get()) {
                    throw new InterruptedException("interrupted by the user");
                }

                CaCertType cert = (CaCertType) certs.next();
                int id = cert.getId();
                if (id < minId) {
                    continue;
                }

                int certArt = (cert.getArt() == null)
                        ? 1
                        : cert.getArt();

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
                } catch (RuntimeException ex) {
                    LOG.error("could not parse certificate in file {}", filename);
                    LOG.debug("could not parse certificate in file " + filename, ex);
                    throw new CertificateException(ex.getMessage(), ex);
                }

                byte[] encodedKey = c.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

                String b64Sha1FpCert = HashCalculator.base64Sha1(encodedCert);

                // cert
                String subjectText = X509Util.cutX500Name(c.getSubject(), maxX500nameLen);

                try {
                    int idx = 1;

                    psCert.setInt(idx++, id);
                    psCert.setInt(idx++, certArt);
                    psCert.setLong(idx++, cert.getUpdate());
                    psCert.setLong(idx++, c.getSerialNumber().getPositiveValue().longValue());

                    psCert.setString(idx++, subjectText);
                    long fpSubject = X509Util.fpCanonicalizedName(c.getSubject());
                    psCert.setLong(idx++, fpSubject);

                    if (cert.getFpRs() != null) {
                        psCert.setLong(idx++, cert.getFpRs());
                    } else {
                        psCert.setNull(idx++, Types.BIGINT);
                    }

                    psCert.setLong(idx++, c.getStartDate().getDate().getTime() / 1000);
                    psCert.setLong(idx++, c.getEndDate().getDate().getTime() / 1000);
                    setBoolean(psCert, idx++, cert.getRev());
                    setInt(psCert, idx++, cert.getRr());
                    setLong(psCert, idx++, cert.getRt());
                    setLong(psCert, idx++, cert.getRit());
                    setInt(psCert, idx++, cert.getPid());
                    setInt(psCert, idx++, cert.getCaId());

                    setInt(psCert, idx++, cert.getRid());
                    psCert.setString(idx++, cert.getUser());
                    psCert.setLong(idx++, FpIdCalculator.hash(encodedKey));
                    Extension extension =
                            c.getExtensions().getExtension(Extension.basicConstraints);
                    boolean ee = true;
                    if (extension != null) {
                        ASN1Encodable asn1 = extension.getParsedValue();
                        ee = !BasicConstraints.getInstance(asn1).isCA();
                    }

                    int iEe = ee
                            ? 1
                            : 0;
                    psCert.setInt(idx++, iEe);

                    psCert.setInt(idx++, cert.getReqType());
                    String tidS = null;
                    if (cert.getTid() != null) {
                        tidS = cert.getTid();
                    }
                    psCert.setString(idx++, tidS);
                    psCert.addBatch();
                } catch (SQLException ex) {
                    throw translate(SQL_ADD_CERT, ex);
                }

                try {
                    int idx = 1;
                    psRawcert.setInt(idx++, cert.getId());
                    psRawcert.setString(idx++, b64Sha1FpCert);
                    psRawcert.setString(idx++, cert.getRs());
                    psRawcert.setString(idx++, Base64.toBase64String(encodedCert));
                    psRawcert.addBatch();
                } catch (SQLException ex) {
                    throw translate(SQL_ADD_CRAW, ex);
                }

                boolean isLastBlock = !certs.hasNext();
                if (numEntriesInBatch > 0
                        && (numEntriesInBatch % numEntriesPerCommit == 0 || isLastBlock)) {
                    if (evaulateOnly) {
                        psCert.clearBatch();
                        psRawcert.clearBatch();
                    } else {
                        String sql = null;
                        try {
                            sql = SQL_ADD_CERT;
                            psCert.executeBatch();

                            sql = SQL_ADD_CRAW;
                            psRawcert.executeBatch();

                            sql = null;
                            commit("(commit import cert to CA)");
                        } catch (Throwable th) {
                            rollback();
                            deleteCertGreatherThan(lastSuccessfulCertId);
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
                    processLog.addNumProcessed(numEntriesInBatch);
                    numEntriesInBatch = 0;
                    echoToFile((numProcessedInLastProcess + processLog.getNumProcessed())
                            + ":" + lastSuccessfulCertId, processLogFile);
                    processLog.printStatus();
                }

            } // end for

            return lastSuccessfulCertId;
        } finally {
            try {
                recoverAutoCommit();
            } catch (DataAccessException ex) {
            }
            zipFile.close();
        }
    } // method doImportCert

    private void deleteCertGreatherThan(
            final int id) {
        deleteFromTableWithLargerId("CRAW", "CID", id, LOG);
        deleteFromTableWithLargerId("CERT", "ID", id, LOG);
    }

    private void dropIndexes()
    throws DataAccessException {
        long start = System.currentTimeMillis();

        dataSource.dropIndex(null, "CERT", "IDX_FPK");
        dataSource.dropIndex(null, "CERT", "IDX_FPS");
        dataSource.dropIndex(null, "CERT", "IDX_FPRS");

        dataSource.dropForeignKeyConstraint(null, "FK_CERT_CS_CA1", "CERT");
        dataSource.dropUniqueConstrain(null, "CONST_CA_SN", "CERT");

        dataSource.dropForeignKeyConstraint(null, "FK_CRAW_CERT1", "CRAW");
        dataSource.dropForeignKeyConstraint(null, "FK_PUBLISHQUEUE_CERT1", "PUBLISHQUEUE");

        dataSource.dropPrimaryKey(null, "PK_CERT", "CERT");
        dataSource.dropPrimaryKey(null, "PK_CRAW", "CRAW");

        long duration = (System.currentTimeMillis() - start) / 1000;
        System.out.println(" dropped indexes in " + StringUtil.formatTime(duration, false));
    }

    private void recoverIndexes()
    throws DataAccessException {
        long start = System.currentTimeMillis();

        dataSource.addPrimaryKey(null, "PK_CERT", "CERT", "ID");
        dataSource.addPrimaryKey(null, "PK_CRAW", "CRAW", "CID");

        dataSource.addForeignKeyConstraint(null, "FK_PUBLISHQUEUE_CERT1", "PUBLISHQUEUE",
                "CID", "CERT", "ID", "CASCADE", "NO ACTION");

        dataSource.addForeignKeyConstraint(null, "FK_CRAW_CERT1", "CRAW",
                "CID", "CERT", "ID", "CASCADE", "NO ACTION");

        dataSource.addForeignKeyConstraint(null, "FK_CERT_CS_CA1", "CERT",
                "CA_ID", "CS_CA", "ID", "CASCADE", "NO ACTION");
        dataSource.addUniqueConstrain(null, "CONST_CA_SN", "CERT", "CA_ID", "SN");

        dataSource.createIndex(null, "IDX_FPK", "CERT", "FP_K");
        dataSource.createIndex(null, "IDX_FPS", "CERT", "FP_S");
        dataSource.createIndex(null, "IDX_FPRS", "CERT", "FP_RS");

        long duration = (System.currentTimeMillis() - start) / 1000;
        System.out.println(" recovered indexes in " + StringUtil.formatTime(duration, false));
    }

}
