/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.pki.ca.dbtool.port.ca;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLStreamException;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ProcessLog;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.common.util.XmlUtil;
import org.xipki.commons.datasource.DataSourceWrapper;
import org.xipki.commons.datasource.springframework.dao.DataAccessException;
import org.xipki.commons.dbtool.InvalidInputException;
import org.xipki.commons.security.HashAlgoType;
import org.xipki.commons.security.util.X509Util;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.DeltaCRLCache;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.PublishQueue;
import org.xipki.pki.ca.dbtool.jaxb.ca.DeltaCRLCacheEntryType;
import org.xipki.pki.ca.dbtool.jaxb.ca.ObjectFactory;
import org.xipki.pki.ca.dbtool.jaxb.ca.ToPublishType;
import org.xipki.pki.ca.dbtool.port.DbPorter;
import org.xipki.pki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.pki.ca.dbtool.xmlio.ca.CaUserType;
import org.xipki.pki.ca.dbtool.xmlio.ca.CaUsersWriter;
import org.xipki.pki.ca.dbtool.xmlio.ca.CertType;
import org.xipki.pki.ca.dbtool.xmlio.ca.CertsWriter;
import org.xipki.pki.ca.dbtool.xmlio.ca.CrlType;
import org.xipki.pki.ca.dbtool.xmlio.ca.CrlsWriter;
import org.xipki.pki.ca.dbtool.xmlio.ca.RequestCertType;
import org.xipki.pki.ca.dbtool.xmlio.ca.RequestCertsWriter;
import org.xipki.pki.ca.dbtool.xmlio.ca.RequestType;
import org.xipki.pki.ca.dbtool.xmlio.ca.RequestsWriter;
import org.xipki.pki.ca.dbtool.xmlio.ca.UserType;
import org.xipki.pki.ca.dbtool.xmlio.ca.UsersWriter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaCertStoreDbExporter extends AbstractCaCertStoreDbPorter {

    private static final Logger LOG = LoggerFactory.getLogger(CaCertStoreDbExporter.class);

    private final Marshaller marshaller;

    private final Unmarshaller unmarshaller;

    private final int numCertsInBundle;

    private final int numCertsPerSelect;

    private final boolean resume;

    CaCertStoreDbExporter(final DataSourceWrapper datasource, final Marshaller marshaller,
            final Unmarshaller unmarshaller, final String baseDir, final int numCertsInBundle,
            final int numCertsPerSelect, final boolean resume, final AtomicBoolean stopMe,
            final boolean evaluateOnly) throws DataAccessException {
        super(datasource, baseDir, stopMe, evaluateOnly);
        this.marshaller = ParamUtil.requireNonNull("marshaller", marshaller);
        this.unmarshaller = ParamUtil.requireNonNull("unmarshaller", unmarshaller);
        this.numCertsInBundle = ParamUtil.requireMin("numCertsInBundle", numCertsInBundle, 1);
        this.numCertsPerSelect = ParamUtil.requireMin("numCertsPerSelect", numCertsPerSelect, 1);
        this.resume = resume;
    }

    @SuppressWarnings("unchecked")
    public void export() throws Exception {
        CertStoreType certstore;
        if (resume) {
            JAXBElement<CertStoreType> root;
            try {
                root = (JAXBElement<CertStoreType>)
                    unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_CERTSTORE));
            } catch (JAXBException ex) {
                throw XmlUtil.convert(ex);
            }

            certstore = root.getValue();
            if (certstore.getVersion() > VERSION) {
                throw new InvalidInputException("could not continue with CertStore greater than "
                        + VERSION + ": " + certstore.getVersion());
            }
        } else {
            certstore = new CertStoreType();
            certstore.setVersion(VERSION);
        }

        Exception exception = null;
        System.out.println("exporting CA certstore from database");
        try {
            if (!resume) {
                exportPublishQueue(certstore);
                exportDeltaCrlCache(certstore);
            }

            File processLogFile = new File(baseDir, DbPorter.EXPORT_PROCESS_LOG_FILENAME);

            Long idProcessedInLastProcess = null;
            CaDbEntryType typeProcessedInLastProcess = null;
            if (processLogFile.exists()) {
                byte[] content = IoUtil.read(processLogFile);
                if (content != null && content.length > 0) {
                    String str = new String(content);
                    int idx = str.indexOf(':');
                    String typeName = str.substring(0, idx).trim();
                    typeProcessedInLastProcess = CaDbEntryType.valueOf(typeName);
                    idProcessedInLastProcess = Long.parseLong(str.substring(idx + 1).trim());
                }
            }

            if (CaDbEntryType.USER == typeProcessedInLastProcess
                        || typeProcessedInLastProcess == null) {
                exception = exportEntries(CaDbEntryType.USER, certstore, processLogFile,
                        idProcessedInLastProcess);
                typeProcessedInLastProcess = null;
                idProcessedInLastProcess = null;
            }

            CaDbEntryType[] types = new CaDbEntryType[] {CaDbEntryType.CAUSER,
                CaDbEntryType.CRL, CaDbEntryType.CERT,
                CaDbEntryType.REQUEST, CaDbEntryType.REQCERT};

            for (CaDbEntryType type : types) {
                if (exception == null
                        && (type == typeProcessedInLastProcess
                            || typeProcessedInLastProcess == null)) {
                    exception = exportEntries(type, certstore, processLogFile,
                            idProcessedInLastProcess);
                    typeProcessedInLastProcess = null;
                    idProcessedInLastProcess = null;
                }
            }

            JAXBElement<CertStoreType> root = new ObjectFactory().createCertStore(certstore);
            try {
                marshaller.marshal(root,
                        new File(baseDir + File.separator + FILENAME_CA_CERTSTORE));
            } catch (JAXBException ex) {
                throw XmlUtil.convert(ex);
            }
        } catch (Exception ex) {
            System.err.println("could not export CA certstore from database");
            exception = ex;
        }

        if (exception == null) {
            System.out.println(" exported CA certstore from database");
        } else {
            throw exception;
        }
    } // method export

    private Exception exportEntries(final CaDbEntryType type, final CertStoreType certstore,
            final File processLogFile, final Long idProcessedInLastProcess) {
        String tablesText = (CaDbEntryType.CERT == type)
                ? "tables CERT and CRAW" : "table " + type.getTableName();

        File dir = new File(baseDir, type.getDirName());
        dir.mkdirs();

        FileOutputStream entriesFileOs = null;
        try {
            entriesFileOs = new FileOutputStream(
                    new File(baseDir, type.getDirName() + ".mf"), true);
            doExportEntries(type, certstore, processLogFile, entriesFileOs,
                    idProcessedInLastProcess);
            return null;
        } catch (Exception ex) {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-");

            System.err.println("\nexporting " + tablesText + " has been cancelled due to error,\n"
                    + "please continue with the option '--resume'");
            LOG.error("Exception", ex);
            return ex;
        } finally {
            if (entriesFileOs != null) {
                IoUtil.closeStream(entriesFileOs);
            }
        }
    } // method exportCrl

    private void doExportEntries(final CaDbEntryType type, final CertStoreType certstore,
            final File processLogFile, final FileOutputStream filenameListOs,
            final Long idProcessedInLastProcess) throws Exception {
        final int numEntriesPerSelect = Math.max(1,
                Math.round(type.getSqlBatchFactor() * numCertsPerSelect));
        final int numEntriesPerZip = Math.max(1,
                Math.round(type.getSqlBatchFactor() * numCertsInBundle));
        final File entriesDir = new File(baseDir, type.getDirName());
        final String tableName = type.getTableName();

        int numProcessedBefore;
        String coreSql;

        switch (type) {
        case CERT:
            numProcessedBefore = certstore.getCountCerts();
            coreSql = "ID,SN,CA_ID,PID,RID,ART,RTYPE,TID,UID,EE,LUPDATE,REV,RR,RT,RIT,FP_RS,"
                    + "REQ_SUBJECT,CERT FROM CERT INNER JOIN CRAW ON CERT.ID>=? "
                    + "AND CERT.ID=CRAW.CID";
            break;
        case CRL:
            numProcessedBefore = certstore.getCountCrls();
            coreSql = "ID,CA_ID,CRL FROM CRL WHERE ID>=?";
            break;
        case USER:
            numProcessedBefore = certstore.getCountUsers();
            coreSql = "ID,NAME,ACTIVE,PASSWORD FROM USERNAME WHERE ID>=?";
            break;
        case CAUSER:
            numProcessedBefore = certstore.getCountCaUsers();
            coreSql = "ID,CA_ID,USER_ID,PERMISSION,PROFILES FROM CA_HAS_USER WHERE ID>=?";
            break;
        case REQUEST:
            numProcessedBefore = certstore.getCountRequests();
            coreSql = "ID,LUPDATE,DATA FROM REQUEST WHERE ID>=?";
            break;
        case REQCERT:
            numProcessedBefore = certstore.getCountReqCerts();
            coreSql = "ID,RID,CID FROM REQCERT WHERE ID>=?";
            break;
        default:
            throw new RuntimeException("unknown CaDbEntryType " + type);
        }

        Long minId = null;
        if (idProcessedInLastProcess != null) {
            minId = idProcessedInLastProcess + 1;
        } else {
            minId = getMin(tableName, "ID");
        }

        String tablesText = (CaDbEntryType.CERT == type)
                ? "tables " + tableName + " and CRAW" : "table " + type.getTableName();
        System.out.println(getExportingText() + tablesText + " from ID " + minId);

        final long maxId = getMax(tableName, "ID");
        long total = getCount(tableName) - numProcessedBefore;
        if (total < 1) {
            total = 1; // to avoid exception
        }

        String sql = datasource.buildSelectFirstSql(coreSql, numEntriesPerSelect, "ID ASC");

        DbiXmlWriter entriesInCurrentFile = createWriter(type);
        PreparedStatement ps = prepareStatement(sql.toString());

        int numEntriesInCurrentFile = 0;

        int sum = 0;
        File currentEntriesZipFile = new File(baseDir,
                "tmp-" + type.getDirName() + "-" + System.currentTimeMillis() + ".zip");
        ZipOutputStream currentEntriesZip = getZipOutputStream(currentEntriesZipFile);

        long minIdOfCurrentFile = -1;
        long maxIdOfCurrentFile = -1;

        ProcessLog processLog = new ProcessLog(total);
        processLog.printHeader();

        try {
            Long id = null;
            boolean interrupted = false;
            long lastMaxId = minId - 1;

            while (true) {
                if (stopMe.get()) {
                    interrupted = true;
                    break;
                }

                ps.setLong(1, lastMaxId + 1);

                ResultSet rs = ps.executeQuery();

                // no entries anymore
                if (!rs.next()) {
                    break;
                }

                do {
                    id = rs.getLong("ID");
                    if (lastMaxId < id) {
                        lastMaxId = id;
                    }

                    if (minIdOfCurrentFile == -1) {
                        minIdOfCurrentFile = id;
                    } else if (minIdOfCurrentFile > id) {
                        minIdOfCurrentFile = id;
                    }

                    if (maxIdOfCurrentFile == -1) {
                        maxIdOfCurrentFile = id;
                    } else if (maxIdOfCurrentFile < id) {
                        maxIdOfCurrentFile = id;
                    }

                    if (CaDbEntryType.CERT == type) {
                        String b64Cert = rs.getString("CERT");
                        byte[] certBytes = Base64.decode(b64Cert);

                        String sha1 = HashAlgoType.SHA1.hexHash(certBytes);
                        String certFileName = sha1 + ".der";
                        if (!evaulateOnly) {
                            ZipEntry certZipEntry = new ZipEntry(certFileName);
                            currentEntriesZip.putNextEntry(certZipEntry);
                            try {
                                currentEntriesZip.write(certBytes);
                            } finally {
                                currentEntriesZip.closeEntry();
                            }
                        }

                        CertType cert = new CertType();
                        cert.setId(id);

                        int art = rs.getInt("ART");
                        cert.setArt(art);

                        int cainfoId = rs.getInt("CA_ID");
                        cert.setCaId(cainfoId);

                        boolean ee = rs.getBoolean("EE");
                        cert.setEe(ee);

                        cert.setFile(certFileName);

                        long fpReqSubject = rs.getLong("FP_RS");
                        if (fpReqSubject != 0) {
                            cert.setFpRs(fpReqSubject);
                            String reqSubject = rs.getString("REQ_SUBJECT");
                            cert.setRs(reqSubject);
                        }

                        int certprofileId = rs.getInt("PID");
                        cert.setPid(certprofileId);

                        int reqType = rs.getInt("RTYPE");
                        cert.setReqType(reqType);

                        int requestorinfoId = rs.getInt("RID");
                        cert.setRid(requestorinfoId);

                        String serial = rs.getString("SN");
                        cert.setSn(serial);

                        String str = rs.getString("TID");
                        if (StringUtil.isNotBlank(str)) {
                            // re-encode so that we have the canonicalized base64-string
                            byte[] tid = Base64.decode(str);
                            cert.setTid(Base64.toBase64String(tid));
                        }

                        int userId = rs.getInt("UID");
                        if (userId != 0) {
                            cert.setUid(userId);
                        }
                        long lastUpdate = rs.getLong("LUPDATE");
                        cert.setUpdate(lastUpdate);

                        boolean revoked = rs.getBoolean("REV");
                        cert.setRev(revoked);

                        if (revoked) {
                            int revReason = rs.getInt("RR");
                            long revTime = rs.getLong("RT");
                            long revInvTime = rs.getLong("RIT");
                            cert.setRr(revReason);
                            cert.setRt(revTime);
                            if (revInvTime != 0) {
                                cert.setRit(revInvTime);
                            }
                        }

                        ((CertsWriter) entriesInCurrentFile).add(cert);
                    } else if (CaDbEntryType.CRL == type) {
                        String b64Crl = rs.getString("CRL");
                        byte[] crlBytes = Base64.decode(b64Crl);

                        X509CRL x509Crl = null;
                        try {
                            x509Crl = X509Util.parseCrl(crlBytes);
                        } catch (Exception ex) {
                            LogUtil.error(LOG, ex, "could not parse CRL with id " + id);
                            if (ex instanceof CRLException) {
                                throw (CRLException) ex;
                            } else {
                                throw new CRLException(ex.getMessage(), ex);
                            }
                        }

                        byte[] octetString = x509Crl.getExtensionValue(Extension.cRLNumber.getId());
                        if (octetString == null) {
                            LOG.warn("CRL without CRL number, ignore it");
                            continue;
                        }
                        String sha1 = HashAlgoType.SHA1.hexHash(crlBytes);

                        final String crlFilename = sha1 + ".crl";
                        if (!evaulateOnly) {
                            ZipEntry certZipEntry = new ZipEntry(crlFilename);
                            currentEntriesZip.putNextEntry(certZipEntry);
                            try {
                                currentEntriesZip.write(crlBytes);
                            } finally {
                                currentEntriesZip.closeEntry();
                            }
                        }

                        CrlType crl = new CrlType();
                        crl.setId(id);

                        int caId = rs.getInt("CA_ID");
                        crl.setCaId(caId);

                        byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
                        BigInteger crlNumber = ASN1Integer.getInstance(extnValue)
                                .getPositiveValue();
                        crl.setCrlNo(crlNumber.toString());
                        crl.setFile(crlFilename);

                        ((CrlsWriter) entriesInCurrentFile).add(crl);
                    } else if (CaDbEntryType.USER == type) {
                        String name = rs.getString("NAME");
                        UserType user = new UserType();
                        user.setId(id);
                        user.setName(name);

                        boolean active = rs.getBoolean("ACTIVE");
                        user.setActive(active);

                        String password = rs.getString("PASSWORD");
                        user.setPassword(password);

                        ((UsersWriter) entriesInCurrentFile).add(user);
                    } else if (CaDbEntryType.CAUSER == type) {
                        CaUserType causer = new CaUserType();
                        causer.setId(id);

                        int caId = rs.getInt("CA_ID");
                        causer.setCaId(caId);

                        int uid = rs.getInt("USER_ID");
                        causer.setUid(uid);

                        int permission = rs.getInt("PERMISSION");
                        causer.setPermission(permission);

                        String profiles = rs.getString("PROFILES");
                        causer.setProfiles(profiles);

                        ((CaUsersWriter) entriesInCurrentFile).add(causer);
                    } else if (CaDbEntryType.REQUEST == type) {
                        long update = rs.getLong("LUPDATE");
                        String b64Data = rs.getString("DATA");
                        byte[] dataBytes = Base64.decode(b64Data);
                        String sha1 = HashAlgoType.SHA1.hexHash(dataBytes);
                        final String dataFilename = sha1 + ".req";
                        if (!evaulateOnly) {
                            ZipEntry certZipEntry = new ZipEntry(dataFilename);
                            currentEntriesZip.putNextEntry(certZipEntry);
                            try {
                                currentEntriesZip.write(dataBytes);
                            } finally {
                                currentEntriesZip.closeEntry();
                            }
                        }
                        RequestType entry = new RequestType();
                        entry.setId(id);
                        entry.setUpdate(update);
                        entry.setFile(dataFilename);
                        ((RequestsWriter) entriesInCurrentFile).add(entry);
                    } else if (CaDbEntryType.REQCERT == type) {
                        long cid = rs.getLong("CID");
                        long rid = rs.getLong("RID");
                        RequestCertType entry = new RequestCertType();
                        entry.setId(id);
                        entry.setCid(cid);
                        entry.setRid(rid);
                        ((RequestCertsWriter) entriesInCurrentFile).add(entry);
                    } else {
                        throw new RuntimeException("unknown CaDbEntryType " + type);
                    }

                    numEntriesInCurrentFile++;
                    sum++;

                    if (numEntriesInCurrentFile == numEntriesPerZip) {
                        String currentEntriesFilename = buildFilename(type.getDirName() + "_",
                                ".zip", minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
                        finalizeZip(currentEntriesZip, "overview.xml", entriesInCurrentFile);
                        currentEntriesZipFile.renameTo(
                                new File(entriesDir, currentEntriesFilename));

                        writeLine(filenameListOs, currentEntriesFilename);
                        setCount(type, certstore, numProcessedBefore + sum);
                        echoToFile(tableName + ":" + Long.toString(id), processLogFile);

                        processLog.addNumProcessed(numEntriesInCurrentFile);
                        processLog.printStatus();

                        // reset
                        entriesInCurrentFile = createWriter(type);
                        numEntriesInCurrentFile = 0;
                        minIdOfCurrentFile = -1;
                        maxIdOfCurrentFile = -1;
                        currentEntriesZipFile = new File(baseDir, "tmp-" + type.getDirName() + "-"
                                + System.currentTimeMillis() + ".zip");
                        currentEntriesZip = getZipOutputStream(currentEntriesZipFile);
                    }
                }
                while (rs.next());

                rs.close();
            } // end for

            if (interrupted) {
                currentEntriesZip.close();
                throw new InterruptedException("interrupted by the user");
            }

            if (numEntriesInCurrentFile > 0) {
                finalizeZip(currentEntriesZip, "overview.xml", entriesInCurrentFile);

                String currentEntriesFilename = buildFilename(type.getDirName() + "_", ".zip",
                        minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
                currentEntriesZipFile.renameTo(new File(entriesDir, currentEntriesFilename));

                writeLine(filenameListOs, currentEntriesFilename);
                setCount(type, certstore, numProcessedBefore + sum);
                if (id != null) {
                    echoToFile(Long.toString(id), processLogFile);
                }

                processLog.addNumProcessed(numEntriesInCurrentFile);
            } else {
                currentEntriesZip.close();
                currentEntriesZipFile.delete();
            }

        } catch (SQLException ex) {
            throw translate(null, ex);
        } finally {
            releaseResources(ps, null);
        } // end try

        processLog.printTrailer();
        // all successful, delete the processLogFile
        processLogFile.delete();
        System.out.println(getExportedText() + sum + " entries from " + tablesText);
    } // method doExportEntries

    private void exportPublishQueue(final CertStoreType certstore)
            throws DataAccessException, IOException, JAXBException {
        System.out.println("exporting table PUBLISHQUEUE");

        StringBuilder sqlBuilder = new StringBuilder("SELECT CID,PID,CA_ID");
        sqlBuilder.append(" FROM PUBLISHQUEUE WHERE CID>=? AND CID<? ORDER BY CID ASC");
        final String sql = sqlBuilder.toString();
        final int minId = (int) getMin("PUBLISHQUEUE", "CID");
        final int maxId = (int) getMax("PUBLISHQUEUE", "CID");

        PublishQueue queue = new PublishQueue();
        certstore.setPublishQueue(queue);
        if (maxId == 0) {
            System.out.println(" exported table PUBLISHQUEUE");
            return;
        }

        PreparedStatement ps = prepareStatement(sql);
        ResultSet rs = null;

        List<ToPublishType> list = queue.getTop();
        final int n = 500;

        try {
            for (int i = minId; i <= maxId; i += n) {
                ps.setInt(1, i);
                ps.setInt(2, i + n);

                rs = ps.executeQuery();

                while (rs.next()) {
                    int certId = rs.getInt("CID");
                    int pubId = rs.getInt("PID");
                    int caId = rs.getInt("CA_ID");

                    ToPublishType toPub = new ToPublishType();
                    toPub.setPubId(pubId);
                    toPub.setCertId(certId);
                    toPub.setCaId(caId);
                    list.add(toPub);
                }
            }
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            releaseResources(ps, rs);
        }
        System.out.println(" exported table PUBLISHQUEUE");
    } // method exportPublishQueue

    private void exportDeltaCrlCache(final CertStoreType certstore)
            throws DataAccessException, IOException, JAXBException {
        System.out.println("exporting table DELTACRL_CACHE");

        final String sql = "SELECT SN,CA_ID FROM DELTACRL_CACHE";

        DeltaCRLCache deltaCache = new DeltaCRLCache();
        certstore.setDeltaCRLCache(deltaCache);

        PreparedStatement ps = prepareStatement(sql);
        ResultSet rs = null;

        List<DeltaCRLCacheEntryType> list = deltaCache.getEntry();

        try {
            rs = ps.executeQuery();

            while (rs.next()) {
                String serial = rs.getString("SN");
                int caId = rs.getInt("CA_ID");

                DeltaCRLCacheEntryType entry = new DeltaCRLCacheEntryType();
                entry.setCaId(caId);
                entry.setSerial(serial);
                list.add(entry);
            }
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            releaseResources(ps, rs);
        }

        System.out.println(" exported table DELTACRL_CACHE");
    } // method exportDeltaCrlCache

    private void finalizeZip(final ZipOutputStream zipOutStream, final String filename,
            final DbiXmlWriter os) throws JAXBException, IOException, XMLStreamException {
        ZipEntry certZipEntry = new ZipEntry(filename);
        zipOutStream.putNextEntry(certZipEntry);
        try {
            os.rewriteToZipStream(zipOutStream);
        } finally {
            zipOutStream.closeEntry();
        }

        zipOutStream.close();
    }

    private static DbiXmlWriter createWriter(final CaDbEntryType type)
            throws IOException, XMLStreamException {
        switch (type) {
        case CERT:
            return new CertsWriter();
        case CRL:
            return new CrlsWriter();
        case USER:
            return new UsersWriter();
        case CAUSER:
            return new CaUsersWriter();
        case REQUEST:
            return new RequestsWriter();
        case REQCERT:
            return new RequestCertsWriter();
        default:
            throw new RuntimeException("unknown CaDbEntryType " + type);
        }
    }

    private static void setCount(final CaDbEntryType type, final CertStoreType certstore,
            final int num) {
        switch (type) {
        case CERT:
            certstore.setCountCerts(num);
            break;
        case CRL:
            certstore.setCountCrls(num);
            break;
        case USER:
            certstore.setCountUsers(num);
            break;
        case CAUSER:
            certstore.setCountCaUsers(num);
            break;
        case REQUEST:
            certstore.setCountRequests(num);
            break;
        case REQCERT:
            certstore.setCountReqCerts(num);
            break;
        default:
            throw new RuntimeException("unknown CaDbEntryType " + type);
        }
    }
}
