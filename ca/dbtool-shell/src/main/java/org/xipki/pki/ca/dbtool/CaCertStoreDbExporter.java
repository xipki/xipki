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

package org.xipki.pki.ca.dbtool;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.dbtool.InvalidInputException;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Cas;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.DeltaCRLCache;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Profiles;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.PublishQueue;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Publishers;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Requestors;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertsType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertstoreCaType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CrlType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CrlsType;
import org.xipki.pki.ca.dbtool.jaxb.ca.DeltaCRLCacheEntryType;
import org.xipki.pki.ca.dbtool.jaxb.ca.NameIdType;
import org.xipki.pki.ca.dbtool.jaxb.ca.ObjectFactory;
import org.xipki.pki.ca.dbtool.jaxb.ca.ToPublishType;
import org.xipki.pki.ca.dbtool.jaxb.ca.UserType;
import org.xipki.pki.ca.dbtool.jaxb.ca.UsersType;
import org.xipki.security.api.HashCalculator;

/**
 * @author Lijun Liao
 */

class CaCertStoreDbExporter extends AbstractCaCertStoreDbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(CaCertStoreDbExporter.class);

    private final Marshaller marshaller;
    private final Unmarshaller unmarshaller;
    private final ObjectFactory objFact = new ObjectFactory();

    private final int numCertsInBundle;
    private final int numUsersInBundle;
    private final int numCrlsInBundle;
    private final int numCertsPerSelect;
    private final int numUsersPerSelect;
    private final int numCrlsPerSelect;
    private final boolean resume;

    CaCertStoreDbExporter(
            final DataSourceWrapper dataSource,
            final Marshaller marshaller,
            final Unmarshaller unmarshaller,
            final String baseDir,
            final int numCertsInBundle,
            final int numCertsPerSelect,
            final boolean resume,
            final AtomicBoolean stopMe,
            final boolean evaluateOnly)
    throws DataAccessException
    {
        super(dataSource, baseDir, stopMe, evaluateOnly);
        ParamUtil.assertNotNull("marshaller", marshaller);
        ParamUtil.assertNotNull("unmarshaller", unmarshaller);
        if(numCertsInBundle < 1)
        {
            throw new IllegalArgumentException("numCertsInBundle could not be less than 1: " + numCertsInBundle);
        }
        if(numCertsPerSelect < 1)
        {
            throw new IllegalArgumentException("numCertsPerSelect could not be less than 1: " + numCertsPerSelect);
        }

        this.numCertsInBundle = numCertsInBundle;
        this.numUsersInBundle = numCertsInBundle * 10;
        this.numCrlsInBundle = Math.max(1, numCertsInBundle / 10);
        this.numCertsPerSelect = numCertsPerSelect;
        this.numUsersPerSelect = numCertsInBundle * 10;
        this.numCrlsPerSelect = Math.max(1, numCertsPerSelect / 10);

        this.marshaller = marshaller;
        this.unmarshaller = unmarshaller;
        this.resume = resume;
    }

    @SuppressWarnings("unchecked")
    public void export()
    throws Exception
    {
        CertStoreType certstore;
        if(resume)
        {
            JAXBElement<CertStoreType> root;
            try
            {
                root = (JAXBElement<CertStoreType>)
                    unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_CertStore));
            } catch(JAXBException e)
            {
                throw XMLUtil.convert(e);
            }

            certstore = root.getValue();
            if(certstore.getVersion() > VERSION)
            {
                throw new InvalidInputException("could not continue with CertStore greater than " +
                        VERSION + ": " + certstore.getVersion());
            }
        }
        else
        {
            certstore = new CertStoreType();
            certstore.setVersion(VERSION);
        }

        Exception exception = null;
        System.out.println("exporting CA certstore from database");
        try
        {
            if(resume == false)
            {
                export_ca(certstore);
                export_requestor(certstore);
                export_publisherinfo(certstore);
                export_certprofileinfo(certstore);
                export_user(certstore);
                export_crl(certstore);
                export_publishQueue(certstore);
                export_deltaCRLCache(certstore);
            }
            File processLogFile = new File(baseDir, DbPorter.EXPORT_PROCESS_LOG_FILENAME);
            exception = export_cert(certstore, processLogFile);

            JAXBElement<CertStoreType> root = new ObjectFactory().createCertStore(certstore);
            try
            {
                marshaller.marshal(root, new File(baseDir + File.separator + FILENAME_CA_CertStore));
            }catch(JAXBException e)
            {
                throw XMLUtil.convert(e);
            }
        }
        catch(Exception e)
        {
            System.err.println("error while exporting CA certstore from database");
            exception = e;
        }

        if(exception == null)
        {
            System.out.println(" exported CA certstore from database");
        }
        else
        {
            throw exception;
        }
    }

    private Exception export_crl(
            final CertStoreType certstore)
    {
        File fCrlsDir = new File(crlsDir);
        fCrlsDir.mkdirs();

        FileOutputStream crlsFileOs = null;
        try
        {
            certstore.setCountCrls(0);
            crlsFileOs = new FileOutputStream(crlsListFile, true);
            do_export_crl(certstore, crlsFileOs);
            return null;
        }catch(DataAccessException | IOException | InterruptedException | JAXBException e)
        {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-crls-");
            System.err.println("\nexporting table CRL has been cancelled due to error");
            LOG.error("Exception", e);
            return e;
        } finally
        {
            IoUtil.closeStream(crlsFileOs);
        }
    }

    private void do_export_crl(
            final CertStoreType certstore,
            final FileOutputStream filenameListOs)
    throws DataAccessException, IOException, JAXBException, InterruptedException
    {
        System.out.println(getExportingText() + "table CRL");

        final int numEntriesPerSelect = numCrlsPerSelect;
        final int numEntriesPerZip = numCrlsInBundle;
        final String entriesDir = crlsDir;

        final int minId = (int) getMin("CRL", "ID");
        final int maxId = (int) getMax("CRL", "ID");

        System.out.println(getExportingText() + "table CRL from ID " + minId);

        ProcessLog processLog;
        {
            long total = getCount("CRL");
            if(total < 1)
            {
                total = 1; // to avoid exception
            }
            processLog = new ProcessLog(total, System.currentTimeMillis(), 0);
        }

        final String sql = "SELECT ID, CA_ID, CRL FROM CRL WHERE ID >= ? AND ID < ? ORDER BY ID ASC";
        PreparedStatement ps = prepareStatement(sql);

        int numCrlsInCurrentFile = 0;
        CrlsType crlsInCurrentFile = new CrlsType();

        int sum = 0;

        File currentCrlsZipFile = new File(baseDir, "tmp-crls-" + System.currentTimeMillis() + ".zip");
        FileOutputStream out = new FileOutputStream(currentCrlsZipFile);
        ZipOutputStream currentCrlsZip = new ZipOutputStream(out);

        int minIdOfCurrentFile = -1;
        int maxIdOfCurrentFile = -1;

        ProcessLog.printHeader();

        try
        {
            Integer id = null;
            boolean interrupted = false;
            for(int i = minId; i <= maxId; i += numEntriesPerSelect)
            {
                if(stopMe.get())
                {
                    interrupted = true;
                    break;
                }

                ps.setInt(1, i);
                ps.setInt(2, i + numEntriesPerSelect);

                ResultSet rs = ps.executeQuery();

                while(rs.next())
                {
                    id = rs.getInt("ID");

                    if(minIdOfCurrentFile == -1)
                    {
                        minIdOfCurrentFile = id;
                    }
                    else if(minIdOfCurrentFile > id)
                    {
                        minIdOfCurrentFile = id;
                    }

                    if(maxIdOfCurrentFile == -1)
                    {
                        maxIdOfCurrentFile = id;
                    }
                    else if(maxIdOfCurrentFile < id)
                    {
                        maxIdOfCurrentFile = id;
                    }

                    int caId = rs.getInt("CA_ID");

                    String b64Crl = rs.getString("CRL");
                    byte[] crlBytes = Base64.decode(b64Crl);
                    String sha1_cert = HashCalculator.hexSha1(crlBytes);

                    final String crlFilename = sha1_cert + ".crl";
                    if(evaulateOnly == false)
                    {
                        ZipEntry certZipEntry = new ZipEntry(crlFilename);
                        currentCrlsZip.putNextEntry(certZipEntry);
                        try
                        {
                            currentCrlsZip.write(crlBytes);
                        }finally
                        {
                            currentCrlsZip.closeEntry();
                        }
                    }

                    CrlType crl = new CrlType();
                    crl.setId(id);
                    crl.setCaId(caId);
                    crl.setFile(crlFilename);

                    crlsInCurrentFile.getCrl().add(crl);
                    numCrlsInCurrentFile ++;
                    sum ++;

                    if(numCrlsInCurrentFile == numEntriesPerZip)
                    {
                        String currentCrlsFilename = DbiUtil.buildFilename("crls_", ".zip",
                                minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
                        finalizeZip(currentCrlsZip, crlsInCurrentFile);
                        currentCrlsZipFile.renameTo(new File(entriesDir, currentCrlsFilename));

                        writeLine(filenameListOs, currentCrlsFilename);
                        certstore.setCountCrls(sum);
                        processLog.addNumProcessed(numCrlsInCurrentFile);
                        processLog.printStatus();

                        // reset
                        crlsInCurrentFile = new CrlsType();
                        numCrlsInCurrentFile = 0;
                        minIdOfCurrentFile = -1;
                        maxIdOfCurrentFile = -1;
                        currentCrlsZipFile = new File(baseDir, "tmp-crls-" + System.currentTimeMillis() + ".zip");
                        out = new FileOutputStream(currentCrlsZipFile);
                        currentCrlsZip = new ZipOutputStream(out);
                    }
                }  // end while(rs.next)
            } // end for

            if(interrupted)
            {
                currentCrlsZip.close();
                throw new InterruptedException("interrupted by the user");
            }

            if(numCrlsInCurrentFile > 0)
            {
                finalizeZip(currentCrlsZip, crlsInCurrentFile);

                String currentCrlsFilename = DbiUtil.buildFilename("crls_", ".zip",
                        minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
                currentCrlsZipFile.renameTo(new File(entriesDir, currentCrlsFilename));

                writeLine(filenameListOs, currentCrlsFilename);
                certstore.setCountCrls(sum);
            }
            else
            {
                currentCrlsZip.close();
                currentCrlsZipFile.delete();
            }

        }catch(SQLException e)
        {
            throw translate(null, e);
        }finally
        {
            releaseResources(ps, null);
        } // end try

        ProcessLog.printTrailer();
        System.out.println(getExportedText() + sum + " CRLs from table CRL");
    }

    private void export_ca(
            final CertStoreType certstore)
    throws DataAccessException
    {
        System.out.println("exporting table CS_CA");
        Cas cas = new Cas();
        final String sql = "SELECT ID, CERT FROM CS_CA";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String cert = rs.getString("CERT");

                CertstoreCaType ca = new CertstoreCaType();
                ca.setId(id);
                ca.setCert(cert);

                cas.getCa().add(ca);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        certstore.setCas(cas);
        System.out.println(" exported table CS_CA");
    }

    private void export_requestor(
            final CertStoreType certstore)
    throws DataAccessException
    {
        System.out.println("exporting table CS_REQUESTOR");
        Requestors infos = new Requestors();
        final String sql = "SELECT ID, NAME FROM CS_REQUESTOR";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String name = rs.getString("NAME");

                NameIdType info = createNameId(name, id);
                infos.getRequestor().add(info);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        certstore.setRequestors(infos);
        System.out.println(" exported table CS_REQUESTOR");
    }

    private void export_publisherinfo(
            final CertStoreType certstore)
    throws DataAccessException
    {
        System.out.println("exporting table CS_PUBLISHER");
        Publishers infos = new Publishers();
        final String sql = "SELECT ID, NAME FROM CS_PUBLISHER";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String name = rs.getString("NAME");

                NameIdType info = createNameId(name, id);
                infos.getPublisher().add(info);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        certstore.setPublishers(infos);
        System.out.println(" exported table CS_PUBLISHER");
    }

    private Exception export_user(
            final CertStoreType certstore)
    {
        File fUsersDir = new File(usersDir);
        fUsersDir.mkdirs();

        FileOutputStream usersFileOs = null;
        try
        {
            certstore.setCountUsers(0);
            usersFileOs = new FileOutputStream(usersListFile, true);
            do_export_user(certstore, usersFileOs);
            return null;
        }catch(DataAccessException | IOException | JAXBException | InterruptedException e)
        {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-users-");
            System.err.println("\nexporting table USERNAME has been cancelled due to error");
            LOG.error("Exception", e);
            return e;
        } finally
        {
            IoUtil.closeStream(usersFileOs);
        }
    }

    private void do_export_user(
            final CertStoreType certstore,
            final FileOutputStream filenameListOs)
    throws DataAccessException, IOException, JAXBException, InterruptedException
    {
        System.out.println(getExportingText() + "table USERNAME");

        final int numEntriesPerSelect = numUsersPerSelect;
        final int numEntriesPerZip = numUsersInBundle;
        final String entriesDir = usersDir;

        final String sql =
                "SELECT ID, NAME, PASSWORD, CN_REGEX FROM USERNAME WHERE ID >= ? AND ID < ? ORDER BY ID ASC";

        final int minId = (int) getMin("USERNAME", "ID");
        final int maxId = (int) getMax("USERNAME", "ID");
        System.out.println(getExportingText() + "table USERNAME from ID " + minId);

        ProcessLog processLog;
        {
            long total = getCount("USERNAME");
            if(total < 1)
            {
                total = 1; // to avoid exception
            }
            processLog = new ProcessLog(total, System.currentTimeMillis(), 0);
        }

        PreparedStatement ps = prepareStatement(sql);

        int numUsersInCurrentFile = 0;
        UsersType usersInCurrentFile = new UsersType();

        int sum = 0;

        int minIdOfCurrentFile = -1;
        int maxIdOfCurrentFile = -1;

        ProcessLog.printHeader();

        try
        {
            Integer id = null;
            boolean interrupted = false;
            for(int i = minId; i <= maxId; i += numEntriesPerSelect)
            {
                if(stopMe.get())
                {
                    interrupted = true;
                    break;
                }

                ps.setInt(1, i);
                ps.setInt(2, i + numEntriesPerSelect);

                ResultSet rs = ps.executeQuery();

                while(rs.next())
                {
                    id = rs.getInt("ID");

                    if(minIdOfCurrentFile == -1)
                    {
                        minIdOfCurrentFile = id;
                    }
                    else if(minIdOfCurrentFile > id)
                    {
                        minIdOfCurrentFile = id;
                    }

                    if(maxIdOfCurrentFile == -1)
                    {
                        maxIdOfCurrentFile = id;
                    }
                    else if(maxIdOfCurrentFile < id)
                    {
                        maxIdOfCurrentFile = id;
                    }

                    String name = rs.getString("NAME");
                    UserType user = new UserType();
                    user.setId(id);
                    user.setName(name);
                    String password = rs.getString("PASSWORD");
                    user.setPassword(password);

                    String cnRegex = rs.getString("CN_REGEX");
                    user.setCnRegex(cnRegex);
                    usersInCurrentFile.getUser().add(user);

                    numUsersInCurrentFile ++;
                    sum ++;

                    if(numUsersInCurrentFile == numEntriesPerZip)
                    {
                        String currentUsersFilename = "users_" + minIdOfCurrentFile + "_" + maxIdOfCurrentFile + ".zip";
                        finalizeZip(entriesDir + File.separator + currentUsersFilename, usersInCurrentFile);
                        certstore.setCountUsers(sum);
                        writeLine(filenameListOs, currentUsersFilename);

                        processLog.addNumProcessed(numUsersInCurrentFile);
                        processLog.printStatus();

                        // reset
                        usersInCurrentFile = new UsersType();
                        numUsersInCurrentFile = 0;
                        minIdOfCurrentFile = -1;
                        maxIdOfCurrentFile = -1;
                    }
                }  // end while(rs.next)
            } // end for

            if(interrupted)
            {
                throw new InterruptedException("interrupted by the user");
            }

            if(numUsersInCurrentFile > 0)
            {
                String currentUsersFilename = "users_" + minIdOfCurrentFile + "_" + maxIdOfCurrentFile + ".zip";
                finalizeZip(entriesDir + File.separator + currentUsersFilename, usersInCurrentFile);
                certstore.setCountUsers(sum);
                writeLine(filenameListOs, currentUsersFilename);

                processLog.addNumProcessed(numUsersInCurrentFile);
                processLog.printStatus();
            }
        }catch(SQLException e)
        {
            throw translate(null, e);
        }finally
        {
            releaseResources(ps, null);
        } // end try

        ProcessLog.printTrailer();
        System.out.println(getExportedText() + sum + " users from table USERNAME");
    }

    private void export_certprofileinfo(
            final CertStoreType certstore)
    throws DataAccessException
    {
        System.out.println("exporting table CS_PROFILE");
        Profiles infos = new Profiles();
        final String sql = "SELECT ID, NAME FROM CS_PROFILE";

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String name = rs.getString("NAME");

                NameIdType info = createNameId(name, id);
                infos.getProfile().add(info);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        certstore.setProfiles(infos);
        System.out.println(" exported table CS_PROFILE");
    }

    /**
     *
     * @return exception instanceof {{@link DataAccessException}, {@link IOException} or {@link JAXBException}.
     */
    private Exception export_cert(
            final CertStoreType certstore,
            final File processLogFile)
    {
        File fCertsDir = new File(certsDir);
        fCertsDir.mkdirs();

        FileOutputStream certsFileOs = null;
        try
        {
            certsFileOs = new FileOutputStream(certsListFile, true);
            do_export_cert(certstore, processLogFile, certsFileOs);
            return null;
        }catch(DataAccessException | IOException | JAXBException | InterruptedException e)
        {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-certs-");
            System.err.println("\nexporting table CERT and CRAW has been cancelled due to error,\n"
                    + "please continue with the option '--resume'");
            LOG.error("Exception", e);
            return e;
        } finally
        {
            IoUtil.closeStream(certsFileOs);
        }
    }

    private void do_export_cert(
            final CertStoreType certstore,
            final File processLogFile,
            final FileOutputStream filenameListOs)
    throws DataAccessException, IOException, JAXBException, InterruptedException
    {
        final int numEntriesPerSelect = numCertsPerSelect;
        final int numEntriesPerZip = numCertsInBundle;
        final String entriesDir = certsDir;

        int numProcessedBefore = certstore.getCountCerts();

        Integer minId = null;
        if(processLogFile.exists())
        {
            byte[] content = IoUtil.read(processLogFile);
            if(content != null && content.length > 0)
            {
                minId = Integer.parseInt(new String(content).trim());
                minId++;
            }
        }

        if(minId == null)
        {
            minId = (int) getMin("CERT", "ID");
        }

        System.out.println(getExportingText() + "tables CERT and CRAW from ID " + minId);

        final int maxId = (int) getMax("CERT", "ID");
        ProcessLog processLog;
        {
            long total = getCount("CERT") - numProcessedBefore;
            if(total < 1)
            {
                total = 1; // to avoid exception
            }
            processLog = new ProcessLog(total, System.currentTimeMillis(), numProcessedBefore);
        }

        StringBuilder certSql = new StringBuilder("SELECT ID, SN, CA_ID, PID, RID, ");
        certSql.append("ART, RTYPE, TID, UNAME, LUPDATE, REV, RR, RT, RIT, FP_RS ");
        certSql.append("FROM CERT WHERE ID >= ? AND ID < ? ORDER BY ID ASC");

        PreparedStatement ps = prepareStatement(certSql.toString());

        final String rawCertSql = "SELECT CID, REQ_SUBJECT, CERT FROM CRAW WHERE CID >= ? AND CID < ?";
        PreparedStatement rawCertPs = prepareStatement(rawCertSql);

        int numCertsInCurrentFile = 0;
        CertsType certsInCurrentFile = new CertsType();

        int sum = 0;
        File currentCertsZipFile = new File(baseDir, "tmp-certs-" + System.currentTimeMillis() + ".zip");
        FileOutputStream out = new FileOutputStream(currentCertsZipFile);
        ZipOutputStream currentCertsZip = new ZipOutputStream(out);

        int minIdOfCurrentFile = -1;
        int maxIdOfCurrentFile = -1;

        ProcessLog.printHeader();

        try
        {
            Integer id = null;
            boolean interrupted = false;
            for(int i = minId; i <= maxId; i += numEntriesPerSelect)
            {
                if(stopMe.get())
                {
                    interrupted = true;
                    break;
                }

                Map<Integer, byte[]> rawCertMaps = new HashMap<>();
                Map<Integer, String> reqSubjectMaps = new HashMap<>();

                // retrieve raw certificates
                rawCertPs.setInt(1, i);
                rawCertPs.setInt(2, i + numEntriesPerSelect);
                ResultSet rawCertRs = rawCertPs.executeQuery();
                while(rawCertRs.next())
                {
                    int certId = rawCertRs.getInt("CID");
                    String b64Cert = rawCertRs.getString("CERT");
                    byte[] certBytes = Base64.decode(b64Cert);
                    rawCertMaps.put(certId, certBytes);

                    String reqSubject = rawCertRs.getString("REQ_SUBJECT");
                    if(StringUtil.isNotBlank(reqSubject))
                    {
                        reqSubjectMaps.put(certId, reqSubject);
                    }
                }
                rawCertRs.close();

                ps.setInt(1, i);
                ps.setInt(2, i + numEntriesPerSelect);

                ResultSet rs = ps.executeQuery();

                while(rs.next())
                {
                    id = rs.getInt("ID");

                    if(minIdOfCurrentFile == -1)
                    {
                        minIdOfCurrentFile = id;
                    }
                    else if(minIdOfCurrentFile > id)
                    {
                        minIdOfCurrentFile = id;
                    }

                    if(maxIdOfCurrentFile == -1)
                    {
                        maxIdOfCurrentFile = id;
                    }
                    else if(maxIdOfCurrentFile < id)
                    {
                        maxIdOfCurrentFile = id;
                    }

                    byte[] certBytes = rawCertMaps.remove(id);
                    if(certBytes == null)
                    {
                        final String msg = "found no certificate in table CRAW for cert_id '" + id + "'";
                        LOG.error(msg);
                        throw new DataAccessException(msg);
                    }

                    String sha1_cert = HashCalculator.hexSha1(certBytes);

                    if(evaulateOnly == false)
                    {
                        ZipEntry certZipEntry = new ZipEntry(sha1_cert + ".der");
                        currentCertsZip.putNextEntry(certZipEntry);
                        try
                        {
                            currentCertsZip.write(certBytes);
                        }finally
                        {
                            currentCertsZip.closeEntry();
                        }
                    }

                    CertType cert = new CertType();
                    cert.setId(id);

                    byte[] tid = null;
                    int art = rs.getInt("ART");
                    int reqType = rs.getInt("RTYPE");
                    String s = rs.getString("TID");
                    if(StringUtil.isNotBlank(s))
                    {
                        tid = Base64.decode(s);
                    }

                    cert.setArt(art);
                    cert.setReqType(reqType);
                    if(tid != null)
                    {
                        cert.setTid(tid);
                    }

                    int cainfo_id = rs.getInt("CA_ID");
                    cert.setCaId(cainfo_id);

                    long serial = rs.getLong("SN");
                    cert.setSn(Long.toHexString(serial));

                    int certprofile_id = rs.getInt("PID");
                    cert.setPid(certprofile_id);

                    int requestorinfo_id = rs.getInt("RID");
                    if(requestorinfo_id != 0)
                    {
                        cert.setRid(requestorinfo_id);
                    }

                    long last_update = rs.getLong("LUPDATE");
                    cert.setUpdate(last_update);

                    boolean revoked = rs.getBoolean("REV");
                    cert.setRev(revoked);

                    if(revoked)
                    {
                        int rev_reason = rs.getInt("RR");
                        long rev_time = rs.getLong("RT");
                        long rev_inv_time = rs.getLong("RIT");
                        cert.setRr(rev_reason);
                        cert.setRt(rev_time);
                        if(rev_inv_time != 0)
                        {
                            cert.setRit(rev_inv_time);
                        }
                    }

                    String user = rs.getString("UNAME");
                    if(user != null)
                    {
                        cert.setUser(user);
                    }
                    cert.setFile(sha1_cert + ".der");

                    long fpReqSubject = rs.getLong("FP_RS");
                    if(fpReqSubject != 0)
                    {
                        cert.setFpRs(fpReqSubject);
                        String reqSubject = reqSubjectMaps.remove(id);
                        cert.setRs(reqSubject);
                    }

                    certsInCurrentFile.getCert().add(cert);
                    numCertsInCurrentFile ++;
                    sum ++;

                    if(numCertsInCurrentFile == numEntriesPerZip)
                    {
                        String currentCertsFilename = DbiUtil.buildFilename("certs_", ".zip",
                                minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
                        finalizeZip(currentCertsZip, certsInCurrentFile);
                        currentCertsZipFile.renameTo(new File(entriesDir, currentCertsFilename));

                        writeLine(filenameListOs, currentCertsFilename);
                        certstore.setCountCerts(numProcessedBefore + sum);
                        echoToFile(Integer.toString(id), processLogFile);

                        processLog.addNumProcessed(numCertsInCurrentFile);
                        processLog.printStatus();

                        // reset
                        certsInCurrentFile = new CertsType();
                        numCertsInCurrentFile = 0;
                        minIdOfCurrentFile = -1;
                        maxIdOfCurrentFile = -1;
                        currentCertsZipFile = new File(baseDir, "tmp-certs-" + System.currentTimeMillis() + ".zip");
                        out = new FileOutputStream(currentCertsZipFile);
                        currentCertsZip = new ZipOutputStream(out);
                    }
                }  // end while(rs.next)

                rawCertMaps.clear();
                rawCertMaps = null;
            } // end for

            if(interrupted)
            {
                currentCertsZip.close();
                throw new InterruptedException("interrupted by the user");
            }

            if(numCertsInCurrentFile > 0)
            {
                finalizeZip(currentCertsZip, certsInCurrentFile);

                String currentCertsFilename = DbiUtil.buildFilename("certs_", ".zip",
                        minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
                currentCertsZipFile.renameTo(new File(entriesDir, currentCertsFilename));

                writeLine(filenameListOs, currentCertsFilename);
                certstore.setCountCerts(numProcessedBefore + sum);
                if(id != null)
                {
                    echoToFile(Integer.toString(id), processLogFile);
                }

                processLog.addNumProcessed(numCertsInCurrentFile);
                processLog.printStatus();
            }
            else
            {
                currentCertsZip.close();
                currentCertsZipFile.delete();
            }

        }catch(SQLException e)
        {
            throw translate(null, e);
        }finally
        {
            releaseResources(ps, null);
        } // end try

        ProcessLog.printTrailer();
        // all successful, delete the processLogFile
        processLogFile.delete();
        System.out.println(getExportedText() + sum + " certificates from tables CERT and CRAW");
    }

    private void export_publishQueue(
            final CertStoreType certstore)
    throws DataAccessException, IOException, JAXBException
    {
        System.out.println("exporting table PUBLISHQUEUE");

        StringBuilder sqlBuilder = new StringBuilder("SELECT");
        sqlBuilder.append(" CID, PID, ");
        sqlBuilder.append("CA_ID");
        sqlBuilder.append(" FROM PUBLISHQUEUE WHERE CID >= ? AND CID < ? ORDER BY CID ASC");
        final String sql = sqlBuilder.toString();
        final int minId = (int) getMin("PUBLISHQUEUE", "CID");
        final int maxId = (int) getMax("PUBLISHQUEUE", "CID");

        PublishQueue queue = new PublishQueue();
        certstore.setPublishQueue(queue);
        if(maxId == 0)
        {
            System.out.println(" exported table PUBLISHQUEUE");
            return;
        }

        PreparedStatement ps = prepareStatement(sql);
        ResultSet rs = null;

        List<ToPublishType> list = queue.getTop();
        final int n = 500;

        try
        {
            for(int i = minId; i <= maxId; i += n)
            {
                ps.setInt(1, i);
                ps.setInt(2, i + n);

                rs = ps.executeQuery();

                while(rs.next())
                {
                    int cert_id = rs.getInt("CID");
                    int pub_id = rs.getInt("PID");
                    int ca_id = rs.getInt("CA_ID");

                    ToPublishType toPub = new ToPublishType();
                    toPub.setPubId(pub_id);
                    toPub.setCertId(cert_id);
                    toPub.setCaId(ca_id);
                    list.add(toPub);
                }
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(ps, rs);
        }
        System.out.println(" exported table PUBLISHQUEUE");
    }

    private void export_deltaCRLCache(
            final CertStoreType certstore)
    throws DataAccessException, IOException, JAXBException
    {
        System.out.println("exporting table DELTACRL_CACHE");

        StringBuilder sqlBuilder = new StringBuilder("SELECT");
        sqlBuilder.append(" SN, ");
        sqlBuilder.append("CA_ID");
        sqlBuilder.append(" FROM DELTACRL_CACHE");
        final String sql = sqlBuilder.toString();

        DeltaCRLCache deltaCache = new DeltaCRLCache();
        certstore.setDeltaCRLCache(deltaCache);

        PreparedStatement ps = prepareStatement(sql);
        ResultSet rs = null;

        List<DeltaCRLCacheEntryType> list = deltaCache.getEntry();

        try
        {
            rs = ps.executeQuery();

            while(rs.next())
            {
                long serial = rs.getLong("SN");
                int ca_id = rs.getInt("CA_ID");

                DeltaCRLCacheEntryType entry = new DeltaCRLCacheEntryType();
                entry.setCaId(ca_id);
                entry.setSerial(serial);
                list.add(entry);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(ps, rs);
        }

        System.out.println(" exported table DELTACRL_CACHE");
    }

    private void finalizeZip(
            final ZipOutputStream zipOutStream,
            final CertsType certsType)
    throws JAXBException, IOException
    {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try
        {
            marshaller.marshal(objFact.createCerts(certsType), bout);
        }catch(JAXBException e)
        {
            throw XMLUtil.convert(e);
        }
        bout.flush();

        ZipEntry certZipEntry = new ZipEntry("certs.xml");
        zipOutStream.putNextEntry(certZipEntry);
        try
        {
            zipOutStream.write(bout.toByteArray());
        }finally
        {
            zipOutStream.closeEntry();
        }

        zipOutStream.close();
    }

    private void finalizeZip(
            final ZipOutputStream zipOutStream,
            final CrlsType crlsType)
    throws JAXBException, IOException
    {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try
        {
            marshaller.marshal(objFact.createCrls(crlsType), bout);
        }catch(JAXBException e)
        {
            throw XMLUtil.convert(e);
        }
        bout.flush();

        ZipEntry certZipEntry = new ZipEntry("crls.xml");
        zipOutStream.putNextEntry(certZipEntry);
        try
        {
            zipOutStream.write(bout.toByteArray());
        }finally
        {
            zipOutStream.closeEntry();
        }

        zipOutStream.close();
    }

    private static NameIdType createNameId(
            final String name,
            final int id)
    {
        NameIdType info = new NameIdType();
        info.setId(id);
        info.setName(name);
        return info;
    }

    private void finalizeZip(
            final String zipFilename,
            final UsersType usersType)
    throws JAXBException, IOException
    {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try
        {
            marshaller.marshal(objFact.createUsers(usersType), bout);
        }catch(JAXBException e)
        {
            throw XMLUtil.convert(e);
        }
        bout.flush();

        File zipFile = new File(baseDir, "tmp-users-" + System.currentTimeMillis() + ".zip");
        FileOutputStream out = new FileOutputStream(zipFile);
        ZipOutputStream zipOutStream = new ZipOutputStream(out);

        ZipEntry certZipEntry = new ZipEntry("users.xml");
        zipOutStream.putNextEntry(certZipEntry);
        try
        {
            zipOutStream.write(bout.toByteArray());
        }finally
        {
            zipOutStream.closeEntry();
        }

        zipOutStream.close();

        zipFile.renameTo(new File(zipFilename));
    }

}
