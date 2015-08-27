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
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.dbtool.InvalidInputException;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Cas;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.CertsFiles;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Crls;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.DeltaCRLCache;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Profiles;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.PublishQueue;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Publishers;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Requestors;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.UsersFiles;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertsType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertstoreCaType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CrlType;
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

class CaCertStoreDbExporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(CaCertStoreDbExporter.class);

    private final Marshaller marshaller;
    private final Unmarshaller unmarshaller;
    private final ObjectFactory objFact = new ObjectFactory();

    private final int numCertsInBundle;
    private final int numCertsPerSelect;
    private final int numCrls;
    private final boolean resume;

    CaCertStoreDbExporter(
            final DataSourceWrapper dataSource,
            final Marshaller marshaller,
            final Unmarshaller unmarshaller,
            final String baseDir,
            final int numCertsInBundle,
            final int numCrls,
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
        if(numCrls < 1)
        {
            throw new IllegalArgumentException("numCrls could not be less than 1: " + numCrls);
        }

        this.numCertsInBundle = numCertsInBundle;
        this.numCertsPerSelect = numCertsInBundle;
        this.numCrls = numCrls;

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

    private void export_crl(
            final CertStoreType certstore)
    throws DataAccessException, IOException
    {
        System.out.println(getExportingText() + "table CRL");
        Crls crls = new Crls();
        final String sql = "SELECT ID, CA_ID FROM CRL";

        Statement stmt = null;
        try
        {
            stmt = createStatement();

            ResultSet rs = stmt.executeQuery(sql);

            Map<Integer, List<Integer>> idMap = new HashMap<>();

            while(rs.next())
            {
                int id = rs.getInt("ID");
                int cainfo_id = rs.getInt("CA_ID");
                List<Integer> ids = idMap.get(cainfo_id);
                if(ids == null)
                {
                    ids = new LinkedList<>();
                    idMap.put(cainfo_id, ids);
                }
                ids.add(id);
            }
            rs.close();

            Set<Integer> ca_ids = idMap.keySet();
            for(Integer ca_id : ca_ids)
            {
                List<Integer> ids = idMap.get(ca_id);
                if(CollectionUtil.isEmpty(ids))
                {
                    continue;
                }

                Collections.sort(ids);
                int startIndex = Math.max(0, ids.size() - numCrls);
                for(int i = startIndex; i < ids.size(); i++)
                {
                    int id = ids.get(i);
                    rs = stmt.executeQuery("SELECT CRL FROM CRL WHERE ID=" + id);
                    if(rs.next() == false)
                    {
                        continue;
                    }

                    String b64Crl = rs.getString("CRL");
                    rs.close();
                    byte[] encodedCrl = Base64.decode(b64Crl);
                    String hexSha1 = HashCalculator.hexSha1(encodedCrl);

                    if(evaulateOnly == false)
                    {
                        File f = new File(baseDir, "CRL" + File.separator + hexSha1 + ".crl");
                        IoUtil.save(f, encodedCrl);
                    }

                    CrlType crl = new CrlType();

                    crl.setId(id);
                    crl.setCaId(ca_id);
                    crl.setCrlFile("CRL/" + hexSha1 + ".crl");

                    crls.getCrl().add(crl);
                }
            }

            rs.close();
            rs = null;
        } catch(SQLException e)
        {
            throw translate(sql, e);
        }
        finally
        {
            releaseResources(stmt, null);
        }

        certstore.setCrls(crls);
        System.out.println(getExportedText() + "table CRL");
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

    private void export_user(
            final CertStoreType certstore)
    throws DataAccessException, JAXBException
    {
        System.out.println(getExportingText() + "table USERNAME");
        UsersFiles usersFiles = new UsersFiles();

        final String tableName = "USERNAME";
        final int minId = (int) getMin(tableName, "ID");
        String coreSql = "ID, NAME, PASSWORD, CN_REGEX FROM " + tableName + " WHERE ID >= ?";
        final int rows = 100;
        final String sql = dataSource.createFetchFirstSelectSQL(coreSql, rows, "ID ASC");

        PreparedStatement ps = prepareStatement(sql);

        int numUsersInCurrentFile = 0;
        UsersType usersInCurrentFile = new UsersType();

        int sum = 0;

        int minIdOfCurrentFile = -1;
        int maxIdOfCurrentFile = -1;

        try
        {
            int startId = minId;
            while(true)
            {
                ps.setInt(1, startId);
                ResultSet rs = ps.executeQuery();
                int n = 0;

                while(rs.next())
                {
                    n++;

                    int id = rs.getInt("ID");
                    startId = id + 1;

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

                    if(numUsersInCurrentFile == numCertsInBundle * 10)
                    {
                        String currentUsersFilename = "users_" + minIdOfCurrentFile + "_" + maxIdOfCurrentFile + ".xml";

                        JAXBElement<UsersType> root = new ObjectFactory().createUsers(usersInCurrentFile);
                        marshaller.marshal(root, new File(baseDir + File.separator + currentUsersFilename));

                        if(evaulateOnly == false)
                        {
                            usersFiles.getUsersFile().add(currentUsersFilename);
                        }

                        System.out.println(" exported " +
                                numUsersInCurrentFile + " users in " + currentUsersFilename);
                        System.out.println(" exported " + sum + " users ...");

                        // reset
                        usersInCurrentFile = new UsersType();
                        numUsersInCurrentFile = 0;
                        minIdOfCurrentFile = -1;
                        maxIdOfCurrentFile = -1;
                    }
                } // end while(rs.next)

                try
                {
                    rs.close();
                } catch(SQLException e)
                {
                }

                if(n == 0)
                {
                    break;
                }
            } // end while(true)

            if(numUsersInCurrentFile > 0)
            {
                String currentCertsFilename = "users_" + minIdOfCurrentFile + "_" + maxIdOfCurrentFile + ".xml";

                JAXBElement<UsersType> root = new ObjectFactory().createUsers(usersInCurrentFile);
                marshaller.marshal(root, new File(baseDir + File.separator + currentCertsFilename));

                usersFiles.getUsersFile().add(currentCertsFilename);

                System.out.println(getExportedText() + numUsersInCurrentFile + " users in " + currentCertsFilename);
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(ps, null);
        }

        certstore.setUsersFiles(usersFiles);
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
        try
        {
            do_export_cert(certstore, processLogFile);
            return null;
        }catch(DataAccessException | IOException | JAXBException | InterruptedException e)
        {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-certs-");
            System.err.println("\nexporting table CERT and CRAW has been cancelled due to error,\n"
                    + "please continue with the option '--resume'");
            LOG.error("Exception", e);
            return e;
        }
    }

    private void do_export_cert(
            final CertStoreType certstore,
            final File processLogFile)
    throws DataAccessException, IOException, JAXBException, InterruptedException
    {
        CertsFiles certsFiles = certstore.getCertsFiles();
        int numProcessedBefore = 0;
        if(certsFiles == null)
        {
            certsFiles = new CertsFiles();
            certstore.setCertsFiles(certsFiles);
        }
        else
        {
            numProcessedBefore = (int) certsFiles.getCountCerts();
        }

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
        certSql.append("ART, RTYPE, TID, UNAME, UPDATE, REV, RR, RT, RIT, FP_RS ");
        certSql.append("FROM CERT WHERE ID >= ? AND ID < ? ORDER BY ID ASC");

        PreparedStatement ps = prepareStatement(certSql.toString());

        final String rawCertSql = "SELECT CID, REQ_SUBJECT, CERT FROM CRAW WHERE CID >= ? AND CID < ?";
        PreparedStatement rawCertPs = prepareStatement(rawCertSql);

        int numCertsInCurrentFile = 0;
        CertsType certsInCurrentFile = new CertsType();

        long sum = 0;
        final int n = numCertsPerSelect;

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
            for(int i = minId; i <= maxId; i += n)
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
                rawCertPs.setInt(2, i + n);
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
                ps.setInt(2, i + n);

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
                    cert.setSerial(Long.toHexString(serial));

                    int certprofile_id = rs.getInt("PID");
                    cert.setProfileId(certprofile_id);

                    int requestorinfo_id = rs.getInt("RID");
                    if(requestorinfo_id != 0)
                    {
                        cert.setRequestorId(requestorinfo_id);
                    }

                    long last_update = rs.getLong("UPDATE");
                    cert.setLastUpdate(last_update);

                    boolean revoked = rs.getBoolean("REV");
                    cert.setRevoked(revoked);

                    if(revoked)
                    {
                        int rev_reason = rs.getInt("RR");
                        long rev_time = rs.getLong("RT");
                        long rev_inv_time = rs.getLong("RIT");
                        cert.setRevReason(rev_reason);
                        cert.setRevTime(rev_time);
                        if(rev_inv_time != 0)
                        {
                            cert.setRevInvTime(rev_inv_time);
                        }
                    }

                    String user = rs.getString("UNAME");
                    if(user != null)
                    {
                        cert.setUser(user);
                    }
                    cert.setCertFile(sha1_cert + ".der");

                    long fpReqSubject = rs.getLong("FP_RS");
                    if(fpReqSubject != 0)
                    {
                        cert.setFpReqSubject(fpReqSubject);
                        String reqSubject = reqSubjectMaps.remove(id);
                        cert.setReqSubject(reqSubject);
                    }

                    certsInCurrentFile.getCert().add(cert);
                    numCertsInCurrentFile ++;
                    sum ++;

                    if(numCertsInCurrentFile == numCertsInBundle)
                    {
                        String currentCertsFilename = DbiUtil.buildFilename("certs_", ".zip",
                                minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
                        finalizeZip(currentCertsZip, certsInCurrentFile);
                        currentCertsZipFile.renameTo(new File(baseDir, currentCertsFilename));

                        certsFiles.getCertsFile().add(currentCertsFilename);
                        certsFiles.setCountCerts(numProcessedBefore + sum);
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
                throw new InterruptedException("interrupted by the user");
            }

            if(numCertsInCurrentFile > 0)
            {
                finalizeZip(currentCertsZip, certsInCurrentFile);

                String currentCertsFilename = DbiUtil.buildFilename("certs_", ".zip",
                        minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
                currentCertsZipFile.renameTo(new File(baseDir, currentCertsFilename));

                certsFiles.getCertsFile().add(currentCertsFilename);
                certsFiles.setCountCerts(numProcessedBefore + sum);
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

    private static NameIdType createNameId(
            final String name,
            final int id)
    {
        NameIdType info = new NameIdType();
        info.setId(id);
        info.setName(name);
        return info;
    }

}
