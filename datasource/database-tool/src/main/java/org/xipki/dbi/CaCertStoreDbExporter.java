/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.dbi;

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
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.dbi.ca.jaxb.CainfoType;
import org.xipki.dbi.ca.jaxb.CertStoreType;
import org.xipki.dbi.ca.jaxb.CertStoreType.Cainfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.Certprofileinfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ca.jaxb.CertStoreType.Crls;
import org.xipki.dbi.ca.jaxb.CertStoreType.PublishQueue;
import org.xipki.dbi.ca.jaxb.CertStoreType.Publisherinfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.Requestorinfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.UsersFiles;
import org.xipki.dbi.ca.jaxb.CertType;
import org.xipki.dbi.ca.jaxb.CertsType;
import org.xipki.dbi.ca.jaxb.CrlType;
import org.xipki.dbi.ca.jaxb.NameIdType;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.dbi.ca.jaxb.ToPublishType;
import org.xipki.dbi.ca.jaxb.UserType;
import org.xipki.dbi.ca.jaxb.UsersType;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class CaCertStoreDbExporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(CaCertStoreDbExporter.class);
    private final Marshaller marshaller;
    private final SHA1Digest sha1md = new SHA1Digest();
    private final ObjectFactory objFact = new ObjectFactory();

    private final int numCertsInBundle;
    private final int numCrls;

    CaCertStoreDbExporter(DataSourceWrapper dataSource, Marshaller marshaller, String baseDir,
            int numCertsInBundle, int numCrls)
    throws SQLException, PasswordResolverException, IOException
    {
        super(dataSource, baseDir);
        ParamChecker.assertNotNull("marshaller", marshaller);
        if(numCertsInBundle < 1)
        {
            numCertsInBundle = 1;
        }
        this.numCertsInBundle = numCertsInBundle;

        if(numCrls < 1)
        {
            numCrls = 1;
        }
        this.numCrls = numCrls;

        this.marshaller = marshaller;
    }

    public void export()
    throws Exception
    {
        CertStoreType certstore = new CertStoreType();
        certstore.setVersion(VERSION);
        System.out.println("Exporting CA certstore from database");
        try
        {
            export_cainfo(certstore);
            export_requestorinfo(certstore);
            export_publisherinfo(certstore);
            export_certprofileinfo(certstore);
            export_user(certstore);
            export_crl(certstore);
            export_cert(certstore);
            export_publishQueue(certstore);

            JAXBElement<CertStoreType> root = new ObjectFactory().createCertStore(certstore);
            marshaller.marshal(root, new File(baseDir + File.separator + FILENAME_CA_CertStore));
        }catch(Exception e)
        {
            System.err.println("Error while exporting CA certstore from database");
            throw e;
        }
        System.out.println(" Exported CA certstore from database");
    }

    private void export_crl(CertStoreType certstore)
    throws Exception
    {
        System.out.println("Exporting table CRL");
        Crls crls = new Crls();
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT ID, CAINFO_ID FROM CRL";
            ResultSet rs = stmt.executeQuery(sql);

            Map<Integer, List<Integer>> idMap = new HashMap<>();

            while(rs.next())
            {
                int id = rs.getInt("ID");
                int cainfo_id = rs.getInt("CAINFO_ID");
                List<Integer> ids = idMap.get(cainfo_id);
                if(ids == null)
                {
                    ids = new LinkedList<>();
                    idMap.put(cainfo_id, ids);
                }
                ids.add(id);
            }
            rs.close();

            Set<Integer> cainfo_ids = idMap.keySet();
            for(Integer cainfo_id : cainfo_ids)
            {
                List<Integer> ids = idMap.get(cainfo_id);
                if(ids.isEmpty())
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

                    String fp = fp(encodedCrl);
                    File f = new File(baseDir, "CRL" + File.separator + fp + ".crl");
                    IoCertUtil.save(f, encodedCrl);

                    CrlType crl = new CrlType();

                    crl.setId(id);
                    crl.setCainfoId(cainfo_id);
                    crl.setCrlFile("CRL/" + fp + ".crl");

                    crls.getCrl().add(crl);
                }
            }

            rs.close();
            rs = null;
        }finally
        {
            releaseResources(stmt, null);
        }

        certstore.setCrls(crls);
        System.out.println(" Exported table CRL");
    }

    private void export_cainfo(CertStoreType certstore)
    throws SQLException
    {
        System.out.println("Exporting table CAINFO");
        Cainfos cainfos = new Cainfos();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT ID, CERT FROM CAINFO";
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String cert = rs.getString("CERT");

                CainfoType cainfo = new CainfoType();
                cainfo.setId(id);
                cainfo.setCert(cert);

                cainfos.getCainfo().add(cainfo);
            }
        }finally
        {
            releaseResources(stmt, rs);
        }

        certstore.setCainfos(cainfos);
        System.out.println(" Exported table CAINFO");
    }

    private void export_requestorinfo(CertStoreType certstore)
    throws SQLException
    {
        System.out.println("Exporting table REQUESTORINFO");
        Requestorinfos infos = new Requestorinfos();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT ID, NAME FROM REQUESTORINFO";
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String name = rs.getString("NAME");

                NameIdType info = createNameId(name, id);
                infos.getRequestorinfo().add(info);
            }
        }finally
        {
            releaseResources(stmt, rs);
        }

        certstore.setRequestorinfos(infos);
        System.out.println(" Exported table REQUESTORINFO");
    }

    private void export_publisherinfo(CertStoreType certstore)
    throws SQLException
    {
        System.out.println("Exporting table PUBLISHERINFO");
        Publisherinfos infos = new Publisherinfos();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT ID, NAME FROM PUBLISHERINFO";
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String name = rs.getString("NAME");

                NameIdType info = createNameId(name, id);
                infos.getPublisherinfo().add(info);
            }
        }finally
        {
            releaseResources(stmt, rs);
        }

        certstore.setPublisherinfos(infos);
        System.out.println(" Exported table PUBLISHERINFO");
    }

    private void export_user(CertStoreType certstore)
    throws SQLException, JAXBException
    {
        System.out.println("Exporting table USERNAME");
        UsersFiles usersFiles = new UsersFiles();

        String tableName = "USERNAME";

        final int minId = getMin(tableName, "ID");
        final int maxId = getMax(tableName, "ID");

        String sql = "SELECT ID, NAME FROM " + tableName +
                " WHERE ID >= ? AND ID < ?" +
                " ORDER BY ID ASC";

        PreparedStatement ps = prepareStatement(sql);

        int numUsersInCurrentFile = 0;
        UsersType usersInCurrentFile = new UsersType();

        int sum = 0;
        final int n = 100;

        int minIdOfCurrentFile = -1;
        int maxIdOfCurrentFile = -1;

        try
        {
            for(int i = minId; i <= maxId; i += n)
            {
                ps.setInt(1, i);
                ps.setInt(2, i + n);

                ResultSet rs = ps.executeQuery();

                while(rs.next())
                {
                    int id = rs.getInt("ID");

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
                    usersInCurrentFile.getUser().add(user);

                    numUsersInCurrentFile ++;
                    sum ++;

                    if(numUsersInCurrentFile == numCertsInBundle * 10)
                    {
                        String currentCertsFilename = DbiUtil.buildFilename("users_", ".xml",
                                minIdOfCurrentFile, maxIdOfCurrentFile, maxId);

                        JAXBElement<UsersType> root = new ObjectFactory().createUsers(usersInCurrentFile);
                        marshaller.marshal(root, new File(baseDir + File.separator + currentCertsFilename));

                        usersFiles.getUsersFile().add(currentCertsFilename);

                        System.out.println(" Exported " + numUsersInCurrentFile + " users in " + currentCertsFilename);
                        System.out.println(" Exported " + sum + " users ...");

                        // reset
                        usersInCurrentFile = new UsersType();
                        numUsersInCurrentFile = 0;
                        minIdOfCurrentFile = -1;
                        maxIdOfCurrentFile = -1;
                    }
                }

                try
                {
                    rs.close();
                } catch(SQLException e)
                {
                }
            }

            if(numUsersInCurrentFile > 0)
            {
                String currentCertsFilename = DbiUtil.buildFilename("users_", ".xml",
                        minIdOfCurrentFile, maxIdOfCurrentFile, maxId);

                JAXBElement<UsersType> root = new ObjectFactory().createUsers(usersInCurrentFile);
                marshaller.marshal(root, new File(baseDir + File.separator + currentCertsFilename));

                usersFiles.getUsersFile().add(currentCertsFilename);

                System.out.println(" Exported " + numUsersInCurrentFile + " users in " + currentCertsFilename);
            }

        }finally
        {
            releaseResources(ps, null);
        }

        certstore.setUsersFiles(usersFiles);
        System.out.println(" Exported " + sum + " users from table USERNAME");
    }

    private void export_certprofileinfo(CertStoreType certstore)
    throws SQLException
    {
        System.out.println("Exporting table CERTPROFILEINFO");
        Certprofileinfos infos = new Certprofileinfos();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT ID, NAME FROM CERTPROFILEINFO";
            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String name = rs.getString("NAME");

                NameIdType info = createNameId(name, id);
                infos.getCertprofileinfo().add(info);
            }
        }finally
        {
            releaseResources(stmt, rs);
        }

        certstore.setCertprofileinfos(infos);
        System.out.println(" Exported table CERTPROFILEINFO");
    }

    private void export_cert(CertStoreType certstore)
    throws SQLException, IOException, JAXBException
    {
        System.out.println("Exporting tables CERT and RAWCERT");
        CertsFiles certsFiles = new CertsFiles();

        final int minId = getMin("CERT", "ID");
        final int maxId = getMax("CERT", "ID");

        String certSql = "SELECT ID, CAINFO_ID, CERTPROFILEINFO_ID," +
                " REQUESTORINFO_ID, LAST_UPDATE, REVOKED," +
                " REV_REASON, REV_TIME, REV_INVALIDITY_TIME, USER_ID" +
                " FROM CERT" +
                " WHERE ID >= ? AND ID < ?" +
                " ORDER BY ID ASC";

        PreparedStatement ps = prepareStatement(certSql);

        String rawCertSql = "SELECT CERT_ID, CERT FROM RAWCERT WHERE CERT_ID >= ? AND CERT_ID < ?";
        PreparedStatement rawCertPs = prepareStatement(rawCertSql);

        int numCertsInCurrentFile = 0;
        CertsType certsInCurrentFile = new CertsType();

        int sum = 0;
        final int n = 100;

        File currentCertsZipFile = new File(baseDir, "tmp-certs-" + System.currentTimeMillis() + ".zip");
        FileOutputStream out = new FileOutputStream(currentCertsZipFile);
        ZipOutputStream currentCertsZip = new ZipOutputStream(out);

        int minIdOfCurrentFile = -1;
        int maxIdOfCurrentFile = -1;

        try
        {
            for(int i = minId; i <= maxId; i += n)
            {
                Map<Integer, byte[]> rawCertMaps = new HashMap<>();

                // retrieve raw certificates
                rawCertPs.setInt(1, i);
                rawCertPs.setInt(2, i + n);
                ResultSet rawCertRs = rawCertPs.executeQuery();
                while(rawCertRs.next())
                {
                    int certId = rawCertRs.getInt("CERT_ID");
                    String b64Cert = rawCertRs.getString("CERT");
                    byte[] certBytes = Base64.decode(b64Cert);
                    rawCertMaps.put(certId, certBytes);
                }
                rawCertRs.close();

                ps.setInt(1, i);
                ps.setInt(2, i + n);

                ResultSet rs = ps.executeQuery();

                while(rs.next())
                {
                    int id = rs.getInt("ID");

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
                        String msg = "Found no certificate in table RAWCERT for cert_id '" + id + "'";
                        LOG.error(msg);
                        System.out.println(msg);
                        continue;
                    }

                    String sha1_fp_cert = IoCertUtil.sha1sum(certBytes);

                    ZipEntry certZipEntry = new ZipEntry(sha1_fp_cert + ".der");
                    currentCertsZip.putNextEntry(certZipEntry);
                    try
                    {
                        currentCertsZip.write(certBytes);
                    }finally
                    {
                        currentCertsZip.closeEntry();
                    }

                    CertType cert = new CertType();
                    cert.setId(id);

                    int cainfo_id = rs.getInt("CAINFO_ID");
                    cert.setCainfoId(cainfo_id);

                    int certprofileinfo_id = rs.getInt("CERTPROFILEINFO_ID");
                    cert.setCertprofileinfoId(certprofileinfo_id);

                    int requestorinfo_id = rs.getInt("REQUESTORINFO_ID");
                    if(requestorinfo_id != 0)
                    {
                        cert.setRequestorinfoId(requestorinfo_id);
                    }

                    long last_update = rs.getLong("LAST_UPDATE");
                    cert.setLastUpdate(last_update);

                    boolean revoked = rs.getBoolean("REVOKED");
                    cert.setRevoked(revoked);

                    if(revoked)
                    {
                        int rev_reason = rs.getInt("REV_REASON");
                        long rev_time = rs.getLong("REV_TIME");
                        long rev_invalidity_time = rs.getLong("REV_INVALIDITY_TIME");
                        cert.setRevReason(rev_reason);
                        cert.setRevTime(rev_time);
                        if(rev_invalidity_time != 0)
                        {
                            cert.setRevInvalidityTime(rev_invalidity_time);
                        }
                    }

                    int user_id = rs.getInt("USER_ID");
                    if(user_id != 0)
                    {
                        cert.setUserId(user_id);
                    }
                    cert.setCertFile(sha1_fp_cert + ".der");

                    certsInCurrentFile.getCert().add(cert);
                    numCertsInCurrentFile ++;
                    sum ++;

                    if(numCertsInCurrentFile == numCertsInBundle)
                    {
                        finalizeZip(currentCertsZip, certsInCurrentFile);

                        String currentCertsFilename = DbiUtil.buildFilename("certs_", ".zip",
                                minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
                        currentCertsZipFile.renameTo(new File(baseDir, currentCertsFilename));

                        certsFiles.getCertsFile().add(currentCertsFilename);

                        System.out.println(" Exported " + numCertsInCurrentFile + " certificates in " + currentCertsFilename);
                        System.out.println(" Exported " + sum + " certificates ...");

                        // reset
                        certsInCurrentFile = new CertsType();
                        numCertsInCurrentFile = 0;
                        minIdOfCurrentFile = -1;
                        maxIdOfCurrentFile = -1;
                        currentCertsZipFile = new File(baseDir, "tmp-certs-" + System.currentTimeMillis() + ".zip");
                        out = new FileOutputStream(currentCertsZipFile);
                        currentCertsZip = new ZipOutputStream(out);
                    }
                }

                rawCertMaps.clear();
                rawCertMaps = null;
            }

            if(numCertsInCurrentFile > 0)
            {
                finalizeZip(currentCertsZip, certsInCurrentFile);

                String currentCertsFilename = DbiUtil.buildFilename("certs_", ".zip",
                        minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
                currentCertsZipFile.renameTo(new File(baseDir, currentCertsFilename));

                certsFiles.getCertsFile().add(currentCertsFilename);

                System.out.println(" Exported " + numCertsInCurrentFile + " certificates in " + currentCertsFilename);
            }
            else
            {
                currentCertsZip.close();
                currentCertsZipFile.delete();
            }

        }finally
        {
            releaseResources(ps, null);
        }

        certstore.setCertsFiles(certsFiles);
        System.out.println(" Exported " + sum + " certificates from tables CERT and RAWCERT");
    }

    private void export_publishQueue(CertStoreType certstore)
    throws SQLException, IOException, JAXBException
    {
        System.out.println("Exporting table PUBLISHQUEUE");

        String sql = "SELECT CERT_ID, PUBLISHER_ID, CAINFO_ID" +
                " FROM PUBLISHQUEUE" +
                " WHERE CERT_ID >= ? AND CERT_ID < ?" +
                " ORDER BY CERT_ID ASC";

        final int minId = getMin("PUBLISHQUEUE", "CERT_ID");
        final int maxId = getMax("PUBLISHQUEUE", "CERT_ID");

        PreparedStatement ps = prepareStatement(sql);
        ResultSet rs = null;

        PublishQueue queue = new PublishQueue();
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
                    int cert_id = rs.getInt("CERT_ID");
                    int pub_id = rs.getInt("PUBLISHER_ID");
                    int ca_id = rs.getInt("CAINFO_ID");

                    ToPublishType toPub = new ToPublishType();
                    toPub.setPubId(pub_id);
                    toPub.setCertId(cert_id);
                    toPub.setCaId(ca_id);
                    list.add(toPub);
                }
            }
        }finally
        {
            releaseResources(ps, rs);
        }

        certstore.setPublishQueue(queue);
        System.out.println(" Exported table PUBLISHQUEUE");
    }

    private void finalizeZip(ZipOutputStream zipOutStream, CertsType certsType)
    throws JAXBException, IOException
    {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        marshaller.marshal(objFact.createCerts(certsType), bout);
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

    private String fp(byte[] data)
    {
        synchronized (sha1md)
        {
            sha1md.reset();
            sha1md.update(data, 0, data.length);
            byte[] digestValue = new byte[20];
            sha1md.doFinal(digestValue, 0);
            return Hex.toHexString(digestValue).toUpperCase();
        }
    }

    private static NameIdType createNameId(String name, int id)
    {
        NameIdType info = new NameIdType();
        info.setId(id);
        info.setName(name);
        return info;
    }

}
