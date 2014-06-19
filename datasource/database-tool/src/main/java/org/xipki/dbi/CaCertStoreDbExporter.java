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
import java.io.InputStream;
import java.sql.Blob;
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
import org.xipki.database.api.DataSource;
import org.xipki.dbi.ca.jaxb.CainfoType;
import org.xipki.dbi.ca.jaxb.CertStoreType;
import org.xipki.dbi.ca.jaxb.CertStoreType.Cainfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.Certprofileinfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ca.jaxb.CertStoreType.Crls;
import org.xipki.dbi.ca.jaxb.CertStoreType.Requestorinfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.UsersFiles;
import org.xipki.dbi.ca.jaxb.CertType;
import org.xipki.dbi.ca.jaxb.CertprofileinfoType;
import org.xipki.dbi.ca.jaxb.CertsType;
import org.xipki.dbi.ca.jaxb.CrlType;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.dbi.ca.jaxb.RequestorinfoType;
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

    CaCertStoreDbExporter(DataSource dataSource, Marshaller marshaller, String baseDir,
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
            export_certprofileinfo(certstore);
            export_user(certstore);
            export_crl(certstore);
            export_cert(certstore);

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

                    Blob blob = rs.getBlob("CRL");
                    byte[] encodedCrl = readBlob(blob);
                    rs.close();

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
            rs = null;
        }finally
        {
            closeStatement(stmt);
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
        try
        {
            stmt = createStatement();
            String sql = "SELECT ID, CERT FROM CAINFO";
            ResultSet rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String cert = rs.getString("CERT");

                CainfoType cainfo = new CainfoType();
                cainfo.setId(id);
                cainfo.setCert(cert);

                cainfos.getCainfo().add(cainfo);
            }

            rs.close();
            rs = null;
        }finally
        {
            closeStatement(stmt);
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
        try
        {
            stmt = createStatement();
            String sql = "SELECT ID, NAME FROM REQUESTORINFO";
            ResultSet rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String name = rs.getString("NAME");

                RequestorinfoType info = new RequestorinfoType();
                info.setId(id);
                info.setName(name);

                infos.getRequestorinfo().add(info);
            }

            rs.close();
            rs = null;
        }finally
        {
            closeStatement(stmt);
        }

        certstore.setRequestorinfos(infos);
        System.out.println(" Exported table REQUESTORINFO");
    }

    private void export_user(CertStoreType certstore)
    throws SQLException, JAXBException
    {
        System.out.println("Exporting table USER");
        UsersFiles usersFiles = new UsersFiles();

        String sql = "SELECT ID, NAME FROM USER" +
                " WHERE ID >= ? AND ID < ?" +
                " ORDER BY ID ASC";

        PreparedStatement ps = prepareStatement(sql);

        final int minId = getMinCertId("USER");
        final int maxId = getMaxCertId("USER");

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
            }

            if(numUsersInCurrentFile > 0)
            {
                String currentCertsFilename = DbiUtil.buildFilename("users_", ".xml",
                        minIdOfCurrentFile, maxIdOfCurrentFile, maxId);

                JAXBElement<UsersType> root = new ObjectFactory().createUsers(usersInCurrentFile);
                marshaller.marshal(root, new File(baseDir + File.separator + currentCertsFilename));

                usersFiles.getUsersFile().add(currentCertsFilename);

                System.out.println(" Exported " + numUsersInCurrentFile + " certificates in " + currentCertsFilename);
            }

        }finally
        {
            closeStatement(ps);
        }

        certstore.setUsersFiles(usersFiles);
        System.out.println(" Exported " + sum + " users from table USER");
    }

    private void export_certprofileinfo(CertStoreType certstore)
    throws SQLException
    {
        System.out.println("Exporting table CERTPROFILEINFO");
        Certprofileinfos infos = new Certprofileinfos();

        Statement stmt = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT ID, NAME FROM CERTPROFILEINFO";
            ResultSet rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String name = rs.getString("NAME");

                CertprofileinfoType info = new CertprofileinfoType();
                info.setId(id);
                info.setName(name);

                infos.getCertprofileinfo().add(info);
            }

            rs.close();
            rs = null;
        }finally
        {
            closeStatement(stmt);
        }

        certstore.setCertprofileinfos(infos);
        System.out.println(" Exported table CERTPROFILEINFO");
    }

    private void export_cert(CertStoreType certstore)
    throws SQLException, IOException, JAXBException
    {
        System.out.println("Exporting tables CERT and RAWCERT");
        CertsFiles certsFiles = new CertsFiles();

        String certSql = "SELECT ID, CAINFO_ID, CERTPROFILEINFO_ID," +
                " REQUESTORINFO_ID, LAST_UPDATE, REVOKED," +
                " REV_REASON, REV_TIME, REV_INVALIDITY_TIME, USER_ID" +
                " FROM CERT" +
                " WHERE ID >= ? AND ID < ?" +
                " ORDER BY ID ASC";

        PreparedStatement ps = prepareStatement(certSql);

        String rawCertSql = "SELECT CERT FROM RAWCERT WHERE CERT_ID = ?";
        PreparedStatement rawCertPs = prepareStatement(rawCertSql);

        final int minId = getMinCertId("CERT");
        final int maxId = getMaxCertId("CERT");

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

                    String cainfo_id = rs.getString("CAINFO_ID");
                    String certprofileinfo_id = rs.getString("CERTPROFILEINFO_ID");
                    String requestorinfo_id = rs.getString("REQUESTORINFO_ID");
                    String last_update = rs.getString("LAST_UPDATE");
                    boolean revoked = rs.getBoolean("REVOKED");
                    String rev_reason = rs.getString("REV_REASON");
                    String rev_time = rs.getString("REV_TIME");
                    String rev_invalidity_time = rs.getString("REV_INVALIDITY_TIME");
                    String user_id = rs.getString("USER_ID");

                    String sha1_fp_cert;
                    rawCertPs.setInt(1, id);
                    ResultSet rawCertRs = rawCertPs.executeQuery();
                    try
                    {
                        if(rawCertRs.next())
                        {
                            String b64Cert = rawCertRs.getString("CERT");
                            byte[] cert = Base64.decode(b64Cert);
                            sha1_fp_cert = IoCertUtil.sha1sum(cert);

                            ZipEntry certZipEntry = new ZipEntry(sha1_fp_cert + ".der");
                            currentCertsZip.putNextEntry(certZipEntry);
                            try
                            {
                                currentCertsZip.write(cert);
                            }finally
                            {
                                currentCertsZip.closeEntry();
                            }
                        }
                        else
                        {
                            String msg = "Found no certificate in table RAWCERT for cert_id '" + id + "'";
                            LOG.error(msg);
                            System.out.println(msg);
                            continue;
                        }
                    }finally
                    {
                        rawCertRs.close();
                    }

                    CertType cert = new CertType();
                    cert.setId(id);
                    cert.setCainfoId(cainfo_id);
                    cert.setCertprofileinfoId(certprofileinfo_id);
                    cert.setRequestorinfoId(requestorinfo_id);
                    cert.setLastUpdate(last_update);
                    cert.setRevoked(revoked);
                    cert.setRevReason(rev_reason);
                    cert.setRevTime(rev_time);
                    cert.setRevInvalidityTime(rev_invalidity_time);
                    cert.setUserId(user_id);
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
            closeStatement(ps);
        }

        certstore.setCertsFiles(certsFiles);
        System.out.println(" Exported " + sum + " certificates from tables CERT and RAWCERT");
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

    private int getMinCertId(String table)
    throws SQLException
    {
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            final String sql = "SELECT MIN(ID) FROM " + table;
            ResultSet rs = stmt.executeQuery(sql);

            rs.next();
            int minCertId = rs.getInt(1);

            rs.close();
            rs = null;

            return minCertId;
        }finally
        {
            closeStatement(stmt);
        }
    }

    private int getMaxCertId(String table)
    throws SQLException
    {
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            final String sql = "SELECT MAX(ID) FROM " + table;
            ResultSet rs = stmt.executeQuery(sql);

            rs.next();
            int maxCertId = rs.getInt(1);

            rs.close();
            rs = null;

            return maxCertId;
        }finally
        {
            closeStatement(stmt);
        }
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

    private static byte[] readBlob(Blob blob)
    {
        InputStream is;
        try
        {
            is = blob.getBinaryStream();
        } catch (SQLException e)
        {
            String msg = "Could not getBinaryStream from Blob";
            LOG.warn(msg + " {}", e.getMessage());
            LOG.debug(msg, e);
            return null;
        }
        try
        {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            byte[] buffer = new byte[2048];
            int readed;

            try
            {
                while((readed = is.read(buffer)) != -1)
                {
                    if(readed > 0)
                    {
                        out.write(buffer, 0, readed);
                    }
                }
            } catch (IOException e)
            {
                String msg = "Could not read CRL from Blob";
                LOG.warn(msg + " {}", e.getMessage());
                LOG.debug(msg, e);
                return null;
            }

            return out.toByteArray();
        }finally
        {
            try
            {
                is.close();
            }catch(IOException e)
            {
            }
        }
    }

}
