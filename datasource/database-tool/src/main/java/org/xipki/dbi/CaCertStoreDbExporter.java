/*
 * Copyright 2014 xipki.org
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
import org.xipki.dbi.ca.jaxb.CertStoreType.Users;
import org.xipki.dbi.ca.jaxb.CertType;
import org.xipki.dbi.ca.jaxb.CertprofileinfoType;
import org.xipki.dbi.ca.jaxb.CertsType;
import org.xipki.dbi.ca.jaxb.CrlType;
import org.xipki.dbi.ca.jaxb.ObjectFactory;
import org.xipki.dbi.ca.jaxb.RequestorinfoType;
import org.xipki.dbi.ca.jaxb.UserType;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

class CaCertStoreDbExporter extends DbPorter
{

    private static final Logger LOG = LoggerFactory.getLogger(CaCertStoreDbExporter.class);
    private final Marshaller marshaller;
    private final SHA1Digest sha1md = new SHA1Digest();
    private final ObjectFactory objFact = new ObjectFactory();

    private final int numCertsInBundle;

    CaCertStoreDbExporter(DataSource dataSource, Marshaller marshaller, String baseDir, int numCertsInBundle)
    throws SQLException, PasswordResolverException, IOException
    {
        super(dataSource, baseDir);
        ParamChecker.assertNotNull("marshaller", marshaller);
        if(numCertsInBundle < 1)
        {
            numCertsInBundle = 1;
        }
        this.numCertsInBundle = numCertsInBundle;

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
            certstore.setCainfos(export_cainfo());
            certstore.setRequestorinfos(export_requestorinfo());
            certstore.setCertprofileinfos(export_certprofileinfo());
            certstore.setUsers(export_user());
            certstore.setCrls(export_crl());
            certstore.setCertsFiles(export_cert());

            JAXBElement<CertStoreType> root = new ObjectFactory().createCertStore(certstore);
            marshaller.marshal(root, new File(baseDir + File.separator + FILENAME_CA_CertStore));
        }catch(Exception e)
        {
            System.err.println("Error while exporting CA certstore from database");
            throw e;
        }
        System.out.println(" Exported CA certstore from database");
    }

    private Crls export_crl()
    throws Exception
    {
        System.out.println("Exporting table crl");
        Crls crls = new Crls();
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT id, cainfo_id, crl FROM crl";
            ResultSet rs = stmt.executeQuery(sql);

            File crlDir = new File(baseDir + File.separator + DIRNAME_CRL);
            while(rs.next())
            {
                int id = rs.getInt("id");
                int cainfo_id = rs.getInt("cainfo_id");
                Blob blob = rs.getBlob("crl");

                byte[] encodedCrl = readBlob(blob);
                String fp = fp(encodedCrl);
                File f = new File(crlDir, fp);
                IoCertUtil.save(f, encodedCrl);

                CrlType crl = new CrlType();

                crl.setId(id);
                crl.setCainfoId(cainfo_id);
                crl.setCrlFile("CRL/" + fp);

                crls.getCrl().add(crl);
            }

            rs.close();
            rs = null;
        }finally
        {
            closeStatement(stmt);
        }

        System.out.println(" Exported table crl");
        return crls;
    }

    private Cainfos export_cainfo()
    throws SQLException
    {
        System.out.println("Exporting table cainfo");
        Cainfos cainfos = new Cainfos();

        Statement stmt = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT id, cert FROM cainfo";
            ResultSet rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("id");
                String cert = rs.getString("cert");

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

        System.out.println(" Exported table cainfo");
        return cainfos;
    }

    private Requestorinfos export_requestorinfo()
    throws SQLException
    {
        System.out.println("Exporting table requestorinfo");
        Requestorinfos infos = new Requestorinfos();

        Statement stmt = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT id, cert FROM requestorinfo";
            ResultSet rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("id");
                String cert = rs.getString("cert");

                RequestorinfoType info = new RequestorinfoType();
                info.setId(id);
                info.setCert(cert);

                infos.getRequestorinfo().add(info);
            }

            rs.close();
            rs = null;
        }finally
        {
            closeStatement(stmt);
        }

        System.out.println(" Exported table cainfo");
        return infos;
    }

    private Users export_user()
    throws SQLException
    {
        System.out.println("Exporting table user");
        Users users = new Users();

        Statement stmt = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT id, name FROM user";
            ResultSet rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("id");
                String name = rs.getString("name");

                UserType user = new UserType();
                user.setId(id);
                user.setName(name);

                users.getUser().add(user);
            }

            rs.close();
            rs = null;
        }finally
        {
            closeStatement(stmt);
        }

        System.out.println(" Exported table user");
        return users;
    }

    private Certprofileinfos export_certprofileinfo()
    throws SQLException
    {
        System.out.println("Exporting table certprofileinfo");
        Certprofileinfos infos = new Certprofileinfos();

        Statement stmt = null;
        try
        {
            stmt = createStatement();
            String sql = "SELECT id, name FROM certprofileinfo";
            ResultSet rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("id");
                String name = rs.getString("name");

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

        System.out.println(" Exported table certprofileinfo");
        return infos;
    }

    private CertsFiles export_cert()
    throws SQLException, IOException, JAXBException
    {
        System.out.println("Exporting tables cert and rawcert");
        CertsFiles certsFiles = new CertsFiles();

        String certSql = "SELECT id, cainfo_id, certprofileinfo_id," +
                " requestorinfo_id, last_update," +
                " revocated, rev_reason, rev_time, rev_invalidity_time, user_id" +
                " FROM cert" +
                " WHERE id >= ? AND id < ?" +
                " ORDER BY id ASC";

        PreparedStatement ps = prepareStatement(certSql);

        String rawCertSql = "SELECT cert FROM rawcert WHERE cert_id = ?";
        PreparedStatement rawCertPs = prepareStatement(rawCertSql);

        //File certDir = new File(baseDir, "CERT");

        final int minCertId = getMinCertId();
        final int maxCertId = getMaxCertId();

        int numCertInCurrentFile = 0;
        CertsType certsInCurrentFile = new CertsType();

        int sum = 0;
        final int n = 100;

        File currentCertsZipFile = new File(baseDir, "tmp-certs-" + System.currentTimeMillis() + ".zip");
        FileOutputStream out = new FileOutputStream(currentCertsZipFile);
        ZipOutputStream currentCertsZip = new ZipOutputStream(out);

        int minCertIdOfCurrentFile = -1;
        int maxCertIdOfCurrentFile = -1;

        try
        {
            for(int i = minCertId; i <= maxCertId; i += n)
            {
                ps.setInt(1, i);
                ps.setInt(2, i + n);

                ResultSet rs = ps.executeQuery();

                while(rs.next())
                {
                    int id = rs.getInt("id");

                    if(minCertIdOfCurrentFile == -1)
                    {
                        minCertIdOfCurrentFile = id;
                    }
                    else if(minCertIdOfCurrentFile > id)
                    {
                        minCertIdOfCurrentFile = id;
                    }

                    if(maxCertIdOfCurrentFile == -1)
                    {
                        maxCertIdOfCurrentFile = id;
                    }
                    else if(maxCertIdOfCurrentFile < id)
                    {
                        maxCertIdOfCurrentFile = id;
                    }

                    String cainfo_id = rs.getString("cainfo_id");
                    String certprofileinfo_id = rs.getString("certprofileinfo_id");
                    String requestorinfo_id = rs.getString("requestorinfo_id");
                    String last_update = rs.getString("last_update");
                    boolean revocated = rs.getBoolean("revocated");
                    String rev_reason = rs.getString("rev_reason");
                    String rev_time = rs.getString("rev_time");
                    String rev_invalidity_time = rs.getString("rev_invalidity_time");
                    String user_id = rs.getString("user_id");

                    String sha1_fp_cert;
                    rawCertPs.setInt(1, id);
                    ResultSet rawCertRs = rawCertPs.executeQuery();
                    try
                    {
                        rawCertRs.next();
                        String b64Cert = rawCertRs.getString("cert");
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
                    cert.setRevocated(revocated);
                    cert.setRevReason(rev_reason);
                    cert.setRevTime(rev_time);
                    cert.setRevInvalidityTime(rev_invalidity_time);
                    cert.setUserId(user_id);
                    cert.setCertFile(sha1_fp_cert + ".der");

                    certsInCurrentFile.getCert().add(cert);
                    numCertInCurrentFile ++;
                    sum ++;

                    if(numCertInCurrentFile == numCertsInBundle)
                    {
                        finalizeZip(currentCertsZip, certsInCurrentFile);

                        String curentCertsFilename = DbiUtil.buildFilename("certs_", ".zip",
                                minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxCertId);
                        currentCertsZipFile.renameTo(new File(baseDir, curentCertsFilename));

                        certsFiles.getCertsFile().add(curentCertsFilename);

                        System.out.println(" Exported " + numCertInCurrentFile + " certificates in " + curentCertsFilename);
                        System.out.println(" Exported " + sum + " certificates ...");

                        // reset
                        certsInCurrentFile = new CertsType();
                        numCertInCurrentFile = 0;
                        minCertIdOfCurrentFile = -1;
                        maxCertIdOfCurrentFile = -1;
                        currentCertsZipFile = new File(baseDir, "tmp-certs-" + System.currentTimeMillis() + ".zip");
                        out = new FileOutputStream(currentCertsZipFile);
                        currentCertsZip = new ZipOutputStream(out);
                    }
                }
            }

            if(numCertInCurrentFile > 0)
            {
                finalizeZip(currentCertsZip, certsInCurrentFile);

                String curentCertsFilename = DbiUtil.buildFilename("certs_", ".zip",
                        minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxCertId);
                currentCertsZipFile.renameTo(new File(baseDir, curentCertsFilename));

                certsFiles.getCertsFile().add(curentCertsFilename);

                System.out.println(" Exported " + numCertInCurrentFile + " certificates in " + curentCertsFilename);
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

        System.out.println(" Exported " + sum + " certificates from tables cert and rawcert");
        return certsFiles;
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

    private int getMinCertId()
    throws SQLException
    {
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            final String sql = "SELECT min(id) FROM cert";
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

    private int getMaxCertId()
    throws SQLException
    {
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            final String sql = "SELECT max(id) FROM cert";
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
