/*
 * Copyright (c) 2014 xipki.org
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
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSource;
import org.xipki.dbi.ocsp.jaxb.CertStoreType;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.Issuers;
import org.xipki.dbi.ocsp.jaxb.CertType;
import org.xipki.dbi.ocsp.jaxb.CertsType;
import org.xipki.dbi.ocsp.jaxb.IssuerType;
import org.xipki.dbi.ocsp.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

class OcspCertStoreDbExporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreDbExporter.class);

    private final Marshaller marshaller;

    private final ObjectFactory objFact = new ObjectFactory();
    private final int numCertsInBundle;

    OcspCertStoreDbExporter(DataSource dataSource, Marshaller marshaller, String baseDir, int numCertsInBundle)
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
        System.out.println("Exporting OCSP certstore from database");
        certstore.setIssuers(export_issuer());
        certstore.setCertsFiles(export_cert());

        JAXBElement<CertStoreType> root = new ObjectFactory().createCertStore(certstore);
        marshaller.marshal(root, new File(baseDir + File.separator + FILENAME_OCSP_CertStore));
        System.out.println(" Exported OCSP certstore from database");
    }

    private Issuers export_issuer()
    throws SQLException
    {
        System.out.println("Exporting table ISSUER");
        Issuers issuers = new Issuers();

        Statement stmt = null;
        try
        {
            stmt = createStatement();

            String sql = "SELECT ID, CERT FROM ISSUER";

            ResultSet rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String cert = rs.getString("CERT");

                IssuerType issuer = new IssuerType();
                issuer.setId(id);
                issuer.setCert(cert);

                issuers.getIssuer().add(issuer);
            }

            rs.close();
            rs = null;
        }finally
        {
            closeStatement(stmt);
        }

        System.out.println(" Exported table ISSUER");
        return issuers;
    }

    private CertsFiles export_cert()
    throws SQLException, IOException, JAXBException
    {
        System.out.println("Exporting tables CERT, CERTHASH and RAWCERT");
        CertsFiles certsFiles = new CertsFiles();

        String revokedColName = "REVOKED";

        PreparedStatement ps = null;
        try
        {
            ps = prepareStatement("SELECT REVOKED FROM CERT WHERE ID=?");
            ps.setInt(1, 1);
            ResultSet rs = ps.executeQuery();
            rs.close();
        } catch(SQLException e)
        {
            revokedColName = "REVOCATED";
        } finally
        {
            closeStatement(ps);
        }

        String certSql = "SELECT ID, ISSUER_ID, LAST_UPDATE, " +
                revokedColName +
                ", REV_REASON, REV_TIME, REV_INVALIDITY_TIME, PROFILE " +
                " FROM CERT" +
                " WHERE ID >= ? AND ID < ?";

        String rawCertSql = "SELECT CERT FROM RAWCERT WHERE CERT_ID = ?";

        PreparedStatement certPs = prepareStatement(certSql);
        PreparedStatement rawCertPs = prepareStatement(rawCertSql);

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
                certPs.setInt(1, i);
                certPs.setInt(2, i + n);

                ResultSet rs = certPs.executeQuery();

                while(rs.next())
                {
                    int id = rs.getInt("ID");

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

                    int issuer_id = rs.getInt("ISSUER_ID");
                    String last_update = rs.getString("LAST_UPDATE");
                    boolean revoked = rs.getBoolean(revokedColName);
                    String rev_reason = rs.getString("REV_REASON");
                    String rev_time = rs.getString("REV_TIME");
                    String rev_invalidity_time = rs.getString("REV_INVALIDITY_TIME");
                    String profile = rs.getString("PROFILE");

                    rawCertPs.setInt(1, id);

                    String sha1_fp_cert;

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
                    cert.setIssuerId(issuer_id);
                    cert.setLastUpdate(last_update);
                    cert.setRevoked(revoked);
                    cert.setRevReason(rev_reason);
                    cert.setRevTime(rev_time);
                    cert.setRevInvalidityTime(rev_invalidity_time);
                    cert.setCertFile(sha1_fp_cert + ".der");
                    cert.setProfile(profile);

                    certsInCurrentFile.getCert().add(cert);
                    numCertInCurrentFile ++;
                    sum ++;

                    if(numCertInCurrentFile == numCertsInBundle)
                    {
                        finalizeZip(currentCertsZip, certsInCurrentFile);

                        String currentCertsFilename = DbiUtil.buildFilename("certs_", ".zip",
                                minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxCertId);
                        currentCertsZipFile.renameTo(new File(baseDir, currentCertsFilename));

                        certsFiles.getCertsFile().add(currentCertsFilename);

                        System.out.println(" Exported " + numCertInCurrentFile + " certificates in " + currentCertsFilename);
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

                String currentCertsFilename = DbiUtil.buildFilename("certs_", ".zip",
                        minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxCertId);
                currentCertsZipFile.renameTo(new File(baseDir, currentCertsFilename));

                certsFiles.getCertsFile().add(currentCertsFilename);

                System.out.println(" Exported " + numCertInCurrentFile + " certificates in " + currentCertsFilename);
            }
            else
            {
                currentCertsZip.close();
                currentCertsZipFile.delete();
            }

        }finally
        {
            closeStatement(certPs);
            closeStatement(rawCertPs);
        }

        System.out.println(" Exported " + sum + " certificates from tables cert, certhash and rawcert");
        return certsFiles;
    }

    private int getMinCertId()
    throws SQLException
    {
        Statement stmt = null;
        try
        {
            stmt = createStatement();
            final String sql = "SELECT MIN(ID) FROM CERT";
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
            final String sql = "SELECT MAX(ID) FROM CERT";
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

}
