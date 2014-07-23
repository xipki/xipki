/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSourceWrapper;
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

/**
 * @author Lijun Liao
 */

class OcspCertStoreDbExporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreDbExporter.class);

    private final Marshaller marshaller;

    private final ObjectFactory objFact = new ObjectFactory();
    private final int numCertsInBundle;

    OcspCertStoreDbExporter(DataSourceWrapper dataSource, Marshaller marshaller, String baseDir, int numCertsInBundle)
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
        ResultSet rs = null;

        try
        {
            stmt = createStatement();

            String sql = "SELECT ID, CERT, REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME" +
                         " FROM ISSUER";

            rs = stmt.executeQuery(sql);

            while(rs.next())
            {
                int id = rs.getInt("ID");
                String cert = rs.getString("CERT");

                IssuerType issuer = new IssuerType();
                issuer.setId(id);
                issuer.setCert(cert);

                boolean revoked = rs.getBoolean("REVOKED");
                issuer.setRevoked(revoked);
                if(revoked)
                {
                    int rev_reason = rs.getInt("REV_REASON");
                    long rev_time = rs.getLong("REV_TIME");
                    long rev_invalidity_time = rs.getLong("REV_INVALIDITY_TIME");
                    issuer.setRevReason(rev_reason);
                    issuer.setRevTime(rev_time);
                    if(rev_invalidity_time != 0)
                    {
                        issuer.setRevInvalidityTime(rev_invalidity_time);
                    }
                }

                issuers.getIssuer().add(issuer);
            }
        }finally
        {
            releaseResources(stmt, rs);
        }

        System.out.println(" Exported table ISSUER");
        return issuers;
    }

    private CertsFiles export_cert()
    throws SQLException, IOException, JAXBException
    {
        System.out.println("Exporting tables CERT, CERTHASH and RAWCERT");
        CertsFiles certsFiles = new CertsFiles();

        String certSql = "SELECT ID, ISSUER_ID, LAST_UPDATE, REVOKED " +
                ", REV_REASON, REV_TIME, REV_INVALIDITY_TIME, PROFILE " +
                " FROM CERT" +
                " WHERE ID >= ? AND ID < ?";

        String rawCertSql = "SELECT CERT_ID, CERT FROM RAWCERT WHERE CERT_ID >= ? AND CERT_ID < ?";

        final int minCertId = getMin("CERT", "ID");
        final int maxCertId = getMax("CERT", "ID");

        PreparedStatement certPs = prepareStatement(certSql);
        PreparedStatement rawCertPs = prepareStatement(rawCertSql);

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

                    int issuer_id = rs.getInt("ISSUER_ID");
                    cert.setIssuerId(issuer_id);

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
                        cert.setRevReason(rev_reason);
                        cert.setRevTime(rev_time);
                        cert.setRevInvalidityTime(rev_invalidity_time);
                    }
                    cert.setCertFile(sha1_fp_cert + ".der");

                    String profile = rs.getString("PROFILE");
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

                rawCertMaps.clear();
                rawCertMaps = null;
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
            releaseResources(certPs, null);
            releaseResources(rawCertPs, null);
        }

        System.out.println(" Exported " + sum + " certificates from tables cert, certhash and rawcert");
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

}
