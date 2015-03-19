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

package org.xipki.dbtool;

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
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.SecurityUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.dbi.ocsp.jaxb.CertStoreType;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.Issuers;
import org.xipki.dbi.ocsp.jaxb.CertType;
import org.xipki.dbi.ocsp.jaxb.CertsType;
import org.xipki.dbi.ocsp.jaxb.IssuerType;
import org.xipki.dbi.ocsp.jaxb.ObjectFactory;

/**
 * @author Lijun Liao
 */

class OcspCertStoreDbExporter extends DbPorter
{
    public static final String PROCESS_LOG_FILENAME = "export.process";

    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreDbExporter.class);

    private final Marshaller marshaller;
    private final Unmarshaller unmarshaller;

    private final ObjectFactory objFact = new ObjectFactory();
    private final int numCertsInBundle;
    private final boolean resume;

    OcspCertStoreDbExporter(DataSourceWrapper dataSource,
            Marshaller marshaller, Unmarshaller unmarshaller, String baseDir, int numCertsInBundle,
            boolean resume)
    throws Exception
    {
        super(dataSource, baseDir);
        ParamChecker.assertNotNull("marshaller", marshaller);
        ParamChecker.assertNotNull("unmarshaller", unmarshaller);
        if(numCertsInBundle < 1)
        {
            numCertsInBundle = 1;
        }
        this.numCertsInBundle = numCertsInBundle;
        this.marshaller = marshaller;
        this.unmarshaller = unmarshaller;
        if(resume)
        {
            File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);
            if(processLogFile.exists() == false)
            {
                throw new Exception("could not process with '--resume' option");
            }
        }
        this.resume = resume;
    }

    public void export()
    throws Exception
    {
        File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);

        CertStoreType certstore;
        if(resume)
        {
            try
            {
                @SuppressWarnings("unchecked")
                JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                        unmarshaller.unmarshal(new File(baseDir, FILENAME_OCSP_CertStore));
                certstore = root.getValue();
            }catch(JAXBException e)
            {
                throw XMLUtil.convert(e);
            }

            if(certstore.getVersion() > VERSION)
            {
                throw new Exception(
                        "could not continue with CertStore greater than " + VERSION + ": " + certstore.getVersion());
            }
        }
        else
        {
            certstore = new CertStoreType();
            certstore.setVersion(VERSION);
        }
        System.out.println("exporting OCSP certstore from database");

        if(resume == false)
        {
            export_issuer(certstore);
        }
        Exception exception = export_cert(certstore, processLogFile);

        JAXBElement<CertStoreType> root = new ObjectFactory().createCertStore(certstore);
        try
        {
            marshaller.marshal(root, new File(baseDir, FILENAME_OCSP_CertStore));
        }catch(JAXBException e)
        {
            throw XMLUtil.convert(e);
        }

        if(exception == null)
        {
            System.out.println(" exported OCSP certstore from database");
        }
        else
        {
            throw exception;
        }
    }

    private void export_issuer(CertStoreType certstore)
    throws DataAccessException
    {
        System.out.println("exporting table ISSUER");
        Issuers issuers = new Issuers();
        certstore.setIssuers(issuers);
        final String sql = "SELECT ID, CERT, REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME FROM ISSUER";

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
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(stmt, rs);
        }

        System.out.println(" exported table ISSUER");
    }

    private Exception export_cert(CertStoreType certstore, File processLogFile)
    {
        try
        {
            do_export_cert(certstore, processLogFile);
            return null;
        }catch(Exception e)
        {
            // delete the temporary files
            deleteTmpFiles(baseDir, "tmp-certs-");
            System.err.println("\nexporting table CERT and RAWCERT has been cancelled due to error,\n"
                    + "please continue with the option '-resume'");
            LOG.error("Exception", e);
            return e;
        }
    }

    private void do_export_cert(CertStoreType certstore, File processLogFile)
    throws DataAccessException, IOException, JAXBException
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

        Integer minCertId = null;
        if(processLogFile.exists())
        {
            byte[] content = IoUtil.read(processLogFile);
            if(content != null && content.length > 0)
            {
                minCertId = Integer.parseInt(new String(content).trim());
                minCertId++;
            }
        }

        if(minCertId == null)
        {
            minCertId = (int) getMin("CERT", "ID");
        }

        System.out.println("exporting tables CERT, CERTHASH and RAWCERT from ID " + minCertId);

        String certSql = "SELECT ID, ISSUER_ID, LAST_UPDATE, REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME, PROFILE " +
                " FROM CERT WHERE ID >= ? AND ID < ?";

        String rawCertSql = "SELECT CERT_ID, CERT FROM RAWCERT WHERE CERT_ID >= ? AND CERT_ID < ?";

        final int maxCertId = (int) getMax("CERT", "ID");
        final long total = getCount("CERT") - numProcessedBefore;

        PreparedStatement certPs = prepareStatement(certSql);
        PreparedStatement rawCertPs = prepareStatement(rawCertSql);

        int numCertInCurrentFile = 0;

        CertsType certsInCurrentFile = new CertsType();

        long sum = 0;
        final int n = 100;

        File currentCertsZipFile = new File(baseDir, "tmp-certs-" + System.currentTimeMillis() + ".zip");
        FileOutputStream out = new FileOutputStream(currentCertsZipFile);
        ZipOutputStream currentCertsZip = new ZipOutputStream(out);

        int minCertIdOfCurrentFile = -1;
        int maxCertIdOfCurrentFile = -1;

        final long startTime = System.currentTimeMillis();
        printHeader();

        String sql = null;

        Integer id = null;
        try
        {
            for(int i = minCertId; i <= maxCertId; i += n)
            {
                Map<Integer, byte[]> rawCertMaps = new HashMap<>();

                // retrieve raw certificates
                sql = rawCertSql;
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

                sql = certSql;
                certPs.setInt(1, i);
                certPs.setInt(2, i + n);

                ResultSet rs = certPs.executeQuery();

                while(rs.next())
                {
                    id = rs.getInt("ID");

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
                        String msg = "found no certificate in table RAWCERT for cert_id '" + id + "'";
                        LOG.error(msg);
                        continue;
                    }

                    String sha1_cert = SecurityUtil.sha1sum(certBytes);

                    ZipEntry certZipEntry = new ZipEntry(sha1_cert + ".der");
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
                    cert.setCertFile(sha1_cert + ".der");

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
                        certsFiles.setCountCerts(numProcessedBefore + sum);
                        echoToFile(Integer.toString(id), processLogFile);

                        printStatus(total, sum, startTime);

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
                certsFiles.setCountCerts(numProcessedBefore + sum);
                echoToFile(Integer.toString(id), processLogFile);

                printStatus(total, sum, startTime);
            }
            else
            {
                currentCertsZip.close();
                currentCertsZipFile.delete();
            }
        }catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            releaseResources(certPs, null);
            releaseResources(rawCertPs, null);
        }

        printTrailer();
        // all successful, delete the processLogFile
        processLogFile.delete();

        System.out.println(" exported " + sum + " certificates from tables cert, certhash and rawcert");
    }

    private void finalizeZip(ZipOutputStream zipOutStream, CertsType certsType)
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

}
