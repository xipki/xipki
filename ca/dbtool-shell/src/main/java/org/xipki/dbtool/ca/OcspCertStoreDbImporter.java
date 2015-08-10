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

package org.xipki.dbtool.ca;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import java.util.StringTokenizer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.HashAlgoType;
import org.xipki.common.HashCalculator;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.X509Util;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.dbi.ocsp.jaxb.CertStoreType;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.Issuers;
import org.xipki.dbi.ocsp.jaxb.CertType;
import org.xipki.dbi.ocsp.jaxb.CertsType;
import org.xipki.dbi.ocsp.jaxb.IssuerType;

/**
 * @author Lijun Liao
 */

class OcspCertStoreDbImporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreDbImporter.class);

    static final String SQL_ADD_CAINFO =
            "INSERT INTO ISSUER (" +
            " ID, SUBJECT," +
            " NOTBEFORE, NOTAFTER," +
            " SHA1_NAME, SHA1_KEY," +
            " SHA224_NAME, SHA224_KEY," +
            " SHA256_NAME, SHA256_KEY," +
            " SHA384_NAME, SHA384_KEY," +
            " SHA512_NAME, SHA512_KEY," +
            " SHA1_CERT, CERT," +
            " REVOKED, REV_REASON, REV_TIME, REV_INV_TIME" +
            " ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    static final String SQL_ADD_CERT =
            "INSERT INTO CERT (" +
            " ID, ISSUER_ID, SERIAL, " +
            " SUBJECT, LAST_UPDATE, NOTBEFORE, NOTAFTER," +
            " REVOKED, REV_REASON, REV_TIME, REV_INV_TIME, PROFILE)" +
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    static final String SQL_ADD_CERTHASH = "INSERT INTO CERTHASH (" +
            "CERT_ID, SHA1, SHA224, SHA256, SHA384, SHA512)" +
            " VALUES (?, ?, ?, ?, ?, ?)";

    static final String SQL_ADD_RAWCERT = "INSERT INTO RAWCERT (CERT_ID, CERT) VALUES (?, ?)";

    private final Unmarshaller unmarshaller;
    private final boolean resume;

    OcspCertStoreDbImporter(
            final DataSourceWrapper dataSource,
            final Unmarshaller unmarshaller,
            final String srcDir,
            final boolean resume)
    throws Exception
    {
        super(dataSource, srcDir);
        ParamChecker.assertNotNull("unmarshaller", unmarshaller);
        this.unmarshaller = unmarshaller;
        File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
        if(resume)
        {
            if(processLogFile.exists() == false)
            {
                throw new Exception("could not process with '--resume' option");
            }
        }
        else
        {
            if(processLogFile.exists())
            {
                throw new Exception("please either specify '--resume' option or delete the file " +
                        processLogFile.getPath() + " first");
            }
        }
        this.resume = resume;
    }

    public void importToDB()
    throws Exception
    {
        CertStoreType certstore;
        try
        {
            @SuppressWarnings("unchecked")
            JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                    unmarshaller.unmarshal(new File(baseDir + File.separator + FILENAME_OCSP_CertStore));
            certstore = root.getValue();
        }catch(JAXBException e)
        {
            throw XMLUtil.convert(e);
        }

        if(certstore.getVersion() > VERSION)
        {
            throw new Exception("could not import CertStore greater than " + VERSION + ": " + certstore.getVersion());
        }

        File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
        System.out.println("importing OCSP certstore to database");
        try
        {
            if(resume == false)
            {
                import_issuer(certstore.getIssuers());
            }
            import_cert(certstore.getCertsFiles(), processLogFile);
            processLogFile.delete();
        }catch(Exception e)
        {
            System.err.println("error while importing OCSP certstore to database");
            throw e;
        }
        System.out.println(" imported OCSP certstore to database");
    }

    private void import_issuer(
            final Issuers issuers)
    throws DataAccessException, CertificateException
    {
        System.out.println("importing table ISSUER");
        PreparedStatement ps = prepareStatement(SQL_ADD_CAINFO);

        try
        {
            for(IssuerType issuer : issuers.getIssuer())
            {
                try
                {
                    String b64Cert = issuer.getCert();
                    byte[] encodedCert = Base64.decode(b64Cert);

                    Certificate c;
                    byte[] encodedName;
                    try
                    {
                        c = Certificate.getInstance(encodedCert);
                        encodedName = c.getSubject().getEncoded("DER");
                    } catch (Exception e)
                    {
                        LOG.error("could not parse certificate of issuer {}", issuer.getId());
                        LOG.debug("could not parse certificate of issuer " + issuer.getId(), e);
                        if(e instanceof CertificateException)
                        {
                            throw (CertificateException) e;
                        }
                        else
                        {
                            throw new CertificateException(e.getMessage(), e);
                        }
                    }
                    byte[] encodedKey = c.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

                    int idx = 1;
                    ps.setInt(idx++, issuer.getId());
                    ps.setString(idx++, X509Util.getRFC4519Name(c.getSubject()));
                    ps.setLong(idx++, c.getTBSCertificate().getStartDate().getDate().getTime() / 1000);
                    ps.setLong(idx++, c.getTBSCertificate().getEndDate().getDate().getTime() / 1000);
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedName));
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedKey));
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA224, encodedName));
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA224, encodedKey));
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA256, encodedName));
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA256, encodedKey));
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA384, encodedName));
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA384, encodedKey));
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA512, encodedName));
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA512, encodedKey));
                    ps.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedCert));
                    ps.setString(idx++, b64Cert);
                    setBoolean(ps, idx++, issuer.isRevoked());
                    setInt(ps, idx++, issuer.getRevReason());
                    setLong(ps, idx++, issuer.getRevTime());
                    setLong(ps, idx++, issuer.getRevInvTime());

                    ps.execute();
                }catch(SQLException e)
                {
                    System.err.println("error while importing issuer with id=" + issuer.getId());
                    throw translate(SQL_ADD_CAINFO, e);
                }catch(CertificateException e)
                {
                    System.err.println("error while importing issuer with id=" + issuer.getId());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" imported table ISSUER");
    }

    private void import_cert(
            final CertsFiles certsfiles,
            final File processLogFile)
    throws Exception
    {
        int numProcessedBefore = 0;
        int minId = 1;
        if(processLogFile.exists())
        {
            byte[] content = IoUtil.read(processLogFile);
            if(content != null && content.length > 2)
            {
                String str = new String(content);
                if(str.trim().equalsIgnoreCase(MSG_CERTS_FINISHED))
                {
                    return;
                }

                StringTokenizer st = new StringTokenizer(str, ":");
                numProcessedBefore = Integer.parseInt(st.nextToken());
                minId = Integer.parseInt(st.nextToken());
                minId++;
            }
        }

        final long total = certsfiles.getCountCerts() - numProcessedBefore;

        final long startTime = System.currentTimeMillis();
        int sum = 0;

        System.out.println("importing certificates from ID " + minId);
        printHeader();

        PreparedStatement ps_cert = prepareStatement(SQL_ADD_CERT);
        PreparedStatement ps_certhash = prepareStatement(SQL_ADD_CERTHASH);
        PreparedStatement ps_rawcert = prepareStatement(SQL_ADD_RAWCERT);

        try
        {
            for(String certsFile : certsfiles.getCertsFile())
            {
                try
                {
                    int[] numAndLastId = do_import_cert(ps_cert, ps_certhash, ps_rawcert, certsFile, minId,
                            processLogFile, sum + numProcessedBefore);
                    int numProcessed = numAndLastId[0];
                    int lastId = numAndLastId[1];
                    minId = lastId + 1;
                    if(numProcessed > 0)
                    {
                        sum += numProcessed;
                        printStatus(total, sum, startTime);
                    }
                }catch(Exception e)
                {
                    System.err.println("\nerror while importing certificates from file " + certsFile +
                            ".\nplease continue with the option '--resume'");
                    LOG.error("Exception", e);
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps_cert, null);
            releaseResources(ps_certhash, null);
            releaseResources(ps_rawcert, null);
        }

        long maxId = getMax("CERT", "ID");
        String seqName = "CERT_ID";
        dataSource.dropAndCreateSequence(seqName, maxId + 1);

        printTrailer();
        echoToFile(MSG_CERTS_FINISHED, processLogFile);
        System.out.println("processed " + sum + " certificates");
    }

    private int[] do_import_cert(
            final PreparedStatement ps_cert,
            final PreparedStatement ps_certhash,
            final PreparedStatement ps_rawcert,
            final String certsZipFile,
            final int minId,
            final File processLogFile,
            final int totalProcessedSum)
    throws IOException, JAXBException, DataAccessException, CertificateException
    {
        ZipFile zipFile = new ZipFile(new File(baseDir, certsZipFile));
        ZipEntry certsXmlEntry = zipFile.getEntry("certs.xml");

        CertsType certs;
        try
        {
            @SuppressWarnings("unchecked")
            JAXBElement<CertsType> rootElement = (JAXBElement<CertsType>)
                    unmarshaller.unmarshal(zipFile.getInputStream(certsXmlEntry));
            certs = rootElement.getValue();
        }catch(JAXBException e)
        {
            try
            {
                zipFile.close();
            }catch(Exception e2)
            {
            }
            throw XMLUtil.convert(e);
        }

        disableAutoCommit();

        try
        {
            List<CertType> list = certs.getCert();
            final int size = list.size();
            final int n = 100;
            int numProcessed = 0;
            int numEntriesInBatch = 0;
            int lastSuccessfulCertId = 0;

            for(int i = 0; i < size; i++)
            {
                CertType cert = list.get(i);
                int id = cert.getId();
                lastSuccessfulCertId = id;
                if(id < minId)
                {
                    continue;
                }

                numEntriesInBatch++;

                String filename = cert.getCertFile();

                // rawcert
                ZipEntry certZipEnty = zipFile.getEntry(filename);
                // rawcert
                byte[] encodedCert = IoUtil.read(zipFile.getInputStream(certZipEnty));

                X509Certificate c;
                try
                {
                    c = X509Util.parseCert(encodedCert);
                } catch (Exception e)
                {
                    LOG.error("could not parse certificate in file {}", filename);
                    LOG.debug("could not parse certificate in file " + filename, e);
                    if(e instanceof CertificateException)
                    {
                        throw (CertificateException) e;
                    }
                    else
                    {
                        throw new CertificateException(e.getMessage(), e);
                    }
                }

                // cert
                try
                {
                    int idx = 1;
                    ps_cert.setInt(idx++, id);
                    ps_cert.setInt(idx++, cert.getIssuerId());
                    ps_cert.setLong(idx++, c.getSerialNumber().longValue());
                    ps_cert.setString(idx++, X509Util.getRFC4519Name(c.getSubjectX500Principal()));
                    ps_cert.setLong(idx++, cert.getLastUpdate());
                    ps_cert.setLong(idx++, c.getNotBefore().getTime() / 1000);
                    ps_cert.setLong(idx++, c.getNotAfter().getTime() / 1000);
                    setBoolean(ps_cert, idx++, cert.isRevoked());
                    setInt(ps_cert, idx++, cert.getRevReason());
                    setLong(ps_cert, idx++, cert.getRevTime());
                    setLong(ps_cert, idx++, cert.getRevInvTime());
                    ps_cert.setString(idx++, cert.getProfile());
                    ps_cert.addBatch();
                }catch(SQLException e)
                {
                    throw translate(SQL_ADD_CERT, e);
                }

                // certhash
                try
                {
                    int idx = 1;
                    ps_certhash.setInt(idx++, cert.getId());
                    ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedCert));
                    ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA224, encodedCert));
                    ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA256, encodedCert));
                    ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA384, encodedCert));
                    ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA512, encodedCert));
                    ps_certhash.addBatch();
                }catch(SQLException e)
                {
                    throw translate(SQL_ADD_CERTHASH, e);
                }

                // rawcert
                try
                {
                    int idx = 1;
                    ps_rawcert.setInt(idx++, cert.getId());
                    ps_rawcert.setString(idx++, Base64.toBase64String(encodedCert));
                    ps_rawcert.addBatch();
                }catch(SQLException e)
                {
                    throw translate(SQL_ADD_RAWCERT, e);
                }

                if(numEntriesInBatch > 0 && (numEntriesInBatch % n == 0 || i == size - 1))
                {
                    String sql = null;
                    try
                    {
                        sql = SQL_ADD_CERT;
                        ps_cert.executeBatch();

                        sql = SQL_ADD_CERTHASH;
                        ps_certhash.executeBatch();

                        sql = SQL_ADD_RAWCERT;
                        ps_rawcert.executeBatch();

                        sql = null;
                        commit("(commit import cert to OCSP)");
                    } catch(SQLException e)
                    {
                        rollback();
                        throw translate(sql, e);
                    } catch(DataAccessException e)
                    {
                        rollback();
                        throw e;
                    }

                    numProcessed += numEntriesInBatch;
                    numEntriesInBatch = 0;
                    echoToFile((totalProcessedSum + numProcessed) + ":" + lastSuccessfulCertId, processLogFile);
                }

            }

            return new int[]{numProcessed, lastSuccessfulCertId};
        }
        finally
        {
            try
            {
                recoverAutoCommit();
            }catch(DataAccessException e)
            {
            }
            zipFile.close();
        }
    }

}
