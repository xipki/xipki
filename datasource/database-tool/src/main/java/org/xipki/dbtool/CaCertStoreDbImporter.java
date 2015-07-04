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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;
import java.util.StringTokenizer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
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
import org.xipki.dbi.ca.jaxb.CertStoreType;
import org.xipki.dbi.ca.jaxb.CertStoreType.Cas;
import org.xipki.dbi.ca.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ca.jaxb.CertStoreType.Crls;
import org.xipki.dbi.ca.jaxb.CertStoreType.DeltaCRLCache;
import org.xipki.dbi.ca.jaxb.CertStoreType.Profiles;
import org.xipki.dbi.ca.jaxb.CertStoreType.PublishQueue;
import org.xipki.dbi.ca.jaxb.CertStoreType.Publishers;
import org.xipki.dbi.ca.jaxb.CertStoreType.Requestors;
import org.xipki.dbi.ca.jaxb.CertStoreType.UsersFiles;
import org.xipki.dbi.ca.jaxb.CertType;
import org.xipki.dbi.ca.jaxb.CertsType;
import org.xipki.dbi.ca.jaxb.CertstoreCaType;
import org.xipki.dbi.ca.jaxb.CrlType;
import org.xipki.dbi.ca.jaxb.DeltaCRLCacheEntryType;
import org.xipki.dbi.ca.jaxb.NameIdType;
import org.xipki.dbi.ca.jaxb.ToPublishType;
import org.xipki.dbi.ca.jaxb.UserType;
import org.xipki.dbi.ca.jaxb.UsersType;

/**
 * @author Lijun Liao
 */

class CaCertStoreDbImporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(CaConfigurationDbImporter.class);

    private static final String SQL_ADD_CERT =
            "INSERT INTO CERT " +
            "(ID, ART, LAST_UPDATE, SERIAL, SUBJECT,"
            + " NOTBEFORE, NOTAFTER, REVOKED, REV_REASON, REV_TIME, REV_INV_TIME,"
            + " PROFILE_ID, CA_ID,"
            + " REQUESTOR_ID, USER_ID, FP_PK, FP_SUBJECT, EE, REQ_TYPE, TID)" +
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SQL_ADD_RAWCERT = "INSERT INTO RAWCERT (CERT_ID, FP, CERT) VALUES (?, ?, ?)";

    private static final String SQL_ADD_USER = "INSERT INTO USERNAME (ID, NAME, PASSWORD,CN_REGEX) VALUES (?, ?, ?, ?)";

    private final Unmarshaller unmarshaller;
    private final boolean resume;

    CaCertStoreDbImporter(
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
                    unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_CertStore));
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
        System.out.println("importing CA certstore to database");
        try
        {
            if(resume == false)
            {
                import_ca(certstore.getCas());
                import_requestor(certstore.getRequestors());
                import_publisher(certstore.getPublishers());
                import_profile(certstore.getProfiles());
                import_user(certstore.getUsersFiles());
                import_crl(certstore.getCrls());
            }

            import_cert(certstore.getCertsFiles(), processLogFile);

            import_publishQueue(certstore.getPublishQueue());
            import_deltaCRLCache(certstore.getDeltaCRLCache());
            processLogFile.delete();
        }catch(Exception e)
        {
            System.err.println("error while importing CA certstore to database");
            throw e;
        }
        System.out.println(" imported CA certstore to database");
    }

    private void import_ca(
            final Cas cas)
    throws DataAccessException, CertificateException, IOException
    {
        final String sql = "INSERT INTO CS_CA (ID, SUBJECT, FP_CERT, CERT) VALUES (?, ?, ?, ?)";
        System.out.println("importing table CS_CA");
        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(CertstoreCaType m : cas.getCa())
            {
                try
                {
                    String b64Cert = m.getCert();
                    byte[] encodedCert = Base64.decode(b64Cert);
                    X509Certificate c = X509Util.parseCert(encodedCert);
                    String hexSha1FpCert = HashCalculator.hexHash(HashAlgoType.SHA1, encodedCert);

                    int idx = 1;
                    ps.setInt(idx++, m.getId());
                    ps.setString(idx++, X509Util.getRFC4519Name(c.getSubjectX500Principal()));
                    ps.setString(idx++, hexSha1FpCert);
                    ps.setString(idx++, b64Cert);

                    ps.execute();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CS_CA with ID=" + m.getId() + ", message: " + e.getMessage());
                    throw translate(sql, e);
                }catch(CertificateException | IOException e)
                {
                    System.err.println("error while importing CS_CA with ID=" + m.getId() + ", message: " + e.getMessage());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CS_CA");
    }

    private void import_requestor(
            final Requestors requestors)
    throws DataAccessException
    {
        final String sql = "INSERT INTO CS_REQUESTOR (ID, NAME) VALUES (?, ?)";
        System.out.println("importing table CS_REQUESTOR");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(NameIdType m : requestors.getRequestor())
            {
                try
                {
                    String name = m.getName();

                    int idx = 1;
                    ps.setInt(idx++, m.getId());
                    ps.setString(idx++, name);

                    ps.execute();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CS_REQUESTOR with ID=" + m.getId() +
                            ", message: " + e.getMessage());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CS_REQUESTOR");
    }

    private void import_publisher(
            final Publishers publishers)
    throws DataAccessException
    {
        final String sql = "INSERT INTO CS_PUBLISHER (ID, NAME) VALUES (?, ?)";

        System.out.println("importing table CS_PUBLISHER");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(NameIdType m : publishers.getPublisher())
            {
                try
                {
                    String name = m.getName();

                    int idx = 1;
                    ps.setInt(idx++, m.getId());
                    ps.setString(idx++, name);

                    ps.execute();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CS_PUBLISHER with ID=" + m.getId() +
                            ", message: " + e.getMessage());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CS_PUBLISHER");
    }

    private void import_profile(
            final Profiles profiles)
    throws DataAccessException
    {
        final String sql = "INSERT INTO CS_PROFILE (ID, NAME) VALUES (?, ?)";
        System.out.println("importing table CS_PROFILE");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(NameIdType m : profiles.getProfile())
            {
                try
                {
                    int idx = 1;
                    ps.setInt(idx++, m.getId());
                    ps.setString(idx++, m.getName());

                    ps.execute();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CS_PROFILE with ID=" + m.getId() +
                            ", message: " + e.getMessage());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CS_PROFILE");
    }

    private void import_user(
            final UsersFiles usersFiles)
    throws DataAccessException, JAXBException
    {
        PreparedStatement ps = prepareStatement(SQL_ADD_USER);

        int sum = 0;
        try
        {
            for(String file : usersFiles.getUsersFile())
            {
                System.out.println("importing users from file " + file);

                try
                {
                    sum += do_import_user(ps, file);
                    System.out.println(" imported users from file " + file);
                    System.out.println(" imported " + sum + " users ...");
                }catch(SQLException e)
                {
                    System.err.println("error while importing users from file " + file);
                    throw translate(SQL_ADD_USER, e);
                }catch(JAXBException e)
                {
                    System.err.println("error while importing users from file " + file);
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" imported " + sum + " users");
    }

    private int do_import_user(
            final PreparedStatement ps_adduser,
            final String usersFile)
    throws JAXBException, SQLException
    {
        System.out.println("importing table USERNAME");

        UsersType users;
        try
        {
            @SuppressWarnings("unchecked")
            JAXBElement<UsersType> rootElement = (JAXBElement<UsersType>)
                    unmarshaller.unmarshal(new File(baseDir, usersFile));
            users = rootElement.getValue();
        }catch(JAXBException e)
        {
            throw XMLUtil.convert(e);
        }

        int sum = 0;
        for(UserType user : users.getUser())
        {
            try
            {
                int idx = 1;
                ps_adduser.setInt(idx++, user.getId());
                ps_adduser.setString(idx++, user.getName());
                ps_adduser.setString(idx++, user.getPassword());
                ps_adduser.setString(idx++, user.getCnRegex());
                ps_adduser.execute();
                sum ++;
            }catch(SQLException e)
            {
                System.err.println("error while importing USERNAME with ID=" +
                        user.getId() + ", message: " + e.getMessage());
                throw e;
            }
        }

        return sum;
    }

    private void import_publishQueue(
            final PublishQueue publishQueue)
    throws DataAccessException
    {
        final String sql = "INSERT INTO PUBLISHQUEUE (CERT_ID, PUBLISHER_ID, CA_ID) VALUES (?, ?, ?)";
        System.out.println("importing table PUBLISHQUEUE");
        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(ToPublishType tbp : publishQueue.getTop())
            {
                try
                {
                    int idx = 1;
                    ps.setInt(idx++, tbp.getCertId());
                    ps.setInt(idx++, tbp.getPubId());
                    ps.setInt(idx++, tbp.getCaId());
                    ps.execute();
                }catch(SQLException e)
                {
                    System.err.println("error while importing PUBLISHQUEUE with CERT_ID=" + tbp.getCertId()
                            + " and PUBLISHER_ID=" + tbp.getPubId() + ", message: " + e.getMessage());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" imported table PUBLISHQUEUE");
    }

    private void import_deltaCRLCache(
            final DeltaCRLCache deltaCRLCache)
    throws DataAccessException
    {
        final String sql = "INSERT INTO DELTACRL_CACHE (ID, SERIAL, CA_ID) VALUES (?, ?, ?)";
        System.out.println("importing table DELTACRL_CACHE");
        PreparedStatement ps = prepareStatement(sql);

        try
        {
            long id = 1;
            for(DeltaCRLCacheEntryType entry : deltaCRLCache.getEntry())
            {
                try
                {
                    int idx = 1;
                    ps.setLong(idx++, id++);
                    ps.setLong(idx++, entry.getSerial());
                    ps.setInt(idx++, entry.getCaId());
                    ps.execute();
                }catch(SQLException e)
                {
                    System.err.println("error while importing DELTACRL_CACHE with caId=" + entry.getCaId() +
                            " and serial=" + entry.getSerial() + ", message: " + e.getMessage());
                    throw translate(sql, e);
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        long maxId = getMax("DELTACRL_CACHE", "ID");
        dataSource.dropAndCreateSequence("DCC_ID", maxId + 1);

        System.out.println(" imported table DELTACRL_CACHE");
    }

    private void import_crl(
            final Crls crls)
    throws Exception
    {
        final String sql = "INSERT INTO CRL (ID, CA_ID, CRL_NO, THISUPDATE, NEXTUPDATE, DELTACRL, BASECRL_NO, CRL)"
                + " VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        System.out.println("importing table CRL");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            int id = 1;
            for(CrlType crl : crls.getCrl())
            {
                try
                {
                    String filename = baseDir + File.separator + crl.getCrlFile();
                    byte[] encodedCrl = IoUtil.read(filename);

                    X509CRL c = null;
                    try
                    {
                        c = X509Util.parseCRL(new ByteArrayInputStream(encodedCrl));
                    } catch (CertificateException | CRLException e)
                    {
                        LOG.error("could not parse CRL in file {}", filename);
                        LOG.debug("could not parse CRL in file " + filename, e);
                    }

                    if(c == null)
                    {
                        continue;
                    }

                    byte[] octetString = c.getExtensionValue(Extension.cRLNumber.getId());
                    if(octetString == null)
                    {
                        LOG.warn("CRL without CRL number, ignore it");
                        continue;
                    }
                    byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
                    BigInteger crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

                    BigInteger baseCrlNumber = null;
                    octetString = c.getExtensionValue(Extension.deltaCRLIndicator.getId());
                    if(octetString != null)
                    {
                        extnValue = DEROctetString.getInstance(octetString).getOctets();
                        baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
                    }

                    int idx = 1;
                    ps.setInt(idx++, id++);
                    ps.setInt(idx++, crl.getCaId());
                    ps.setLong(idx++, crlNumber.longValue());
                    ps.setLong(idx++, c.getThisUpdate().getTime() / 1000);
                    if(c.getNextUpdate() != null)
                    {
                        ps.setLong(idx++, c.getNextUpdate().getTime() / 1000);
                    }
                    else
                    {
                        ps.setNull(idx++, Types.INTEGER);
                    }

                    if(baseCrlNumber == null)
                    {
                        setBoolean(ps, idx++, false);
                        ps.setNull(idx++, Types.BIGINT);
                    }
                    else
                    {
                        setBoolean(ps, idx++, true);
                        ps.setLong(idx++, baseCrlNumber.longValue());
                    }

                    String s = Base64.toBase64String(encodedCrl);
                    ps.setString(idx++, s);

                    ps.executeUpdate();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CRL with ID=" + crl.getId() + ", message: " + e.getMessage());
                    throw translate(sql, e);
                }catch(Exception e)
                {
                    System.err.println("error while importing CRL with ID=" + crl.getId() + ", message: " + e.getMessage());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" imported table CRL");
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
                if(str.trim().equalsIgnoreCase(DbPorter.MSG_CERTS_FINISHED))
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
        PreparedStatement ps_rawcert = prepareStatement(SQL_ADD_RAWCERT);

        try
        {
            for(String certsFile : certsfiles.getCertsFile())
            {
                try
                {
                    int[] numAndLastId = do_import_cert(ps_cert, ps_rawcert, certsFile, minId,
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
            releaseResources(ps_rawcert, null);
        }

        long maxId = getMax("CERT", "ID");
        dataSource.dropAndCreateSequence("CERT_ID", maxId + 1);

        printTrailer();
        echoToFile(MSG_CERTS_FINISHED, processLogFile);
        System.out.println(" imported " + sum + " certificates");
    }

    private int[] do_import_cert(
            final PreparedStatement ps_cert,
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

                int certArt = cert.getArt() == null ? 1 : cert.getArt();

                numEntriesInBatch++;

                String filename = cert.getCertFile();

                // rawcert
                ZipEntry certZipEnty = zipFile.getEntry(filename);

                // rawcert
                byte[] encodedCert = IoUtil.read(zipFile.getInputStream(certZipEnty));

                Certificate c;
                try
                {
                    c = Certificate.getInstance(encodedCert);
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

                byte[] encodedKey = c.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

                String hexSha1FpCert = HashCalculator.hexHash(HashAlgoType.SHA1, encodedCert);

                // cert

                try
                {
                    int idx = 1;
                    ps_cert.setInt(idx++, id);
                    ps_cert.setInt(idx++, certArt);
                    ps_cert.setLong(idx++, cert.getLastUpdate());
                    ps_cert.setLong(idx++, c.getSerialNumber().getPositiveValue().longValue());
                    ps_cert.setString(idx++, X509Util.getRFC4519Name(c.getSubject()));
                    ps_cert.setLong(idx++, c.getTBSCertificate().getStartDate().getDate().getTime() / 1000);
                    ps_cert.setLong(idx++, c.getTBSCertificate().getEndDate().getDate().getTime() / 1000);
                    setBoolean(ps_cert, idx++, cert.isRevoked());
                    setInt(ps_cert, idx++, cert.getRevReason());
                    setLong(ps_cert, idx++, cert.getRevTime());
                    setLong(ps_cert, idx++, cert.getRevInvTime());
                    setInt(ps_cert, idx++, cert.getProfileId());
                    setInt(ps_cert, idx++, cert.getCaId());
                    setInt(ps_cert, idx++, cert.getRequestorId());
                    setInt(ps_cert, idx++, cert.getUserId());

                    ps_cert.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedKey));
                    String sha1FpSubject = X509Util.sha1sum_canonicalized_name(c.getSubject());
                    ps_cert.setString(idx++, sha1FpSubject);
                    Extension extension = c.getTBSCertificate().getExtensions().getExtension(Extension.basicConstraints);
                    boolean ee = true;
                    if(extension != null)
                    {
                        ASN1Encodable asn1 = extension.getParsedValue();
                        try
                        {
                            ee = BasicConstraints.getInstance(asn1).isCA() == false;
                        }catch(Exception e)
                        {
                        }
                    }
                    ps_cert.setInt(idx++, ee ? 1 : 0);
                    ps_cert.setInt(idx++, cert.getReqType());
                    String tidS = null;
                    if(cert.getTid() != null)
                    {
                        tidS = Hex.toHexString(cert.getTid());
                    }
                    ps_cert.setString(idx++, tidS);
                    ps_cert.addBatch();
                }catch(SQLException e)
                {
                    throw translate(SQL_ADD_CERT, e);
                }

                try
                {
                    int idx = 1;
                    ps_rawcert.setInt(idx++, cert.getId());
                    ps_rawcert.setString(idx++, hexSha1FpCert);
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

                        sql = SQL_ADD_RAWCERT;
                        ps_rawcert.executeBatch();

                        sql = null;
                        commit("(commit import cert to CA)");
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
