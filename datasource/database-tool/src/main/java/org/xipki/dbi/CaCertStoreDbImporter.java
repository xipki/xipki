/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi;

import java.io.ByteArrayInputStream;
import java.io.File;
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
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.database.api.DatabaseType;
import org.xipki.dbi.ca.jaxb.CainfoType;
import org.xipki.dbi.ca.jaxb.CertStoreType;
import org.xipki.dbi.ca.jaxb.CertStoreType.Cainfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.Certprofileinfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ca.jaxb.CertStoreType.Crls;
import org.xipki.dbi.ca.jaxb.CertStoreType.DeltaCRLCache;
import org.xipki.dbi.ca.jaxb.CertStoreType.PublishQueue;
import org.xipki.dbi.ca.jaxb.CertStoreType.Publisherinfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.Requestorinfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.UsersFiles;
import org.xipki.dbi.ca.jaxb.CertType;
import org.xipki.dbi.ca.jaxb.CertsType;
import org.xipki.dbi.ca.jaxb.CrlType;
import org.xipki.dbi.ca.jaxb.DeltaCRLCacheEntryType;
import org.xipki.dbi.ca.jaxb.NameIdType;
import org.xipki.dbi.ca.jaxb.ToPublishType;
import org.xipki.dbi.ca.jaxb.UserType;
import org.xipki.dbi.ca.jaxb.UsersType;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.HashCalculator;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class CaCertStoreDbImporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(CaConfigurationDbImporter.class);

    private final Unmarshaller unmarshaller;
    private final boolean resume;

    CaCertStoreDbImporter(DataSourceWrapper dataSource, Unmarshaller unmarshaller, String srcDir, boolean resume)
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
                throw new Exception("Could not process with '-resume' option");
            }
        }
        else
        {
            if(processLogFile.exists())
            {
                throw new Exception("Please either specify '-resume' option or delete the file " +
                        processLogFile.getPath() + " first");
            }
        }
        this.resume = resume;
    }

    public void importToDB()
    throws Exception
    {
        @SuppressWarnings("unchecked")
        JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_CertStore));
        CertStoreType certstore = root.getValue();
        if(certstore.getVersion() > VERSION)
        {
            throw new Exception("Cannot import CertStore greater than " + VERSION + ": " + certstore.getVersion());
        }

        File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
        System.out.println("Importing CA certstore to database");
        try
        {
            if(resume == false)
            {
                import_cainfo(certstore.getCainfos());
                import_requestorinfo(certstore.getRequestorinfos());
                import_publisherinfo(certstore.getPublisherinfos());
                import_certprofileinfo(certstore.getCertprofileinfos());
                import_user(certstore.getUsersFiles());
                import_crl(certstore.getCrls());
            }

            import_cert(certstore.getCertsFiles(), processLogFile);

            import_publishQueue(certstore.getPublishQueue());
            import_deltaCRLCache(certstore.getDeltaCRLCache());
            processLogFile.delete();
        }catch(Exception e)
        {
            System.err.println("Error while importing CA certstore to database");
            throw e;
        }
        System.out.println(" Imported CA certstore to database");
    }

    private void import_cainfo(Cainfos cainfos)
    throws Exception
    {
        final String SQL_ADD_CAINFO =
                "INSERT INTO CAINFO" +
                " (ID, SUBJECT, SHA1_FP_CERT, CERT)" +
                " VALUES (?, ?, ?, ?)";

        System.out.println("Importing table CAINFO");
        PreparedStatement ps = prepareStatement(SQL_ADD_CAINFO);

        try
        {
            for(CainfoType info : cainfos.getCainfo())
            {
                try
                {
                    String b64Cert = info.getCert();
                    byte[] encodedCert = Base64.decode(b64Cert);

                    X509Certificate c = IoCertUtil.parseCert(encodedCert);

                    String hexSha1FpCert = HashCalculator.hexHash(HashAlgoType.SHA1, encodedCert);

                    int idx = 1;
                    ps.setInt   (idx++, info.getId());
                    ps.setString(idx++, IoCertUtil.canonicalizeName(c.getSubjectX500Principal()));
                    ps.setString(idx++, hexSha1FpCert);
                    ps.setString(idx++, b64Cert);

                    ps.execute();
                }catch(Exception e)
                {
                    System.err.println("Error while importing cainfo with ID=" + info.getId() + ", message: " + e.getMessage());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" Imported table CAINFO");
    }

    private void import_requestorinfo(Requestorinfos requestorinfos)
    throws Exception
    {
        final String sql = "INSERT INTO REQUESTORINFO (ID, NAME) VALUES (?, ?)";

        System.out.println("Importing table REQUESTORINFO");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(NameIdType info : requestorinfos.getRequestorinfo())
            {
                try
                {
                    String name = info.getName();

                    int idx = 1;
                    ps.setInt   (idx++, info.getId());
                    ps.setString(idx++, name);

                    ps.execute();
                }catch(Exception e)
                {
                    System.err.println("Error while importing requestorinfo with ID=" + info.getId() +
                            ", message: " + e.getMessage());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" Imported table REQUESTORINFO");
    }

    private void import_publisherinfo(Publisherinfos publisherinfos)
    throws Exception
    {
        final String sql = "INSERT INTO PUBLISHERINFO (ID, NAME) VALUES (?, ?)";

        System.out.println("Importing table PUBLISHERINFO");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(NameIdType info : publisherinfos.getPublisherinfo())
            {
                try
                {
                    String name = info.getName();

                    int idx = 1;
                    ps.setInt   (idx++, info.getId());
                    ps.setString(idx++, name);

                    ps.execute();
                }catch(Exception e)
                {
                    System.err.println("Error while importing publisherinfo with ID=" + info.getId() +
                            ", message: " + e.getMessage());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" Imported table PUBLISHERINFO");
    }

    private void import_certprofileinfo(Certprofileinfos certprofileinfos)
    throws Exception
    {
        final String sql = "INSERT INTO CERTPROFILEINFO (ID, NAME) VALUES (?, ?)";

        System.out.println("Importing table CERTPROFILEINFO");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(NameIdType info : certprofileinfos.getCertprofileinfo())
            {
                try
                {
                    int idx = 1;
                    ps.setInt   (idx++, info.getId());
                    ps.setString(idx++, info.getName());

                    ps.execute();
                }catch(Exception e)
                {
                    System.err.println("Error while importing CERTPROFILEINFO with ID=" + info.getId() +
                            ", message: " + e.getMessage());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" Imported table certprofileinfo");
    }

    private void import_user(UsersFiles usersFiles)
    throws Exception
    {
        int sum = 0;
        for(String file : usersFiles.getUsersFile())
        {
            System.out.println("Importing users from file " + file);

            try
            {
                sum += do_import_user(file);
                System.out.println(" Imported users from file " + file);
                System.out.println(" Imported " + sum + " users ...");
            }catch(Exception e)
            {
                System.err.println("Error while importing users from file " + file);
                throw e;
            }
        }

        long maxId = getMax("USERNAME", "ID");
        alterSequence("USER_ID", maxId + 1);

        System.out.println(" Imported " + sum + " users");
    }

    private int do_import_user(String usersFile)
    throws Exception
    {
        final String sql = "INSERT INTO USERNAME (ID, NAME) VALUES (?, ?)";

        System.out.println("Importing table USERNAME");

        @SuppressWarnings("unchecked")
        JAXBElement<UsersType> rootElement = (JAXBElement<UsersType>)
                unmarshaller.unmarshal(new File(baseDir, usersFile));
        UsersType users = rootElement.getValue();

        PreparedStatement ps = prepareStatement(sql);

        int sum = 0;
        try
        {
            for(UserType user : users.getUser())
            {
                try
                {
                    int idx = 1;
                    ps.setInt   (idx++, user.getId());
                    ps.setString(idx++, user.getName());

                    ps.execute();
                    sum ++;
                }catch(Exception e)
                {
                    System.err.println("Error while importing USERNAME with ID=" +
                            user.getId() + ", message: " + e.getMessage());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        return sum;
    }

    private void import_publishQueue(PublishQueue publishQueue)
    throws Exception
    {
        final String SQL = "INSERT INTO PUBLISHQUEUE" +
                " (CERT_ID, PUBLISHER_ID, CAINFO_ID)" +
                " VALUES (?, ?, ?)";

        System.out.println("Importing table PUBLISHQUEUE");
        PreparedStatement ps = prepareStatement(SQL);

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
                }catch(Exception e)
                {
                    System.err.println("Error while importing PUBLISHQUEUE with CERT_ID=" + tbp.getCertId()
                            + " and PUBLISHER_ID=" + tbp.getPubId() + ", message: " + e.getMessage());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        System.out.println(" Imported table PUBLISHQUEUE");
    }

    private void import_deltaCRLCache(DeltaCRLCache deltaCRLCache)
    throws Exception
    {
        final String SQL_ORACLE = "INSERT INTO DELTACRL_CACHE" +
                " (ID, SERIAL, CAINFO_ID)" +
                " VALUES (?, ?, ?)";
        final String SQL_OTHER = "INSERT INTO DELTACRL_CACHE" +
                " (SERIAL, CAINFO_ID)" +
                " VALUES (?, ?)";

        boolean oracle = dataSource.getDatabaseType() == DatabaseType.ORACLE;

        System.out.println("Importing table DELTACRL_CACHE");
        PreparedStatement ps = prepareStatement(oracle ? SQL_ORACLE : SQL_OTHER);

        try
        {
            long id = 1;
            for(DeltaCRLCacheEntryType entry : deltaCRLCache.getEntry())
            {
                try
                {
                    int idx = 1;
                    if(oracle)
                    {
                        ps.setLong(idx++, id++);
                    }
                    ps.setLong(idx++, entry.getSerial());
                    ps.setInt(idx++, entry.getCaId());
                    ps.execute();
                }catch(Exception e)
                {
                    System.err.println("Error while importing DELTACRL_CACHE with ID=" + entry.getId() +
                            ", message: " + e.getMessage());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        long maxId = getMax("DELTACRL_CACHE", "ID");
        alterSequence("DCC_ID", maxId + 1);

        System.out.println(" Imported table DELTACRL_CACHE");
    }

    private void import_crl(Crls crls)
    throws Exception
    {
        final String sql = "INSERT INTO CRL (ID, CAINFO_ID, CRL_NUMBER, THISUPDATE, NEXTUPDATE, DELTACRL, BASECRL_NUMBER, CRL)"
                + " VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        System.out.println("Importing table CRL");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            int id = 1;
            for(CrlType crl : crls.getCrl())
            {
                try
                {
                    String filename = baseDir + File.separator + crl.getCrlFile();
                    byte[] encodedCrl = IoCertUtil.read(filename);

                    X509CRL c = null;
                    try
                    {
                        c = IoCertUtil.parseCRL(new ByteArrayInputStream(encodedCrl));
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
                    ps.setInt (idx++, id++);
                    ps.setInt (idx++, crl.getCainfoId());
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
                        ps.setBoolean(idx++, true);
                        ps.setNull(idx++, Types.BIGINT);
                    }
                    else
                    {
                        ps.setBoolean(idx++, true);
                        ps.setLong(idx++, baseCrlNumber.longValue());
                    }

                    String s = Base64.toBase64String(encodedCrl);
                    ps.setString(idx++, s);

                    ps.executeUpdate();
                }catch(Exception e)
                {
                    System.err.println("Error while importing CRL with ID=" + crl.getId() + ", message: " + e.getMessage());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }

        long maxId = getMax("CRL", "ID");
        alterSequence("CRL_ID", maxId + 1);

        System.out.println(" Imported table CRL");
    }

    private void import_cert(CertsFiles certsfiles, File processLogFile)
    throws Exception
    {
        int numProcessedBefore = 0;
        int minId = 1;
        if(processLogFile.exists())
        {
            byte[] content = IoCertUtil.read(processLogFile);
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

        System.out.println("Importing certificates from ID " + minId);
        printHeader();

        for(String certsFile : certsfiles.getCertsFile())
        {
            try
            {
                int[] numAndLastId = do_import_cert(certsFile, minId);
                int numProcessed = numAndLastId[0];
                int lastId = numAndLastId[1];
                if(numProcessed > 0)
                {
                    sum += numProcessed;
                    echoToFile((sum + numProcessedBefore) + ":" + lastId, processLogFile);
                    printStatus(total, sum, startTime);
                }
            }catch(Exception e)
            {
                System.err.println("\nError while importing certificates from file " + certsFile +
                        ".\nPlease continue with the option '-resume'");
                LOG.error("Exception", e);
                throw e;
            }
        }

        long maxId = getMax("CERT", "ID");
        alterSequence("CERT_ID", maxId + 1);

        printTrailer();
        echoToFile(MSG_CERTS_FINISHED, processLogFile);
        System.out.println(" Imported " + sum + " certificates");
    }

    private int[] do_import_cert(String certsZipFile, int minId)
    throws Exception
    {
        final String SQL_ADD_CERT =
                "INSERT INTO CERT " +
                "(ID, LAST_UPDATE, SERIAL, SUBJECT,"
                + " NOTBEFORE, NOTAFTER, REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME,"
                + " CERTPROFILEINFO_ID, CAINFO_ID,"
                + " REQUESTORINFO_ID, USER_ID, SHA1_FP_PK, SHA1_FP_SUBJECT, EE)" +
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        final String SQL_ADD_RAWCERT = "INSERT INTO RAWCERT (CERT_ID, SHA1_FP, CERT) VALUES (?, ?, ?)";

        PreparedStatement ps_cert = prepareStatement(SQL_ADD_CERT);
        PreparedStatement ps_rawcert = prepareStatement(SQL_ADD_RAWCERT);

        ZipFile zipFile = new ZipFile(new File(baseDir, certsZipFile));
        ZipEntry certsXmlEntry = zipFile.getEntry("certs.xml");

        @SuppressWarnings("unchecked")
        JAXBElement<CertsType> rootElement = (JAXBElement<CertsType>)
                unmarshaller.unmarshal(zipFile.getInputStream(certsXmlEntry));
        CertsType certs = rootElement.getValue();

        disableAutoCommit();

        try
        {
            List<CertType> list = certs.getCert();
            final int size = list.size();
            int n = 0;
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

                n++;

                String filename = cert.getCertFile();

                // rawcert
                ZipEntry certZipEnty = zipFile.getEntry(filename);

                // rawcert
                byte[] encodedCert = DbiUtil.read(zipFile.getInputStream(certZipEnty));

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
                        throw new CertificateException(e);
                    }
                }

                byte[] encodedKey = c.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

                String hexSha1FpCert = HashCalculator.hexHash(HashAlgoType.SHA1, encodedCert);

                // cert
                int idx = 1;
                ps_cert.setInt   (idx++, id);
                ps_cert.setLong(idx++, cert.getLastUpdate());
                ps_cert.setLong(idx++, c.getSerialNumber().getPositiveValue().longValue());
                ps_cert.setString(idx++, IoCertUtil.canonicalizeName(c.getSubject()));
                ps_cert.setLong(idx++, c.getTBSCertificate().getStartDate().getDate().getTime() / 1000);
                ps_cert.setLong(idx++, c.getTBSCertificate().getEndDate().getDate().getTime() / 1000);
                setBoolean(ps_cert, idx++, cert.isRevoked());
                setInt(ps_cert, idx++, cert.getRevReason());
                setLong(ps_cert, idx++, cert.getRevTime());
                setLong(ps_cert, idx++, cert.getRevInvalidityTime());
                setInt(ps_cert, idx++, cert.getCertprofileinfoId());
                setInt(ps_cert, idx++, cert.getCainfoId());
                setInt(ps_cert, idx++, cert.getRequestorinfoId());
                setInt(ps_cert, idx++, cert.getUserId());

                ps_cert.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedKey));
                String sha1FpSubject = IoCertUtil.sha1sum_canonicalized_name(c.getSubject());
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

                ps_cert.addBatch();

                ps_rawcert.setInt   (1, cert.getId());
                ps_rawcert.setString(2, hexSha1FpCert);
                ps_rawcert.setString(3, Base64.toBase64String(encodedCert));
                ps_rawcert.addBatch();
            }

            try
            {
                ps_cert.executeBatch();
                ps_rawcert.executeBatch();
                commit();
            } catch(SQLException e)
            {
                rollback();
                throw e;
            }

            return new int[]{n, lastSuccessfulCertId};
        }
        finally
        {
            try
            {
                recoverAutoCommit();
            }catch(SQLException e)
            {
            }

            releaseResources(ps_cert, null);
            releaseResources(ps_rawcert, null);
            zipFile.close();
        }
    }

    private void alterSequence(String seqName, long startValue)
    throws SQLException
    {
        try
        {
            dataSource.dropSequence(seqName);
        }catch(SQLException e)
        {
        }
        dataSource.createSequence(seqName, startValue);
    }

}
