/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.x509.Certificate;
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
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.HashCalculator;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class OcspCertStoreDbImporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreDbImporter.class);

    private final Unmarshaller unmarshaller;

    OcspCertStoreDbImporter(DataSourceWrapper dataSource, Unmarshaller unmarshaller, String srcDir)
    throws SQLException, PasswordResolverException, NoSuchAlgorithmException
    {
        super(dataSource, srcDir);
        ParamChecker.assertNotNull("unmarshaller", unmarshaller);
        this.unmarshaller = unmarshaller;
    }

    public void importToDB()
    throws Exception
    {
        @SuppressWarnings("unchecked")
        JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                unmarshaller.unmarshal(new File(baseDir + File.separator + FILENAME_OCSP_CertStore));
        CertStoreType certstore = root.getValue();
        if(certstore.getVersion() > VERSION)
        {
            throw new Exception("Cannot import CertStore greater than " + VERSION + ": " + certstore.getVersion());
        }

        System.out.println("Importing OCSP certstore to database");
        try
        {
            import_issuer(certstore.getIssuers());
            import_cert(certstore.getCertsFiles());
        }catch(Exception e)
        {
            System.err.println("Error while importing OCSP certstore to database");
            throw e;
        }
        System.out.println(" Imported OCSP certstore to database");
    }

    private void import_issuer(Issuers issuers)
    throws Exception
    {
        final String SQL_ADD_CAINFO =
                "INSERT INTO ISSUER (" +
                " ID, SUBJECT," +
                " NOTBEFORE, NOTAFTER," +
                " SHA1_FP_NAME, SHA1_FP_KEY," +
                " SHA224_FP_NAME, SHA224_FP_KEY," +
                " SHA256_FP_NAME, SHA256_FP_KEY," +
                " SHA384_FP_NAME, SHA384_FP_KEY," +
                " SHA512_FP_NAME, SHA512_FP_KEY," +
                " SHA1_fp_cert, cert," +
                " REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME" +
                " ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        System.out.println("Importing table ISSUER");
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
                            throw new CertificateException(e);
                        }
                    }
                    byte[] encodedKey = c.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

                    int idx = 1;
                    ps.setInt   (idx++, issuer.getId());
                    ps.setString(idx++, IoCertUtil.canonicalizeName(c.getSubject()));
                    ps.setLong  (idx++, c.getTBSCertificate().getStartDate().getDate().getTime() / 1000);
                    ps.setLong  (idx++, c.getTBSCertificate().getEndDate().getDate().getTime() / 1000);
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
                    setLong(ps, idx++, issuer.getRevInvalidityTime());

                    ps.execute();
                }catch(Exception e)
                {
                    System.err.println("Error while importing issuer with id=" + issuer.getId());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
        }
        System.out.println(" Imported table ISSUER");
    }

    private void import_cert(CertsFiles certsfiles)
    throws Exception
    {
        int sum = 0;

        for(String certsFile : certsfiles.getCertsFile())
        {
            System.out.println("Importing certificates from file " + certsFile);
            try
            {
                sum += do_import_cert(certsFile);

                System.out.println(" Imported certificates from file " + certsFile);
                System.out.println(" Imported " + sum + " certificates ...");
            }catch(Exception e)
            {
                System.err.println("Error while importing certificates from file " + certsFile);
                throw e;
            }

        }
        System.out.println(" Imported " + sum + " certificates");
    }

    private int do_import_cert(String certsZipFile)
    throws Exception
    {
        final String SQL_ADD_CERT =
                "INSERT INTO CERT (" +
                " ID, ISSUER_ID, SERIAL, " +
                " SUBJECT, LAST_UPDATE, NOTBEFORE, NOTAFTER," +
                " REVOKED, REV_REASON, REV_TIME, REV_INVALIDITY_TIME, PROFILE)" +
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        final String SQL_ADD_CERTHASH = "INSERT INTO CERTHASH (" +
                "CERT_ID, SHA1_FP, SHA224_FP, SHA256_FP, SHA384_FP, SHA512_FP)" +
                " VALUES (?, ?, ?, ?, ?, ?)";

        final String SQL_ADD_RAWCERT = "INSERT INTO RAWCERT (CERT_ID, CERT) VALUES (?, ?)";

        PreparedStatement ps_cert = prepareStatement(SQL_ADD_CERT);
        PreparedStatement ps_certhash = prepareStatement(SQL_ADD_CERTHASH);
        PreparedStatement ps_rawcert = prepareStatement(SQL_ADD_RAWCERT);

        ZipFile zipFile = new ZipFile(new File(baseDir, certsZipFile));
        ZipEntry certsXmlEntry = zipFile.getEntry("certs.xml");

        @SuppressWarnings("unchecked")
        JAXBElement<CertsType> rootElement = (JAXBElement<CertsType>)
                unmarshaller.unmarshal(zipFile.getInputStream(certsXmlEntry));
        CertsType certs = rootElement.getValue();

        int sum = 0;

        try
        {
            for(CertType cert : certs.getCert())
            {
                try
                {
                    String filename = cert.getCertFile();

                    // rawcert
                    ZipEntry certZipEnty = zipFile.getEntry(filename);
                    // rawcert
                    byte[] encodedCert = DbiUtil.read(zipFile.getInputStream(certZipEnty));

                    X509Certificate c;
                    try
                    {
                        c = IoCertUtil.parseCert(encodedCert);
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

                    // cert
                    int idx = 1;
                    ps_cert.setInt   (idx++, cert.getId());
                    ps_cert.setInt   (idx++, cert.getIssuerId());
                    ps_cert.setLong(idx++, c.getSerialNumber().longValue());
                    ps_cert.setString(idx++, IoCertUtil.canonicalizeName(c.getSubjectX500Principal()));
                    ps_cert.setLong(idx++, cert.getLastUpdate());
                    ps_cert.setLong  (idx++, c.getNotBefore().getTime() / 1000);
                    ps_cert.setLong  (idx++, c.getNotAfter().getTime() / 1000);
                    setBoolean(ps_cert, idx++, cert.isRevoked());
                    setInt(ps_cert, idx++, cert.getRevReason());
                    setLong(ps_cert, idx++, cert.getRevTime());
                    setLong(ps_cert, idx++, cert.getRevInvalidityTime());
                    ps_cert.setString(idx++, cert.getProfile());
                    ps_cert.executeUpdate();

                    // certhash
                    idx = 1;
                    ps_certhash.setInt(idx++, cert.getId());
                    ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedCert));
                    ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA224, encodedCert));
                    ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA256, encodedCert));
                    ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA384, encodedCert));
                    ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA512, encodedCert));

                    ps_certhash.executeUpdate();

                    // rawcert
                    ps_rawcert.setInt   (1, cert.getId());
                    ps_rawcert.setString(2, Base64.toBase64String(encodedCert));

                    ps_rawcert.executeUpdate();

                    sum++;
                }catch(Exception e)
                {
                    System.err.println("Error while importing certificate with ID=" + cert.getId());
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps_cert, null);
            releaseResources(ps_rawcert, null);
            zipFile.close();
        }

        return sum;
    }

}
