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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Base64;
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
import org.xipki.dbi.ca.jaxb.RequestorinfoType;
import org.xipki.dbi.ca.jaxb.UserType;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.HashCalculator;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

class CaCertStoreDbImporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(CaConfigurationDbImporter.class);

    private final Unmarshaller unmarshaller;
    private final HashCalculator hashCalculator;

    CaCertStoreDbImporter(DataSource dataSource, Unmarshaller unmarshaller, String srcDir)
            throws SQLException, PasswordResolverException, IOException, NoSuchAlgorithmException
    {
        super(dataSource, srcDir);
        ParamChecker.assertNotNull("unmarshaller", unmarshaller);
        this.unmarshaller = unmarshaller;
        this.hashCalculator = new HashCalculator();
    }

    public void importToDB() throws Exception
    {
        @SuppressWarnings("unchecked")
        JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>)
                unmarshaller.unmarshal(new File(baseDir + File.separator + FILENAME_CA_CertStore));
        CertStoreType certstore = root.getValue();

        System.out.println("Importing CA certstore to database");
        import_cainfo(certstore.getCainfos());
        import_requestorinfo(certstore.getRequestorinfos());
        import_certprofileinfo(certstore.getCertprofileinfos());
        import_user(certstore.getUsers());
        import_crl(certstore.getCrls());
        import_cert(certstore.getCertsFiles());
        System.out.println("Imported CA certstore to database");
    }

    private void import_cainfo(Cainfos cainfos)
            throws SQLException, CertificateException, IOException
    {
        final String SQL_ADD_CAINFO =
                "INSERT INTO cainfo" +
                " (id, subject, sha1_fp_cert, cert)" +
                " VALUES (?, ?, ?, ?)";

        System.out.println("Importing table cainfo");
        PreparedStatement ps = prepareStatement(SQL_ADD_CAINFO);

        try
        {
            for(CainfoType info : cainfos.getCainfo())
            {
                String b64Cert = info.getCert();
                byte[] encodedCert = Base64.decode(b64Cert);

                X509Certificate c;
                try
                {
                    c = IoCertUtil.parseCert(encodedCert);
                } catch (Exception e)
                {
                    LOG.error("could not parse certificate of cainfo {}", info.getId());
                    LOG.debug("could not parse certificate of cainfo " + info.getId(), e);
                    if(e instanceof CertificateException)
                    {
                        throw (CertificateException) e;
                    }
                    else
                    {
                        throw new CertificateException(e);
                    }
                }

                String hexSha1FpCert = hashCalculator.hexHash(HashAlgoType.SHA1, encodedCert);

                int idx = 1;
                ps.setInt   (idx++, info.getId());
                ps.setString(idx++, c.getSubjectX500Principal().getName());
                ps.setString(idx++, hexSha1FpCert);
                ps.setString(idx++, b64Cert);

                ps.execute();
            }
        }finally
        {
            closeStatement(ps);
        }

        System.out.println("Imported table cainfo");
    }

    private void import_requestorinfo(Requestorinfos requestorinfos)
            throws SQLException, CertificateException, IOException
    {
        final String sql = "INSERT INTO requestorinfo (id, subject, sha1_fp_cert, cert) VALUES (?, ?, ?, ?)";

        System.out.println("Importing table requestorinfo");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(RequestorinfoType info : requestorinfos.getRequestorinfo())
            {
                String b64Cert = info.getCert();
                byte[] encodedCert = Base64.decode(b64Cert);
                X509Certificate cert = IoCertUtil.parseCert(encodedCert);
                String hexSha1FpCert = hashCalculator.hexHash(HashAlgoType.SHA1, encodedCert);

                int idx = 1;
                ps.setInt   (idx++, info.getId());
                ps.setString(idx++, cert.getSubjectX500Principal().getName());
                ps.setString(idx++, hexSha1FpCert);
                ps.setString(idx++, b64Cert);

                ps.execute();
            }
        }finally
        {
            closeStatement(ps);
        }

        System.out.println("Imported table requestorinfo");
    }

    private void import_certprofileinfo(Certprofileinfos certprofileinfos)
            throws SQLException
    {
        final String sql = "INSERT INTO certprofileinfo (id, name) VALUES (?, ?)";

        System.out.println("Importing table certprofileinfo");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(CertprofileinfoType info : certprofileinfos.getCertprofileinfo())
            {
                int idx = 1;
                ps.setInt   (idx++, info.getId());
                ps.setString(idx++, info.getName());

                ps.execute();
            }
        }finally
        {
            closeStatement(ps);
        }

        System.out.println("Imported table certprofileinfo");
    }

    private void import_user(Users users)
            throws SQLException
    {
        final String sql = "INSERT INTO user (id, name) VALUES (?, ?)";

        System.out.println("Importing table user");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(UserType user : users.getUser())
            {
                int idx = 1;
                ps.setInt   (idx++, user.getId());
                ps.setString(idx++, user.getName());

                ps.execute();
            }
        }finally
        {
            closeStatement(ps);
        }

        System.out.println("Imported table user");
    }

    private void import_crl(Crls crls)
            throws SQLException, IOException, CertificateException, CRLException
    {
        final String sql = "INSERT INTO crl (cainfo_id, crl_number, thisUpdate, nextUpdate, crl) VALUES (?, ?, ?, ?, ?)";

        System.out.println("Importing table crl");

        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(CrlType crl : crls.getCrl())
            {
                String filename = baseDir + File.separator + crl.getCrlFile();
                byte[] encodedCrl = IoCertUtil.read(filename);

                X509CRL c = null;
                try
                {
                    c = IoCertUtil.parseCRL(new ByteArrayInputStream(encodedCrl));
                } catch (CertificateException e)
                {
                    LOG.error("could not parse CRL in file {}", filename);
                    LOG.debug("could not parse CRL in file " + filename, e);
                    //throw e;
                } catch (CRLException e)
                {
                    LOG.error("could not parse CRL in file {}", filename);
                    LOG.debug("could not parse CRL in file " + filename, e);
                    //throw e;
                }

                if(c == null)
                {
                    continue;
                }

                byte[] octetString = c.getExtensionValue(Extension.cRLNumber.getId());
                byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
                BigInteger crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

                int idx = 1;
                ps.setInt   (idx++, crl.getCainfoId());
                ps.setString(idx++, crlNumber.toString());
                ps.setLong(idx++, c.getThisUpdate().getTime() / 1000);
                if(c.getNextUpdate() != null)
                {
                    ps.setLong(idx++, c.getNextUpdate().getTime() / 1000);
                }
                else
                {
                    ps.setNull(idx++, Types.INTEGER);
                }

                InputStream is = new ByteArrayInputStream(encodedCrl);
                ps.setBlob(idx++, is);

                ps.executeUpdate();
            }
        }finally
        {
            closeStatement(ps);
        }

        System.out.println("Imported table crl");
    }

    private void import_cert(CertsFiles certsfiles)
            throws SQLException, JAXBException, IOException, CertificateException
    {
        int sum = 0;
        for(String certsFile : certsfiles.getCertsFile())
        {
            System.out.println("Importing certificates specified in file " + certsFile);
            @SuppressWarnings("unchecked")
            JAXBElement<CertsType> root = (JAXBElement<CertsType>)
                    unmarshaller.unmarshal(new File(baseDir + File.separator + certsFile));
            sum += do_import_cert(root.getValue());
            System.out.println("Imported certificates specified in file " + certsFile);
            System.out.println("Imported " + sum + " certificates ...");
        }
        System.out.println("Imported " + sum + " certificates");
    }

    private int do_import_cert(CertsType certs)
        throws SQLException, IOException, CertificateException
    {
        final String SQL_ADD_CERT =
                "INSERT INTO cert " +
                "(id, last_update, serial, subject,"
                + " notbefore, notafter, revocated, rev_reason, rev_time, rev_invalidity_time,"
                + " certprofileinfo_id, cainfo_id,"
                + " requestorinfo_id, user_id, sha1_fp_pk, sha1_fp_subject)" +
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        final String SQL_ADD_RAWCERT = "INSERT INTO rawcert (cert_id, sha1_fp, cert) VALUES (?, ?, ?)";

        PreparedStatement ps_cert = prepareStatement(SQL_ADD_CERT);
        PreparedStatement ps_rawcert = prepareStatement(SQL_ADD_RAWCERT);

        int sum = 0;
        try
        {
            for(CertType cert : certs.getCert())
            {
                // rawcert
                String filename = baseDir + File.separator + cert.getCertFile();
                byte[] encodedCert = IoCertUtil.read(filename);

                Certificate c;
                try
                {
                    c = Certificate.getInstance(encodedCert);
                } catch (Exception e)
                {
                    LOG.error("could not parse certificate in file {}", filename);
                    LOG.debug("could not parse certificate in file " + filename, e);
                    throw new CertificateException(e);
                }

                byte[] encodedKey = c.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

                String hexSha1FpCert = hashCalculator.hexHash(HashAlgoType.SHA1, encodedCert);

                // cert
                int idx = 1;
                ps_cert.setInt   (idx++, cert.getId());
                ps_cert.setString(idx++, cert.getLastUpdate());
                ps_cert.setString(idx++, c.getSerialNumber().toString());
                ps_cert.setString(idx++, IoCertUtil.canonicalizeName(c.getSubject()));
                ps_cert.setLong(idx++, c.getTBSCertificate().getStartDate().getDate().getTime() / 1000);
                ps_cert.setLong(idx++, c.getTBSCertificate().getEndDate().getDate().getTime() / 1000);
                ps_cert.setBoolean(idx++, cert.isRevocated());
                ps_cert.setString(idx++, cert.getRevReason());
                ps_cert.setString(idx++, cert.getRevTime());
                ps_cert.setString(idx++, cert.getRevInvalidityTime());
                ps_cert.setString(idx++, cert.getCertprofileinfoId());
                ps_cert.setString(idx++, cert.getCainfoId());
                ps_cert.setString(idx++, cert.getRequestorinfoId());
                ps_cert.setString(idx++, cert.getUserId());

                ps_cert.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA1, encodedKey));
                String sha1FpSubject = IoCertUtil.sha1sum_canonicalized_name(c.getSubject());
                ps_cert.setString(idx++, sha1FpSubject);

                ps_cert.executeUpdate();

                ps_rawcert.setInt   (1, cert.getId());
                ps_rawcert.setString(2, hexSha1FpCert);
                ps_rawcert.setString(3, Base64.toBase64String(encodedCert));

                ps_rawcert.executeUpdate();
                sum++;
            }
        }finally
        {
            closeStatement(ps_cert);
            closeStatement(ps_rawcert);
        }

        return sum;
    }

}
