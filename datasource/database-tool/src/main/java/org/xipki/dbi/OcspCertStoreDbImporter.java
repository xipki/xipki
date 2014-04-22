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

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.x509.Certificate;
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
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.HashCalculator;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

class OcspCertStoreDbImporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreDbImporter.class);

    private final Unmarshaller unmarshaller;
    private final HashCalculator hashCalculator;

    OcspCertStoreDbImporter(DataSource dataSource, Unmarshaller unmarshaller, String srcDir)
            throws SQLException, PasswordResolverException, NoSuchAlgorithmException
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
                unmarshaller.unmarshal(new File(baseDir + File.separator + FILENAME_OCSP_CertStore));
        CertStoreType certstore = root.getValue();

        import_issuer(certstore.getIssuers());
        import_cert(certstore.getCertsFiles());
    }

    private void import_issuer(Issuers issuers)
            throws SQLException, CertificateException
    {
        final String SQL_ADD_CAINFO =
                "INSERT INTO issuer (" +
                " id, subject," +
                " sha1_fp_name, sha1_fp_key," +
                " sha224_fp_name, sha224_fp_key," +
                " sha256_fp_name, sha256_fp_key," +
                " sha384_fp_name, sha384_fp_key," +
                " sha512_fp_name, sha512_fp_key," +
                " sha1_fp_cert, cert" +
                " ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        PreparedStatement ps = prepareStatement(SQL_ADD_CAINFO);

        try
        {
            for(IssuerType issuer : issuers.getIssuer())
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
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA1, encodedName));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA1, encodedKey));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA224, encodedName));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA224, encodedKey));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA256, encodedName));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA256, encodedKey));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA384, encodedName));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA384, encodedKey));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA512, encodedName));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA512, encodedKey));
                ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA1, encodedCert));
                ps.setString(idx++, b64Cert);

                ps.execute();
            }
        }finally
        {
            closeStatement(ps);
        }
    }

    private void import_cert(CertsFiles certsfiles)
            throws SQLException, JAXBException, IOException, CertificateException
    {
        for(String certsFile : certsfiles.getCertsFile())
        {
            @SuppressWarnings("unchecked")
            JAXBElement<CertsType> root = (JAXBElement<CertsType>)
                    unmarshaller.unmarshal(new File(baseDir + File.separator + certsFile));
            do_import_cert(root.getValue());
        }
    }

    private void do_import_cert(CertsType certs)
        throws SQLException, IOException, CertificateException
    {
        final String SQL_ADD_CERT =
                "INSERT INTO cert (" +
                " id, issuer_id, serial, " +
                " subject, last_update, notbefore, notafter," +
                " revocated, rev_reason, rev_time, rev_invalidity_time)" +
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        final String SQL_ADD_CERTHASH = "INSERT INTO certhash (" +
                "cert_id, sha1_fp, sha224_fp, sha256_fp, sha384_fp, sha512_fp)" +
                " VALUES (?, ?, ?, ?, ?, ?)";

        final String SQL_ADD_RAWCERT = "INSERT INTO rawcert (cert_id, cert) VALUES (?, ?)";

        PreparedStatement ps_cert = prepareStatement(SQL_ADD_CERT);
        PreparedStatement ps_certhash = prepareStatement(SQL_ADD_CERTHASH);
        PreparedStatement ps_rawcert = prepareStatement(SQL_ADD_RAWCERT);

        try
        {
            for(CertType cert : certs.getCert())
            {
                // rawcert
                String filename = baseDir + File.separator + cert.getCertFile();
                byte[] encodedCert = IoCertUtil.read(filename);
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
                ps_cert.setString(idx++, c.getSerialNumber().toString());
                ps_cert.setString(idx++, c.getSubjectX500Principal().getName());
                ps_cert.setString(idx++, cert.getLastUpdate());
                ps_cert.setLong  (idx++, c.getNotBefore().getTime() / 1000);
                ps_cert.setLong  (idx++, c.getNotAfter().getTime() / 1000);
                ps_cert.setBoolean(idx++, cert.isRevocated());
                ps_cert.setString(idx++, cert.getRevReason());
                ps_cert.setString(idx++, cert.getRevTime());
                ps_cert.setString(idx++, cert.getRevInvalidityTime());

                ps_cert.executeUpdate();

                // certhash
                idx = 1;
                ps_certhash.setInt(idx++, cert.getId());
                ps_certhash.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA1, encodedCert));
                ps_certhash.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA224, encodedCert));
                ps_certhash.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA256, encodedCert));
                ps_certhash.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA384, encodedCert));
                ps_certhash.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA512, encodedCert));

                ps_certhash.executeUpdate();

                // rawcert
                ps_rawcert.setInt   (1, cert.getId());
                ps_rawcert.setString(2, Base64.toBase64String(encodedCert));

                ps_rawcert.executeUpdate();
            }
        }finally
        {
            closeStatement(ps_cert);
            closeStatement(ps_rawcert);
        }
    }

}
