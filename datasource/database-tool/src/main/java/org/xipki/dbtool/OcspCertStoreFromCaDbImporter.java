/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.HashAlgoType;
import org.xipki.common.HashCalculator;
import org.xipki.common.IoUtil;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.dbi.ca.jaxb.CAConfigurationType;
import org.xipki.dbi.ca.jaxb.CaHasPublisherType;
import org.xipki.dbi.ca.jaxb.CaType;
import org.xipki.dbi.ca.jaxb.CainfoType;
import org.xipki.dbi.ca.jaxb.CertStoreType;
import org.xipki.dbi.ca.jaxb.CertStoreType.Cainfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ca.jaxb.CertType;
import org.xipki.dbi.ca.jaxb.CertsType;
import org.xipki.dbi.ca.jaxb.NameIdType;
import org.xipki.dbi.ca.jaxb.PublisherType;

/**
 * @author Lijun Liao
 */

class OcspCertStoreFromCaDbImporter extends DbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreFromCaDbImporter.class);

    private final Unmarshaller unmarshaller;
    private final String publisherName;
    private final boolean resume;

    OcspCertStoreFromCaDbImporter(DataSourceWrapper dataSource, Unmarshaller unmarshaller,
            String srcDir, String publisherName, boolean resume)
    throws Exception
    {
        super(dataSource, srcDir);
        ParamChecker.assertNotNull("unmarshaller", unmarshaller);
        ParamChecker.assertNotEmpty("publisherName", publisherName);
        this.unmarshaller = unmarshaller;
        this.publisherName = publisherName;
        File processLogFile = new File(baseDir, DbPorter.IMPORT_TO_OCSP_PROCESS_LOG_FILENAME);
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

        @SuppressWarnings("unchecked")
        JAXBElement<CAConfigurationType> rootCaConf = (JAXBElement<CAConfigurationType>)
                unmarshaller.unmarshal(new File(baseDir + File.separator + FILENAME_CA_Configuration));
        CAConfigurationType caConf = rootCaConf.getValue();
        if(caConf.getVersion() > VERSION)
        {
            throw new Exception("Cannot import CA Configuration greater than " + VERSION + ": " + certstore.getVersion());
        }

        System.out.println("Importing CA certstore to OCSP database");
        try
        {
            PublisherType publisherType = null;
            for(PublisherType type : caConf.getPublishers().getPublisher())
            {
                if(publisherName.equals(type.getName()))
                {
                    publisherType = type;
                    break;
                }
            }

            if(publisherType == null)
            {
                throw new Exception("Unknown publisher " + publisherName);
            }

            String type = publisherType.getType();
            if("ocsp".equalsIgnoreCase(type) || "java:org.xipki.ca.server.publisher.DefaultCertPublisher".equals(type))
            {
            }
            else
            {
                throw new Exception("Unkwown publisher type " + type);
            }

            CmpUtf8Pairs utf8pairs = new CmpUtf8Pairs(publisherType.getConf());
            String v = utf8pairs.getValue("publish.goodcerts");
            boolean revokedOnly = false;
            if(v != null)
            {
                revokedOnly = (Boolean.parseBoolean(v) == false);
            }

            Set<String> relatedCaNames = new HashSet<>();
            for(CaHasPublisherType ctype : caConf.getCaHasPublishers().getCaHasPublisher())
            {
                if(ctype.getPublisherName().equals(publisherName))
                {
                    relatedCaNames.add(ctype.getCaName());
                }
            }

            List<CaType> relatedCas = new LinkedList<>();
            for(CaType cType : caConf.getCas().getCa())
            {
                if(relatedCaNames.contains(cType.getName()))
                {
                    relatedCas.add(cType);
                }
            }

            Map<Integer, String> profileMap = new HashMap<Integer, String>();
            for(NameIdType ni : certstore.getCertprofileinfos().getCertprofileinfo())
            {
                profileMap.put(ni.getId(), ni.getName());
            }

            List<Integer> relatedCaIds;
            if(resume)
            {
                relatedCaIds = getIssuerIds(certstore.getCainfos(), relatedCas);
            }
            else
            {
                relatedCaIds = import_issuer(certstore.getCainfos(), relatedCas);
            }

            File processLogFile = new File(baseDir, DbPorter.IMPORT_TO_OCSP_PROCESS_LOG_FILENAME);
            import_cert(certstore.getCertsFiles(), profileMap, revokedOnly, relatedCaIds, processLogFile);
            processLogFile.delete();
        }catch(Exception e)
        {
            System.err.println("Error while importing OCSP certstore to database");
            throw e;
        }
        System.out.println(" Imported OCSP certstore to database");
    }

    private List<Integer> getIssuerIds(Cainfos issuers, List<CaType> cas)
    throws Exception
    {
        List<Integer> relatedCaIds = new LinkedList<>();
        for(CainfoType issuer : issuers.getCainfo())
        {
            String b64Cert = issuer.getCert();
            byte[] encodedCert = Base64.decode(b64Cert);

            // retrieve the revocation information of the CA, if possible
            CaType ca = null;
            for(CaType caType : cas)
            {
                if(Arrays.equals(encodedCert, Base64.decode(caType.getCert())))
                {
                    ca = caType;
                    break;
                }
            }

            if(ca == null)
            {
                continue;
            }
            relatedCaIds.add(issuer.getId());
        }
        return relatedCaIds;
    }

    private List<Integer> import_issuer(Cainfos issuers, List<CaType> cas)
    throws Exception
    {
        System.out.println("Importing table ISSUER");
        PreparedStatement ps = prepareStatement(OcspCertStoreDbImporter.SQL_ADD_CAINFO);

        List<Integer> relatedCaIds = new LinkedList<>();

        try
        {
            for(CainfoType issuer : issuers.getCainfo())
            {
                try
                {
                    String b64Cert = issuer.getCert();
                    byte[] encodedCert = Base64.decode(b64Cert);

                    // retrieve the revocation information of the CA, if possible
                    CaType ca = null;
                    for(CaType caType : cas)
                    {
                        if(Arrays.equals(encodedCert, Base64.decode(caType.getCert())))
                        {
                            ca = caType;
                            break;
                        }
                    }

                    if(ca == null)
                    {
                        continue;
                    }

                    relatedCaIds.add(issuer.getId());

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
                    ps.setInt(idx++, issuer.getId());
                    ps.setString(idx++, SecurityUtil.canonicalizeName(c.getSubject()));
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

                    setBoolean(ps, idx++, ca.isRevoked());
                    setInt(ps, idx++, ca.getRevReason());
                    setLong(ps, idx++, ca.getRevTime());
                    setLong(ps, idx++, ca.getRevInvalidityTime());

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
        return relatedCaIds;
    }

    private void import_cert(CertsFiles certsfiles, Map<Integer, String> profileMap,
            boolean revokedOnly, List<Integer> caIds, File processLogFile)
    throws Exception
    {
        int numProcessedBefore = 0;
        int minId = 0;
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
        long sum = 0;

        System.out.println("Importing certificates from ID " + minId);
        printHeader();

        PreparedStatement ps_cert = prepareStatement(OcspCertStoreDbImporter.SQL_ADD_CERT);
        PreparedStatement ps_certhash = prepareStatement(OcspCertStoreDbImporter.SQL_ADD_CERTHASH);
        PreparedStatement ps_rawcert = prepareStatement(OcspCertStoreDbImporter.SQL_ADD_RAWCERT);

        try
        {
            for(String certsFile : certsfiles.getCertsFile())
            {
                try
                {
                    int[] numAndLastId = do_import_cert(ps_cert, ps_certhash, ps_rawcert,
                            certsFile, profileMap, revokedOnly, caIds, minId);
                    int numProcessed = numAndLastId[0];
                    int lastId = numAndLastId[1];
                    if(numProcessed > 0)
                    {
                        sum += numProcessed;
                        DbPorter.echoToFile((sum + numProcessedBefore) + ":" + lastId, processLogFile);
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
        } finally
        {
            releaseResources(ps_cert, null);
            releaseResources(ps_certhash, null);
            releaseResources(ps_rawcert, null);
        }

        printTrailer();
        DbPorter.echoToFile(MSG_CERTS_FINISHED, processLogFile);
        System.out.println("Processed " + sum + " certificates");
    }

    private int[] do_import_cert(PreparedStatement ps_cert, PreparedStatement ps_certhash, PreparedStatement ps_rawcert,
            String certsZipFile, Map<Integer, String> profileMap,
            boolean revokedOnly, List<Integer> caIds, int minId)
    throws Exception
    {
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

                if(revokedOnly && cert.isRevoked() == false)
                {
                    continue;
                }

                int caId = cert.getCainfoId();
                if(caIds.contains(caId) == false)
                {
                    continue;
                }

                String filename = cert.getCertFile();

                // rawcert
                ZipEntry certZipEnty = zipFile.getEntry(filename);
                // rawcert
                byte[] encodedCert = DbiUtil.read(zipFile.getInputStream(certZipEnty));

                X509Certificate c;
                try
                {
                    c = SecurityUtil.parseCert(encodedCert);
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
                String seqName = "CERT_ID";
                int currentId = (int) dataSource.nextSeqValue(seqName);

                int idx = 1;
                ps_cert.setInt(idx++, currentId);
                ps_cert.setInt(idx++, caId);
                ps_cert.setLong(idx++, c.getSerialNumber().longValue());
                ps_cert.setString(idx++, SecurityUtil.canonicalizeName(c.getSubjectX500Principal()));
                ps_cert.setLong(idx++, cert.getLastUpdate());
                ps_cert.setLong(idx++, c.getNotBefore().getTime() / 1000);
                ps_cert.setLong(idx++, c.getNotAfter().getTime() / 1000);
                setBoolean(ps_cert, idx++, cert.isRevoked());
                setInt(ps_cert, idx++, cert.getRevReason());
                setLong(ps_cert, idx++, cert.getRevTime());
                setLong(ps_cert, idx++, cert.getRevInvalidityTime());

                int certProfileId = cert.getCertprofileinfoId();
                String certProfileName = profileMap.get(certProfileId);
                ps_cert.setString(idx++, certProfileName);
                ps_cert.addBatch();

                // certhash
                idx = 1;
                ps_certhash.setInt(idx++, currentId);
                ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA1, encodedCert));
                ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA224, encodedCert));
                ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA256, encodedCert));
                ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA384, encodedCert));
                ps_certhash.setString(idx++, HashCalculator.hexHash(HashAlgoType.SHA512, encodedCert));
                ps_certhash.addBatch();

                // rawcert
                ps_rawcert.setInt(1, currentId);
                ps_rawcert.setString(2, Base64.toBase64String(encodedCert));
                ps_rawcert.addBatch();
            }

            try
            {
                ps_cert.executeBatch();
                ps_certhash.executeBatch();
                ps_rawcert.executeBatch();
                commit();
            }catch(SQLException e)
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
            zipFile.close();
        }
    }

}
