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

package org.xipki.pki.ca.dbtool;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;
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
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.qa.AbstractLoadTest;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Cas;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.DeltaCRLCache;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Profiles;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.PublishQueue;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Publishers;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertStoreType.Requestors;
import org.xipki.pki.ca.dbtool.xmlio.CaCertType;
import org.xipki.pki.ca.dbtool.xmlio.CaCertsReader;
import org.xipki.pki.ca.dbtool.xmlio.CaCrlType;
import org.xipki.pki.ca.dbtool.xmlio.CaCrlsReader;
import org.xipki.pki.ca.dbtool.xmlio.CaUserType;
import org.xipki.pki.ca.dbtool.xmlio.CaUsersReader;
import org.xipki.pki.ca.dbtool.jaxb.ca.CertstoreCaType;
import org.xipki.pki.ca.dbtool.jaxb.ca.DeltaCRLCacheEntryType;
import org.xipki.pki.ca.dbtool.jaxb.ca.NameIdType;
import org.xipki.pki.ca.dbtool.jaxb.ca.ToPublishType;
import org.xipki.security.api.FpIdCalculator;
import org.xipki.security.api.HashCalculator;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

class CaCertStoreDbImporter extends AbstractCaCertStoreDbPorter
{
    private static final Logger LOG = LoggerFactory.getLogger(CaConfigurationDbImporter.class);

    private static final String SQL_ADD_CERT =
            "INSERT INTO CERT " +
            "(ID, ART, LUPDATE, SN, SUBJECT, FP_S, FP_CN, FP_RS," // 8
            + " NBEFORE, NAFTER, REV, RR, RT, RIT, PID, CA_ID," // 8
            + " RID, UNAME, FP_K, EE, RTYPE, TID)" + // 6
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SQL_ADD_CRAW =
            "INSERT INTO CRAW (CID, SHA1, REQ_SUBJECT, CERT) VALUES (?, ?, ?, ?)";

    private static final String SQL_ADD_CRL =
            "INSERT INTO CRL (ID, CA_ID, CRL_NO, THISUPDATE, NEXTUPDATE, DELTACRL, BASECRL_NO, CRL)"
                    + " VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SQL_ADD_USER = "INSERT INTO USERNAME (ID, NAME, PASSWORD,CN_REGEX) VALUES (?, ?, ?, ?)";

    private final Unmarshaller unmarshaller;
    private final boolean resume;
    private final int numCertsPerCommit;
    private final int numUsersPerCommit;
    private final int numCrlsPerCommit;

    CaCertStoreDbImporter(
            final DataSourceWrapper dataSource,
            final Unmarshaller unmarshaller,
            final String srcDir,
            final int numCertsPerCommit,
            final boolean resume,
            final AtomicBoolean stopMe,
            final boolean evaluateOnly)
    throws Exception
    {
        super(dataSource, srcDir, stopMe, evaluateOnly);
        if(numCertsPerCommit < 1)
        {
            throw new IllegalArgumentException("numCertsPerCommit could not be less than 1: " + numCertsPerCommit);
        }
        ParamUtil.assertNotNull("unmarshaller", unmarshaller);
        this.unmarshaller = unmarshaller;
        this.numCertsPerCommit = numCertsPerCommit;
        this.numUsersPerCommit = numCertsPerCommit * 10;
        this.numCrlsPerCommit = Math.max(1, numCertsPerCommit / 10);

        this.resume = resume;

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
                dropIndexes();

                import_ca(certstore.getCas());
                import_requestor(certstore.getRequestors());
                import_publisher(certstore.getPublishers());
                import_profile(certstore.getProfiles());
                import_user(certstore);
                import_crl(certstore);
            }

            import_cert(certstore, processLogFile);

            import_publishQueue(certstore.getPublishQueue());
            import_deltaCRLCache(certstore.getDeltaCRLCache());

            recoverIndexes();
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
        final String sql = "INSERT INTO CS_CA (ID, SUBJECT, SHA1_CERT, CERT) VALUES (?, ?, ?, ?)";
        System.out.println("importing table CS_CA");
        PreparedStatement ps = prepareStatement(sql);

        try
        {
            for(CertstoreCaType m : cas.getCa())
            {
                try
                {
                    String b64Cert = getValue(m.getCert());
                    byte[] encodedCert = Base64.decode(b64Cert);
                    Certificate c = Certificate.getInstance(encodedCert);
                    String b64Sha1FpCert = HashCalculator.base64Sha1(encodedCert);

                    int idx = 1;
                    ps.setInt(idx++, m.getId());
                    ps.setString(idx++, X509Util.cutX500Name(c.getSubject(), maxX500nameLen));
                    ps.setString(idx++, b64Sha1FpCert);
                    ps.setString(idx++, b64Cert);

                    ps.execute();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CS_CA with ID=" + m.getId() + ", message: " + e.getMessage());
                    throw translate(sql, e);
                }catch(IllegalArgumentException | IOException e)
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
            final CertStoreType certstore)
    throws Exception
    {
        System.out.println(getImportingText() + "table USERNAME");

        PreparedStatement ps = prepareStatement(SQL_ADD_USER);

        ProcessLog processLog = new ProcessLog(certstore.getCountUsers(), System.currentTimeMillis(), 0);
        System.out.println(getImportingText() + "users from ID 1");
        ProcessLog.printHeader();

        DbPortFileNameIterator usersFileIterator = new DbPortFileNameIterator(usersListFile);

        int sum = 0;
        try
        {
            while(usersFileIterator.hasNext())
            {
                String file = usersDir + File.separator + usersFileIterator.next();

                try
                {
                    sum += do_import_user(ps, file, processLog);
                }catch(SQLException e)
                {
                    System.err.println("error while importing users from file " + file);
                    throw translate(SQL_ADD_USER, e);
                }catch(Exception e)
                {
                    System.err.println("error while importing users from file " + file);
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
            usersFileIterator.close();
        }

        ProcessLog.printTrailer();
        System.out.println(getImportedText() + sum + " users");
        System.out.println(getImportedText() + "table USERNAME");
    }

    private int do_import_user(
            final PreparedStatement ps_adduser,
            final String usersZipFile,
            final ProcessLog processLog)
    throws Exception
    {
        final int numEntriesPerCommit = numUsersPerCommit;

        ZipFile zipFile = new ZipFile(new File(usersZipFile));
        ZipEntry usersXmlEntry = zipFile.getEntry("users.xml");

        CaUsersReader users;
        try
        {
            users = new CaUsersReader(zipFile.getInputStream(usersXmlEntry));
        }catch(Exception e)
        {
            try
            {
                zipFile.close();
            }catch(Exception e2)
            {
            }
            throw e;
        }

        int numProcessed = 0;
        int numEntriesInBatch = 0;

        disableAutoCommit();

        try
        {
            while(users.hasNext())
            {
                if(stopMe.get())
                {
                    throw new InterruptedException("interrupted by the user");
                }

                CaUserType user = (CaUserType) users.next();

                numEntriesInBatch++;
                try
                {
                    int idx = 1;
                    ps_adduser.setInt(idx++, user.getId());
                    ps_adduser.setString(idx++, user.getName());
                    ps_adduser.setString(idx++, user.getPassword());
                    ps_adduser.setString(idx++, user.getCnRegex());
                    ps_adduser.addBatch();
                }catch(SQLException e)
                {
                    System.err.println("error while importing USERNAME with ID=" +
                            user.getId() + ", message: " + e.getMessage());
                    throw e;
                }

                if(numEntriesInBatch > 0 && (numEntriesInBatch % numEntriesPerCommit == 0 || users.hasNext() == false))
                {
                    if(evaulateOnly)
                    {
                        ps_adduser.clearBatch();
                    } else
                    {
                        String sql = null;
                        try
                        {
                            sql = SQL_ADD_USER;
                            ps_adduser.executeBatch();

                            sql = null;
                            commit("(commit import user to CA)");
                        } catch(SQLException e)
                        {
                            rollback();
                            throw translate(sql, e);
                        } catch(DataAccessException e)
                        {
                            rollback();
                            throw e;
                        }
                    }

                    processLog.addNumProcessed(numEntriesInBatch);
                    numProcessed += numEntriesInBatch;
                    numEntriesInBatch = 0;
                    processLog.printStatus();
                }
            }
            return numProcessed;
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

    private void import_publishQueue(
            final PublishQueue publishQueue)
    throws DataAccessException
    {
        final String sql = "INSERT INTO PUBLISHQUEUE (CID, PID, CA_ID) VALUES (?, ?, ?)";
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
                    System.err.println("error while importing PUBLISHQUEUE with CID=" + tbp.getCertId()
                            + " and PID=" + tbp.getPubId() + ", message: " + e.getMessage());
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
        final String sql = "INSERT INTO DELTACRL_CACHE (ID, SN, CA_ID) VALUES (?, ?, ?)";
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
            final CertStoreType certstore)
    throws Exception
    {
        System.out.println(getImportingText() + "table CRL");

        PreparedStatement ps = prepareStatement(SQL_ADD_CRL);

        ProcessLog processLog = new ProcessLog(certstore.getCountCrls(), System.currentTimeMillis(), 0);
        System.out.println(getImportingText() + "CRLs from ID 1");
        ProcessLog.printHeader();

        DbPortFileNameIterator crlsFileIterator = new DbPortFileNameIterator(crlsListFile);

        int sum = 0;
        try
        {
            while(crlsFileIterator.hasNext())
            {
                String file = crlsDir + File.separator + crlsFileIterator.next();

                try
                {
                    sum += do_import_crl(ps, file, processLog);
                }catch(SQLException e)
                {
                    System.err.println("error while importing CRLs from file " + file);
                    throw translate(SQL_ADD_USER, e);
                }catch(JAXBException e)
                {
                    System.err.println("error while importing CRLs from file " + file);
                    throw e;
                }
            }
        }finally
        {
            releaseResources(ps, null);
            crlsFileIterator.close();
        }

        ProcessLog.printTrailer();
        System.out.println(getImportedText() + sum + " CRLs");
        System.out.println(getImportedText() + "table CRL");
    }

    @SuppressWarnings("resource")
    private int do_import_crl(
            final PreparedStatement ps_addCrl,
            final String crlsZipFile,
            final ProcessLog processLog)
    throws Exception
    {
        final int numEntriesPerCommit = numCrlsPerCommit;

        ZipFile zipFile = new ZipFile(new File(crlsZipFile));
        ZipEntry certsXmlEntry = zipFile.getEntry("crls.xml");

        CaCrlsReader crls;
        try
        {
            crls = new CaCrlsReader(zipFile.getInputStream(certsXmlEntry));
        }catch(Exception e)
        {
            try
            {
                zipFile.close();
            }catch(Exception e2)
            {
            }
            throw e;
        }

        int numProcessed = 0;
        int numEntriesInBatch = 0;

        disableAutoCommit();

        try
        {
            while(crls.hasNext())
            {
                if(stopMe.get())
                {
                    throw new InterruptedException("interrupted by the user");
                }

                CaCrlType crl = (CaCrlType) crls.next();

                numEntriesInBatch++;
                String filename = crl.getFile();

                // CRL
                ZipEntry zipEnty = zipFile.getEntry(filename);

                // rawcert
                byte[] encodedCrl = IoUtil.read(zipFile.getInputStream(zipEnty));

                X509CRL c = null;
                try
                {
                    c = X509Util.parseCRL(new ByteArrayInputStream(encodedCrl));
                } catch (Exception e)
                {
                    LOG.error("could not parse CRL in file {}", filename);
                    LOG.debug("could not parse CRL in file " + filename, e);
                    if(e instanceof CRLException)
                    {
                        throw (CRLException) e;
                    }
                    else
                    {
                        throw new CRLException(e.getMessage(), e);
                    }
                }

                try
                {
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
                    ps_addCrl.setInt(idx++, crl.getId());
                    ps_addCrl.setInt(idx++, crl.getCaId());
                    ps_addCrl.setLong(idx++, crlNumber.longValue());
                    ps_addCrl.setLong(idx++, c.getThisUpdate().getTime() / 1000);
                    if(c.getNextUpdate() != null)
                    {
                        ps_addCrl.setLong(idx++, c.getNextUpdate().getTime() / 1000);
                    }
                    else
                    {
                        ps_addCrl.setNull(idx++, Types.INTEGER);
                    }

                    if(baseCrlNumber == null)
                    {
                        setBoolean(ps_addCrl, idx++, false);
                        ps_addCrl.setNull(idx++, Types.BIGINT);
                    }
                    else
                    {
                        setBoolean(ps_addCrl, idx++, true);
                        ps_addCrl.setLong(idx++, baseCrlNumber.longValue());
                    }

                    String s = Base64.toBase64String(encodedCrl);
                    ps_addCrl.setString(idx++, s);

                    ps_addCrl.addBatch();
                }catch(SQLException e)
                {
                    System.err.println("error while importing CRL with ID=" +
                            crl.getId() + ", message: " + e.getMessage());
                    throw e;
                }

                if(numEntriesInBatch > 0 && (numEntriesInBatch % numEntriesPerCommit == 0 || crls.hasNext() == false))
                {
                    if(evaulateOnly)
                    {
                        ps_addCrl.clearBatch();
                    } else
                    {
                        String sql = null;
                        try
                        {
                            sql = SQL_ADD_CRL;
                            ps_addCrl.executeBatch();

                            sql = null;
                            commit("(commit import CRL to CA)");
                        } catch(SQLException e)
                        {
                            rollback();
                            throw translate(sql, e);
                        } catch(DataAccessException e)
                        {
                            rollback();
                            throw e;
                        }
                    }

                    processLog.addNumProcessed(numEntriesInBatch);
                    numProcessed += numEntriesInBatch;
                    numEntriesInBatch = 0;
                    processLog.printStatus();

                }
            }
            return numProcessed;
        }
        finally
        {
            try
            {
                recoverAutoCommit();
            }catch(DataAccessException e)
            {
            }
        }
    }

    private void import_cert(
            final CertStoreType certstore,
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

        deleteCertGreatherThan(minId - 1);

        final long total = certstore.getCountCerts() - numProcessedBefore;
        final ProcessLog processLog = new ProcessLog(total, System.currentTimeMillis(), numProcessedBefore);

        System.out.println(getImportingText() + "certificates from ID " + minId);
        ProcessLog.printHeader();

        PreparedStatement ps_cert = prepareStatement(SQL_ADD_CERT);
        PreparedStatement ps_rawcert = prepareStatement(SQL_ADD_CRAW);

        DbPortFileNameIterator certsFileIterator = new DbPortFileNameIterator(certsListFile);
        try
        {
            while(certsFileIterator.hasNext())
            {
                String certsFile = certsDir + File.separator + certsFileIterator.next();

                // extract the toId from the filename
                int fromIdx = certsFile.indexOf('-');
                int toIdx = certsFile.indexOf(".zip");
                if(fromIdx != -1 && toIdx != -1)
                {
                    try
                    {
                        long toId = Integer.parseInt(certsFile.substring(fromIdx + 1, toIdx));
                        if(toId < minId)
                        {
                            // try next file
                            continue;
                        }
                    }catch(Exception e)
                    {
                        LOG.warn("invalid file name '{}', but will still be processed", certsFile);
                    }
                } else
                {
                    LOG.warn("invalid file name '{}', but will still be processed", certsFile);
                }

                try
                {
                    int lastId = do_import_cert(ps_cert, ps_rawcert, certsFile, minId,
                            processLogFile, processLog);
                    minId = lastId + 1;
                }catch(Exception e)
                {
                    System.err.println("\nerror while importing certificates from file " + certsFile +
                            ".\nplease continue with the option '--resume'");
                    LOG.error("Exception", e);
                    throw e;
                }
            } // end for
        }finally
        {
            releaseResources(ps_cert, null);
            releaseResources(ps_rawcert, null);
            certsFileIterator.close();
        }

        long maxId = getMax("CERT", "ID");
        dataSource.dropAndCreateSequence("CID", maxId + 1);

        ProcessLog.printTrailer();
        echoToFile(MSG_CERTS_FINISHED, processLogFile);
        System.out.println(getImportedText() + processLog.getNumProcessed() + " certificates");
    }

    private int do_import_cert(
            final PreparedStatement ps_cert,
            final PreparedStatement ps_rawcert,
            final String certsZipFile,
            final int minId,
            final File processLogFile,
            final ProcessLog processLog)
    throws Exception
    {
        final int numEntriesPerCommit = numCertsPerCommit;

        ZipFile zipFile = new ZipFile(new File(certsZipFile));
        ZipEntry certsXmlEntry = zipFile.getEntry("certs.xml");

        CaCertsReader certs;
        try
        {
            certs = new CaCertsReader(zipFile.getInputStream(certsXmlEntry));
        }catch(Exception e)
        {
            try
            {
                zipFile.close();
            }catch(Exception e2)
            {
            }
            throw e;
        }

        disableAutoCommit();

        try
        {
            int numEntriesInBatch = 0;
            int lastSuccessfulCertId = 0;

            while(certs.hasNext())
            {
                if(stopMe.get())
                {
                    throw new InterruptedException("interrupted by the user");
                }

                CaCertType cert = (CaCertType) certs.next();
                int id = cert.getId();
                if(id < minId)
                {
                    continue;
                }

                int certArt = cert.getArt() == null ? 1 : cert.getArt();

                numEntriesInBatch++;

                String filename = cert.getFile();

                // rawcert
                ZipEntry certZipEnty = zipFile.getEntry(filename);

                // rawcert
                byte[] encodedCert = IoUtil.read(zipFile.getInputStream(certZipEnty));

                TBSCertificate c;
                try
                {
                    Certificate cc = Certificate.getInstance(encodedCert);
                    c = cc.getTBSCertificate();
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

                String b64Sha1FpCert = HashCalculator.base64Sha1(encodedCert);

                // cert
                String subjectText = X509Util.cutX500Name(c.getSubject(), maxX500nameLen);

                try
                {
                    int idx = 1;

                    ps_cert.setInt(idx++, id);
                    ps_cert.setInt(idx++, certArt);
                    ps_cert.setLong(idx++, cert.getUpdate());
                    ps_cert.setLong(idx++, c.getSerialNumber().getPositiveValue().longValue());

                    ps_cert.setString(idx++, subjectText);
                    long fpSubject = X509Util.fp_canonicalized_name(c.getSubject());
                    ps_cert.setLong(idx++, fpSubject);

                    String cn = X509Util.getCommonName(c.getSubject());
                    if(StringUtil.isNotBlank(cn))
                    {
                        long fpCn = FpIdCalculator.hash(cn);
                        ps_cert.setLong(idx++, fpCn);
                    } else
                    {
                        ps_cert.setNull(idx++, Types.BIGINT);
                    }

                    if(cert.getFpRs() != null)
                    {
                        ps_cert.setLong(idx++, cert.getFpRs());
                    } else
                    {
                        ps_cert.setNull(idx++, Types.BIGINT);
                    }

                    ps_cert.setLong(idx++, c.getStartDate().getDate().getTime() / 1000);
                    ps_cert.setLong(idx++, c.getEndDate().getDate().getTime() / 1000);
                    setBoolean(ps_cert, idx++, cert.getRev());
                    setInt(ps_cert, idx++, cert.getRr());
                    setLong(ps_cert, idx++, cert.getRt());
                    setLong(ps_cert, idx++, cert.getRit());
                    setInt(ps_cert, idx++, cert.getPid());
                    setInt(ps_cert, idx++, cert.getCaId());

                    setInt(ps_cert, idx++, cert.getRid());
                    ps_cert.setString(idx++, cert.getUser());
                    ps_cert.setLong(idx++, FpIdCalculator.hash(encodedKey));
                    Extension extension = c.getExtensions().getExtension(Extension.basicConstraints);
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
                        tidS = cert.getTid();
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
                    ps_rawcert.setString(idx++, b64Sha1FpCert);
                    ps_rawcert.setString(idx++, cert.getRs());
                    ps_rawcert.setString(idx++, Base64.toBase64String(encodedCert));
                    ps_rawcert.addBatch();
                }catch(SQLException e)
                {
                    throw translate(SQL_ADD_CRAW, e);
                }

                if(numEntriesInBatch > 0 && (numEntriesInBatch % numEntriesPerCommit == 0 || certs.hasNext() == false))
                {
                    if(evaulateOnly)
                    {
                        ps_cert.clearBatch();
                        ps_rawcert.clearBatch();
                    } else
                    {
                        String sql = null;
                        try
                        {
                            sql = SQL_ADD_CERT;
                            ps_cert.executeBatch();

                            sql = SQL_ADD_CRAW;
                            ps_rawcert.executeBatch();

                            sql = null;
                            commit("(commit import cert to CA)");
                        } catch(Throwable t)
                        {
                            rollback();
                            deleteCertGreatherThan(lastSuccessfulCertId);
                            if(t instanceof SQLException)
                            {
                                throw translate(sql, (SQLException) t);
                            } else if(t instanceof Exception)
                            {
                                throw (Exception) t;
                            } else
                            {
                                throw new Exception(t);
                            }
                        }
                    }

                    lastSuccessfulCertId = id;
                    processLog.addNumProcessed(numEntriesInBatch);
                    numEntriesInBatch = 0;
                    echoToFile((processLog.getSumInLastProcess() + processLog.getNumProcessed()) + ":" +
                            lastSuccessfulCertId, processLogFile);

                    processLog.printStatus();
                }

            } // end for

            return lastSuccessfulCertId;
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

    private void deleteCertGreatherThan(
            final int id)
    {
        deleteFromTableWithLargerId("CRAW", "CID", id, LOG);
        deleteFromTableWithLargerId("CERT", "ID", id, LOG);
    }

    private void dropIndexes()
    throws DataAccessException
    {
        System.out.println("dropping indexes");
        long start = System.currentTimeMillis();

        dataSource.dropIndex(null, "CERT", "IDX_FPK");
        dataSource.dropIndex(null, "CERT", "IDX_FPS");
        dataSource.dropIndex(null, "CERT", "IDX_FPCN");
        dataSource.dropIndex(null, "CERT", "IDX_FPRS");

        dataSource.dropForeignKeyConstraint(null, "FK_CERT_CS_CA1", "CERT");
        dataSource.dropUniqueConstrain(null, "CONST_CA_SN", "CERT");

        dataSource.dropForeignKeyConstraint(null, "FK_CRAW_CERT1", "CRAW");
        dataSource.dropForeignKeyConstraint(null, "FK_PUBLISHQUEUE_CERT1", "PUBLISHQUEUE");

        dataSource.dropPrimaryKey(null, "PK_CERT", "CERT");
        dataSource.dropPrimaryKey(null, "PK_CRAW", "CRAW");

        long duration = (System.currentTimeMillis() - start) / 1000;
        System.out.println(" dropped indexes in " + AbstractLoadTest.formatTime(duration));
    }

    private void recoverIndexes()
    throws DataAccessException
    {
        System.out.println("recovering indexes");
        long start = System.currentTimeMillis();

        dataSource.addPrimaryKey(null, "PK_CERT", "CERT", "ID");
        dataSource.addPrimaryKey(null, "PK_CRAW", "CRAW", "CID");

        dataSource.addForeignKeyConstraint(null, "FK_PUBLISHQUEUE_CERT1", "PUBLISHQUEUE",
                "CID", "CERT", "ID", "CASCADE", "NO ACTION");

        dataSource.addForeignKeyConstraint(null, "FK_CRAW_CERT1", "CRAW",
                "CID", "CERT", "ID", "CASCADE", "NO ACTION");

        dataSource.addForeignKeyConstraint(null, "FK_CERT_CS_CA1", "CERT",
                "CA_ID", "CS_CA", "ID", "CASCADE", "NO ACTION");
        dataSource.addUniqueConstrain(null, "CONST_CA_SN", "CERT", "CA_ID", "SN");

        dataSource.createIndex(null, "IDX_FPK", "CERT", "FP_K");
        dataSource.createIndex(null, "IDX_FPS", "CERT", "FP_S");
        dataSource.createIndex(null, "IDX_FPCN", "CERT", "FP_CN");
        dataSource.createIndex(null, "IDX_FPRS", "CERT", "FP_RS");

        long duration = (System.currentTimeMillis() - start) / 1000;
        System.out.println(" recovered indexes in " + AbstractLoadTest.formatTime(duration));
    }

}
