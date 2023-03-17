// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.util.JSON;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Database importer of OCSP CertStore.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class OcspCertstoreDbImporter extends AbstractOcspCertstoreDbImporter {

  private static final Logger LOG = LoggerFactory.getLogger(OcspCertstoreDbImporter.class);

  private final boolean resume;

  private final int numCertsPerCommit;

  OcspCertstoreDbImporter(DataSourceWrapper datasource, String srcDir, int numCertsPerCommit,
                          boolean resume, AtomicBoolean stopMe)
      throws Exception {
    super(datasource, srcDir, stopMe);

    this.numCertsPerCommit = Args.positive(numCertsPerCommit, "numCertsPerCommit");
    File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
    if (resume) {
      if (!processLogFile.exists()) {
        throw new Exception("could not process with '--resume' option");
      }
    } else {
      if (processLogFile.exists()) {
        throw new Exception("please either specify '--resume' option or delete the file "
            + processLogFile.getPath() + " first");
      }
    }
    this.resume = resume;
  } // constructor

  public void importToDb() throws Exception {
    OcspCertstore certstore;
    try (InputStream is = Files.newInputStream(Paths.get(baseDir, FILENAME_OCSP_CERTSTORE))) {
      certstore = JSON.parseObject(is, OcspCertstore.class);
    }
    certstore.validate();

    if (certstore.getVersion() > VERSION_V2) {
      throw new Exception("could not import Certstore greater than " + VERSION_V2 + ": " + certstore.getVersion());
    }

    File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
    System.out.println("importing OCSP certstore to database");
    try {
      if (!resume) {
        importCertHashAlgo(certstore.getCerthashAlgo());
        importCrlInfo(certstore.getCrlInfos());
        importIssuer(certstore.getIssuers());
      }
      importCert(certstore, processLogFile);
      processLogFile.delete();
    } catch (Exception ex) {
      System.err.println("could not import OCSP certstore to database");
      throw ex;
    }
    System.out.println(" imported OCSP certstore to database");
  } // method importToDB

  private void importCertHashAlgo(String certHashAlgo) throws DataAccessException {
    String sql = "UPDATE DBSCHEMA SET VALUE2=? WHERE NAME='CERTHASH_ALGO'";
    PreparedStatement ps = prepareStatement(sql);
    try {
      ps.setString(1, certHashAlgo);
      ps.executeUpdate();
      dbSchemaInfo.setVariable("CERTHASH_ALGO", certHashAlgo);
    } catch (SQLException ex) {
      System.err.println("could not import DBSCHEMA");
      throw translate(sql, ex);
    } finally {
      releaseResources(ps, null);
    }
  }

  private void importIssuer(List<OcspCertstore.Issuer> issuers)
      throws DataAccessException, CertificateException, IOException {
    if (CollectionUtil.isEmpty(issuers)) {
      return;
    }

    System.out.print("    importing table ISSUER ... ");
    boolean succ = false;
    PreparedStatement ps = prepareStatement(SQL_ADD_ISSUER);

    try {
      for (OcspCertstore.Issuer issuer : issuers) {
        try {
          String b64Cert = StringUtil.toUtf8String(IoUtil.read(new File(baseDir, issuer.getCertFile())));
          byte[] encodedCert = Base64.decode(b64Cert);

          Certificate cert;
          try {
            cert = Certificate.getInstance(encodedCert);
          } catch (RuntimeException ex) {
            LOG.error("could not parse certificate of issuer {}", issuer.getId());
            LOG.debug("could not parse certificate of issuer " + issuer.getId(), ex);
            throw new CertificateException(ex.getMessage(), ex);
          }

          int idx = 1;
          ps.setInt(idx++, issuer.getId());
          ps.setString(idx++, X509Util.cutX500Name(cert.getSubject(), maxX500nameLen));
          ps.setLong(idx++, cert.getTBSCertificate().getStartDate().getDate().getTime() / 1000);
          ps.setLong(idx++, cert.getTBSCertificate().getEndDate().getDate().getTime() / 1000);
          ps.setString(idx++, sha1(encodedCert));
          ps.setString(idx++, issuer.getRevInfo());
          ps.setString(idx++, b64Cert);
          if (issuer.getCrlId() == null) {
            ps.setNull(idx, Types.INTEGER);
          } else {
            ps.setInt(idx, issuer.getCrlId());
          }

          ps.execute();
        } catch (SQLException ex) {
          System.err.println("could not import issuer with id=" + issuer.getId());
          throw translate(SQL_ADD_ISSUER, ex);
        } catch (CertificateException ex) {
          System.err.println("could not import issuer with id=" + issuer.getId());
          throw ex;
        }
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  }

  private void importCrlInfo(List<OcspCertstore.CrlInfo> crlInfos) throws DataAccessException {
    if (CollectionUtil.isEmpty(crlInfos)) {
      return;
    }

    System.out.print("    importing table CRL_INFO ... ");
    boolean succ = false;
    PreparedStatement ps = prepareStatement(SQL_ADD_CRLINFO);

    try {
      for (OcspCertstore.CrlInfo crlInfo : crlInfos) {
        try {
          int idx = 1;
          ps.setInt(idx++, crlInfo.getId());
          ps.setString(idx++, crlInfo.getName());
          ps.setString(idx, crlInfo.getInfo());
          ps.execute();
        } catch (SQLException ex) {
          System.err.println("could not import CRL_INFO with id=" + crlInfo.getId());
          throw translate(SQL_ADD_CRLINFO, ex);
        }
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  }

  private void importCert(OcspCertstore certstore, File processLogFile) throws Exception {
    int numProcessedBefore = 0;
    long minId = 1;
    if (processLogFile.exists()) {
      byte[] content = IoUtil.read(processLogFile);
      if (content != null && content.length > 2) {
        String str = StringUtil.toUtf8String(content);
        if (str.trim().equalsIgnoreCase(MSG_CERTS_FINISHED)) {
          return;
        }

        StringTokenizer st = new StringTokenizer(str, ":");
        numProcessedBefore = Integer.parseInt(st.nextToken());
        minId = 1 + Long.parseLong(st.nextToken());
      }
    }

    deleteCertGreaterThan(minId - 1, LOG);

    final long total = certstore.getCountCerts() - numProcessedBefore;
    final ProcessLog processLog = new ProcessLog(total);

    System.out.println("importing certificates from ID " + minId);
    processLog.printHeader();

    PreparedStatement psCert = prepareStatement(SQL_ADD_CERT);
    OcspDbEntryType type = OcspDbEntryType.CERT;

    try (DbPortFileNameIterator certsFileIterator = new DbPortFileNameIterator(
            baseDir + File.separator + type.getDirName() + ".mf")) {
      while (certsFileIterator.hasNext()) {
        String certsFile = baseDir + File.separator + type.getDirName() + File.separator + certsFileIterator.next();

        // extract the toId from the filename
        int fromIdx = certsFile.indexOf('-');
        int toIdx = certsFile.indexOf(".zip");
        if (fromIdx != -1 && toIdx != -1) {
          try {
            long toId = Long.parseLong(certsFile.substring(fromIdx + 1, toIdx));
            if (toId < minId) {
              // try next file
              continue;
            }
          } catch (Exception ex) {
            LOG.warn("invalid file name '{}', but will still be processed", certsFile);
          }
        } else {
          LOG.warn("invalid file name '{}', but will still be processed", certsFile);
        }

        try {
          long lastId = importCert0(psCert, certsFile, minId, processLogFile, processLog, numProcessedBefore);
          minId = lastId + 1;
        } catch (Exception ex) {
          System.err.println("\ncould not import certificates from file " + certsFile
                  + ".\nplease continue with the option '--resume'");
          LOG.error("Exception", ex);
          throw ex;
        }
      } // end for
    } finally {
      releaseResources(psCert, null);
    }

    processLog.printTrailer();
    echoToFile(MSG_CERTS_FINISHED, processLogFile);
    System.out.println(" imported " + processLog.numProcessed() + " certificates");
  } // method importCert

  private long importCert0(PreparedStatement psCert, String certsZipFile, long minId,
                           File processLogFile, ProcessLog processLog, int numProcessedInLastProcess)
      throws Exception {
    ZipFile zipFile = new ZipFile(new File(certsZipFile));
    ZipEntry certsEntry = zipFile.getEntry("certs.json");

    OcspCertstore.Certs certs;
    try {
      certs = JSON.parseObject(zipFile.getInputStream(certsEntry), OcspCertstore.Certs.class);
    } catch (Exception ex) {
      try {
        zipFile.close();
      } catch (Exception e2) {
        LOG.error("could not close ZIP file {}: {}", certsZipFile, e2.getMessage());
        LOG.debug("could not close ZIP file " + certsZipFile, e2);
      }
      throw ex;
    }
    certs.validate();

    disableAutoCommit();

    try {
      int numEntriesInBatch = 0;
      long lastSuccessfulCertId = 0;

      List<OcspCertstore.Cert> list = certs.getCerts();
      final int n = list.size();

      for (int i = 0; i < n; i++) {
        if (stopMe.get()) {
          throw new InterruptedException("interrupted by the user");
        }

        OcspCertstore.Cert cert = list.get(i);
        long id = cert.getId();
        if (id < minId) {
          continue;
        }

        numEntriesInBatch++;

        // cert
        try {
          int idx = 1;
          psCert.setLong(idx++, id);
          psCert.setInt(idx++, cert.getIid());
          psCert.setString(idx++, cert.getSn());
          psCert.setLong(idx++, cert.getUpdate());
          psCert.setLong(idx++, cert.getNbefore());
          psCert.setLong(idx++, cert.getNafter());
          setBoolean(psCert, idx++, cert.getRev());
          setInt(psCert, idx++, cert.getRr());
          setLong(psCert, idx++, cert.getRt());
          setLong(psCert, idx++, cert.getRit());
          psCert.setString(idx++, cert.getHash());
          psCert.setString(idx++, cert.getSubject());
          if (cert.getCrlId() == null) {
            psCert.setNull(idx, Types.INTEGER);
          } else {
            psCert.setInt(idx, cert.getCrlId());
          }
          psCert.addBatch();
        } catch (SQLException ex) {
          throw translate(SQL_ADD_CERT, ex);
        }

        boolean isLastBlock = i == n - 1;

        if (numEntriesInBatch > 0 && (numEntriesInBatch % this.numCertsPerCommit == 0 || isLastBlock)) {
          try {
            psCert.executeBatch();
            commit("(commit import cert to OCSP)");
          } catch (Throwable th) {
            rollback();
            deleteCertGreaterThan(lastSuccessfulCertId, LOG);
            if (th instanceof SQLException) {
              throw translate(SQL_ADD_CERT, (SQLException) th);
            } else if (th instanceof Exception) {
              throw (Exception) th;
            } else {
              throw new Exception(th);
            }
          }

          lastSuccessfulCertId = id;
          processLog.addNumProcessed(numEntriesInBatch);
          numEntriesInBatch = 0;
          echoToFile((numProcessedInLastProcess + processLog.numProcessed())
              + ":" + lastSuccessfulCertId, processLogFile);
          processLog.printStatus();
        }
      } // end for

      return lastSuccessfulCertId;
    } finally {
      recoverAutoCommit();
      zipFile.close();
    }
  } // method importCert0

}
