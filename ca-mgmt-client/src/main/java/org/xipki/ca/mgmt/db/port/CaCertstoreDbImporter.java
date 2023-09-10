// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.FpIdCalculator;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.JSON;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.xipki.util.DateUtil.toEpochSecond;
import static org.xipki.util.SqlUtil.buildInsertSql;

/**
 * Database importer of CA CertStore.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class CaCertstoreDbImporter extends DbPorter {

  private static final Logger LOG = LoggerFactory.getLogger(CaCertstoreDbImporter.class);

  private static final String SQL_ADD_CERT = buildInsertSql("CERT",
      "ID,LUPDATE,SN,SUBJECT,FP_S,FP_RS,FP_SAN,NBEFORE,NAFTER,REV,RR,RT,RIT,"
      + "PID,CA_ID,RID,EE,TID,SHA1,REQ_SUBJECT,CRL_SCOPE,CERT,PRIVATE_KEY");

  private static final String SQL_ADD_CRL = buildInsertSql("CRL",
      "ID,CA_ID,CRL_NO,THISUPDATE,NEXTUPDATE,DELTACRL,BASECRL_NO,CRL_SCOPE,SHA1,CRL");

  private final int numCertsPerCommit;

  private final CaCertstore.Caconf caconf;

  CaCertstoreDbImporter(DataSourceWrapper datasource, String srcDir, int numCertsPerCommit,
      boolean resume, AtomicBoolean stopMe, CaCertstore.Caconf caconf)
      throws Exception {
    super(datasource, srcDir, stopMe);

    this.caconf = Args.notNull(caconf, "caconf");
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
  } // constructor

  private void importProfile(List<CaCertstore.IdNameTypeConf> profiles) throws DataAccessException {
    System.out.print("    importing table PROFILE ... ");
    boolean succ = false;
    final String sql = buildInsertSql("PROFILE", "ID,NAME");
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      for (CaCertstore.IdNameTypeConf certprofile : profiles) {
        try {
          ps.setInt(1, certprofile.getId());
          ps.setString(2, certprofile.getName());

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import PROFILE with NAME=" + certprofile.getName());
          throw translate(sql, ex);
        }
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importProfile

  private void importRequestor(List<CaCertstore.IdNameTypeConf> requestors) throws DataAccessException {
    System.out.print("    importing table REQUESTOR ... ");
    final String sql = buildInsertSql("REQUESTOR", "ID,NAME");
    boolean succ = false;
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaCertstore.IdNameTypeConf requestor : requestors) {
        try {
          ps.setInt(1, requestor.getId());
          ps.setString(2, requestor.getName());
          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import REQUESTOR with NAME=" + requestor.getName());
          throw translate(sql, ex);
        }
      }

      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importRequestor

  private void importCa(List<CaCertstore.Ca> cas)
      throws DataAccessException, CertificateException, IOException {
    System.out.print("    importing table CA ... ");
    boolean succ = false;

    final String sql = buildInsertSql("CA", "ID,NAME,SUBJECT,REV_INFO,CERT");

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaCertstore.Ca ca : cas) {
        try {
          byte[] certBytes = readContent(ca.getCert());
          X509Cert cert = X509Util.parseCert(certBytes);

          int idx = 1;
          ps.setInt(   idx++, ca.getId());
          ps.setString(idx++, ca.getName().toLowerCase());
          ps.setString(idx++, X509Util.cutX500Name(cert.getSubject(), maxX500nameLen));
          ps.setString(idx++, ca.getRevInfo());
          ps.setString(idx, Base64.encodeToString(certBytes));

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import CA with NAME=" + ca.getName());
          throw translate(sql, ex);
        } catch (CertificateException | IOException ex) {
          System.err.println("could not import CA with NAME=" + ca.getName());
          throw ex;
        }
      }

      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method importCa

  public void importToDb() throws Exception {
    if (dbSchemaVersion >= 8) {
      importRequestor(caconf.getRequestors());
      importProfile(caconf.getProfiles());
      importCa(caconf.getCas());
    }

    CaCertstore certstore = JSON.parseObject(Paths.get(baseDir, FILENAME_CA_CERTSTORE), CaCertstore.class);
    certstore.validate();

    if (certstore.getVersion() > VERSION_V2) {
      throw new Exception("could not import Certstore greater than " + VERSION_V2 + ": " + certstore.getVersion());
    }

    File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
    System.out.println("importing CA certstore to database");
    try {
      CaDbEntryType typeProcessedInLastProcess = null;
      Integer numProcessedInLastProcess = null;
      Long idProcessedInLastProcess = null;
      if (processLogFile.exists()) {
        byte[] content = IoUtil.read(processLogFile);
        if (content.length > 5) {
          StringTokenizer st = new StringTokenizer(StringUtil.toUtf8String(content), ":");
          String type = st.nextToken();
          typeProcessedInLastProcess = CaDbEntryType.valueOf(type);
          numProcessedInLastProcess = Integer.parseInt(st.nextToken());
          idProcessedInLastProcess = Long.parseLong(st.nextToken());
        }
      }

      boolean entriesFinished = false;
      // finished for the given type
      if (typeProcessedInLastProcess != null && idProcessedInLastProcess == -1) {
        numProcessedInLastProcess = 0;
        idProcessedInLastProcess = 0L;

        if (typeProcessedInLastProcess == CaDbEntryType.CRL) {
          typeProcessedInLastProcess = CaDbEntryType.CERT;
        } else if (typeProcessedInLastProcess == CaDbEntryType.CERT) {
          entriesFinished = true;
        } else {
          throw new IllegalStateException("unsupported CaDbEntryType " + typeProcessedInLastProcess);
        }
      }

      if (!entriesFinished) {
        Exception exception = null;
        if (CaDbEntryType.CRL == typeProcessedInLastProcess || typeProcessedInLastProcess == null) {
          exception = importEntries(CaDbEntryType.CRL, certstore, processLogFile,
              numProcessedInLastProcess, idProcessedInLastProcess);
          typeProcessedInLastProcess = null;
          numProcessedInLastProcess = null;
          idProcessedInLastProcess = null;
        }

        CaDbEntryType[] types = {CaDbEntryType.CERT};

        for (CaDbEntryType type : types) {
          if (exception == null && (type == typeProcessedInLastProcess || typeProcessedInLastProcess == null)) {
            exception = importEntries(type, certstore, processLogFile,
                numProcessedInLastProcess, idProcessedInLastProcess);
          }
        }

        if (exception != null) {
          throw exception;
        }
      }

      processLogFile.delete();
    } catch (Exception ex) {
      System.err.println("could not import CA certstore to database");
      throw ex;
    }
    System.out.println(" imported CA certstore to database");
  } // method importToDb

  private Exception importEntries(CaDbEntryType type, CaCertstore certstore,
      File processLogFile, Integer numProcessedInLastProcess, Long idProcessedInLastProcess) {
    String tablesText = "table " + type.getTableName();

    try {
      int numProcessedBefore = 0;
      long minId = 1;
      if (idProcessedInLastProcess != null) {
        minId = idProcessedInLastProcess + 1;
        numProcessedBefore = numProcessedInLastProcess;
      }

      deleteFromTableWithLargerId(type.getTableName(), "ID", minId - 1, LOG);

      final long total;
      String sql;

      if (type == CaDbEntryType.CERT) {
        total = certstore.getCountCerts();
        sql = SQL_ADD_CERT;
      } else if (type == CaDbEntryType.CRL) {
        total = certstore.getCountCrls();
        sql = SQL_ADD_CRL;
      } else {
        throw new IllegalStateException("unsupported DbEntryType " + type);
      }

      final long remainingTotal = total - numProcessedBefore;
      final ProcessLog processLog = new ProcessLog(remainingTotal);

      System.out.println("importing entries to " + tablesText + " from ID " + minId);
      processLog.printHeader();

      PreparedStatement stmt = null;
      try (DbPortFileNameIterator entriesFileIterator = new DbPortFileNameIterator(
              baseDir + File.separator + type.getDirName() + ".mf")) {

        stmt = prepareStatement(sql);

        while (entriesFileIterator.hasNext()) {
          String entriesFile = baseDir + File.separator + type.getDirName()
              + File.separator + entriesFileIterator.next();

          // extract the toId from the filename
          int fromIdx = entriesFile.indexOf('-');
          int toIdx = entriesFile.indexOf(".zip");
          if (fromIdx != -1 && toIdx != -1) {
            try {
              long toId = Integer.parseInt(entriesFile.substring(fromIdx + 1, toIdx));
              if (toId < minId) {
                // try next file
                continue;
              }
            } catch (Exception ex) {
              LOG.warn("invalid file name '{}', but will still be processed", entriesFile);
            }
          } else {
            LOG.warn("invalid file name '{}', but will still be processed", entriesFile);
          }

          try {
            long lastId;
            if (type == CaDbEntryType.CERT) {
              lastId = importCerts(entriesFile, minId, processLogFile, processLog, numProcessedBefore, stmt, sql);
            } else { // if (type == CaDbEntryType.CRL) {
              lastId = importCrls(entriesFile, minId, processLogFile, processLog, numProcessedBefore, stmt, sql);
            }

            minId = lastId + 1;
          } catch (Exception ex) {
            System.err.println("\ncould not import entries from file " + entriesFile
                + ".\nplease continue with the option '--resume'");
            LOG.error("Exception", ex);
            return ex;
          }
        } // end for
      } finally {
        releaseResources(stmt, null);
      }

      processLog.printTrailer();
      echoToFile(type + ":" + (numProcessedBefore + processLog.numProcessed()) + ":-1", processLogFile);

      System.out.println(" imported " + processLog.numProcessed() + " entries");
      return null;
    } catch (Exception ex) {
      System.err.println("\nimporting " + tablesText + " has been cancelled due to error,\n"
          + "please continue with the option '--resume'");
      LOG.error("Exception", ex);
      return ex;
    }
  } // method importEntries

  private long importCerts(String entriesZipFile, long minId, File processLogFile, ProcessLog processLog,
                           int numProcessedInLastProcess, PreparedStatement stmt, String sql)
      throws Exception {
    final CaDbEntryType type = CaDbEntryType.CERT;
    final int numEntriesPerCommit = Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsPerCommit));

    ZipFile zipFile = new ZipFile(new File(entriesZipFile));

    CaCertstore.Certs certs;
    try {
      certs = JSON.parseObjectAndClose(
                zipFile.getInputStream(zipFile.getEntry("overview.json")), CaCertstore.Certs.class);
    } catch (Exception ex) {
      try {
        zipFile.close();
      } catch (Exception e2) {
        LOG.error("could not close ZIP file {}: {}", entriesZipFile, e2.getMessage());
        LOG.debug("could not close ZIP file " + entriesZipFile, e2);
      }
      throw ex;
    }
    certs.validate();

    disableAutoCommit();

    try {
      int numEntriesInBatch = 0;
      long lastSuccessfulEntryId = 0;

      List<CaCertstore.Cert> list = certs.getCerts();
      final int n = list.size();

      for (int i = 0; i < n; i++) {
        CaCertstore.Cert cert = list.get(i);

        if (stopMe.get()) {
          throw new InterruptedException("interrupted by the user");
        }

        long id = cert.getId();
        if (id < minId) {
          continue;
        }

        numEntriesInBatch++;

        String filename = cert.getFile();
        // rawcert
        byte[] encodedCert = IoUtil.readAllBytesAndClose(zipFile.getInputStream(zipFile.getEntry(filename)));

        TBSCertificate tbsCert;
        try {
          tbsCert = Certificate.getInstance(encodedCert).getTBSCertificate();
        } catch (RuntimeException ex) {
          LOG.error("could not parse certificate in file {}", filename);
          LOG.debug("could not parse certificate in file " + filename, ex);
          throw new CertificateException(ex.getMessage(), ex);
        }

        String b64Sha1FpCert = HashAlgo.SHA1.base64Hash(encodedCert);

        // cert's subject
        String subjectText = X509Util.cutX500Name(tbsCert.getSubject(), maxX500nameLen);

        // private key
        String privateKey = null;
        if (cert.getPrivateKeyFile() != null) {
          ZipEntry keyZipEnty = zipFile.getEntry(cert.getPrivateKeyFile());
          if (keyZipEnty != null) {
            privateKey = new String(IoUtil.readAllBytesAndClose(zipFile.getInputStream(keyZipEnty)));
          }
        }

        try {
          int idx = 1;

          stmt.setLong(idx++, id);
          stmt.setLong(idx++, cert.getUpdate());
          stmt.setString(idx++, tbsCert.getSerialNumber().getPositiveValue().toString(16));

          stmt.setString(idx++, subjectText);
          long fpSubject = X509Util.fpCanonicalizedName(tbsCert.getSubject());
          stmt.setLong(idx++, fpSubject);

          if (cert.getFpRs() != null) {
            stmt.setLong(idx++, cert.getFpRs());
          } else {
            stmt.setNull(idx++, Types.BIGINT);
          }

          byte[] san = X509Util.getCoreExtValue(tbsCert.getExtensions(), Extension.subjectAlternativeName);
          if (san != null) {
            stmt.setLong(idx++, FpIdCalculator.hash(san));
          } else {
            stmt.setNull(idx++, Types.BIGINT);
          }

          stmt.setLong(idx++, toEpochSecond(tbsCert.getStartDate().getDate()));
          stmt.setLong(idx++, toEpochSecond(tbsCert.getEndDate().getDate()));
          setInt(stmt, idx++, cert.getRev());
          setInt(stmt, idx++, cert.getRr());
          setLong(stmt, idx++, cert.getRt());
          setLong(stmt, idx++, cert.getRit());
          setInt(stmt, idx++, cert.getPid());
          setInt(stmt, idx++, cert.getCaId());

          setInt(stmt, idx++, cert.getRid());
          Extension extension = tbsCert.getExtensions().getExtension(Extension.basicConstraints);
          boolean ee = true;
          if (extension != null) {
            ASN1Encodable asn1 = extension.getParsedValue();
            ee = !BasicConstraints.getInstance(asn1).isCA();
          }

          stmt.setInt(idx++, ee ? 1 : 0);
          String tidS = null;
          if (cert.getTid() != null) {
            tidS = cert.getTid();
          }
          stmt.setString(idx++, tidS);
          stmt.setString(idx++, b64Sha1FpCert);
          stmt.setString(idx++, cert.getRs());
          stmt.setInt(idx++, cert.getCrlScope());
          stmt.setString(idx++, Base64.encodeToString(encodedCert));
          stmt.setString(idx, privateKey);
          stmt.addBatch();
        } catch (SQLException ex) {
          throw translate(sql, ex);
        }

        boolean isLastBlock = i == n - 1;
        if (numEntriesInBatch > 0
            && (numEntriesInBatch % numEntriesPerCommit == 0 || isLastBlock)) {
          try {
            stmt.executeBatch();
            commit("(commit import to CA)");
          } catch (Throwable th) {
            rollback();
            deleteFromTableWithLargerId(type.getTableName(), "ID", id, LOG);
            if (th instanceof SQLException) {
              throw translate(sql, (SQLException) th);
            } else if (th instanceof Exception) {
              throw (Exception) th;
            } else {
              throw new Exception(th);
            }
          }

          lastSuccessfulEntryId = id;
          processLog.addNumProcessed(numEntriesInBatch);
          numEntriesInBatch = 0;
          echoToFile(type + ":" + (numProcessedInLastProcess + processLog.numProcessed())
              + ":" + lastSuccessfulEntryId, processLogFile);
          processLog.printStatus();
        }

      } // end while

      return lastSuccessfulEntryId;
    } finally {
      recoverAutoCommit();
      zipFile.close();
    }
  } // method importCerts

  private long importCrls(
      String entriesZipFile, long minId, File processLogFile, ProcessLog processLog, int numProcessedInLastProcess,
      PreparedStatement stmt, String sql)
      throws Exception {
    final CaDbEntryType type = CaDbEntryType.CRL;
    final int numEntriesPerCommit = Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsPerCommit));

    ZipFile zipFile = new ZipFile(new File(entriesZipFile));

    CaCertstore.Crls crls;
    try {
      crls = JSON.parseObjectAndClose(
              zipFile.getInputStream(zipFile.getEntry("overview.json")), CaCertstore.Crls.class);
    } catch (Exception ex) {
      try {
        zipFile.close();
      } catch (Exception e2) {
        LOG.error("could not close ZIP file {}: {}", entriesZipFile, e2.getMessage());
        LOG.debug("could not close ZIP file " + entriesZipFile, e2);
      }
      throw ex;
    }
    crls.validate();

    disableAutoCommit();

    try {
      int numEntriesInBatch = 0;
      long lastSuccessfulEntryId = 0;

      List<CaCertstore.Crl> list = crls.getCrls();
      final int n = list.size();

      for (int i = 0; i < n; i++) {
        CaCertstore.Crl crl = list.get(i);

        long id = crl.getId();
        if (id < minId) {
          continue;
        }

        numEntriesInBatch++;

        String filename = crl.getFile();

        // CRL
        ZipEntry zipEnty = zipFile.getEntry(filename);

        // rawcert
        byte[] encodedCrl = IoUtil.readAllBytesAndClose(zipFile.getInputStream(zipEnty));
        String b64Sha1 = HashAlgo.SHA1.base64Hash(encodedCrl);

        X509CRLHolder x509crl;
        try {
          x509crl = X509Util.parseCrl(encodedCrl);
        } catch (Exception ex) {
          LOG.error("could not parse CRL in file {}", filename);
          LOG.debug("could not parse CRL in file " + filename, ex);
          if (ex instanceof CRLException) {
            throw ex;
          } else {
            throw new CRLException(ex.getMessage(), ex);
          }
        }

        try {
          Extensions extns = x509crl.getExtensions();
          byte[] extnValue = X509Util.getCoreExtValue(extns, Extension.cRLNumber);
          if (extnValue == null) {
            LOG.warn("CRL without CRL number, ignore it");
            continue;
          }
          BigInteger crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

          extnValue = X509Util.getCoreExtValue(extns, Extension.deltaCRLIndicator);
          BigInteger baseCrlNumber = (extnValue == null) ? null : ASN1Integer.getInstance(extnValue).getPositiveValue();

          int idx = 1;
          stmt.setLong(idx++, crl.getId());
          stmt.setInt(idx++, crl.getCaId());
          stmt.setLong(idx++, crlNumber.longValue());
          stmt.setLong(idx++, toEpochSecond(x509crl.getThisUpdate()));
          if (x509crl.getNextUpdate() != null) {
            stmt.setLong(idx++, toEpochSecond(x509crl.getNextUpdate()));
          } else {
            stmt.setNull(idx++, Types.INTEGER);
          }

          if (baseCrlNumber == null) {
            setBoolean(stmt, idx++, false);
            stmt.setNull(idx++, Types.BIGINT);
          } else {
            setBoolean(stmt, idx++, true);
            stmt.setLong(idx++, baseCrlNumber.longValue());
          }

          stmt.setInt(idx++, crl.getCrlScope());
          stmt.setString(idx++, b64Sha1);
          stmt.setString(idx, Base64.encodeToString(encodedCrl));

          stmt.addBatch();
        } catch (SQLException ex) {
          System.err.println("could not import CRL with ID=" + crl.getId() + ", message: " + ex.getMessage());
          throw ex;
        }

        boolean isLastBlock = i == n - 1;
        if (numEntriesInBatch > 0
            && (numEntriesInBatch % numEntriesPerCommit == 0 || isLastBlock)) {
          try {
            stmt.executeBatch();
            commit("(commit import to CA)");
          } catch (Throwable th) {
            rollback();
            deleteFromTableWithLargerId(type.getTableName(), "ID", id, LOG);
            if (th instanceof SQLException) {
              throw translate(sql, (SQLException) th);
            } else if (th instanceof Exception) {
              throw (Exception) th;
            } else {
              throw new Exception(th);
            }
          }

          lastSuccessfulEntryId = id;
          processLog.addNumProcessed(numEntriesInBatch);
          numEntriesInBatch = 0;
          echoToFile(type + ":" + (numProcessedInLastProcess + processLog.numProcessed()) + ":"
              + lastSuccessfulEntryId, processLogFile);
          processLog.printStatus();
        }

      } // end while

      return lastSuccessfulEntryId;
    } finally {
      recoverAutoCommit();
      zipFile.close();
    }
  } // method importCrls

}
