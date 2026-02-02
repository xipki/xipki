// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.CaConfType;
import org.xipki.ca.api.mgmt.entry.BaseCaInfo;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;
import org.xipki.util.benchmark.ProcessLog;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Database importer of OCSP CertStore from CA CertStore.
 *
 * @author Lijun Liao (xipki)
 */

class OcspCertStoreFromCaDbImporter extends AbstractOcspCertstoreDbImporter {

  private static final Logger LOG =
      LoggerFactory.getLogger(OcspCertStoreFromCaDbImporter.class);

  private final String publisherName;

  private final boolean resume;

  private final int numCertsPerCommit;

  OcspCertStoreFromCaDbImporter(
      DataSourceWrapper datasource, String srcDir, String publisherName,
      int numCertsPerCommit, boolean resume, AtomicBoolean stopMe)
      throws Exception {
    super(datasource, srcDir, stopMe);

    this.publisherName = Args.toNonBlankLower(publisherName, "publisherName");
    this.numCertsPerCommit = Args.positive(numCertsPerCommit,
        "numCertsPerCommit");

    File processLogFile = new File(baseDir,
        DbPorter.IMPORT_TO_OCSP_PROCESS_LOG_FILENAME);

    if (resume) {
      if (!processLogFile.exists()) {
        throw new Exception("could not process with '--resume' option");
      }
    } else {
      if (processLogFile.exists()) {
        throw new Exception(
            "please either specify '--resume' or delete the file " +
            processLogFile.getPath() + " first");
      }
    }
    this.resume = resume;
  } // constructor

  public void importToDb() throws Exception {
    JsonMap json = JsonParser.parseMap(
        Paths.get(baseDir, FILENAME_CA_CERTSTORE), false);
    CaCertstore certstore = CaCertstore.parse(json);

    if (certstore.version() > VERSION_V2) {
      throw new Exception("could not import CertStore greater than " +
          VERSION_V2 + ": " + certstore.version());
    }

    json = JsonParser.parseMap(Paths.get(baseDir, FILENAME_CA_CONFIGURATION),
        false);
    CaConfType.CaSystem caconf = CaConfType.CaSystem.parse(json);

    System.out.println("importing CA certstore to OCSP database");
    try {
      CaConfType.NameTypeConf publisherType = null;
      for (CaConfType.NameTypeConf type : caconf.publishers()) {
        if (publisherName.equals(type.name())) {
          publisherType = type;
          break;
        }
      }

      if (publisherType == null) {
        throw new Exception("unknown publisher " + publisherName);
      }

      String type = publisherType.type();
      if (!"ocsp".equalsIgnoreCase(type)) {
        throw new Exception("Unkwown publisher type " + type);
      }

      ConfPairs confPairs = new ConfPairs(readContent(publisherType.conf()));
      String str = confPairs.value("publish.goodcerts");
      boolean revokedOnly = false;
      if (str != null) {
        revokedOnly = !Boolean.parseBoolean(str);
      }

      Set<Integer> relatedCaIds = new HashSet<>();
      for (CaConfType.Ca ca : caconf.cas()) {
        if (ca.publishers().contains(publisherName)) {
          relatedCaIds.add(ca.id());
        }
      }

      List<CaConfType.Ca> relatedCas = new LinkedList<>();
      for (CaConfType.Ca m : caconf.cas()) {
        if (relatedCaIds.contains(m.id())) {
          relatedCas.add(m);
        }
      }

      if (relatedCas.isEmpty()) {
        System.out.println("No CA has publisher " + publisherName);
        return;
      }

      List<Integer> relatedCertStoreCaIds = resume ? getIssuerIds(relatedCas)
          : importIssuer(relatedCas);

      File processLogFile = new File(baseDir,
          DbPorter.IMPORT_TO_OCSP_PROCESS_LOG_FILENAME);
      importCert(certstore, revokedOnly, relatedCertStoreCaIds, processLogFile);
      IoUtil.deleteFile0(processLogFile);
    } catch (Exception ex) {
      System.err.println("could not import OCSP certstore to database");
      throw ex;
    }
    System.out.println(" imported OCSP certstore to database");
  } // method importToDb

  private List<Integer> getIssuerIds(List<CaConfType.Ca> cas)
      throws IOException {
    List<Integer> relatedCaIds = new LinkedList<>();
    for (CaConfType.Ca issuer : cas) {
      byte[] encodedCert = issuer.caInfo().cert() == null ? null
          : readContent(issuer.caInfo().cert());

      // retrieve the revocation information of the CA, if possible
      CaConfType.Ca ca = null;
      for (CaConfType.Ca caType : cas) {
        byte[] certBytes = caType.caInfo().cert() == null ? null
            : readContent(caType.caInfo().cert());
        if (Arrays.equals(encodedCert, certBytes)) {
          ca = caType;
          break;
        }
      }

      if (ca == null) {
        continue;
      }
      relatedCaIds.add(issuer.id());
    }
    return relatedCaIds;
  } // method getIssuerIds

  private List<Integer> importIssuer(List<CaConfType.Ca> cas)
      throws DataAccessException, CertificateException, IOException {
    System.out.print("    importing table ISSUER ... ");
    boolean succ = false;
    final String sql = SQL_ADD_ISSUER;
    PreparedStatement ps = prepareStatement(sql);

    List<Integer> relatedCaIds = new LinkedList<>();

    try {
      for (CaConfType.Ca issuer : cas) {
        importIssuer0(issuer, sql, ps, relatedCaIds);
      }
      succ = true;
    } finally {
      releaseResources(ps, null);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }

    return relatedCaIds;
  } // method importIssuer

  private void importIssuer0(CaConfType.Ca issuer, String sql,
                             PreparedStatement ps, List<Integer> relatedCaIds)
      throws IOException, DataAccessException, CertificateException {
    try {
      byte[] encodedCert = readContent(issuer.caInfo().cert());
      relatedCaIds.add(issuer.id());

      Certificate cert;
      try {
        cert = Certificate.getInstance(encodedCert);
      } catch (RuntimeException ex) {
        String msg = "could not parse certificate of issuer " + issuer.id();
        LogUtil.error(LOG, ex, msg);
        throw new CertificateException(ex.getMessage(), ex);
      }

      String revInfoStr = null;
      BaseCaInfo base = issuer.caInfo().base();
      if (base.revocationInfo() != null) {
        revInfoStr = base.revocationInfo().encode();
      }

      int idx = 1;
      ps.setInt(idx++, issuer.id());
      ps.setString(idx++,
          X509Util.cutX500Name(cert.getSubject(), maxX500nameLen));
      ps.setLong(idx++, DateUtil.toEpochSecond(
          cert.getTBSCertificate().getStartDate().getDate()));
      ps.setLong(idx++, DateUtil.toEpochSecond(
          cert.getTBSCertificate().getEndDate().getDate()));
      ps.setString(idx++, HashAlgo.SHA1.base64Hash(encodedCert));
      ps.setString(idx++, revInfoStr);
      ps.setString(idx++, Base64.encodeToString(encodedCert));
      ps.setNull(idx, Types.INTEGER); // CRL_ID

      ps.execute();
    } catch (SQLException ex) {
      System.err.println("could not import issuer with id=" + issuer.id());
      throw translate(sql, ex);
    } catch (CertificateException ex) {
      System.err.println("could not import issuer with id=" + issuer.id());
      throw ex;
    }
  } // method importIssuer0

  private void importCert(
      CaCertstore certstore, boolean revokedOnly, List<Integer> caIds,
      File processLogFile) throws Exception {
    HashAlgo certhashAlgo = getCertHashAlgo();

    int numProcessedBefore = 0;
    long minId = 1;
    if (processLogFile.exists()) {
      byte[] content = IoUtil.read(processLogFile);
      if (content.length > 2) {
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

    final long total = certstore.countCerts() - numProcessedBefore;
    final ProcessLog processLog = new ProcessLog(total);
    // all initial values for importLog will be not evaluated, so just any
    // number
    final ProcessLog importLog = new ProcessLog(total);

    System.out.println("importing certificates from ID " + minId);
    processLog.printHeader();

    PreparedStatement psCert = prepareStatement(SQL_ADD_CERT);

    try (DbPortFileNameIterator certsFileIterator = new DbPortFileNameIterator(
        baseDir + File.separator + CaDbEntryType.CERT.dirName() + ".mf")) {
      while (certsFileIterator.hasNext()) {
        String certsFile = baseDir + File.separator +
            CaDbEntryType.CERT.dirName() + File.separator +
            certsFileIterator.next();

        // extract the toId from the filename
        int fromIdx = certsFile.indexOf('-');
        int toIdx = certsFile.indexOf(".zip");
        if (fromIdx != -1 && toIdx != -1) {
          try {
            long toId = Integer.parseInt(
                certsFile.substring(fromIdx + 1, toIdx));
            if (toId < minId) {
              // try next file
              continue;
            }
          } catch (Exception ex) {
            LOG.warn("invalid file name '{}', but will still be processed",
                certsFile);
          }
        } else {
          LOG.warn("invalid file name '{}', but will still be processed",
              certsFile);
        }

        try {
          long lastId = importCert0(certhashAlgo, psCert, certsFile,
              revokedOnly, caIds, minId, processLogFile, processLog,
              numProcessedBefore, importLog);
          minId = lastId + 1;
        } catch (Exception ex) {
          System.err.println(
              "\ncould not import certificates from file " + certsFile +
              ".\nplease continue with the option '--resume'");
          LOG.error("Exception", ex);
          throw ex;
        }
      }
    } finally {
      releaseResources(psCert, null);
    }

    processLog.printTrailer();
    DbPorter.echoToFile(MSG_CERTS_FINISHED, processLogFile);
    System.out.println("processed " + processLog.numProcessed() +
        " and imported " + importLog.numProcessed() + " certificates");
  } // method importCert

  private long importCert0(
      HashAlgo certhashAlgo, PreparedStatement psCert, String certsZipFile,
      boolean revokedOnly, List<Integer> caIds, long minId,
      File processLogFile, ProcessLog processLog,
      int numProcessedInLastProcess, ProcessLog importLog)
      throws Exception {
    ZipFile zipFile = new ZipFile(new File(certsZipFile));
    ZipEntry certsEntry = zipFile.getEntry("overview.json");

    CaCertstore.Certs certs;
    try {
      JsonMap json = JsonParser.parseMap(zipFile.getInputStream(certsEntry),
          false);
      certs = CaCertstore.Certs.parse(json);
    } catch (Exception ex) {
      try {
        zipFile.close();
      } catch (Exception e2) {
        LOG.error("could not close ZIP file {}: {}",
            certsZipFile, e2.getMessage());
        LOG.debug("could not close ZIP file {}", certsZipFile, e2);
      }
      throw ex;
    }

    disableAutoCommit();

    try {
      int numProcessedEntriesInBatch = 0;
      int numImportedEntriesInBatch = 0;
      long lastSuccessfulCertId = 0;

      List<CaCertstore.Cert> list = certs.certs();
      final int n = list.size();

      for (int i = 0; i < n; i++) {
        if (stopMe.get()) {
          throw new InterruptedException("interrupted by the user");
        }

        CaCertstore.Cert cert = list.get(i);

        final long id = cert.id();
        lastSuccessfulCertId = id;
        if (id < minId) {
          continue;
        }

        numProcessedEntriesInBatch++;

        if (!revokedOnly || (cert.rev() == 1)) {
          int caId = cert.caId();
          if (caIds.contains(caId)) {
            numImportedEntriesInBatch++;

            String filename = cert.file();

            // rawcert
            byte[] encodedCert = IoUtil.readAllBytesAndClose(
                zipFile.getInputStream(zipFile.getEntry(filename)));
            String certhash = certhashAlgo.base64Hash(encodedCert);

            TBSCertificate tbsCert;
            try {
              tbsCert = Certificate.getInstance(encodedCert)
                  .getTBSCertificate();
            } catch (RuntimeException ex) {
              LogUtil.error(LOG, ex,
                  "could not parse certificate in file " + filename);
              throw new CertificateException(ex.getMessage(), ex);
            }

            String subject = X509Util.cutX500Name(
                tbsCert.getSubject(), maxX500nameLen);

            // cert
            try {
              int idx = 1;
              psCert.setLong(idx++, id);
              psCert.setInt(idx++, caId);
              psCert.setString(idx++, tbsCert.getSerialNumber()
                  .getPositiveValue().toString(16));
              psCert.setLong(idx++, cert.update());
              psCert.setLong(idx++, DateUtil.toEpochSecond(
                  tbsCert.getStartDate().getDate()));
              psCert.setLong(idx++, DateUtil.toEpochSecond(
                  tbsCert.getEndDate().getDate()));
              setInt(psCert, idx++, cert.rev());
              setInt(psCert, idx++, cert.rr());
              setLong(psCert, idx++, cert.rt());
              setLong(psCert, idx++, cert.rit());

              psCert.setString(idx++, certhash);
              psCert.setString(idx++, subject);
              psCert.setNull(idx, Types.INTEGER);

              psCert.addBatch();
            } catch (SQLException ex) {
              throw translate(SQL_ADD_CERT, ex);
            }

          } // end if (caIds.contains(caId))
        } // end if (revokedOnly

        boolean isLastBlock = i == n - 1;

        if (numImportedEntriesInBatch > 0
            && (numImportedEntriesInBatch % this.numCertsPerCommit == 0
                || isLastBlock)) {
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

          processLog.addNumProcessed(numProcessedEntriesInBatch);
          importLog.addNumProcessed(numImportedEntriesInBatch);
          numProcessedEntriesInBatch = 0;
          numImportedEntriesInBatch = 0;
          String filename =
              (numProcessedInLastProcess + processLog.numProcessed()) +
              ":" + lastSuccessfulCertId;
          echoToFile(filename, processLogFile);
          processLog.printStatus();
        } else if (isLastBlock) {
          processLog.addNumProcessed(numProcessedEntriesInBatch);
          importLog.addNumProcessed(numImportedEntriesInBatch);
          numProcessedEntriesInBatch = 0;
          numImportedEntriesInBatch = 0;
          String filename =
              (numProcessedInLastProcess + processLog.numProcessed()) +
              ":" + lastSuccessfulCertId;
          echoToFile(filename, processLogFile);
          processLog.printStatus();
        }
        // if (numImportedEntriesInBatch)
      } // end for

      return lastSuccessfulCertId;
    } finally {
      recoverAutoCommit();
      zipFile.close();
    }
  } // method importCert0

  private HashAlgo getCertHashAlgo() throws DataAccessException {
    String certHashAlgoStr = Optional.ofNullable(
        dbSchemaInfo.get("CERTHASH_ALGO"))
        .orElseThrow(() -> new DataAccessException(
            "Column with NAME='CERTHASH_ALGO' is not defined in " +
            "table DBSCHEMA"));

    try {
      return HashAlgo.getInstance(certHashAlgoStr);
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalArgumentException(ex);
    }
  } // method getCertHashAlgo

}
