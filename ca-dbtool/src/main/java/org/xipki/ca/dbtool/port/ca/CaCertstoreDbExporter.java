/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.dbtool.port.ca;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLStreamException;
import javax.xml.validation.Schema;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.jaxb.ca.CertstoreType;
import org.xipki.ca.dbtool.jaxb.ca.CertstoreType.DeltaCrlCache;
import org.xipki.ca.dbtool.jaxb.ca.CertstoreType.PublishQueue;
import org.xipki.ca.dbtool.jaxb.ca.DeltaCrlCacheEntryType;
import org.xipki.ca.dbtool.jaxb.ca.ObjectFactory;
import org.xipki.ca.dbtool.jaxb.ca.ToPublishType;
import org.xipki.ca.dbtool.port.DbPorter;
import org.xipki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.ca.dbtool.xmlio.ca.CertType;
import org.xipki.ca.dbtool.xmlio.ca.CertsWriter;
import org.xipki.ca.dbtool.xmlio.ca.CrlType;
import org.xipki.ca.dbtool.xmlio.ca.CrlsWriter;
import org.xipki.ca.dbtool.xmlio.ca.RequestCertType;
import org.xipki.ca.dbtool.xmlio.ca.RequestCertsWriter;
import org.xipki.ca.dbtool.xmlio.ca.RequestType;
import org.xipki.ca.dbtool.xmlio.ca.RequestsWriter;
import org.xipki.common.ProcessLog;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.common.util.XmlUtil;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.dbtool.InvalidInputException;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaCertstoreDbExporter extends AbstractCaCertstoreDbPorter {

  private static final Logger LOG = LoggerFactory.getLogger(CaCertstoreDbExporter.class);

  private final Marshaller marshaller;

  private final Unmarshaller unmarshaller;

  private final int numCertsInBundle;

  private final int numCertsPerSelect;

  private final boolean resume;

  CaCertstoreDbExporter(DataSourceWrapper datasource, String baseDir, int numCertsInBundle,
      int numCertsPerSelect, boolean resume, AtomicBoolean stopMe, boolean evaluateOnly)
          throws DataAccessException, JAXBException {
    super(datasource, baseDir, stopMe, evaluateOnly);

    this.numCertsInBundle = ParamUtil.requireMin("numCertsInBundle", numCertsInBundle, 1);
    this.numCertsPerSelect = ParamUtil.requireMin("numCertsPerSelect", numCertsPerSelect, 1);
    this.resume = resume;

    Schema schema = DbPorter.retrieveSchema("/xsd/dbi-ca.xsd");
    JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);

    marshaller = jaxbContext.createMarshaller();
    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
    marshaller.setSchema(schema);

    unmarshaller = jaxbContext.createUnmarshaller();
    unmarshaller.setSchema(schema);
  }

  @SuppressWarnings("unchecked")
  public void export() throws Exception {
    CertstoreType certstore;
    if (resume) {
      JAXBElement<CertstoreType> root;
      try {
        root = (JAXBElement<CertstoreType>)
          unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_CERTSTORE));
      } catch (JAXBException ex) {
        throw XmlUtil.convert(ex);
      }

      certstore = root.getValue();
      if (certstore.getVersion() > VERSION) {
        throw new InvalidInputException("could not continue with CertStore greater than "
            + VERSION + ": " + certstore.getVersion());
      }
    } else {
      certstore = new CertstoreType();
      certstore.setVersion(VERSION);
    }

    Exception exception = null;
    System.out.println("exporting CA certstore from database");
    try {
      if (!resume) {
        exportPublishQueue(certstore);
        exportDeltaCrlCache(certstore);
      }

      File processLogFile = new File(baseDir, DbPorter.EXPORT_PROCESS_LOG_FILENAME);

      Long idProcessedInLastProcess = null;
      CaDbEntryType typeProcessedInLastProcess = null;
      if (processLogFile.exists()) {
        byte[] content = IoUtil.read(processLogFile);
        if (content != null && content.length > 0) {
          String str = new String(content);
          int idx = str.indexOf(':');
          String typeName = str.substring(0, idx).trim();
          typeProcessedInLastProcess = CaDbEntryType.valueOf(typeName);
          idProcessedInLastProcess = Long.parseLong(str.substring(idx + 1).trim());
        }
      }

      if (CaDbEntryType.CRL == typeProcessedInLastProcess || typeProcessedInLastProcess == null) {
        exception = exportEntries(CaDbEntryType.CRL, certstore, processLogFile,
            idProcessedInLastProcess);
        typeProcessedInLastProcess = null;
        idProcessedInLastProcess = null;
      }

      CaDbEntryType[] types = {CaDbEntryType.CERT, CaDbEntryType.REQUEST, CaDbEntryType.REQCERT};

      for (CaDbEntryType type : types) {
        if (exception == null
            && (type == typeProcessedInLastProcess || typeProcessedInLastProcess == null)) {
          exception = exportEntries(type, certstore, processLogFile, idProcessedInLastProcess);
          typeProcessedInLastProcess = null;
          idProcessedInLastProcess = null;
        }
      }

      JAXBElement<CertstoreType> root = new ObjectFactory().createCertstore(certstore);
      try {
        marshaller.marshal(root, new File(baseDir + File.separator + FILENAME_CA_CERTSTORE));
      } catch (JAXBException ex) {
        throw XmlUtil.convert(ex);
      }
    } catch (Exception ex) {
      System.err.println("could not export CA certstore from database");
      exception = ex;
    }

    if (exception == null) {
      System.out.println(" exported CA certstore from database");
    } else {
      throw exception;
    }
  } // method export

  private Exception exportEntries(CaDbEntryType type, CertstoreType certstore,
      File processLogFile, Long idProcessedInLastProcess) {
    String tablesText = "table " + type.getTableName();

    File dir = new File(baseDir, type.getDirName());
    dir.mkdirs();

    FileOutputStream entriesFileOs = null;
    try {
      entriesFileOs = new FileOutputStream(new File(baseDir, type.getDirName() + ".mf"), true);
      exportEntries(type, certstore, processLogFile, entriesFileOs, idProcessedInLastProcess);
      return null;
    } catch (Exception ex) {
      // delete the temporary files
      deleteTmpFiles(baseDir, "tmp-");

      System.err.println("\nexporting " + tablesText + " has been cancelled due to error,\n"
          + "please continue with the option '--resume'");
      LOG.error("Exception", ex);
      return ex;
    } finally {
      if (entriesFileOs != null) {
        IoUtil.closeStream(entriesFileOs);
      }
    }
  }

  private void exportEntries(CaDbEntryType type, CertstoreType certstore, File processLogFile,
      FileOutputStream filenameListOs, Long idProcessedInLastProcess) throws Exception {
    final int numEntriesPerSelect = Math.max(1,
        Math.round(type.getSqlBatchFactor() * numCertsPerSelect));
    final int numEntriesPerZip =
        Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsInBundle));
    final File entriesDir = new File(baseDir, type.getDirName());
    final String tableName = type.getTableName();

    int numProcessedBefore;
    String coreSql;

    switch (type) {
      case CERT:
        numProcessedBefore = certstore.getCountCerts();
        coreSql = "ID,SN,CA_ID,PID,RID,RTYPE,TID,UID,EE,LUPDATE,REV,RR,RT,RIT,FP_RS,"
            + "REQ_SUBJECT,CERT FROM CERT WHERE ID>=?";
        break;
      case CRL:
        numProcessedBefore = certstore.getCountCrls();
        coreSql = "ID,CA_ID,CRL FROM CRL WHERE ID>=?";
        break;
      case REQUEST:
        numProcessedBefore = certstore.getCountRequests();
        coreSql = "ID,LUPDATE,DATA FROM REQUEST WHERE ID>=?";
        break;
      case REQCERT:
        numProcessedBefore = certstore.getCountReqCerts();
        coreSql = "ID,RID,CID FROM REQCERT WHERE ID>=?";
        break;
      default:
        throw new RuntimeException("unknown CaDbEntryType " + type);
    }

    Long minId = (idProcessedInLastProcess != null) ? idProcessedInLastProcess + 1
        : min(tableName, "ID");

    String tablesText = "table " + type.getTableName();
    System.out.println(exportingText() + tablesText + " from ID " + minId);

    final long maxId = max(tableName, "ID");
    long total = count(tableName) - numProcessedBefore;
    if (total < 1) {
      total = 1; // to avoid exception
    }

    String sql = datasource.buildSelectFirstSql(numEntriesPerSelect, "ID ASC", coreSql);

    DbiXmlWriter entriesInCurrentFile = createWriter(type);
    PreparedStatement ps = prepareStatement(sql.toString());

    int numEntriesInCurrentFile = 0;

    int sum = 0;
    File currentEntriesZipFile = new File(baseDir,
        "tmp-" + type.getDirName() + "-" + System.currentTimeMillis() + ".zip");
    ZipOutputStream currentEntriesZip = getZipOutputStream(currentEntriesZipFile);

    long minIdOfCurrentFile = -1;
    long maxIdOfCurrentFile = -1;

    ProcessLog processLog = new ProcessLog(total);
    processLog.printHeader();

    try {
      Long id = null;
      boolean interrupted = false;
      long lastMaxId = minId - 1;

      while (true) {
        if (stopMe.get()) {
          interrupted = true;
          break;
        }

        ps.setLong(1, lastMaxId + 1);

        ResultSet rs = ps.executeQuery();

        // no entries anymore
        if (!rs.next()) {
          break;
        }

        do {
          id = rs.getLong("ID");
          if (lastMaxId < id) {
            lastMaxId = id;
          }

          if (minIdOfCurrentFile == -1) {
            minIdOfCurrentFile = id;
          } else if (minIdOfCurrentFile > id) {
            minIdOfCurrentFile = id;
          }

          if (maxIdOfCurrentFile == -1) {
            maxIdOfCurrentFile = id;
          } else if (maxIdOfCurrentFile < id) {
            maxIdOfCurrentFile = id;
          }

          if (CaDbEntryType.CERT == type) {
            String b64Cert = rs.getString("CERT");
            byte[] certBytes = Base64.decodeFast(b64Cert);

            String sha1 = HashAlgo.SHA1.hexHash(certBytes);
            String certFileName = sha1 + ".der";
            if (!evaulateOnly) {
              ZipEntry certZipEntry = new ZipEntry(certFileName);
              currentEntriesZip.putNextEntry(certZipEntry);
              try {
                currentEntriesZip.write(certBytes);
              } finally {
                currentEntriesZip.closeEntry();
              }
            }

            CertType cert = new CertType();
            cert.setId(id);
            cert.setCaId(rs.getInt("CA_ID"));
            cert.setEe(rs.getBoolean("EE"));
            cert.setFile(certFileName);

            long fpReqSubject = rs.getLong("FP_RS");
            if (fpReqSubject != 0) {
              cert.setFpRs(fpReqSubject);
              cert.setRs(rs.getString("REQ_SUBJECT"));
            }

            cert.setPid(rs.getInt("PID"));
            cert.setReqType(rs.getInt("RTYPE"));
            cert.setRid(rs.getInt("RID"));
            cert.setSn(rs.getString("SN"));

            String str = rs.getString("TID");
            if (StringUtil.isNotBlank(str)) {
              cert.setTid(str);
            }

            int userId = rs.getInt("UID");
            if (userId != 0) {
              cert.setUid(userId);
            }
            cert.setUpdate(rs.getLong("LUPDATE"));

            boolean revoked = rs.getBoolean("REV");
            cert.setRev(revoked);

            if (revoked) {
              cert.setRr(rs.getInt("RR"));
              cert.setRt(rs.getLong("RT"));
              long revInvTime = rs.getLong("RIT");
              if (revInvTime != 0) {
                cert.setRit(revInvTime);
              }
            }

            ((CertsWriter) entriesInCurrentFile).add(cert);
          } else if (CaDbEntryType.CRL == type) {
            String b64Crl = rs.getString("CRL");
            byte[] crlBytes = Base64.decodeFast(b64Crl);

            X509CRL x509Crl = null;
            try {
              x509Crl = X509Util.parseCrl(crlBytes);
            } catch (CRLException ex) {
              LogUtil.error(LOG, ex, "could not parse CRL with id " + id);
              throw ex;
            } catch (Exception ex) {
              LogUtil.error(LOG, ex, "could not parse CRL with id " + id);
              throw new CRLException(ex.getMessage(), ex);
            }

            byte[] octetString = x509Crl.getExtensionValue(Extension.cRLNumber.getId());
            if (octetString == null) {
              LOG.warn("CRL without CRL number, ignore it");
              continue;
            }
            String sha1 = HashAlgo.SHA1.hexHash(crlBytes);

            final String crlFilename = sha1 + ".crl";
            if (!evaulateOnly) {
              ZipEntry certZipEntry = new ZipEntry(crlFilename);
              currentEntriesZip.putNextEntry(certZipEntry);
              try {
                currentEntriesZip.write(crlBytes);
              } finally {
                currentEntriesZip.closeEntry();
              }
            }

            CrlType crl = new CrlType();
            crl.setId(id);

            crl.setCaId(rs.getInt("CA_ID"));

            byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
            BigInteger crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
            crl.setCrlNo(crlNumber.toString());
            crl.setFile(crlFilename);

            ((CrlsWriter) entriesInCurrentFile).add(crl);
          } else if (CaDbEntryType.REQUEST == type) {
            long update = rs.getLong("LUPDATE");
            String b64Data = rs.getString("DATA");
            byte[] dataBytes = Base64.decodeFast(b64Data);
            String sha1 = HashAlgo.SHA1.hexHash(dataBytes);
            final String dataFilename = sha1 + ".req";
            if (!evaulateOnly) {
              ZipEntry certZipEntry = new ZipEntry(dataFilename);
              currentEntriesZip.putNextEntry(certZipEntry);
              try {
                currentEntriesZip.write(dataBytes);
              } finally {
                currentEntriesZip.closeEntry();
              }
            }
            RequestType entry = new RequestType();
            entry.setId(id);
            entry.setUpdate(update);
            entry.setFile(dataFilename);
            ((RequestsWriter) entriesInCurrentFile).add(entry);
          } else if (CaDbEntryType.REQCERT == type) {
            long cid = rs.getLong("CID");
            long rid = rs.getLong("RID");
            RequestCertType entry = new RequestCertType();
            entry.setId(id);
            entry.setCid(cid);
            entry.setRid(rid);
            ((RequestCertsWriter) entriesInCurrentFile).add(entry);
          } else {
            throw new RuntimeException("unknown CaDbEntryType " + type);
          }

          numEntriesInCurrentFile++;
          sum++;

          if (numEntriesInCurrentFile == numEntriesPerZip) {
            String currentEntriesFilename = buildFilename(type.getDirName() + "_", ".zip",
                minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
            finalizeZip(currentEntriesZip, "overview.xml", entriesInCurrentFile);
            currentEntriesZipFile.renameTo(new File(entriesDir, currentEntriesFilename));

            writeLine(filenameListOs, currentEntriesFilename);
            setCount(type, certstore, numProcessedBefore + sum);
            echoToFile(tableName + ":" + Long.toString(id), processLogFile);

            processLog.addNumProcessed(numEntriesInCurrentFile);
            processLog.printStatus();

            // reset
            entriesInCurrentFile = createWriter(type);
            numEntriesInCurrentFile = 0;
            minIdOfCurrentFile = -1;
            maxIdOfCurrentFile = -1;
            currentEntriesZipFile = new File(baseDir, "tmp-" + type.getDirName() + "-"
                + System.currentTimeMillis() + ".zip");
            currentEntriesZip = getZipOutputStream(currentEntriesZipFile);
          }
        } while (rs.next());

        rs.close();
      } // end for

      if (interrupted) {
        currentEntriesZip.close();
        throw new InterruptedException("interrupted by the user");
      }

      if (numEntriesInCurrentFile > 0) {
        finalizeZip(currentEntriesZip, "overview.xml", entriesInCurrentFile);

        String currentEntriesFilename = buildFilename(type.getDirName() + "_", ".zip",
            minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
        currentEntriesZipFile.renameTo(new File(entriesDir, currentEntriesFilename));

        writeLine(filenameListOs, currentEntriesFilename);
        setCount(type, certstore, numProcessedBefore + sum);
        if (id != null) {
          echoToFile(Long.toString(id), processLogFile);
        }

        processLog.addNumProcessed(numEntriesInCurrentFile);
      } else {
        currentEntriesZip.close();
        currentEntriesZipFile.delete();
      }

    } catch (SQLException ex) {
      throw translate(null, ex);
    } finally {
      releaseResources(ps, null);
    } // end try

    processLog.printTrailer();
    // all successful, delete the processLogFile
    processLogFile.delete();
    System.out.println(exportedText() + sum + " entries from " + tablesText);
  } // method exportEntries

  private void exportPublishQueue(CertstoreType certstore) throws DataAccessException {
    System.out.println("exporting table PUBLISHQUEUE");

    String sql = "SELECT CID,PID,CA_ID FROM PUBLISHQUEUE WHERE CID>=? AND CID<? ORDER BY CID ASC";
    final int minId = (int) min("PUBLISHQUEUE", "CID");
    final int maxId = (int) max("PUBLISHQUEUE", "CID");

    PublishQueue queue = new PublishQueue();
    certstore.setPublishQueue(queue);
    if (maxId == 0) {
      System.out.println(" exported table PUBLISHQUEUE");
      return;
    }

    PreparedStatement ps = prepareStatement(sql);
    ResultSet rs = null;

    List<ToPublishType> list = queue.getTop();
    final int n = 500;

    try {
      for (int i = minId; i <= maxId; i += n) {
        ps.setInt(1, i);
        ps.setInt(2, i + n);

        rs = ps.executeQuery();

        while (rs.next()) {
          ToPublishType toPub = new ToPublishType();
          toPub.setPubId(rs.getInt("PID"));
          toPub.setCertId(rs.getInt("CID"));
          toPub.setCaId(rs.getInt("CA_ID"));
          list.add(toPub);
        }
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(ps, rs);
    }
    System.out.println(" exported table PUBLISHQUEUE");
  } // method exportPublishQueue

  private void exportDeltaCrlCache(CertstoreType certstore) throws DataAccessException {
    System.out.println("exporting table DELTACRL_CACHE");

    final String sql = "SELECT SN,CA_ID FROM DELTACRL_CACHE";

    DeltaCrlCache deltaCache = new DeltaCrlCache();
    certstore.setDeltaCrlCache(deltaCache);

    PreparedStatement ps = prepareStatement(sql);
    ResultSet rs = null;

    List<DeltaCrlCacheEntryType> list = deltaCache.getEntry();

    try {
      rs = ps.executeQuery();

      while (rs.next()) {
        String serial = rs.getString("SN");
        int caId = rs.getInt("CA_ID");

        DeltaCrlCacheEntryType entry = new DeltaCrlCacheEntryType();
        entry.setCaId(caId);
        entry.setSerial(serial);
        list.add(entry);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(ps, rs);
    }

    System.out.println(" exported table DELTACRL_CACHE");
  } // method exportDeltaCrlCache

  private void finalizeZip(ZipOutputStream zipOutStream, String filename, DbiXmlWriter os)
      throws IOException, XMLStreamException {
    ZipEntry certZipEntry = new ZipEntry(filename);
    zipOutStream.putNextEntry(certZipEntry);
    try {
      os.rewriteToZipStream(zipOutStream);
    } finally {
      zipOutStream.closeEntry();
    }

    zipOutStream.close();
  }

  private static DbiXmlWriter createWriter(CaDbEntryType type)
      throws IOException, XMLStreamException {
    switch (type) {
      case CERT:
        return new CertsWriter();
      case CRL:
        return new CrlsWriter();
      case REQUEST:
        return new RequestsWriter();
      case REQCERT:
        return new RequestCertsWriter();
      default:
        throw new RuntimeException("unknown CaDbEntryType " + type);
    }
  }

  private static void setCount(CaDbEntryType type, CertstoreType certstore, int num) {
    switch (type) {
      case CERT:
        certstore.setCountCerts(num);
        break;
      case CRL:
        certstore.setCountCrls(num);
        break;
      case REQUEST:
        certstore.setCountRequests(num);
        break;
      case REQCERT:
        certstore.setCountReqCerts(num);
        break;
      default:
        throw new RuntimeException("unknown CaDbEntryType " + type);
    }
  }
}
