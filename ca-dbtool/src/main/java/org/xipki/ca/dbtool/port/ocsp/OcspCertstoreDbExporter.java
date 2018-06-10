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

package org.xipki.ca.dbtool.port.ocsp;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.jaxb.ocsp.CertstoreType;
import org.xipki.ca.dbtool.jaxb.ocsp.CertstoreType.Issuers;
import org.xipki.ca.dbtool.jaxb.ocsp.IssuerType;
import org.xipki.ca.dbtool.jaxb.ocsp.ObjectFactory;
import org.xipki.ca.dbtool.port.DbPorter;
import org.xipki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.ca.dbtool.xmlio.ocsp.OcspCertType;
import org.xipki.ca.dbtool.xmlio.ocsp.OcspCertsWriter;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.IoUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.ProcessLog;
import org.xipki.util.XmlUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class OcspCertstoreDbExporter extends DbPorter {

  public static final String PROCESS_LOG_FILENAME = "export.process";

  private static final Logger LOG = LoggerFactory.getLogger(OcspCertstoreDbExporter.class);

  private final Marshaller marshaller;

  private final Unmarshaller unmarshaller;

  private final int numCertsInBundle;

  private final int numCertsPerSelect;

  private final boolean resume;

  OcspCertstoreDbExporter(DataSourceWrapper datasource, String baseDir, int numCertsInBundle,
      int numCertsPerSelect, boolean resume, AtomicBoolean stopMe) throws Exception {
    super(datasource, baseDir, stopMe);

    this.numCertsInBundle = ParamUtil.requireMin("numCertsInBundle", numCertsInBundle, 1);
    this.numCertsPerSelect = ParamUtil.requireMin("numCertsPerSelect", numCertsPerSelect, 1);

    JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
    marshaller = jaxbContext.createMarshaller();
    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

    Schema schema = DbPorter.retrieveSchema("/xsd/dbi-ocsp.xsd");
    marshaller.setSchema(schema);

    unmarshaller = jaxbContext.createUnmarshaller();
    unmarshaller.setSchema(schema);

    if (resume) {
      File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);
      if (!processLogFile.exists()) {
        throw new Exception("could not process with '--resume' option");
      }
    }
    this.resume = resume;
  } // constructor

  public void export() throws Exception {
    CertstoreType certstore;
    if (resume) {
      try {
        @SuppressWarnings("unchecked")
        JAXBElement<CertstoreType> root = (JAXBElement<CertstoreType>)
            unmarshaller.unmarshal(new File(baseDir, FILENAME_OCSP_CERTSTORE));
        certstore = root.getValue();
      } catch (JAXBException ex) {
        throw XmlUtil.convert(ex);
      }

      if (certstore.getVersion() > VERSION) {
        throw new Exception("could not continue with Certstore greater than " + VERSION
            + ": " + certstore.getVersion());
      }
    } else {
      certstore = new CertstoreType();
      certstore.setVersion(VERSION);
    }
    System.out.println("exporting OCSP certstore from database");

    if (!resume) {
      exportHashAlgo(certstore);
      exportIssuer(certstore);
    }

    File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);
    Exception exception = exportCert(certstore, processLogFile);

    JAXBElement<CertstoreType> root = new ObjectFactory().createCertstore(certstore);
    try {
      marshaller.marshal(root, new File(baseDir, FILENAME_OCSP_CERTSTORE));
    } catch (JAXBException ex) {
      throw XmlUtil.convert(ex);
    }

    if (exception == null) {
      System.out.println(" exported OCSP certstore from database");
    } else {
      throw exception;
    }
  } // method export

  private void exportHashAlgo(CertstoreType certstore) throws DataAccessException {
    String certHashAlgoStr = dbSchemaInfo.getVariableValue("CERTHASH_ALGO");
    if (certHashAlgoStr == null) {
      throw new DataAccessException("CERTHASH_ALGO is not defined in table DBSCHEMA");
    }

    certstore.setCerthashAlgo(certHashAlgoStr);
  }

  private void exportIssuer(CertstoreType certstore) throws DataAccessException, IOException {
    System.out.println("exporting table ISSUER");
    Issuers issuers = new Issuers();
    certstore.setIssuers(issuers);
    final String sql = "SELECT ID,CERT,REV_INFO FROM ISSUER";

    Statement stmt = null;
    ResultSet rs = null;

    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      String issuerCertsDir = "issuer-conf";
      new File(issuerCertsDir).mkdirs();

      while (rs.next()) {
        int id = rs.getInt("ID");

        IssuerType issuer = new IssuerType();
        issuer.setId(id);

        String certFileName = issuerCertsDir + "/cert-issuer-" + id;
        IoUtil.save(new File(baseDir, certFileName), rs.getString("CERT").getBytes("UTF-8"));
        issuer.setCertFile(certFileName);
        issuer.setRevInfo(rs.getString("REV_INFO"));

        issuers.getIssuer().add(issuer);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    System.out.println(" exported table ISSUER");
  } // method exportIssuer

  private Exception exportCert(CertstoreType certstore, File processLogFile) {
    new File(baseDir, OcspDbEntryType.CERT.getDirName()).mkdirs();

    FileOutputStream certsFileOs = null;

    try {
      certsFileOs = new FileOutputStream(
          new File(baseDir, OcspDbEntryType.CERT.getDirName() + ".mf"), true);
      exportCert0(certstore, processLogFile, certsFileOs);
      return null;
    } catch (Exception ex) {
      // delete the temporary files
      deleteTmpFiles(baseDir, "tmp-certs-");
      System.err.println("\nexporting table CERT has been cancelled due to error,\n"
          + "please continue with the option '--resume'");
      LOG.error("Exception", ex);
      return ex;
    } finally {
      IoUtil.closeStream(certsFileOs);
    }
  } // method exportCert

  private void exportCert0(CertstoreType certstore, File processLogFile,
      FileOutputStream certsFileOs) throws Exception {
    File certsDir = new File(baseDir, OcspDbEntryType.CERT.getDirName());
    Long minId = null;
    if (processLogFile.exists()) {
      byte[] content = IoUtil.read(processLogFile);
      if (content != null && content.length > 0) {
        minId = Long.parseLong(new String(content).trim());
        minId++;
      }
    }

    if (minId == null) {
      minId = min("CERT", "ID");
    }

    System.out.println("exporting table CERT from ID " + minId);

    final String coreSql = "ID,SN,IID,LUPDATE,REV,RR,RT,RIT,PN,NAFTER,NBEFORE,HASH,SUBJECT "
        + "FROM CERT WHERE ID>=?";
    final String certSql = datasource.buildSelectFirstSql(numCertsPerSelect, "ID ASC", coreSql);

    final long maxId = max("CERT", "ID");

    int numProcessedBefore = certstore.getCountCerts();
    final long total = count("CERT") - numProcessedBefore;
    ProcessLog processLog = new ProcessLog(total);

    PreparedStatement certPs = prepareStatement(certSql);

    int sum = 0;
    int numCertInCurrentFile = 0;

    OcspCertsWriter certsInCurrentFile = new OcspCertsWriter();

    File currentCertsZipFile = new File(baseDir,
        "tmp-certs-" + System.currentTimeMillis() + ".zip");
    ZipOutputStream currentCertsZip = getZipOutputStream(currentCertsZipFile);

    long minCertIdOfCurrentFile = -1;
    long maxCertIdOfCurrentFile = -1;

    processLog.printHeader();

    String sql = null;
    Long id = null;

    try {
      boolean interrupted = false;

      long lastMaxId = minId - 1;

      while (true) {
        if (stopMe.get()) {
          interrupted = true;
          break;
        }

        sql = certSql;
        certPs.setLong(1, lastMaxId + 1);

        ResultSet rs = certPs.executeQuery();

        if (!rs.next()) {
          break;
        }

        do {
          id = rs.getLong("ID");
          if (lastMaxId < id) {
            lastMaxId = id;
          }

          if (minCertIdOfCurrentFile == -1) {
            minCertIdOfCurrentFile = id;
          } else if (minCertIdOfCurrentFile > id) {
            minCertIdOfCurrentFile = id;
          }

          if (maxCertIdOfCurrentFile == -1) {
            maxCertIdOfCurrentFile = id;
          } else if (maxCertIdOfCurrentFile < id) {
            maxCertIdOfCurrentFile = id;
          }

          OcspCertType cert = new OcspCertType();

          cert.setId(id);

          cert.setIid(rs.getInt("IID"));
          cert.setSn(rs.getString("SN"));
          cert.setUpdate(rs.getLong("LUPDATE"));

          boolean revoked = rs.getBoolean("REV");
          cert.setRev(revoked);

          if (revoked) {
            cert.setRr(rs.getInt("RR"));
            cert.setRt(rs.getLong("RT"));
            long rit = rs.getLong("RIT");
            if (rit != 0) {
              cert.setRit(rit);
            }
          }

          cert.setProfile(rs.getString("PN"));

          String hash = rs.getString("HASH");
          if (hash != null) {
            cert.setHash(hash);
          }

          String subject = rs.getString("SUBJECT");
          if (subject != null) {
            cert.setSubject(subject);
          }

          long nafter = rs.getLong("NAFTER");
          if (nafter != 0) {
            cert.setNafter(nafter);
          }

          long nbefore = rs.getLong("NBEFORE");
          if (nbefore != 0) {
            cert.setNbefore(nbefore);
          }

          certsInCurrentFile.add(cert);
          numCertInCurrentFile++;
          sum++;

          if (numCertInCurrentFile == numCertsInBundle) {
            finalizeZip(currentCertsZip, certsInCurrentFile);

            String currentCertsFilename = buildFilename("certs_", ".zip",
                minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxId);
            currentCertsZipFile.renameTo(new File(certsDir, currentCertsFilename));

            writeLine(certsFileOs, currentCertsFilename);
            certstore.setCountCerts(numProcessedBefore + sum);
            echoToFile(Long.toString(id), processLogFile);

            processLog.addNumProcessed(numCertInCurrentFile);
            processLog.printStatus();

            // reset
            certsInCurrentFile = new OcspCertsWriter();
            numCertInCurrentFile = 0;
            minCertIdOfCurrentFile = -1;
            maxCertIdOfCurrentFile = -1;
            currentCertsZipFile = new File(baseDir,
                "tmp-certs-" + System.currentTimeMillis() + ".zip");
            currentCertsZip = getZipOutputStream(currentCertsZipFile);
          } // end if
        } while (rs.next());

        rs.close();
      } // end for

      if (interrupted) {
        throw new InterruptedException("interrupted by the user");
      }

      if (numCertInCurrentFile > 0) {
        finalizeZip(currentCertsZip, certsInCurrentFile);

        String currentCertsFilename = buildFilename("certs_", ".zip",
            minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxId);
        currentCertsZipFile.renameTo(new File(certsDir, currentCertsFilename));

        writeLine(certsFileOs, currentCertsFilename);
        certstore.setCountCerts(numProcessedBefore + sum);
        if (id != null) {
          echoToFile(Long.toString(id), processLogFile);
        }

        processLog.addNumProcessed(numCertInCurrentFile);
      } else {
        currentCertsZip.close();
        currentCertsZipFile.delete();
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(certPs, null);
    }

    processLog.printTrailer();
    // all successful, delete the processLogFile
    processLogFile.delete();

    System.out.println(" exported " + processLog.numProcessed() + " certificates from tables CERT");
  } // method exportCert0

  private void finalizeZip(ZipOutputStream zipOutStream, DbiXmlWriter certsType)
      throws IOException, XMLStreamException {
    ZipEntry certZipEntry = new ZipEntry("certs.xml");
    zipOutStream.putNextEntry(certZipEntry);
    try {
      certsType.rewriteToZipStream(zipOutStream);
    } finally {
      zipOutStream.closeEntry();
    }

    zipOutStream.close();
  }

}
