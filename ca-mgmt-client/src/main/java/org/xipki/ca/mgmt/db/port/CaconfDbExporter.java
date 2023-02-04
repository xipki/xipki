/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.mgmt.db.port;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.mgmt.entry.CaConfColumn;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.util.JSON;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Database exporter of CA configuration.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaconfDbExporter extends DbPorter {

  CaconfDbExporter(DataSourceWrapper datasource, String destDir, AtomicBoolean stopMe)
      throws DataAccessException {
    super(datasource, destDir, stopMe);
  }

  public void export() throws Exception {
    CaCertstore.Caconf caconf = new CaCertstore.Caconf();
    caconf.setVersion(VERSION_V2);

    System.out.println("exporting CA configuration from database");

    exportDbSchema(caconf);
    exportSigner(caconf);
    exportRequestor(caconf);
    exportPublisher(caconf);
    exportCa(caconf);
    exportProfile(caconf);
    exportCaalias(caconf);
    exportCaHasRequestor(caconf);
    exportCaHasPublisher(caconf);
    exportCaHasProfile(caconf);
    if (dbSchemaVersion >= 7) {
      exportKeypairGen(caconf);
    }

    caconf.validate();
    try (OutputStream os = Files.newOutputStream(Paths.get(baseDir, FILENAME_CA_CONFIGURATION))) {
      JSON.writePrettyJSON(caconf, os);
    }
    System.out.println(" exported CA configuration from database");
  } // method export

  private void exportCaalias(CaCertstore.Caconf caconf) throws DataAccessException, InvalidConfException {
    System.out.println("exporting table CAALIAS");
    List<CaCertstore.Caalias> caaliases = new LinkedList<>();
    final String sql = "SELECT NAME,CA_ID FROM CAALIAS";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaCertstore.Caalias caalias = new CaCertstore.Caalias();
        caalias.setName(rs.getString("NAME"));
        caalias.setCaId(rs.getInt("CA_ID"));

        caalias.validate();
        caaliases.add(caalias);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCaaliases(caaliases);
    System.out.println(" exported table CAALIAS");
  } // method exportCaalias

  private void exportRequestor(CaCertstore.Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table REQUESTOR");
    List<CaCertstore.IdNameTypeConf> requestors = new LinkedList<>();
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM REQUESTOR";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        CaCertstore.IdNameTypeConf requestor = new CaCertstore.IdNameTypeConf();
        requestor.setId(rs.getInt("ID"));
        requestor.setName(name);
        requestor.setType(rs.getString("TYPE"));
        requestor.setConf(buildFileOrValue(rs.getString("CONF"), "ca-conf/cert-requestor-" + name + ".conf"));

        requestor.validate();
        requestors.add(requestor);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setRequestors(requestors);
    System.out.println(" exported table REQUESTOR");
  } // method exportRequestor

  private void exportDbSchema(CaCertstore.Caconf caconf) throws DataAccessException, InvalidConfException {
    System.out.println("exporting table DBSCHEMA");
    List<CaCertstore.DbSchemaEntry> entries = new LinkedList<>();
    final String sql = "SELECT NAME,VALUE2 FROM DBSCHEMA";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaCertstore.DbSchemaEntry entry = new CaCertstore.DbSchemaEntry();
        entry.setName(rs.getString("NAME"));
        entry.setValue(rs.getString("VALUE2"));
        entry.validate();
        entries.add(entry);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setDbSchemas(entries);
    System.out.println(" exported table DBSCHEMA");
  } // method exportDbSchema

  private void exportSigner(CaCertstore.Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table SIGNER");
    List<CaCertstore.Signer> signers = new LinkedList<>();
    final String sql = "SELECT NAME,TYPE,CONF,CERT FROM SIGNER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        CaCertstore.Signer signer = new CaCertstore.Signer();
        signer.setName(name);
        signer.setType(rs.getString("TYPE"));
        signer.setConf(buildFileOrValue(rs.getString("CONF"), "ca-conf/conf-signer-" + name));
        signer.setCert(buildFileOrBase64Binary(rs.getString("CERT"), "ca-conf/cert-signer-" + name + ".der"));

        signer.validate();
        signers.add(signer);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setSigners(signers);
    System.out.println(" exported table SIGNER");
  } // method exportSigner

  private void exportKeypairGen(CaCertstore.Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table KEYPAIR_GEN");
    List<CaCertstore.NameTypeConf> keypairGens = new LinkedList<>();
    final String sql = "SELECT NAME,TYPE,CONF FROM KEYPAIR_GEN";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");
        CaCertstore.NameTypeConf entry = new CaCertstore.NameTypeConf();
        entry.setName(name);
        entry.setType(rs.getString("TYPE"));
        entry.setConf(buildFileOrValue(rs.getString("CONF"), "ca-conf/conf-publisher-" + name));

        entry.validate();
        keypairGens.add(entry);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setKeypairGens(keypairGens);
    System.out.println(" exported table KEYPAIR_GEN");
  } // method exportKeypairGen

  private void exportPublisher(CaCertstore.Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table PUBLISHER");
    List<CaCertstore.IdNameTypeConf> publishers = new LinkedList<>();
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM PUBLISHER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        CaCertstore.IdNameTypeConf publisher = new CaCertstore.IdNameTypeConf();
        publisher.setId(rs.getInt("ID"));
        publisher.setName(name);
        publisher.setType(rs.getString("TYPE"));
        publisher.setConf(buildFileOrValue(rs.getString("CONF"), "ca-conf/conf-publisher-" + name));

        publisher.validate();
        publishers.add(publisher);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setPublishers(publishers);
    System.out.println(" exported table PUBLISHER");
  } // method exportPublisher

  private void exportProfile(CaCertstore.Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table PROFILE");
    List<CaCertstore.IdNameTypeConf> profiles = new LinkedList<>();
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM PROFILE";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        CaCertstore.IdNameTypeConf profile = new CaCertstore.IdNameTypeConf();
        profile.setId(rs.getInt("ID"));
        profile.setName(name);
        profile.setType(rs.getString("TYPE"));
        profile.setConf(buildFileOrValue(rs.getString("CONF"), "ca-conf/certprofile-" + name));

        profile.validate();
        profiles.add(profile);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setProfiles(profiles);
    System.out.println(" exported table PROFILE");
  } // method exportProfile

  private void exportCa(CaCertstore.Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table CA");
    List<CaCertstore.Ca> cas = new LinkedList<>();

    //String columns =
    //    "ID,NAME,STATUS,NEXT_CRLNO,CRL_SIGNER_NAME,CMP_RESPONDER_NAME,SCEP_RESPONDER_NAME,"
    //    + "SUBJECT,REV_INFO,SIGNER_TYPE,SIGNER_CONF,CERT,CERTCHAIN,CONF "
    //
    String columns = "SELECT ID,NAME,STATUS,NEXT_CRLNO,CRL_SIGNER_NAME,REV_INFO,SIGNER_TYPE,SIGNER_CONF,CERT,CERTCHAIN";
    if (dbSchemaVersion >= 7) {
      columns += ",CONF";
    } else {
      columns += ",SN_SIZE,CA_URIS,MAX_VALIDITY,PERMISSION,NUM_CRLS,EXPIRATION_PERIOD,"
          + "VALIDITY_MODE,CRL_CONTROL,CTLOG_CONTROL,REVOKE_SUSPENDED_CONTROL,KEEP_EXPIRED_CERT_DAYS,EXTRA_CONTROL";
    }

    final String sql = columns + " FROM CA";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaCertstore.Ca ca = new CaCertstore.Ca();
        ca.setId(rs.getInt("ID"));
        String name = rs.getString("NAME");
        ca.setName(name);
        ca.setNextCrlNo(rs.getLong("NEXT_CRLNO"));
        ca.setStatus(rs.getString("STATUS"));
        ca.setCert(buildFileOrBase64Binary(rs.getString("CERT"), "ca-conf/cert-ca-" + name + ".der"));
        ca.setCertchain(buildFileOrValue(rs.getString("CERTCHAIN"), "ca-conf/certchain-ca-" + name + ".pem"));
        ca.setSignerType(rs.getString("SIGNER_TYPE"));
        ca.setSignerConf(buildFileOrValue(rs.getString("SIGNER_CONF"), "ca-conf/signerconf-ca-" + name));
        ca.setRevInfo(rs.getString("REV_INFO"));
        ca.setCrlSignerName(rs.getString("CRL_SIGNER_NAME"));

        String confColumn;
        if (dbSchemaVersion >= 7) {
          confColumn = rs.getString("CONF");
          CaConfColumn.decode(confColumn); // validate the confColumn
        } else {
          CaConfColumn ccc = new CaConfColumn();
          ccc.setSnSize(rs.getInt("SN_SIZE"));

          String str = rs.getString("CA_URIS");
          if (StringUtil.isNotBlank(str)) {
            CaUris caUris = CaUris.decode(str);
            ccc.setCacertUris(caUris.getCacertUris());
            ccc.setCrlUris(caUris.getCrlUris());
            ccc.setDeltaCrlUris(caUris.getDeltaCrlUris());
            ccc.setOcspUris(caUris.getOcspUris());
          }

          ccc.setMaxValidity(rs.getString("MAX_VALIDITY"));

          str = rs.getString("CRL_CONTROL");
          if (StringUtil.isNotBlank(str)) {
            ccc.setCrlControl(new ConfPairs(str).asMap());
          }

          str = rs.getString("CTLOG_CONTROL");
          if (StringUtil.isNotBlank(str)) {
            ccc.setCtlogControl(new ConfPairs(str).asMap());
          }

          ccc.setPermission(rs.getInt("PERMISSION"));
          ccc.setExpirationPeriod(rs.getInt("EXPIRATION_PERIOD"));
          ccc.setKeepExpiredCertDays(rs.getInt("KEEP_EXPIRED_CERT_DAYS"));
          ccc.setValidityMode(rs.getString("VALIDITY_MODE"));

          str = rs.getString("EXTRA_CONTROL");
          if (StringUtil.isNotBlank(str)) {
            ccc.setExtraControl(new ConfPairs(str).asMap());
          }

          ccc.setNumCrls(rs.getInt("NUM_CRLS"));

          str = rs.getString("REVOKE_SUSPENDED_CONTROL");
          if (StringUtil.isNotBlank(str)) {
            ccc.setRevokeSuspendedControl(new ConfPairs(str).asMap());
          }

          ccc.setKeypairGenNames(Collections.singletonList("software"));
          ccc.setSaveCert(true);
          ccc.setSaveKeypair(false);

          confColumn = ccc.encode();
        }

        ca.validate();
        ca.setConfColumn(buildFileOrValue(confColumn, "ca-conf/" + name + ".conf"));
        cas.add(ca);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCas(cas);
    System.out.println(" exported table CA");
  } // method exportCa

  private void exportCaHasRequestor(CaCertstore.Caconf caconf)
      throws DataAccessException, InvalidConfException {
    System.out.println("exporting table CA_HAS_REQUESTOR");
    List<CaCertstore.CaHasRequestor> caHasRequestors = new LinkedList<>();
    final String sql = "SELECT CA_ID,REQUESTOR_ID,PERMISSION,PROFILES FROM CA_HAS_REQUESTOR";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaCertstore.CaHasRequestor caHasRequestor = new CaCertstore.CaHasRequestor();
        caHasRequestor.setCaId(rs.getInt("CA_ID"));
        caHasRequestor.setRequestorId(rs.getInt("REQUESTOR_ID"));
        caHasRequestor.setPermission(rs.getInt("PERMISSION"));
        caHasRequestor.setProfiles(rs.getString("PROFILES"));

        caHasRequestor.validate();
        caHasRequestors.add(caHasRequestor);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCaHasRequestors(caHasRequestors);
    System.out.println(" exported table CA_HAS_REQUESTOR");
  } // method exportCaHasRequestor

  private void exportCaHasPublisher(CaCertstore.Caconf caconf)
      throws DataAccessException, InvalidConfException {
    System.out.println("exporting table CA_HAS_PUBLISHER");
    List<CaCertstore.CaHasPublisher> caHasPublishers = new LinkedList<>();
    final String sql = "SELECT CA_ID,PUBLISHER_ID FROM CA_HAS_PUBLISHER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaCertstore.CaHasPublisher caHasPublisher = new CaCertstore.CaHasPublisher();
        caHasPublisher.setCaId(rs.getInt("CA_ID"));
        caHasPublisher.setPublisherId(rs.getInt("PUBLISHER_ID"));

        caHasPublisher.validate();
        caHasPublishers.add(caHasPublisher);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCaHasPublishers(caHasPublishers);
    System.out.println(" exported table CA_HAS_PUBLISHER");
  } // method exportCaHasPublisher

  private void exportCaHasProfile(CaCertstore.Caconf caconf)
      throws DataAccessException, InvalidConfException {
    System.out.println("exporting table CA_HAS_PROFILE");
    List<CaCertstore.CaHasProfile> caHasProfiles = new LinkedList<>();
    final String sql = "SELECT CA_ID,PROFILE_ID FROM CA_HAS_PROFILE";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaCertstore.CaHasProfile caHasProfile = new CaCertstore.CaHasProfile();
        caHasProfile.setCaId(rs.getInt("CA_ID"));
        caHasProfile.setProfileId(rs.getInt("PROFILE_ID"));

        caHasProfile.validate();
        caHasProfiles.add(caHasProfile);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCaHasProfiles(caHasProfiles);
    System.out.println(" exported table CA_HAS_PROFILE");
  } // method exportCaHasProfile

}
