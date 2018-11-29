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

package org.xipki.ca.mgmt.db.port;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.xipki.ca.mgmt.db.message.Ca;
import org.xipki.ca.mgmt.db.message.CaHasEntry.CaHasProfile;
import org.xipki.ca.mgmt.db.message.CaHasEntry.CaHasPublisher;
import org.xipki.ca.mgmt.db.message.CaHasEntry.CaHasRequestor;
import org.xipki.ca.mgmt.db.message.CaHasEntry.CaHasUser;
import org.xipki.ca.mgmt.db.message.Caalias;
import org.xipki.ca.mgmt.db.message.Caconf;
import org.xipki.ca.mgmt.db.message.IdNameTypeConf;
import org.xipki.ca.mgmt.db.message.Signer;
import org.xipki.ca.mgmt.db.message.User;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.conf.InvalidConfException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaconfDbExporter extends DbPorter {

  CaconfDbExporter(DataSourceWrapper datasource, String destDir, AtomicBoolean stopMe)
      throws DataAccessException {
    super(datasource, destDir, stopMe);
  }

  public void export() throws Exception {
    Caconf caconf = new Caconf();
    caconf.setVersion(VERSION);

    System.out.println("exporting CA configuration from database");

    exportSigner(caconf);
    exportRequestor(caconf);
    exportUser(caconf);
    exportPublisher(caconf);
    exportCa(caconf);
    exportProfile(caconf);
    exportCaalias(caconf);
    exportCaHasRequestor(caconf);
    exportCaHasUser(caconf);
    exportCaHasPublisher(caconf);
    exportCaHasProfile(caconf);

    System.out.println(" exported CA configuration from database");
  }

  private void exportCaalias(Caconf caconf) throws DataAccessException, InvalidConfException {
    System.out.println("exporting table CAALIAS");
    List<Caalias> caaliases = new LinkedList<>();
    final String sql = "SELECT NAME,CA_ID FROM CAALIAS";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        Caalias caalias = new Caalias();
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

  private void exportRequestor(Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table REQUESTOR");
    List<IdNameTypeConf> requestors = new LinkedList<>();
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM REQUESTOR";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        IdNameTypeConf requestor = new IdNameTypeConf();
        requestor.setId(rs.getInt("ID"));
        requestor.setName(name);
        requestor.setType(rs.getString("TYPE"));
        requestor.setConf(buildFileOrValue(
            rs.getString("CONF"), "ca-conf/cert-requestor-" + name + ".conf"));

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

  private void exportUser(Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table TUSER");
    List<User> users = new LinkedList<>();
    final String sql = "SELECT ID,NAME,ACTIVE,PASSWORD FROM TUSER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        User user = new User();
        user.setId(rs.getInt("ID"));
        user.setName(rs.getString("NAME"));
        user.setActive(rs.getInt("ACTIVE"));
        user.setPassword(rs.getString("PASSWORD"));

        user.validate();
        users.add(user);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setUsers(users);
    System.out.println(" exported table TUSER");
  } // method exportUser

  private void exportSigner(Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table SIGNER");
    List<Signer> signers = new LinkedList<>();
    final String sql = "SELECT NAME,TYPE,CONF,CERT FROM SIGNER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        Signer signer = new Signer();
        signer.setName(name);
        signer.setType(rs.getString("TYPE"));
        signer.setConf(buildFileOrValue(rs.getString("CONF"), "ca-conf/conf-signer-" + name));
        signer.setCert(buildFileOrBase64Binary(
            rs.getString("CERT"), "ca-conf/cert-signer-" + name + ".der"));

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

  private void exportPublisher(Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table PUBLISHER");
    List<IdNameTypeConf> publishers = new LinkedList<>();
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM PUBLISHER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        IdNameTypeConf publisher = new IdNameTypeConf();
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

  private void exportProfile(Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table PROFILE");
    List<IdNameTypeConf> profiles = new LinkedList<>();
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM PROFILE";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        IdNameTypeConf profile = new IdNameTypeConf();
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

  private void exportCa(Caconf caconf)
      throws DataAccessException, IOException, InvalidConfException {
    System.out.println("exporting table CA");
    List<Ca> cas = new LinkedList<>();
    String sql = "SELECT ID,NAME,SN_SIZE,STATUS,CA_URIS,MAX_VALIDITY,CERT,SIGNER_TYPE,SIGNER_CONF,"
        + "PERMISSION,NUM_CRLS,EXPIRATION_PERIOD,KEEP_EXPIRED_CERT_DAYS,REV_INFO,DUPLICATE_KEY,"
        + "DUPLICATE_SUBJECT,PROTOCOL_SUPPORT,SAVE_REQ,VALIDITY_MODE,NEXT_CRLNO,CMP_RESPONDER_NAME,"
        + "SCEP_RESPONDER_NAME,CRL_SIGNER_NAME,CMP_CONTROL,SCEP_CONTROL,CRL_CONTROL,EXTRA_CONTROL "
        + "FROM CA";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        Ca ca = new Ca();
        ca.setId(rs.getInt("ID"));
        ca.setName(name);
        ca.setSnSize(rs.getInt("SN_SIZE"));
        ca.setNextCrlNo(rs.getLong("NEXT_CRLNO"));
        ca.setStatus(rs.getString("STATUS"));
        ca.setCaUris(rs.getString("CA_URIS"));
        ca.setMaxValidity(rs.getString("MAX_VALIDITY"));
        ca.setCert(buildFileOrBase64Binary(
            rs.getString("CERT"), "ca-conf/cert-ca-" + name + ".der"));
        ca.setSignerType(rs.getString("SIGNER_TYPE"));
        ca.setSignerConf(buildFileOrValue(
            rs.getString("SIGNER_CONF"), "ca-conf/signerconf-ca-" + name));
        ca.setCmpResponderName(rs.getString("CMP_RESPONDER_NAME"));
        ca.setScepResponderName(rs.getString("SCEP_RESPONDER_NAME"));
        ca.setCrlSignerName(rs.getString("CRL_SIGNER_NAME"));
        ca.setCmpControl(rs.getString("CMP_CONTROL"));
        ca.setScepControl(rs.getString("SCEP_CONTROL"));
        ca.setCrlControl(rs.getString("CRL_CONTROL"));
        ca.setDuplicateKey(rs.getInt("DUPLICATE_KEY"));
        ca.setDuplicateSubject(rs.getInt("DUPLICATE_SUBJECT"));
        ca.setProtocolSupport(rs.getString("PROTOCOL_SUPPORT"));
        ca.setSaveReq(rs.getInt("SAVE_REQ"));
        ca.setPermission(rs.getInt("PERMISSION"));
        ca.setExpirationPeriod(rs.getInt("EXPIRATION_PERIOD"));
        ca.setKeepExpiredCertDays(rs.getInt("KEEP_EXPIRED_CERT_DAYS"));
        ca.setValidityMode(rs.getString("VALIDITY_MODE"));
        ca.setExtraControl(rs.getString("EXTRA_CONTROL"));
        ca.setNumCrls(rs.getInt("NUM_CRLS"));
        ca.setRevInfo(rs.getString("REV_INFO"));

        ca.validate();
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

  private void exportCaHasRequestor(Caconf caconf)
      throws DataAccessException, InvalidConfException {
    System.out.println("exporting table CA_HAS_REQUESTOR");
    List<CaHasRequestor> caHasRequestors = new LinkedList<>();
    final String sql = "SELECT CA_ID,REQUESTOR_ID,RA,PERMISSION,PROFILES FROM CA_HAS_REQUESTOR";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaHasRequestor caHasRequestor = new CaHasRequestor();
        caHasRequestor.setCaId(rs.getInt("CA_ID"));
        caHasRequestor.setRequestorId(rs.getInt("REQUESTOR_ID"));
        caHasRequestor.setRa(rs.getInt("RA"));
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

  private void exportCaHasUser(Caconf caconf) throws DataAccessException, InvalidConfException {
    System.out.println("exporting table CA_HAS_USER");
    List<CaHasUser> caHasUsers = new LinkedList<>();
    final String sql = "SELECT ID,CA_ID,USER_ID,PERMISSION,PROFILES FROM CA_HAS_USER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaHasUser caHasUser = new CaHasUser();
        caHasUser.setId(rs.getInt("ID"));
        caHasUser.setCaId(rs.getInt("CA_ID"));
        caHasUser.setUserId(rs.getInt("USER_ID"));
        caHasUser.setPermission(rs.getInt("PERMISSION"));
        caHasUser.setProfiles(rs.getString("PROFILES"));

        caHasUser.validate();
        caHasUsers.add(caHasUser);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCaHasUsers(caHasUsers);
    System.out.println(" exported table CA_HAS_USER");
  } // method exportCaHasRequestor

  private void exportCaHasPublisher(Caconf caconf)
      throws DataAccessException, InvalidConfException {
    System.out.println("exporting table CA_HAS_PUBLISHER");
    List<CaHasPublisher> caHasPublishers = new LinkedList<>();
    final String sql = "SELECT CA_ID,PUBLISHER_ID FROM CA_HAS_PUBLISHER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaHasPublisher caHasPublisher = new CaHasPublisher();
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

  private void exportCaHasProfile(Caconf caconf) throws DataAccessException, InvalidConfException {
    System.out.println("exporting table CA_HAS_PROFILE");
    List<CaHasProfile> caHasProfiles = new LinkedList<>();
    final String sql = "SELECT CA_ID,PROFILE_ID FROM CA_HAS_PROFILE";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaHasProfile caHasProfile = new CaHasProfile();
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
