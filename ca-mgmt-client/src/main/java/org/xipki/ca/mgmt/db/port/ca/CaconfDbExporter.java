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

package org.xipki.ca.mgmt.db.port.ca;

import java.io.File;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.xipki.ca.mgmt.db.jaxb.ca.CaHasProfileType;
import org.xipki.ca.mgmt.db.jaxb.ca.CaHasPublisherType;
import org.xipki.ca.mgmt.db.jaxb.ca.CaHasRequestorType;
import org.xipki.ca.mgmt.db.jaxb.ca.CaHasUserType;
import org.xipki.ca.mgmt.db.jaxb.ca.CaType;
import org.xipki.ca.mgmt.db.jaxb.ca.CaaliasType;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.CaHasProfiles;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.CaHasPublishers;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.CaHasRequestors;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.CaHasUsers;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.Caaliases;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.Cas;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.Profiles;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.Publishers;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.Requestors;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.Signers;
import org.xipki.ca.mgmt.db.jaxb.ca.CaconfType.Users;
import org.xipki.ca.mgmt.db.jaxb.ca.ObjectFactory;
import org.xipki.ca.mgmt.db.jaxb.ca.ProfileType;
import org.xipki.ca.mgmt.db.jaxb.ca.PublisherType;
import org.xipki.ca.mgmt.db.jaxb.ca.RequestorType;
import org.xipki.ca.mgmt.db.jaxb.ca.SignerType;
import org.xipki.ca.mgmt.db.jaxb.ca.UserType;
import org.xipki.ca.mgmt.db.port.DbPorter;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.XmlUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaconfDbExporter extends DbPorter {

  private Marshaller marshaller;

  CaconfDbExporter(DataSourceWrapper datasource, String destDir, AtomicBoolean stopMe)
      throws DataAccessException, JAXBException {
    super(datasource, destDir, stopMe);

    JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
    marshaller = jaxbContext.createMarshaller();
    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
    marshaller.setSchema(DbPorter.retrieveSchema("/xsd/dbi-ca.xsd"));
  }

  public void export() throws Exception {
    CaconfType caconf = new CaconfType();
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

    JAXBElement<CaconfType> root = new ObjectFactory().createCaconf(caconf);
    try {
      marshaller.marshal(root, new File(baseDir, FILENAME_CA_CONFIGURATION));
    } catch (JAXBException ex) {
      throw XmlUtil.convert(ex);
    }

    System.out.println(" exported CA configuration from database");
  }

  private void exportCaalias(CaconfType caconf) throws DataAccessException {
    System.out.println("exporting table CAALIAS");
    Caaliases caaliases = new Caaliases();
    final String sql = "SELECT NAME,CA_ID FROM CAALIAS";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaaliasType caalias = new CaaliasType();
        caalias.setName(rs.getString("NAME"));
        caalias.setCaId(rs.getInt("CA_ID"));

        caaliases.getCaalias().add(caalias);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCaaliases(caaliases);
    System.out.println(" exported table CAALIAS");
  } // method exportCaalias

  private void exportRequestor(CaconfType caconf) throws DataAccessException, IOException {
    System.out.println("exporting table REQUESTOR");
    Requestors requestors = new Requestors();
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM REQUESTOR";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        RequestorType requestor = new RequestorType();
        requestor.setId(rs.getInt("ID"));
        requestor.setName(name);
        requestor.setType(rs.getString("TYPE"));
        requestor.setConf(buildFileOrValue(
            rs.getString("CONF"), "ca-conf/cert-requestor-" + name + ".conf"));
        requestors.getRequestor().add(requestor);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setRequestors(requestors);
    System.out.println(" exported table REQUESTOR");
  } // method exportRequestor

  private void exportUser(CaconfType caconf) throws DataAccessException, IOException {
    System.out.println("exporting table TUSER");
    Users users = new Users();
    final String sql = "SELECT ID,NAME,ACTIVE,PASSWORD FROM TUSER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        UserType user = new UserType();
        user.setId(rs.getInt("ID"));
        user.setName(rs.getString("NAME"));
        user.setActive(rs.getInt("ACTIVE"));
        user.setPassword(rs.getString("PASSWORD"));
        users.getUser().add(user);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setUsers(users);
    System.out.println(" exported table TUSER");
  } // method exportUser

  private void exportSigner(CaconfType caconf) throws DataAccessException, IOException {
    System.out.println("exporting table SIGNER");
    Signers signers = new Signers();
    final String sql = "SELECT NAME,TYPE,CONF,CERT FROM SIGNER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        SignerType signer = new SignerType();
        signer.setName(name);
        signer.setType(rs.getString("TYPE"));
        signer.setConf(buildFileOrValue(rs.getString("CONF"), "ca-conf/conf-signer-" + name));
        signer.setCert(buildFileOrBase64Binary(
            rs.getString("CERT"), "ca-conf/cert-signer-" + name + ".der"));
        signers.getSigner().add(signer);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setSigners(signers);
    System.out.println(" exported table SIGNER");
  } // method exportSigner

  private void exportPublisher(CaconfType caconf) throws DataAccessException, IOException {
    System.out.println("exporting table PUBLISHER");
    Publishers publishers = new Publishers();
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM PUBLISHER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        PublisherType publisher = new PublisherType();
        publisher.setId(rs.getInt("ID"));
        publisher.setName(name);
        publisher.setType(rs.getString("TYPE"));
        publisher.setConf(buildFileOrValue(rs.getString("CONF"), "ca-conf/conf-publisher-" + name));

        publishers.getPublisher().add(publisher);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setPublishers(publishers);
    System.out.println(" exported table PUBLISHER");
  } // method exportPublisher

  private void exportProfile(CaconfType caconf) throws DataAccessException, IOException {
    System.out.println("exporting table PROFILE");
    Profiles profiles = new Profiles();
    final String sql = "SELECT ID,NAME,TYPE,CONF FROM PROFILE";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        String name = rs.getString("NAME");

        ProfileType profile = new ProfileType();
        profile.setId(rs.getInt("ID"));
        profile.setName(name);
        profile.setType(rs.getString("TYPE"));
        profile.setConf(buildFileOrValue(rs.getString("CONF"), "ca-conf/certprofile-" + name));

        profiles.getProfile().add(profile);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setProfiles(profiles);
    System.out.println(" exported table PROFILE");
  } // method exportProfile

  private void exportCa(CaconfType caconf) throws DataAccessException, IOException {
    System.out.println("exporting table CA");
    Cas cas = new Cas();
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

        CaType ca = new CaType();
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

        cas.getCa().add(ca);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCas(cas);
    System.out.println(" exported table CA");
  } // method exportCa

  private void exportCaHasRequestor(CaconfType caconf) throws DataAccessException {
    System.out.println("exporting table CA_HAS_REQUESTOR");
    CaHasRequestors caHasRequestors = new CaHasRequestors();
    final String sql = "SELECT CA_ID,REQUESTOR_ID,RA,PERMISSION,PROFILES FROM CA_HAS_REQUESTOR";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaHasRequestorType caHasRequestor = new CaHasRequestorType();
        caHasRequestor.setCaId(rs.getInt("CA_ID"));
        caHasRequestor.setRequestorId(rs.getInt("REQUESTOR_ID"));
        caHasRequestor.setRa(rs.getBoolean("RA"));
        caHasRequestor.setPermission(rs.getInt("PERMISSION"));
        caHasRequestor.setProfiles(rs.getString("PROFILES"));

        caHasRequestors.getCaHasRequestor().add(caHasRequestor);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCaHasRequestors(caHasRequestors);
    System.out.println(" exported table CA_HAS_REQUESTOR");
  } // method exportCaHasRequestor

  private void exportCaHasUser(CaconfType caconf) throws DataAccessException {
    System.out.println("exporting table CA_HAS_USER");
    CaHasUsers caHasUsers = new CaHasUsers();
    final String sql = "SELECT ID,CA_ID,USER_ID,PERMISSION,PROFILES FROM CA_HAS_USER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaHasUserType caHasUser = new CaHasUserType();
        caHasUser.setId(rs.getInt("ID"));
        caHasUser.setCaId(rs.getInt("CA_ID"));
        caHasUser.setUserId(rs.getInt("USER_ID"));
        caHasUser.setPermission(rs.getInt("PERMISSION"));
        caHasUser.setProfiles(rs.getString("PROFILES"));

        caHasUsers.getCaHasUser().add(caHasUser);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCaHasUsers(caHasUsers);
    System.out.println(" exported table CA_HAS_USER");
  } // method exportCaHasRequestor

  private void exportCaHasPublisher(CaconfType caconf) throws DataAccessException {
    System.out.println("exporting table CA_HAS_PUBLISHER");
    CaHasPublishers caHasPublishers = new CaHasPublishers();
    final String sql = "SELECT CA_ID,PUBLISHER_ID FROM CA_HAS_PUBLISHER";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaHasPublisherType caHasPublisher = new CaHasPublisherType();
        caHasPublisher.setCaId(rs.getInt("CA_ID"));
        caHasPublisher.setPublisherId(rs.getInt("PUBLISHER_ID"));

        caHasPublishers.getCaHasPublisher().add(caHasPublisher);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    caconf.setCaHasPublishers(caHasPublishers);
    System.out.println(" exported table CA_HAS_PUBLISHER");
  } // method exportCaHasPublisher

  private void exportCaHasProfile(CaconfType caconf) throws DataAccessException {
    System.out.println("exporting table CA_HAS_PROFILE");
    CaHasProfiles caHasProfiles = new CaHasProfiles();
    final String sql = "SELECT CA_ID,PROFILE_ID FROM CA_HAS_PROFILE";

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        CaHasProfileType caHasProfile = new CaHasProfileType();
        caHasProfile.setCaId(rs.getInt("CA_ID"));
        caHasProfile.setProfileId(rs.getInt("PROFILE_ID"));

        caHasProfiles.getCaHasProfile().add(caHasProfile);
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
