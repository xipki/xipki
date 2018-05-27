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
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.xipki.ca.dbtool.jaxb.ca.CaHasProfileType;
import org.xipki.ca.dbtool.jaxb.ca.CaHasPublisherType;
import org.xipki.ca.dbtool.jaxb.ca.CaHasRequestorType;
import org.xipki.ca.dbtool.jaxb.ca.CaHasUserType;
import org.xipki.ca.dbtool.jaxb.ca.CaType;
import org.xipki.ca.dbtool.jaxb.ca.CaaliasType;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.CaHasProfiles;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.CaHasPublishers;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.CaHasRequestors;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.CaHasUsers;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.Caaliases;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.Cas;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.Profiles;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.Publishers;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.Requestors;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.Signers;
import org.xipki.ca.dbtool.jaxb.ca.CaconfType.Users;
import org.xipki.ca.dbtool.jaxb.ca.ObjectFactory;
import org.xipki.ca.dbtool.jaxb.ca.ProfileType;
import org.xipki.ca.dbtool.jaxb.ca.PublisherType;
import org.xipki.ca.dbtool.jaxb.ca.RequestorType;
import org.xipki.ca.dbtool.jaxb.ca.SignerType;
import org.xipki.ca.dbtool.jaxb.ca.UserType;
import org.xipki.ca.dbtool.port.DbPorter;
import org.xipki.common.util.Base64;
import org.xipki.common.util.XmlUtil;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.dbtool.InvalidInputException;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaconfDbImporter extends DbPorter {

  private final Unmarshaller unmarshaller;

  CaconfDbImporter(DataSourceWrapper datasource, String srcDir, AtomicBoolean stopMe)
      throws DataAccessException, JAXBException {
    super(datasource, srcDir, stopMe);

    JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
    unmarshaller = jaxbContext.createUnmarshaller();
    unmarshaller.setSchema(DbPorter.retrieveSchema("/xsd/dbi-ca.xsd"));
  }

  public void importToDb() throws Exception {
    CaconfType caconf;
    try {
      @SuppressWarnings("unchecked")
      JAXBElement<CaconfType> root = (JAXBElement<CaconfType>)
          unmarshaller.unmarshal(new File(baseDir, FILENAME_CA_CONFIGURATION));
      caconf = root.getValue();
    } catch (JAXBException ex) {
      throw XmlUtil.convert(ex);
    }

    if (caconf.getVersion() > VERSION) {
      throw new InvalidInputException("could not import CA configuration greater than "
          + VERSION + ": " + caconf.getVersion());
    }

    System.out.println("importing CA configuration to database");
    try {
      importSigner(caconf.getSigners());
      importRequestor(caconf.getRequestors());
      importUser(caconf.getUsers());
      importPublisher(caconf.getPublishers());
      importProfile(caconf.getProfiles());
      importCa(caconf.getCas());
      importCaalias(caconf.getCaaliases());
      importCaHasRequestor(caconf.getCaHasRequestors());
      importCaHasUser(caconf.getCaHasUsers());
      importCaHasPublisher(caconf.getCaHasPublishers());
      importCaHasCertprofile(caconf.getCaHasProfiles());
    } catch (Exception ex) {
      System.err.println("could not import CA configuration to database. message: "
          + ex.getMessage());
      throw ex;
    }
    System.out.println(" imported CA configuration to database");
  } // method importToDb

  private void importSigner(Signers signers) throws DataAccessException, IOException {
    System.out.println("importing table SIGNER");
    if (signers == null) {
      System.out.println(" imported table SIGNER: nothing to import");
      return;
    }
    final String sql = "INSERT INTO SIGNER (NAME,TYPE,CERT,CONF) VALUES (?,?,?,?)";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (SignerType signer : signers.getSigner()) {
        byte[] certBytes = binary(signer.getCert());
        String b64Cert = (certBytes == null) ? null : Base64.encodeToString(certBytes);
        try {
          int idx = 1;
          ps.setString(idx++, signer.getName());
          ps.setString(idx++, signer.getType());
          ps.setString(idx++, b64Cert);
          ps.setString(idx++, value(signer.getConf()));

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import SIGNER with NAME=" + signer.getName());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }

    System.out.println(" imported table SIGNER");
  } // method importSigner

  private void importRequestor(Requestors requestors) throws DataAccessException, IOException {
    System.out.println("importing table REQUESTOR");
    final String sql = "INSERT INTO REQUESTOR (ID,NAME,CERT) VALUES (?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (RequestorType requestor : requestors.getRequestor()) {
        byte[] certBytes = binary(requestor.getCert());
        String b64Cert = (certBytes == null) ? null : Base64.encodeToString(certBytes);
        try {
          ps.setInt(1, requestor.getId());
          ps.setString(2, requestor.getName());
          ps.setString(3, b64Cert);

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import REQUESTOR with NAME=" + requestor.getName());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }
    System.out.println(" imported table REQUESTOR");
  } // method importRequestor

  private void importUser(Users users) throws DataAccessException, IOException {
    System.out.println("importing table TUSER");
    final String sql = "INSERT INTO TUSER (ID,NAME,ACTIVE,PASSWORD) VALUES (?,?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (UserType user : users.getUser()) {
        try {
          ps.setInt(1, user.getId());
          ps.setString(2, user.getName());
          ps.setInt(3, user.getActive());
          ps.setString(4, user.getPassword());

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import TUSER with NAME=" + user.getName());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }
    System.out.println(" imported table TUSER");
  } // method importUser

  private void importPublisher(Publishers publishers) throws DataAccessException, IOException {
    System.out.println("importing table PUBLISHER");
    final String sql = "INSERT INTO PUBLISHER (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      for (PublisherType publisher : publishers.getPublisher()) {
        try {
          int idx = 1;
          ps.setInt(idx++, publisher.getId());
          ps.setString(idx++, publisher.getName());
          ps.setString(idx++, publisher.getType());
          ps.setString(idx++, value(publisher.getConf()));

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import PUBLISHER with NAME=" + publisher.getName());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }
    System.out.println(" imported table PUBLISHER");
  } // method importPublisher

  private void importProfile(Profiles profiles) throws DataAccessException, IOException {
    System.out.println("importing table PROFILE");
    final String sql = "INSERT INTO PROFILE (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      for (ProfileType certprofile : profiles.getProfile()) {
        try {
          int idx = 1;
          ps.setInt(idx++, certprofile.getId());
          ps.setString(idx++, certprofile.getName());
          ps.setString(idx++, certprofile.getType());

          String conf = value(certprofile.getConf());
          ps.setString(idx++, conf);

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import PROFILE with NAME=" + certprofile.getName());
          throw translate(sql, ex);
        } catch (IOException ex) {
          System.err.println("could not import PROFILE with NAME=" + certprofile.getName());
          throw ex;
        }
      }
    } finally {
      releaseResources(ps, null);
    }
    System.out.println(" imported table PROFILE");
  } // method importProfile

  private void importCa(Cas cas) throws DataAccessException, CertificateException, IOException {
    System.out.println("importing table CA");
    String sql = "INSERT INTO CA (ID,NAME,SUBJECT,SN_SIZE,NEXT_CRLNO,STATUS,CA_URIS,MAX_VALIDITY,"
        + "CERT,SIGNER_TYPE,CRL_SIGNER_NAME,CMP_RESPONDER_NAME,SCEP_RESPONDER_NAME,"
        + "CRL_CONTROL,CMP_CONTROL,SCEP_CONTROL,"
        + "DUPLICATE_KEY,DUPLICATE_SUBJECT,PROTOCOL_SUPPORT,SAVE_REQ,PERMISSION,NUM_CRLS,"
        + "EXPIRATION_PERIOD,KEEP_EXPIRED_CERT_DAYS,REV_INFO,VALIDITY_MODE,EXTRA_CONTROL,"
        + "SIGNER_CONF) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaType ca : cas.getCa()) {
        try {
          byte[] certBytes = binary(ca.getCert());
          X509Certificate cert = X509Util.parseCert(certBytes);

          int idx = 1;
          ps.setInt(idx++, ca.getId());
          ps.setString(idx++, ca.getName().toLowerCase());
          ps.setString(idx++, X509Util.cutX500Name(cert.getSubjectX500Principal(), maxX500nameLen));
          ps.setInt(idx++, ca.getSnSize());
          ps.setLong(idx++, ca.getNextCrlNo());
          ps.setString(idx++, ca.getStatus());
          ps.setString(idx++, ca.getCaUris());
          ps.setString(idx++, ca.getMaxValidity());
          ps.setString(idx++, Base64.encodeToString(certBytes));
          ps.setString(idx++, ca.getSignerType());
          ps.setString(idx++, ca.getCrlSignerName());
          ps.setString(idx++, ca.getCmpResponderName());
          ps.setString(idx++, ca.getScepResponderName());
          ps.setString(idx++, ca.getCrlControl());
          ps.setString(idx++, ca.getCmpControl());
          ps.setString(idx++, ca.getScepControl());
          ps.setInt(idx++, ca.getDuplicateKey());
          ps.setInt(idx++, ca.getDuplicateSubject());
          ps.setString(idx++, ca.getProtocolSupport());
          ps.setInt(idx++, ca.getSaveReq());
          ps.setInt(idx++, ca.getPermission());
          Integer numCrls = ca.getNumCrls();
          int tmpNumCrls = (numCrls == null) ? 30 : numCrls.intValue();
          ps.setInt(idx++, tmpNumCrls);
          ps.setInt(idx++, ca.getExpirationPeriod());
          ps.setInt(idx++, ca.getKeepExpiredCertDays());
          ps.setString(idx++, ca.getRevInfo());
          ps.setString(idx++, ca.getValidityMode());
          ps.setString(idx++, ca.getExtraControl());
          ps.setString(idx++, value(ca.getSignerConf()));

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import CA with NAME=" + ca.getName());
          throw translate(sql, ex);
        } catch (CertificateException | IOException ex) {
          System.err.println("could not import CA with NAME=" + ca.getName());
          throw ex;
        }
      }
    } finally {
      releaseResources(ps, null);
    }

    System.out.println(" imported table CA");
  } // method importCa

  private void importCaalias(Caaliases caaliases) throws DataAccessException {
    System.out.println("importing table CAALIAS");
    final String sql = "INSERT INTO CAALIAS (NAME,CA_ID) VALUES (?,?)";
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaaliasType caalias : caaliases.getCaalias()) {
        try {
          ps.setString(1, caalias.getName());
          ps.setInt(2, caalias.getCaId());

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import CAALIAS with NAME=" + caalias.getName());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }
    System.out.println(" imported table CAALIAS");
  } // method importCaalias

  private void importCaHasRequestor(CaHasRequestors caHasRequestors) throws DataAccessException {
    System.out.println("importing table CA_HAS_REQUESTOR");
    final String sql = "INSERT INTO CA_HAS_REQUESTOR (CA_ID,REQUESTOR_ID,RA,PERMISSION,PROFILES)"
        + " VALUES (?,?,?,?,?)";
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaHasRequestorType entry : caHasRequestors.getCaHasRequestor()) {
        try {
          int idx = 1;
          ps.setInt(idx++, entry.getCaId());
          ps.setInt(idx++, entry.getRequestorId());
          setBoolean(ps, idx++, entry.isRa());
          ps.setInt(idx++, entry.getPermission());
          ps.setString(idx++, entry.getProfiles());

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import CA_HAS_REQUESTOR with CA_ID="
              + entry.getCaId() + " and REQUESTOR_ID=" + entry.getRequestorId());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }
    System.out.println(" imported table CA_HAS_REQUESTOR");
  } // method importCaHasRequestor

  private void importCaHasUser(CaHasUsers caHasUsers) throws DataAccessException {
    System.out.println("importing table CA_HAS_USER");
    final String sql = "INSERT INTO CA_HAS_USER (ID,CA_ID,USER_ID,PERMISSION,PROFILES)"
        + " VALUES (?,?,?,?,?)";
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaHasUserType entry : caHasUsers.getCaHasUser()) {
        try {
          int idx = 1;
          ps.setInt(idx++, entry.getId());
          ps.setInt(idx++, entry.getCaId());
          ps.setInt(idx++, entry.getUserId());
          ps.setInt(idx++, entry.getPermission());
          ps.setString(idx++, entry.getProfiles());

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import CA_HAS_USER with CA_ID="
              + entry.getCaId() + " and USER_ID=" + entry.getUserId());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }
    System.out.println(" imported table CA_HAS_USER");
  } // method importCaHasRequestor

  private void importCaHasPublisher(CaHasPublishers caHasPublishers) throws Exception {
    System.out.println("importing table CA_HAS_PUBLISHER");
    final String sql = "INSERT INTO CA_HAS_PUBLISHER (CA_ID,PUBLISHER_ID) VALUES (?,?)";
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaHasPublisherType entry : caHasPublishers.getCaHasPublisher()) {
        try {
          ps.setInt(1, entry.getCaId());
          ps.setInt(2, entry.getPublisherId());

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import CA_HAS_PUBLISHER with CA_ID="
              + entry.getCaId() + " and PUBLISHER_ID=" + entry.getPublisherId());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }
    System.out.println(" imported table CA_HAS_PUBLISHER");
  } // method importCaHasPublisher

  private void importCaHasCertprofile(CaHasProfiles caHasCertprofiles)
      throws DataAccessException {
    System.out.println("importing table CA_HAS_PROFILE");
    final String sql = "INSERT INTO CA_HAS_PROFILE (CA_ID,PROFILE_ID) VALUES (?,?)";
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaHasProfileType entry : caHasCertprofiles.getCaHasProfile()) {
        try {
          ps.setInt(1, entry.getCaId());
          ps.setInt(2, entry.getProfileId());

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import CA_HAS_PROFILE with CA_ID="
              + entry.getCaId() + " and PROFILE_ID=" + entry.getProfileId());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }
    System.out.println(" imported table CA_HAS_PROFILE");
  } // method importCaHasCertprofile

}
