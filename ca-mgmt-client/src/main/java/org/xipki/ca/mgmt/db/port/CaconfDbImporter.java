/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaconfDbImporter extends DbPorter {

  CaconfDbImporter(DataSourceWrapper datasource, String srcDir, AtomicBoolean stopMe)
      throws DataAccessException {
    super(datasource, srcDir, stopMe);
  }

  public void importToDb() throws Exception {
    CaCertstore.Caconf caconf;
    try (InputStream is = Files.newInputStream(Paths.get(baseDir, FILENAME_CA_CONFIGURATION))) {
      caconf = JSON.parseObject(is, CaCertstore.Caconf.class);
    }
    caconf.validate();

    if (caconf.getVersion() > VERSION) {
      throw new Exception("could not import CA configuration greater than "
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

  private void importSigner(List<CaCertstore.Signer> signers)
      throws DataAccessException, IOException {
    System.out.println("importing table SIGNER");
    if (signers == null) {
      System.out.println(" imported table SIGNER: nothing to import");
      return;
    }
    final String sql = "INSERT INTO SIGNER (NAME,TYPE,CERT,CONF) VALUES (?,?,?,?)";

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaCertstore.Signer signer : signers) {
        String b64Cert = (signer.getCert() == null) ? null
            : Base64.encodeToString(readContent(signer.getCert()));
        try {
          int idx = 1;
          ps.setString(idx++, signer.getName());
          ps.setString(idx++, signer.getType());
          ps.setString(idx++, b64Cert);
          ps.setString(idx++, readContent(signer.getConf()));

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

  private void importRequestor(List<CaCertstore.IdNameTypeConf> requestors)
      throws DataAccessException, IOException {
    System.out.println("importing table REQUESTOR");
    final String sql = "INSERT INTO REQUESTOR (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaCertstore.IdNameTypeConf requestor : requestors) {
        try {
          ps.setInt(1, requestor.getId());
          ps.setString(2, requestor.getName());
          ps.setString(3, requestor.getType());
          ps.setString(4, readContent(requestor.getConf()));

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

  private void importUser(List<CaCertstore.User> users) throws DataAccessException, IOException {
    System.out.println("importing table TUSER");
    final String sql = "INSERT INTO TUSER (ID,NAME,ACTIVE,PASSWORD) VALUES (?,?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaCertstore.User user : users) {
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

  private void importPublisher(List<CaCertstore.IdNameTypeConf> publishers)
      throws DataAccessException, IOException {
    System.out.println("importing table PUBLISHER");
    final String sql = "INSERT INTO PUBLISHER (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      for (CaCertstore.IdNameTypeConf publisher : publishers) {
        try {
          int idx = 1;
          ps.setInt(idx++, publisher.getId());
          ps.setString(idx++, publisher.getName());
          ps.setString(idx++, publisher.getType());
          ps.setString(idx++, readContent(publisher.getConf()));

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

  private void importProfile(List<CaCertstore.IdNameTypeConf> profiles)
      throws DataAccessException, IOException {
    System.out.println("importing table PROFILE");
    final String sql = "INSERT INTO PROFILE (ID,NAME,TYPE,CONF) VALUES (?,?,?,?)";
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      for (CaCertstore.IdNameTypeConf certprofile : profiles) {
        try {
          int idx = 1;
          ps.setInt(idx++, certprofile.getId());
          ps.setString(idx++, certprofile.getName());
          ps.setString(idx++, certprofile.getType());
          ps.setString(idx++, readContent(certprofile.getConf()));

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

  private void importCa(List<CaCertstore.Ca> cas)
      throws DataAccessException, CertificateException, IOException {
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

      for (CaCertstore.Ca ca : cas) {
        try {
          byte[] certBytes = readContent(ca.getCert());
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
          ps.setString(idx++, readContent(ca.getSignerConf()));

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

  private void importCaalias(List<CaCertstore.Caalias> caaliases) throws DataAccessException {
    System.out.println("importing table CAALIAS");
    final String sql = "INSERT INTO CAALIAS (NAME,CA_ID) VALUES (?,?)";
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaCertstore.Caalias caalias : caaliases) {
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

  private void importCaHasRequestor(List<CaCertstore.CaHasRequestor> caHasRequestors)
      throws DataAccessException {
    System.out.println("importing table CA_HAS_REQUESTOR");
    final String sql = "INSERT INTO CA_HAS_REQUESTOR (CA_ID,REQUESTOR_ID,RA,PERMISSION,PROFILES)"
        + " VALUES (?,?,?,?,?)";
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaCertstore.CaHasRequestor entry : caHasRequestors) {
        try {
          int idx = 1;
          ps.setInt(idx++, entry.getCaId());
          ps.setInt(idx++, entry.getRequestorId());
          ps.setInt(idx++, entry.getRa());
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

  private void importCaHasUser(List<CaCertstore.CaHasUser> caHasUsers) throws DataAccessException {
    System.out.println("importing table CA_HAS_USER");
    final String sql = "INSERT INTO CA_HAS_USER (ID,CA_ID,USER_ID,PERMISSION,PROFILES)"
        + " VALUES (?,?,?,?,?)";
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaCertstore.CaHasUser entry : caHasUsers) {
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

  private void importCaHasPublisher(List<CaCertstore.CaHasPublisher> caHasPublishers)
      throws Exception {
    System.out.println("importing table CA_HAS_PUBLISHER");
    final String sql = "INSERT INTO CA_HAS_PUBLISHER (CA_ID,PUBLISHER_ID) VALUES (?,?)";
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaCertstore.CaHasPublisher entry : caHasPublishers) {
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

  private void importCaHasCertprofile(List<CaCertstore.CaHasProfile> caHasCertprofiles)
      throws DataAccessException {
    System.out.println("importing table CA_HAS_PROFILE");
    final String sql = "INSERT INTO CA_HAS_PROFILE (CA_ID,PROFILE_ID) VALUES (?,?)";
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaCertstore.CaHasProfile entry : caHasCertprofiles) {
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
