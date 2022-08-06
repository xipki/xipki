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

import com.alibaba.fastjson.JSON;
import org.xipki.ca.mgmt.db.DbSchemaInfo;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.xipki.util.SqlUtil.buildInsertSql;

/**
 * Database importer of CA configuration.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaconfDbImporter extends DbPorter {

  CaconfDbImporter(DataSourceWrapper datasource, String srcDir, AtomicBoolean stopMe)
      throws DataAccessException {
    super(datasource, srcDir, stopMe);
  }

  public void importToDb()
      throws Exception {
    CaCertstore.Caconf caconf;
    try (InputStream is = Files.newInputStream(Paths.get(baseDir, FILENAME_CA_CONFIGURATION))) {
      caconf = JSON.parseObject(is, CaCertstore.Caconf.class);
    }
    caconf.validate();

    if (caconf.getVersion() > VERSION_V2) {
      throw new Exception("could not import CA configuration greater than "
          + VERSION_V2 + ": " + caconf.getVersion());
    }

    System.out.println("importing CA configuration to database");
    try {
      importDbSchema(caconf.getDbSchemas());
      importSigner(caconf.getSigners());
      importRequestor(caconf.getRequestors());
      importPublisher(caconf.getPublishers());
      importProfile(caconf.getProfiles());
      importCa(caconf.getCas(), caconf.getVersion());
      importCaalias(caconf.getCaaliases());
      importCaHasRequestor(caconf.getCaHasRequestors());
      importCaHasPublisher(caconf.getCaHasPublishers());
      importCaHasCertprofile(caconf.getCaHasProfiles());
      importKeypairGen(caconf.getKeypairGens());
    } catch (Exception ex) {
      System.err.println("could not import CA configuration to database. message: "
          + ex.getMessage());
      throw ex;
    }
    System.out.println(" imported CA configuration to database");
  } // method importToDb

  private void importDbSchema(List<CaCertstore.DbSchemaEntry> entries)
          throws DataAccessException {
    System.out.println("importing table DBSCHEMA");
    if (entries == null) {
      System.out.println(" imported table DBSCHEMA: nothing to import");
      return;
    }

    DbSchemaInfo dbSchemaInfo = new DbSchemaInfo(datasource);
    Set<String> dbSchemaNames = dbSchemaInfo.getVariableNames();

    final String sql = buildInsertSql("DBSCHEMA", "NAME,VALUE2");
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaCertstore.DbSchemaEntry entry : entries) {
        String name = entry.getName();
        if (dbSchemaNames.contains(name)) {
          // do not import existing entry (with the same name)
          continue;
        }

        try {
          ps.setString(1, name);
          ps.setString(2, entry.getValue());

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import DBSCHEMA with NAME=" + name);
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }
    System.out.println(" imported table DBSCHEMA");
  } // method importDbSchema

  private void importSigner(List<CaCertstore.Signer> signers)
      throws DataAccessException, IOException {
    System.out.println("importing table SIGNER");
    if (signers == null) {
      System.out.println(" imported table SIGNER: nothing to import");
      return;
    }
    final String sql = buildInsertSql("SIGNER", "NAME,TYPE,CERT,CONF");

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
          ps.setString(idx, readContent(signer.getConf()));

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
    final String sql = buildInsertSql("REQUESTOR", "ID,NAME,TYPE,CONF");
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

  private void importPublisher(List<CaCertstore.IdNameTypeConf> publishers)
      throws DataAccessException, IOException {
    System.out.println("importing table PUBLISHER");
    final String sql = buildInsertSql("PUBLISHER", "ID,NAME,TYPE,CONF");
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      for (CaCertstore.IdNameTypeConf publisher : publishers) {
        try {
          int idx = 1;
          ps.setInt(idx++, publisher.getId());
          ps.setString(idx++, publisher.getName());
          ps.setString(idx++, publisher.getType());
          ps.setString(idx, readContent(publisher.getConf()));

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
    final String sql = buildInsertSql("PROFILE", "ID,NAME,TYPE,CONF");
    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);
      for (CaCertstore.IdNameTypeConf certprofile : profiles) {
        try {
          int idx = 1;
          ps.setInt(idx++, certprofile.getId());
          ps.setString(idx++, certprofile.getName());
          ps.setString(idx++, certprofile.getType());
          ps.setString(idx, readContent(certprofile.getConf()));

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

  private void importKeypairGen(List<CaCertstore.NameTypeConf> keypairGens)
          throws DataAccessException, IOException {
    System.out.println("importing table KEYPAIR_GEN");
    if (keypairGens == null) {
      System.out.println(" imported table KEYPAIR_GEN: nothing to import");
      return;
    }
    final String deleteSql = "DELETE FROM KEYPAIR_GEN WHERE NAME=?";
    final String sql = buildInsertSql("KEYPAIR_GEN", "NAME,TYPE,CONF");

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(deleteSql);
      for (CaCertstore.NameTypeConf entry : keypairGens) {
        String name = entry.getName();
        try {
          ps.setString(1, name);
          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not delete KEYPAIR_GEN with NAME=" + name);
          throw translate(deleteSql, ex);
        }
      }
    } finally {
        releaseResources(ps, null);
    }

    ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaCertstore.NameTypeConf entry : keypairGens) {
        String name = entry.getName();
        try {
          ps.setString(1, entry.getName());
          ps.setString(2, entry.getType());
          ps.setString(3, readContent(entry.getConf()));

          ps.executeUpdate();
        } catch (SQLException ex) {
          System.err.println("could not import KEYPAIR_GEN with NAME=" + name);
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }

    System.out.println(" imported table SIGNER");
  } // method importKeypairGen

  private void importCa(List<CaCertstore.Ca> cas, int confVersion)
      throws DataAccessException, CertificateException, IOException {
    System.out.println("importing table CA");

    final String sql = buildInsertSql("CA",
        "ID,NAME,STATUS,NEXT_CRLNO,CRL_SIGNER_NAME," +
        "SUBJECT,REV_INFO,SIGNER_TYPE,SIGNER_CONF,CERT,CERTCHAIN,CONF");

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      for (CaCertstore.Ca ca : cas) {
        try {
          byte[] certBytes = readContent(ca.getCert());
          X509Cert cert = X509Util.parseCert(certBytes);

          int idx = 1;
          ps.setInt(idx++, ca.getId());
          ps.setString(idx++, ca.getName().toLowerCase());
          ps.setString(idx++, ca.getStatus());
          ps.setLong(idx++, ca.getNextCrlNo());
          ps.setString(idx++, ca.getCrlSignerName());
          ps.setString(idx++, X509Util.cutX500Name(cert.getSubject(), maxX500nameLen));
          ps.setString(idx++, ca.getRevInfo());
          ps.setString(idx++, ca.getSignerType());
          ps.setString(idx++, readContent(ca.getSignerConf()));
          ps.setString(idx++, Base64.encodeToString(certBytes));
          ps.setString(idx++, readContent(ca.getCertchain()));

          String confColumn = readContent(ca.getConfColumn());
          ps.setString(idx++, confColumn);

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

  private void importCaalias(List<CaCertstore.Caalias> caaliases)
      throws DataAccessException {
    System.out.println("importing table CAALIAS");
    final String sql = buildInsertSql("CAALIAS", "NAME,CA_ID");
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
    final String sql = buildInsertSql("CA_HAS_REQUESTOR", "CA_ID,REQUESTOR_ID,PERMISSION,PROFILES");
    PreparedStatement ps = prepareStatement(sql);
    try {
      for (CaCertstore.CaHasRequestor entry : caHasRequestors) {
        try {
          int idx = 1;
          ps.setInt(idx++, entry.getCaId());
          ps.setInt(idx++, entry.getRequestorId());
          ps.setInt(idx++, entry.getPermission());
          ps.setString(idx, entry.getProfiles());

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

  private void importCaHasPublisher(List<CaCertstore.CaHasPublisher> caHasPublishers)
      throws Exception {
    System.out.println("importing table CA_HAS_PUBLISHER");
    final String sql = buildInsertSql("CA_HAS_PUBLISHER", "CA_ID,PUBLISHER_ID");
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
    final String sql = buildInsertSql("CA_HAS_PROFILE", "CA_ID,PROFILE_ID");
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
