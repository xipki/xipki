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

package org.xipki.ca.server.mgmt;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.mgmt.CaConf;
import org.xipki.ca.api.mgmt.CaConfType;
import org.xipki.ca.api.mgmt.CaConfType.NameTypeConf;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.ca.server.PasswordHash;
import org.xipki.ca.server.db.CaManagerQueryExecutor;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.util.Base64;
import org.xipki.util.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.xipki.ca.server.CaUtil.*;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.StringUtil.concat;

/**
 * Load / export CA configuration.
 *
 * @author Lijun Liao
 */

class ConfLoader {

  private static final Logger LOG = LoggerFactory.getLogger(ConfLoader.class);

  CaManagerImpl manager;

  ConfLoader(CaManagerImpl manager) {
    this.manager = notNull(manager, "manager");
  } // constructor

  Map<String, X509Cert> loadConf(InputStream zippedConfStream) throws CaMgmtException {
    manager.assertMasterModeAndSetuped();

    notNull(zippedConfStream, "zippedConfStream");

    SecurityFactory securityFactory = manager.securityFactory;
    CaManagerQueryExecutor queryExecutor = manager.queryExecutor;

    CaConf conf;
    try {
      conf = new CaConf(zippedConfStream, securityFactory);
    } catch (IOException | InvalidConfException ex) {
      throw new CaMgmtException("could not parse the CA configuration", ex);
    } catch (RuntimeException ex) {
      throw new CaMgmtException("caught RuntimeException while parsing the CA configuration", ex);
    }

    Map<String, X509Cert> generatedRootCerts = new HashMap<>(2);

    // Responder
    for (String name : conf.getSignerNames()) {
      SignerEntry entry = conf.getSigner(name);
      SignerEntry entryB = manager.signerDbEntries.get(name);
      if (entryB != null) {
        if (entry.equals(entryB)) {
          LOG.info("ignore existed signer {}", name);
          continue;
        } else {
          throw logAndCreateException(
              concat("signer ", name, " existed, could not re-added it"));
        }
      }

      try {
        manager.addSigner(entry);
        LOG.info("added signer {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add signer ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    final boolean ignoreId = true;
    // Requestor
    for (String name : conf.getRequestorNames()) {
      RequestorEntry entry = conf.getRequestor(name);
      RequestorEntry entryB = manager.getRequestor(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.info("ignore existed CMP requestor {}", name);
          continue;
        } else {
          throw logAndCreateException(
              concat("CMP requestor ", name, " existed, could not re-added it"));
        }
      }

      try {
        manager.addRequestor(entry);
        LOG.info("added CMP requestor {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add CMP requestor ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // Publisher
    for (String name : conf.getPublisherNames()) {
      PublisherEntry entry = conf.getPublisher(name);
      PublisherEntry entryB = manager.getPublisher(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.info("ignore existed publisher {}", name);
          continue;
        } else {
          throw logAndCreateException(
              concat("publisher ", name, " existed, could not re-added it"));
        }
      }

      try {
        manager.addPublisher(entry);
        LOG.info("added publisher {}", name);
      } catch (CaMgmtException ex) {
        String msg = "could not add publisher " + name;
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // Certprofile
    for (String name : conf.getCertprofileNames()) {
      CertprofileEntry entry = conf.getCertprofile(name);
      CertprofileEntry entryB = manager.getCertprofile(name);
      if (entryB != null) {
        if (entry.equals(entryB, ignoreId)) {
          LOG.info("ignore existed certprofile {}", name);
          continue;
        } else {
          throw logAndCreateException(
              concat("certprofile ", name, " existed, could not re-added it"));
        }
      }

      try {
        manager.addCertprofile(entry);
        LOG.info("added certprofile {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add certprofile ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // User
    for (String name : conf.getUserNames()) {
      Object obj = conf.getUser(name);
      UserEntry entryB = queryExecutor.getUser(name, true);

      if (entryB != null) {
        boolean equals;
        if (obj instanceof UserEntry) {
          UserEntry entry = (UserEntry) obj;
          equals = entry.equals(entryB, ignoreId);
        } else {
          AddUserEntry entry = (AddUserEntry) obj;
          equals = PasswordHash.validatePassword(entry.getPassword(), entryB.getHashedPassword());
        }

        if (equals) {
          LOG.info("ignore existed user {}", name);
          continue;
        } else {
          throw logAndCreateException(concat("user ", name, " existed, could not re-added it"));
        }
      }

      try {
        if (obj instanceof UserEntry) {
          queryExecutor.addUser((UserEntry) obj);
        } else {
          queryExecutor.addUser((AddUserEntry) obj);
        }
        LOG.info("added user {}", name);
      } catch (CaMgmtException ex) {
        String msg = concat("could not add user ", name);
        LogUtil.error(LOG, ex, msg);
        throw new CaMgmtException(msg);
      }
    }

    // CA
    for (String caName : conf.getCaNames()) {
      CaConf.SingleCa scc = conf.getCa(caName);
      CaConf.GenSelfIssued genSelfIssued = scc.getGenSelfIssued();
      CaEntry caEntry = scc.getCaEntry();
      if (caEntry != null) {
        if (manager.caInfos.containsKey(caName)) {
          CaEntry entryB = manager.caInfos.get(caName).getCaEntry();
          if (caEntry.getCert() == null && genSelfIssued != null) {
            SignerConf signerConf = new SignerConf(caEntry.getSignerConf());
            ConcurrentContentSigner signer;
            try {
              signer = securityFactory.createSigner(caEntry.getSignerType(), signerConf,
                  (X509Cert) null);
            } catch (ObjectCreationException ex) {
              throw new CaMgmtException(concat("could not create signer for CA ", caName), ex);
            }
            caEntry.setCert(signer.getCertificate());
          }

          if (caEntry.equals(entryB, true, true)) {
            LOG.info("ignore existing CA {}", caName);
          } else {
            throw logAndCreateException(concat("CA ", caName, " existed, could not re-added it"));
          }
        } else {
          if (genSelfIssued != null) {
            X509Cert cert = manager.generateRootCa(caEntry, genSelfIssued.getProfile(),
                genSelfIssued.getSubject(), genSelfIssued.getSerialNumber());
            LOG.info("generated root CA {}", caName);
            generatedRootCerts.put(caName, cert);
          } else {
            try {
              manager.addCa(caEntry);
              LOG.info("added CA {}", caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not add CA ", caName);
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      }

      if (scc.getAliases() != null) {
        Set<String> aliasesB = manager.getAliasesForCa(caName);
        for (String aliasName : scc.getAliases()) {
          if (aliasesB != null && aliasesB.contains(aliasName)) {
            LOG.info("ignored adding existing CA alias {} to CA {}", aliasName, caName);
          } else {
            try {
              manager.addCaAlias(aliasName, caName);
              LOG.info("associated alias {} to CA {}", aliasName, caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not associate alias ", aliasName, " to CA ", caName);
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      }

      if (scc.getProfileNames() != null) {
        Set<String> profilesB = manager.caHasProfiles.get(caName);
        for (String profileName : scc.getProfileNames()) {
          if (profilesB != null && profilesB.contains(profileName)) {
            LOG.info("ignored adding certprofile {} to CA {}", profileName, caName);
          } else {
            try {
              manager.addCertprofileToCa(profileName, caName);
              LOG.info("added certprofile {} to CA {}", profileName, caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not add certprofile ", profileName, " to CA ", caName);
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      }

      if (scc.getPublisherNames() != null) {
        Set<String> publishersB = manager.caHasPublishers.get(caName);
        for (String publisherName : scc.getPublisherNames()) {
          if (publishersB != null && publishersB.contains(publisherName)) {
            LOG.info("ignored adding publisher {} to CA {}", publisherName, caName);
          } else {
            try {
              manager.addPublisherToCa(publisherName, caName);
              LOG.info("added publisher {} to CA {}", publisherName, caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not add publisher ", publisherName, " to CA ", caName);
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      }

      if (scc.getRequestors() != null) {
        Set<CaHasRequestorEntry> requestorsB = manager.caHasRequestors.get(caName);

        for (CaHasRequestorEntry requestor : scc.getRequestors()) {
          String requestorName = requestor.getRequestorIdent().getName();
          CaHasRequestorEntry requestorB = null;
          if (requestorsB != null) {
            for (CaHasRequestorEntry m : requestorsB) {
              if (m.getRequestorIdent().getName().equals(requestorName)) {
                requestorB = m;
                break;
              }
            }
          }

          if (requestorB != null) {
            if (requestor.equals(requestorB, ignoreId)) {
              LOG.info("ignored adding requestor {} to CA {}", requestorName, caName);
            } else {
              throw logAndCreateException(
                  concat("could not add requestor ", requestorName, " to CA", caName));
            }
          } else {
            try {
              manager.addRequestorToCa(requestor, caName);
              LOG.info("added publisher {} to CA {}", requestorName, caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not add requestor ", requestorName, " to CA ", caName);
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      } // scc.getRequestors()

      if (scc.getUsers() != null) {
        List<CaHasUserEntry> usersB = queryExecutor.getCaHasUsersForCa(caName, manager.idNameMap);

        for (CaHasUserEntry user : scc.getUsers()) {
          String userName = user.getUserIdent().getName();
          CaHasUserEntry userB = null;
          if (usersB != null) {
            for (CaHasUserEntry m : usersB) {
              if (m.getUserIdent().getName().equals(userName)) {
                userB = m;
                break;
              }
            }
          }

          if (userB != null) {
            if (user.equals(userB, ignoreId)) {
              LOG.info("ignored adding user {} to CA {}", userName, caName);
            } else {
              throw logAndCreateException(
                  concat("could not add user ", userName, " to CA", caName));
            }
          } else {
            try {
              manager.addUserToCa(user, caName);
              LOG.info("added user {} to CA {}", userName, caName);
            } catch (CaMgmtException ex) {
              String msg = concat("could not add user ", userName, " to CA ", caName);
              LogUtil.error(LOG, ex, msg);
              throw new CaMgmtException(msg);
            }
          }
        }
      } // scc.getUsers()
    } // cas

    return generatedRootCerts.isEmpty() ? null : generatedRootCerts;
  } // method loadConf

  InputStream exportConf(List<String> caNames) throws CaMgmtException, IOException {
    manager.assertMasterModeAndSetuped();

    if (caNames != null) {
      List<String> tmpCaNames = new ArrayList<>(caNames.size());
      for (String name : caNames) {
        name = name.toLowerCase();
        if (manager.x509cas.containsKey(name)) {
          tmpCaNames.add(name);
        }
      }
      caNames = tmpCaNames;
    } else {
      caNames = new ArrayList<>(manager.x509cas.keySet());
    }

    ByteArrayOutputStream bytesStream = new ByteArrayOutputStream(1048576); // initial 1M
    ZipOutputStream zipStream = new ZipOutputStream(bytesStream);
    zipStream.setLevel(Deflater.BEST_SPEED);

    CaConfType.CaSystem root = new CaConfType.CaSystem();
    CaManagerQueryExecutor queryExecutor = manager.queryExecutor;

    try {
      Set<String> includeSignerNames = new HashSet<>();
      Set<String> includeRequestorNames = new HashSet<>();
      Set<String> includeProfileNames = new HashSet<>();
      Set<String> includePublisherNames = new HashSet<>();
      Set<String> includeUserNames = new HashSet<>();

      // users
      List<CaConfType.User> users = new LinkedList<>();
      root.setUsers(users);

      // cas
      if (CollectionUtil.isNotEmpty(caNames)) {
        List<CaConfType.Ca> list = new LinkedList<>();

        for (String name : manager.x509cas.keySet()) {
          if (!caNames.contains(name)) {
            continue;
          }

          CaConfType.Ca ca = new CaConfType.Ca();
          ca.setName(name);

          Set<String> strs = manager.getAliasesForCa(name);
          if (CollectionUtil.isNotEmpty(strs)) {
            ca.setAliases(new ArrayList<>(strs));
          }

          // CaHasRequestors
          Set<CaHasRequestorEntry> requestors = manager.caHasRequestors.get(name);
          if (CollectionUtil.isNotEmpty(requestors)) {
            ca.setRequestors(new ArrayList<>());

            for (CaHasRequestorEntry m : requestors) {
              String requestorName = m.getRequestorIdent().getName();
              includeRequestorNames.add(requestorName);

              CaConfType.CaHasRequestor chr = new CaConfType.CaHasRequestor();
              chr.setRequestorName(requestorName);
              chr.setRa(m.isRa());
              chr.setProfiles(new ArrayList<>(m.getProfiles()));
              chr.setPermissions(getPermissions(m.getPermission()));

              ca.getRequestors().add(chr);
            }
          }

          // CaHasUsers
          List<CaHasUserEntry> caHasUsers = queryExecutor.getCaHasUsersForCa(name,
              manager.idNameMap);
          if (CollectionUtil.isNotEmpty(caHasUsers)) {
            ca.setUsers(new ArrayList<>());

            for (CaHasUserEntry m : caHasUsers) {
              String username = m.getUserIdent().getName();
              CaConfType.CaHasUser chu = new CaConfType.CaHasUser();
              chu.setUserName(username);
              chu.setProfiles(new ArrayList<>(m.getProfiles()));
              chu.setPermissions(getPermissions(m.getPermission()));
              ca.getUsers().add(chu);

              if (includeUserNames.contains(username)) {
                continue;
              }

              // add also the user to the users
              UserEntry userEntry = queryExecutor.getUser(username);
              CaConfType.User userType = new CaConfType.User();
              if (!userEntry.isActive()) {
                userType.setActive(Boolean.FALSE);
              }
              userType.setName(username);
              userType.setHashedPassword(userEntry.getHashedPassword());
              users.add(userType);

              includeUserNames.add(username);
            }
          }

          strs = manager.caHasProfiles.get(name);
          if (CollectionUtil.isNotEmpty(strs)) {
            includeProfileNames.addAll(strs);
            ca.setProfiles(new ArrayList<>(strs));
          }

          strs = manager.caHasPublishers.get(name);
          if (CollectionUtil.isNotEmpty(strs)) {
            includePublisherNames.addAll(strs);
            ca.setPublishers(new ArrayList<>(strs));
          }

          CaConfType.CaInfo caInfoType = new CaConfType.CaInfo();
          ca.setCaInfo(caInfoType);

          CaEntry entry = manager.x509cas.get(name).getCaInfo().getCaEntry();
          // CA URIs
          CaUris caUris = entry.getCaUris();
          if (caUris != null) {
            CaConfType.CaUris caUrisType = new CaConfType.CaUris();
            caUrisType.setCacertUris(caUris.getCacertUris());
            caUrisType.setOcspUris(caUris.getOcspUris());
            caUrisType.setCrlUris(caUris.getCrlUris());
            caUrisType.setDeltacrlUris(caUris.getDeltaCrlUris());
            caInfoType.setCaUris(caUrisType);
          }

          // Certificate
          byte[] certBytes = entry.getCert().getEncoded();
          caInfoType.setCert(createFileOrBinary(zipStream, certBytes,
              concat("files/ca-", name, "-cert.der")));

          // certchain
          List<X509Cert> certchain = entry.getCertchain();
          if (CollectionUtil.isNotEmpty(certchain)) {
            List<FileOrBinary> ccList = new LinkedList<>();

            for (int i = 0; i < certchain.size(); i++) {
              certBytes = certchain.get(i).getEncoded();
              ccList.add(createFileOrBinary(zipStream, certBytes,
                  concat("files/ca-", name, "-certchain-" + i + ".der")));
            }
            caInfoType.setCertchain(ccList);
          }

          if (entry.getCmpControl() != null) {
            caInfoType.setCmpControl(
                new HashMap<>(new ConfPairs(entry.getCmpControl().getConf()).asMap()));
          }

          if (entry.getCmpResponderName() != null) {
            includeSignerNames.add(entry.getCmpResponderName());
            caInfoType.setCmpResponderName(entry.getCmpResponderName());
          }

          if (entry.getCrlControl() != null) {
            caInfoType.setCrlControl(
                new HashMap<>(new ConfPairs(entry.getCrlControl().getConf()).asMap()));
          }

          if (entry.getCrlSignerName() != null) {
            includeSignerNames.add(entry.getCrlSignerName());
            caInfoType.setCrlSignerName(entry.getCrlSignerName());
          }

          if (entry.getCtlogControl() != null) {
            caInfoType.setCtlogControl(
                new HashMap<>(new ConfPairs(entry.getCtlogControl().getConf()).asMap()));
          }

          if (entry.getDhpocControl() != null) {
            FileOrValue fv = createFileOrValue(
                zipStream, entry.getDhpocControl(), concat("files/ca-", name, "-dhpoc.conf"));
            caInfoType.setDhpocControl(fv);
          }

          caInfoType.setExpirationPeriod(entry.getExpirationPeriod());
          if (entry.getExtraControl() != null) {
            caInfoType.setExtraControl(entry.getExtraControl().asMap());
          }

          caInfoType.setKeepExpiredCertDays(entry.getKeepExpiredCertInDays());
          caInfoType.setMaxValidity(entry.getMaxValidity().toString());
          caInfoType.setNextCrlNo(entry.getNextCrlNumber());
          caInfoType.setNumCrls(entry.getNumCrls());
          caInfoType.setPermissions(getPermissions(entry.getPermission()));

          caInfoType.setProtocolSupport(
              StringUtil.splitAsSet(entry.getProtocoSupport().getEncoded(), ","));

          if (entry.getRevokeSuspendedControl() != null) {
            caInfoType.setRevokeSuspendedControl(
                new HashMap<>(new ConfPairs(entry.getRevokeSuspendedControl().getConf()).asMap()));
          }

          caInfoType.setSaveReq(entry.isSaveRequest());
          if (entry.getScepControl() != null) {
            caInfoType.setScepControl(
                new HashMap<>(new ConfPairs(entry.getScepControl().getConf()).asMap()));
          }

          if (entry.getScepResponderName() != null) {
            includeSignerNames.add(entry.getScepResponderName());
            caInfoType.setScepResponderName(entry.getScepResponderName());
          }

          caInfoType.setSignerConf(createFileOrValue(zipStream, entry.getSignerConf(),
              concat("files/ca-", name, "-signerconf.conf")));
          caInfoType.setSignerType(entry.getSignerType());
          caInfoType.setSnSize(entry.getSerialNoLen());

          caInfoType.setStatus(entry.getStatus().getStatus());
          caInfoType.setValidityMode(entry.getValidityMode().name());

          list.add(ca);
        }

        if (!list.isEmpty()) {
          root.setCas(list);
        }
      }

      // clear the users if the list is empty
      if (users.isEmpty()) {
        root.setUsers(null);
      }

      // requestors
      if (CollectionUtil.isNotEmpty(manager.requestorDbEntries)) {
        List<CaConfType.Requestor> list = new LinkedList<>();

        for (String name : manager.requestorDbEntries.keySet()) {
          if (!includeRequestorNames.contains(name)) {
            continue;
          }

          RequestorEntry entry = manager.requestorDbEntries.get(name);
          CaConfType.Requestor type = new CaConfType.Requestor();
          type.setName(name);
          type.setType(entry.getType());

          if (RequestorEntry.TYPE_CERT.equalsIgnoreCase(entry.getType())) {
            FileOrBinary fob = createFileOrBinary(zipStream,
                Base64.decode(entry.getConf()), concat("files/requestor-", name, ".der"));
            type.setBinaryConf(fob);
          } else {
            FileOrValue fov = createFileOrValue(zipStream,
                entry.getConf(), concat("files/requestor-", name, ".conf"));
            type.setConf(fov);
          }

          list.add(type);
        }

        if (!list.isEmpty()) {
          root.setRequestors(list);
        }
      }

      // publishers
      if (CollectionUtil.isNotEmpty(manager.publisherDbEntries)) {
        List<NameTypeConf> list = new LinkedList<>();

        for (String name : manager.publisherDbEntries.keySet()) {
          if (!includePublisherNames.contains(name)) {
            continue;
          }
          PublisherEntry entry = manager.publisherDbEntries.get(name);
          NameTypeConf conf = new NameTypeConf();
          conf.setName(name);
          conf.setType(entry.getType());
          conf.setConf(createFileOrValue(zipStream, entry.getConf(),
              concat("files/publisher-", name, ".conf")));
          list.add(conf);
        }

        if (!list.isEmpty()) {
          root.setPublishers(list);
        }
      }

      // profiles
      if (CollectionUtil.isNotEmpty(manager.certprofileDbEntries)) {
        List<NameTypeConf> list = new LinkedList<>();
        for (String name : manager.certprofileDbEntries.keySet()) {
          if (!includeProfileNames.contains(name)) {
            continue;
          }
          CertprofileEntry entry = manager.certprofileDbEntries.get(name);
          NameTypeConf conf = new NameTypeConf();
          conf.setName(name);
          conf.setType(entry.getType());
          conf.setConf(createFileOrValue(zipStream, entry.getConf(),
              concat("files/certprofile-", name, ".conf")));
          list.add(conf);
        }

        if (!list.isEmpty()) {
          root.setProfiles(list);
        }
      }

      // signers
      if (CollectionUtil.isNotEmpty(manager.signerDbEntries)) {
        List<CaConfType.Signer> list = new LinkedList<>();

        for (String name : manager.signerDbEntries.keySet()) {
          if (!includeSignerNames.contains(name)) {
            continue;
          }

          SignerEntry entry = manager.signerDbEntries.get(name);
          CaConfType.Signer conf = new CaConfType.Signer();
          conf.setName(name);
          conf.setType(entry.getType());
          conf.setConf(createFileOrValue(zipStream, entry.getConf(),
              concat("files/signer-", name, ".conf")));
          conf.setCert(createFileOrBase64Value(zipStream, entry.getBase64Cert(),
              concat("files/signer-", name, ".der")));

          list.add(conf);
        }

        if (!list.isEmpty()) {
          root.setSigners(list);
        }
      }

      // add the CAConf XML file
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      try {
        root.validate();
        JSON.writeJSONString(bout, root, SerializerFeature.PrettyFormat);
      } catch (InvalidConfException ex) {
        LogUtil.error(LOG, ex, "could not marshal CAConf");
        throw new CaMgmtException(concat("could not marshal CAConf: ", ex.getMessage()), ex);
      } finally {
        bout.flush();
      }

      zipStream.putNextEntry(new ZipEntry("caconf.json"));
      try {
        zipStream.write(bout.toByteArray());
      } finally {
        zipStream.closeEntry();
      }
    } finally {
      zipStream.flush();
      zipStream.close();
    }

    return new ByteArrayInputStream(bytesStream.toByteArray());
  } // method exportConf

  private static CaMgmtException logAndCreateException(String msg) {
    LOG.error(msg);
    return new CaMgmtException(msg);
  }

}
