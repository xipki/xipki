// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaConf;
import org.xipki.ca.api.mgmt.CaConfType;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaProfileEntry;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.mgmt.entry.BaseCaInfo;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.mgmt.CaProfileIdAliases;
import org.xipki.ca.server.mgmt.SelfSignedCertBuilder;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.ConcurrentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.OperationException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.io.FileOrBinary;
import org.xipki.util.io.FileOrValue;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * This class represents the file-based CA configuration.
 * @author Lijun Liao (xipki)
 */
public class FileCaConfStore implements CaConfStore {

  private static final Logger LOG =
      LoggerFactory.getLogger(FileCaConfStore.class);

  private static final CaMgmtException readOnlyException =
      new CaMgmtException("File based CaConfStore is read-only");

  private static final int REQUESTOR_BY_CA_ID = 1;

  private final Map<String, String> dbSchemas;

  private final int dbSchemaversion = 9;

  private final List<String> caNames;

  private final List<String> keyPairGenNames;

  private final List<String> profileNames;

  private final List<String> publisherNames;

  private final List<String> requestorNames;

  private final List<String> signerNames;

  private final Map<String, CaEntry> caTable = new HashMap<>();

  private final Map<String, CertprofileEntry> certprofileTable =
      new HashMap<>();

  private final Map<String, PublisherEntry> publisherTable = new HashMap<>();

  private final Map<String, RequestorEntry> requestorTable = new HashMap<>();

  private final Map<String, SignerEntry> signerTable = new HashMap<>();

  private final Map<String, KeypairGenEntry> keypairGenTable = new HashMap<>();

  private final Map<String, Integer> requestorNameToIdMap;

  private final Map<String, Set<CaHasRequestorEntry>> caHasRequestors;

  private final Map<String, Set<CaProfileIdAliases>> caHasProfiles;

  private final Map<String, Set<Integer>> caHasPublisherIds;

  private final Map<String, String> aliasToCaNames;

  private final Map<String, Integer> aliasToCaIds;

  private final boolean needsCertStore;

  public FileCaConfStore(SecurityFactory securityFactory,
                         CertprofileFactoryRegister certprofileFactoryRegister,
                         List<String> confFiles)
      throws IOException, CaMgmtException, InvalidConfException {
    Args.notEmpty(confFiles, "confFiles");

    String baseDir = null;
    for (String confFile : confFiles) {
      File fileobj = new File(IoUtil.expandFilepath(confFile, true));
      if (baseDir == null) {
        baseDir = fileobj.getParent();
      } else {
        if (!CompareUtil.equals(baseDir, fileobj.getParent())) {
          throw new IllegalArgumentException(
              "Not all confFiles have the same parent dir");
        }
      }
    }

    if (baseDir == null) {
      baseDir = ".";
    }

    CaConfType.CaSystem root = mergeConfs(confFiles);

    //-- make sure all names, IDs are unique
    Map<String, Integer> profileNameIdMap =
        assertNameIdUnique(root.profiles(), "profile");
    profileNames = List.copyOf(profileNameIdMap.keySet());

    Map<String, Integer> publisherNameIdMap =
        assertNameIdUnique(root.publishers(), "publisher");
    publisherNames = List.copyOf(publisherNameIdMap.keySet());

    signerNames = Collections.unmodifiableList(
        assertNameUnique(root.signers(), "signer"));

    Map<String, Integer> requestorNameIdMap =
        assertNameIdUnique(root.requestors(), "requestor");
    if (requestorNameIdMap.containsKey(RequestorInfo.NAME_BY_CA)) {
      throw new InvalidConfException(
          "requestor name " + RequestorInfo.NAME_BY_CA +
              " is reserved and shall no be used");
    }
    requestorNameIdMap.put(RequestorInfo.NAME_BY_CA, REQUESTOR_BY_CA_ID);

    this.requestorNames = List.copyOf(requestorNameIdMap.keySet());
    this.requestorNameToIdMap = Collections.unmodifiableMap(requestorNameIdMap);

    keyPairGenNames = Collections.unmodifiableList(
        assertNameUnique(root.keypairGens(), "keypairGen"));

    Map<String, Integer> caNameIdMap = assertNameIdUnique(root.cas(), "CA");
    caNames = List.copyOf(caNameIdMap.keySet());

    //-- make sure the requestor does not have reserved id
    for (CaConfType.Requestor m : root.requestors()) {
      if (m.id() == REQUESTOR_BY_CA_ID) {
        throw new InvalidConfException("requestor id " + m.id()
            + " is reserved and shall not be used");
      }
    }

    //-- make sure all referenced names (e.g. signer, requestor, publisher)
    // are present.
    Map<String, Integer> caAliasNameIdMap = new HashMap<>();
    for (CaConfType.Ca ca : root.cas()) {
      // aliases
      for (String alias : ca.aliases()) {
        if (caAliasNameIdMap.containsKey(alias)) {
          throw new InvalidConfException("duplicated CA alias " + alias);
        }
        caAliasNameIdMap.put(alias, ca.id());
      }

      // publisher
      for (String m : ca.publishers()) {
        if (!publisherNameIdMap.containsKey(m)) {
          throw new InvalidConfException("unknown publisher " + m);
        }
      }

      // requestor
      for (CaConfType.CaHasRequestor m : ca.requestors()) {
        if (!requestorNameIdMap.containsKey(m.requestorName())) {
          throw new InvalidConfException("unknown requestor " +
              m.requestorName());
        }
      }

      // profile
      Set<String> localProfileNames = new HashSet<>();
      for (String profile : ca.profiles()) {
        CaProfileEntry entry = CaProfileEntry.decode(profile);
        if (!profileNameIdMap.containsKey(entry.profileName())) {
          throw new InvalidConfException("unknown certprofile " +
              entry.profileName());
        }

        localProfileNames.add(entry.profileName());
        for (String alias : entry.profileAliases()) {
          if (localProfileNames.contains(alias)) {
            throw new InvalidConfException(
                "duplicated cerprofile alias " + alias);
          }
          localProfileNames.add(alias);
        }
      }

      CaConfType.CaInfo caInfo = ca.caInfo();
      if (caInfo != null) {
        // CRL signner
        BaseCaInfo base = caInfo.base();
        String tname = base.crlSignerName();
        if (tname != null && !signerNames.contains(tname)) {
          throw new InvalidConfException("unknown signer " + tname);
        }

        if (base.keypairGenNames() != null) {
          for (String m : base.keypairGenNames()) {
            if (!keyPairGenNames.contains(m)) {
              throw new InvalidConfException("unknown keypairGen " + m);
            }
          }
        }
      }
    }

    //-- DB Schemas
    // add default db schemas if not set.
    if (!root.dbSchemas().containsKey("VENDOR")) {
      root.dbSchemas().put("VENDOR", "XIPKI");
    }

    if (!root.dbSchemas().containsKey("X500NAME_MAXLEN")) {
      root.dbSchemas().put("X500NAME_MAXLEN", "350");
    }

    if (!root.dbSchemas().containsKey("VERSION")) {
      root.dbSchemas().put("VERSION", "9");
    }

    this.dbSchemas = Collections.unmodifiableMap(root.dbSchemas());

    // Signers
    for (CaConfType.Signer m : root.signers()) {
      String name = m.name();
      try {
        SignerEntry entry = new SignerEntry(name, m.type(),
            getValue(m.conf(), baseDir), getBase64Value(m.cert(),
            baseDir));
        signerTable.put(name, entry);
        LOG.info("initialized signer {}", name);
      } catch (Exception ex) {
        throw new InvalidConfException("error initializing signer " + name, ex);
      }
    }

    // Requestors
    for (CaConfType.Requestor m : root.requestors()) {
      NameId ident = new NameId(m.id(), m.name());
      try {
        String conf;
        if (m.conf() != null) {
          conf = getValue(m.conf(), baseDir);
        } else {
          if ("cert".equalsIgnoreCase(m.type())) {
            byte[] binary = getBinary(m.binaryConf(), baseDir);
            if (binary == null) {
              conf = null;
            } else {
              binary = X509Util.toDerEncoded(binary);
              conf = Base64.encodeToString(binary);
            }
          } else {
            conf = getBase64Value(m.binaryConf(), baseDir);
          }
        }

        RequestorEntry entry = new RequestorEntry(ident, m.type(), conf);
        requestorTable.put(ident.name(), entry);
        LOG.info("initialized requestor {}", ident);
      } catch (Exception ex) {
        throw new InvalidConfException("error initializing requestor " + ident,
            ex);
      }
    }

    // Publishers
    for (CaConfType.NameTypeConf m : root.publishers()) {
      NameId ident = new NameId(m.id(), m.name());
      try {
        PublisherEntry entry = new PublisherEntry(ident, m.type(),
            getValue(m.conf(), baseDir));

        publisherTable.put(ident.name(), entry);
        LOG.info("initialized publisher {}", ident);
      } catch (Exception ex) {
        throw new InvalidConfException(
            "error initializing publisher " + ident, ex);
      }
    }

    // KeypairGen
    for (CaConfType.NameTypeConf m : root.keypairGens()) {
      String name = m.name();
      try {
        KeypairGenEntry entry = new KeypairGenEntry(name, m.type(),
            getValue(m.conf(), baseDir));

        keypairGenTable.put(name, entry);
        LOG.info("initialized KeyPairGen {}", name);
      } catch (RuntimeException ex) {
        throw new InvalidConfException("error initializing KeyPairGen " + name,
            ex);
      }
    }

    // Profiles
    for (CaConfType.NameTypeConf m : root.profiles()) {
      NameId ident = new NameId(m.id(), m.name());
      try {
        CertprofileEntry entry = new CertprofileEntry(ident, m.type(),
            getValue(m.conf(), baseDir));

        certprofileTable.put(ident.name(), entry);
        LOG.info("initialized certprofile {}", ident);
      } catch (RuntimeException ex) {
        throw new InvalidConfException(
            "error initializing certprofile " + ident, ex);
      }
    }

    // CAs
    Map<String, String> caAliasToNameMap = new HashMap<>();
    Map<String, Set<String>> caHasPublisherMap = new HashMap<>();
    Map<String, Set<CaProfileIdAliases>> caHasProfileMap = new HashMap<>();
    Map<String, Set<CaHasRequestorEntry>> caHasRequestorMap = new HashMap<>();

    if (root.cas() != null) {
      for (CaConfType.Ca m : root.cas()) {
        String caName = m.name();
        NameId ident = new NameId(m.id(), caName);
        try {
          CaEntry entry = buildCaEntry(m, baseDir, certprofileFactoryRegister,
                            securityFactory);
          caTable.put(caName, entry);
          LOG.info("initialized CA {}", ident);
        } catch (Exception ex) {
          throw new InvalidConfException("error initializing CA " + ident, ex);
        }

        // Alias
        if (m.aliases() != null) {
          for (String alias : m.aliases()) {
            caAliasToNameMap.put(alias, caName);
          }
        }

        // Publisher
        if (m.publishers() != null) {
           caHasPublisherMap.put(caName, new HashSet<>(m.publishers()));
        }

        // Certprofile
        if (m.profiles() != null) {
          Set<CaProfileIdAliases> set = new HashSet<>();
          for (String combinedProfile : m.profiles()) {
            try {
              CaProfileEntry entry0 = CaProfileEntry.decode(combinedProfile);
              String profileName = entry0.profileName();
              CertprofileEntry certprofileEntry =
                  certprofileTable.get(profileName);

              CaProfileIdAliases entry = new CaProfileIdAliases(
                  certprofileEntry.ident().id(),
                  entry0.getEncodedAliases());

              set.add(entry);
            } catch (Exception ex) {
              throw new CaMgmtException("invalid syntax of CaProfileEntry '"
                  + combinedProfile + "'", ex);
            }
          }
          caHasProfileMap.put(caName, set);
        }

        // Requestor
        if (m.requestors() != null) {
          Set<CaHasRequestorEntry> set = new HashSet<>();
          for (CaConfType.CaHasRequestor c : m.requestors()) {
            RequestorEntry entry0 = requestorTable.get(c.requestorName());
            set.add(new CaHasRequestorEntry(
                entry0.ident(), c.permissions(),
                c.profiles() == null ? Collections.emptyList()
                    : c.profiles()));
          }
          caHasRequestorMap.put(caName, set);
        }

        CaConfType.CaInfo caInfo = m.caInfo();
        if (caInfo != null) {
          // KeyPairGen
        }
      }
    }

    this.caHasProfiles = Collections.unmodifiableMap(caHasProfileMap);
    this.caHasRequestors = Collections.unmodifiableMap(caHasRequestorMap);

    this.aliasToCaNames = Collections.unmodifiableMap(caAliasToNameMap);
    Map<String, Integer> map = new HashMap<>();
    for (Map.Entry<String, String> m : this.aliasToCaNames.entrySet()) {
      int caId = caNameIdMap.get(m.getValue());
      map.put(m.getKey(), caId);
    }
    this.aliasToCaIds = Collections.unmodifiableMap(map);

    Map<String, Set<Integer>> caHasPublisherIds = new HashMap<>();
    for (Map.Entry<String, Set<String>> m : caHasPublisherMap.entrySet()) {
      String caName = m.getKey();
      Set<Integer> ids = new HashSet<>();
      for (String publisheName : m.getValue()) {
        ids.add(publisherNameIdMap.get(publisheName));
      }
      caHasPublisherIds.put(caName, ids);
    }
    this.caHasPublisherIds = Collections.unmodifiableMap(caHasPublisherIds);

    boolean saveCertOrKey = false;
    for (CaConfType.Ca ca : root.cas()) {
      BaseCaInfo base = ca.caInfo().base();
      if (base.isSaveCert() || base.isSaveKeypair()) {
        saveCertOrKey = true;
        break;
      }
    }

    this.needsCertStore = saveCertOrKey;
  }

  private CaEntry buildCaEntry(
      CaConfType.Ca ca, String baseDir,
      CertprofileFactoryRegister certprofileFactoryRegister,
      SecurityFactory securityFactory)
      throws InvalidConfException, IOException, CaMgmtException {
    NameId ident = new NameId(ca.id(), ca.name());
    CaConfType.CaInfo ci = ca.caInfo();

    if (ci.genSelfIssued() != null) {
      if (ci.cert() != null) {
        throw new InvalidConfException(
            "cert.file of CA " + ident + " may not be set");
      }

      // check if the certificate has been generated before.
      File certFile = new File(baseDir,
          "generated-rootcerts/" + ident.name() + ".pem");
      X509Cert cert;
      if (certFile.exists()) {
        try {
          cert = X509Util.parseCert(certFile);
        } catch (CertificateException e) {
          throw new CaMgmtException("error parsing certificate " +
              certFile.getPath());
        }
      } else {
        CaConfType.GenSelfIssued gsi = ci.genSelfIssued();
        Instant notBefore = gsi.notBefore() == null ? null
            : DateUtil.parseUtcTimeyyyyMMddhhmmss(gsi.notBefore());
        Instant notAfter = gsi.notAfter() == null ? null
            : DateUtil.parseUtcTimeyyyyMMddhhmmss(gsi.notAfter());
        CaConf.GenSelfIssued genSelfIssued = new CaConf.GenSelfIssued(
            gsi.profile(), gsi.subject(), gsi.serialNumber(),
            notBefore, notAfter);

        IdentifiedCertprofile certprofile;
        try {
          CertprofileEntry certprofileConfEntry =
              certprofileTable.get(gsi.profile());
          Certprofile certprofile0 = certprofileFactoryRegister.newCertprofile(
              certprofileConfEntry.type());

          certprofile0.initialize(certprofileConfEntry.conf());
          certprofile = new IdentifiedCertprofile(certprofileConfEntry,
                        certprofile0);
        } catch (ObjectCreationException | CertprofileException
                 | RuntimeException ex) {
          throw new CaMgmtException("error initializing certprofile " +
              gsi.profile());
        }

        String signerConf = getValue(ci.signerConf(), baseDir);

        try {
          cert = SelfSignedCertBuilder.generateSelfSigned(securityFactory,
              ci.base().signerType(), signerConf, certprofile,
              genSelfIssued.subject(), genSelfIssued.serialNumber(),
              genSelfIssued.notBefore(), genSelfIssued.notAfter());
        } catch (OperationException ex) {
          throw new CaMgmtException(
              ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }

        // save the binary, and replace the configuration file.
        IoUtil.save(certFile,
            X509Util.toPemCert(cert).getBytes(StandardCharsets.UTF_8));
      }

      ci.setCert(FileOrBinary.ofBinary(cert.getEncoded()));
    }

    CaEntry caEntry = new CaEntry(ci.base(), ident,
        getValue(ci.signerConf(), baseDir));

    if (caEntry.base().caUris() == null) {
      caEntry.base().setCaUris(CaUris.EMPTY_INSTANCE);
    }

    X509Cert caCert;

    if (ci.cert() != null) {
      byte[] bytes = getBinary(ci.cert(), baseDir);
      try {
        caCert = X509Util.parseCert(bytes);
      } catch (CertificateException ex) {
        throw new InvalidConfException("invalid certificate of CA " + ident,
            ex);
      }
    } else {
      // extract from the signer configuration
      try {
        List<CaEntry.CaSignerConf> signerConfs =
            CaEntry.splitCaSignerConfs(getValue(ci.signerConf(), baseDir));
        SignerConf signerConf = new SignerConf(signerConfs.get(0).conf());

        ConcurrentSigner signer = securityFactory.createSigner(
            ci.base().signerType(), signerConf, (X509Cert) null);
        try {
          caCert = signer.getX509Cert();
        } finally {
          signer.close();
        }
      } catch (IOException | ObjectCreationException | XiSecurityException ex) {
        throw new InvalidConfException(
            "could not create CA signer for CA " + ident, ex);
      }
    }

    caEntry.setCert(caCert);

    // certchain
    if (CollectionUtil.isNotEmpty(ci.getCertchain())) {
      List<X509Cert> certchain = new LinkedList<>();
      for (FileOrBinary cc : ci.getCertchain()) {
        byte[] bytes = getBinary(cc, baseDir);
        try {
          certchain.add(X509Util.parseCert(bytes));
        } catch (CertificateException ex) {
          throw new InvalidConfException("invalid certchain for CA " + ident,
              ex);
        }
      }

      caEntry.setCertchain(certchain);
    }

    BaseCaInfo base = caEntry.base();
    if (base.crlControl() != null && !base.isSaveCert()) {
      throw new InvalidConfException(
          "crlControl shall be null, since saveCert=true");
    }

    return caEntry;
  }

  private static String getValue(FileOrValue fv, String baseDir)
      throws IOException {
    if (fv == null) {
      return null;
    }

    if (fv.value() != null) {
      String value = fv.value();
      if (value.contains("${basedir}")) {
        value = value.replace("${basedir}", baseDir);
      }
      return value;
    }

    String expandedPath = IoUtil.expandFilepath(fv.file());
    Path path = Paths.get(expandedPath);
    if (!path.isAbsolute()) {
      path = Paths.get(baseDir, expandedPath);
    }

    return StringUtil.toUtf8String(Files.readAllBytes(path));
  }

  private static CaConfType.CaSystem mergeConfs(List<String> confFiles)
      throws InvalidConfException {
    CaConfType.CaSystem conf0 = CaConfType.CaSystem.parse(
        Paths.get(IoUtil.expandFilepath(confFiles.get(0), true)));

    Map<String, String> dbSchemas = conf0.dbSchemas();
    if (dbSchemas == null) {
      dbSchemas = new HashMap<>();
      conf0.setDbSchemas(dbSchemas);
    }

    List<CaConfType.NameTypeConf> profiles = conf0.profiles();
    if (profiles == null) {
      profiles = new LinkedList<>();
      conf0.setProfiles(profiles);
    }

    List<CaConfType.Requestor> requestors = conf0.requestors();
    if (requestors == null) {
      requestors = new LinkedList<>();
      conf0.setRequestors(requestors);
    }

    List<CaConfType.NameTypeConf> publishers = conf0.publishers();
    if (publishers == null) {
      publishers = new LinkedList<>();
      conf0.setPublishers(publishers);
    }

    List<CaConfType.Signer> signers = conf0.signers();
    if (signers == null) {
      signers = new LinkedList<>();
      conf0.setSigners(signers);
    }

    List<CaConfType.NameTypeConf> keypairGens = conf0.keypairGens();
    if (keypairGens == null) {
      keypairGens = new LinkedList<>();
      conf0.setKeypairGens(keypairGens);
    }

    List<CaConfType.Ca> cas = conf0.cas();
    if (cas == null) {
      cas = new LinkedList<>();
      conf0.setCas(cas);
    }

    for (int i = 1; i < confFiles.size(); i++) {
      CaConfType.CaSystem root = CaConfType.CaSystem.parse(
          Paths.get(IoUtil.expandFilepath(confFiles.get(i), true)));

      // Db Schemas
      if (root.dbSchemas() != null) {
        for (Map.Entry<String, String> entry : root.dbSchemas().entrySet()) {
          String name = entry.getKey();
          if (dbSchemas.containsKey(name)) {
            if (!CompareUtil.equals(dbSchemas.get(name), entry.getValue())) {
              throw new InvalidConfException("Duplicated DbSchema '" +
                  name + "' but with differnt values");
            }
          }
        }
      }

      // Requestors
      if (root.requestors() != null) {
        requestors.addAll(root.requestors());
      }

      // Publishers
      if (root.publishers() != null) {
        publishers.addAll(root.publishers());
      }

      // Cert-profiles
      if (root.profiles() != null) {
        profiles.addAll(root.profiles());
      }

      // KeypairGens
      if (root.keypairGens() != null) {
        keypairGens.addAll(root.keypairGens());
      }

      // Signers
      if (root.signers() != null) {
        signers.addAll(root.signers());
      }

      if (root.cas() != null) {
        cas.addAll(root.cas());
      }
    }

    boolean withSoftwareKeyPairGen = false;
    String nameSoftware = "software";
    for (CaConfType.NameTypeConf kg : keypairGens) {
      if (nameSoftware.equalsIgnoreCase(kg.name())) {
        withSoftwareKeyPairGen = true;

        if (!"software".equalsIgnoreCase(kg.type())) {
          throw new InvalidConfException(
              "KeyPairGen name 'software' is reserved");
        }

        break;
      }
    }

    if (!withSoftwareKeyPairGen) {
      CaConfType.NameTypeConf sw = new CaConfType.NameTypeConf(
          null, nameSoftware, "software", null);
      keypairGens.add(sw);
    }

    return conf0;
  }

  private static Map<String, Integer> assertNameIdUnique(
      List<? extends CaConfType.IdNameConf> list, String type)
      throws InvalidConfException {
    Map<String, Integer> nameIdMap = new HashMap<>();
    for (CaConfType.IdNameConf c : list) {
      String name = c.name();
      if (nameIdMap.containsKey(name)) {
        throw new InvalidConfException(
            "Duplicated name of " + type + " " + name);
      }

      Integer id = c.id();
      if (id == null) {
        throw new InvalidConfException("id shall not be null");
      }

      if (id == 0) {
        throw new InvalidConfException("id value 0 is not allowed");
      }

      if (nameIdMap.containsValue(id)) {
        throw new InvalidConfException(
            "Duplicated id of " + type + " " + name);
      }

      nameIdMap.put(name, id);
    }
    return nameIdMap;
  }

  private static List<String> assertNameUnique(
      List<? extends CaConfType.NameTypeConf> list, String type)
      throws InvalidConfException {
    List<String> names = new ArrayList<>(list.size());
    for (CaConfType.NameTypeConf c : list) {
      String name = c.name();
      if (names.contains(name)) {
        throw new InvalidConfException(
            "Duplicated name of " + type + " " + name);
      }
      names.add(name);
    }
    return names;
  }

  private static String getBase64Value(FileOrBinary fb, String baseDir)
      throws IOException {
    byte[] binary = getBinary(fb, baseDir);
    return binary == null ? null : Base64.encodeToString(binary);
  }

  private static byte[] getBinary(FileOrBinary fb, String baseDir)
      throws IOException {
    if (fb == null) {
      return null;
    }

    if (fb.binary() != null) {
      return fb.binary();
    }

    String expandedPath = IoUtil.expandFilepath(fb.file());
    Path path = Paths.get(expandedPath);
    if (!path.isAbsolute()) {
      path = Paths.get(baseDir, expandedPath);
    }

    return Files.readAllBytes(path);
  }

  @Override
  public boolean needsCertStore() {
    return needsCertStore;
  }

  @Override
  public SystemEvent getSystemEvent(String eventName) throws CaMgmtException {
    return null;
  }

  @Override
  public void changeSystemEvent(SystemEvent systemEvent)
      throws CaMgmtException {
    // do nothing
  }

  @Override
  public Map<String, Integer> createCaAliases() throws CaMgmtException {
    return aliasToCaIds;
  }

  @Override
  public CertprofileEntry createCertprofile(String name)
      throws CaMgmtException {
    return Optional.ofNullable(certprofileTable.get(name)).orElseThrow(
        () -> new CaMgmtException("Unknown Certprofile " + name));
  }

  @Override
  public PublisherEntry createPublisher(String name) throws CaMgmtException {
    return Optional.ofNullable(publisherTable.get(name)).orElseThrow(
        () -> new CaMgmtException("Unknown Publisher " + name));
  }

  @Override
  public Integer getRequestorId(String requestorName) throws CaMgmtException {
    return requestorNameToIdMap.get(requestorName);
  }

  @Override
  public RequestorEntry createRequestor(String name) throws CaMgmtException {
    return Optional.ofNullable(requestorTable.get(name)).orElseThrow(
        () -> new CaMgmtException("Unknown Requestor " + name));
  }

  @Override
  public SignerEntry createSigner(String name) throws CaMgmtException {
    return Optional.ofNullable(signerTable.get(name)).orElseThrow(
        () -> new CaMgmtException("Unknown Signer " + name));
  }

  @Override
  public KeypairGenEntry createKeypairGen(String name) throws CaMgmtException {
    return Optional.ofNullable(keypairGenTable.get(name)).orElseThrow(
        () -> new CaMgmtException("Unknown KeypairGen " + name));
  }

  @Override
  public CaInfo createCaInfo(String name, CertStore certstore)
      throws CaMgmtException {
    CaEntry caEntry = caTable.get(name);
    if (caEntry == null) {
      throw new CaMgmtException("unknown CA " + name);
    }

    try {
      return new CaInfo(caEntry, certstore);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex);
    }
  }

  @Override
  public Set<CaHasRequestorEntry> createCaHasRequestors(NameId ca)
      throws CaMgmtException {
    return caHasRequestors.get(ca.name());
  }

  @Override
  public Set<CaProfileIdAliases> createCaHasProfiles(NameId ca)
      throws CaMgmtException {
    return caHasProfiles.get(ca.name());
  }

  @Override
  public Set<Integer> createCaHasPublishers(NameId ca) throws CaMgmtException {
    return caHasPublisherIds.get(ca.name());
  }

  @Override
  public void addCa(CaEntry caEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addCaAlias(String aliasName, NameId ca) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addCertprofile(CertprofileEntry dbEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addCertprofileToCa(NameId profile, NameId ca,
                                 List<String> aliases)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addPublisherToCa(NameId publisher, NameId ca)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addRequestor(RequestorEntry dbEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public NameId addEmbeddedRequestor(String requestorName)
      throws CaMgmtException {
    if (RequestorInfo.NAME_BY_CA.equals(requestorName)) {
      return new NameId(REQUESTOR_BY_CA_ID, RequestorInfo.NAME_BY_CA);
    }

    throw readOnlyException;
  }

  @Override
  public void addRequestorToCa(CaHasRequestorEntry requestor, NameId ca)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addPublisher(PublisherEntry dbEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void changeCa(ChangeCaEntry changeCaEntry,
                       BaseCaInfo currentCaConf,
                       SecurityFactory securityFactory)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void commitNextCrlNoIfLess(NameId ca, long nextCrlNo)
      throws CaMgmtException {
    // Not supported. Relies solely on the analysis of the CRLs saved in
    // the database.
  }

  @Override
  public IdentifiedCertprofile changeCertprofile(
      NameId nameId, String type, String conf, CaManagerImpl certprofileManager)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public RequestorEntryWrapper changeRequestor(
      NameId nameId, String type, String conf) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public SignerEntry changeSigner(
      String name, String type, String conf, String base64Cert,
      CaManagerImpl signerManager)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public KeypairGenEntryWrapper changeKeypairGen(
      String name, String type, String conf, CaManagerImpl manager)
          throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public IdentifiedCertPublisher changePublisher(
      String name, String type, String conf, CaManagerImpl publisherManager)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void removeCaAlias(String aliasName) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void removeCertprofileFromCa(String profileName, String caName)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void removeRequestorFromCa(String requestorName, String caName)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void removePublisherFromCa(String publisherName, String caName)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void removeDbSchema(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void revokeCa(String caName, CertRevocationInfo revocationInfo)
      throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addKeypairGen(KeypairGenEntry dbEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void addSigner(SignerEntry dbEntry) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void unlockCa() throws CaMgmtException {
  }

  @Override
  public void unrevokeCa(String caName) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public int getDbSchemaVersion() {
    return dbSchemaversion;
  }

  @Override
  public void addDbSchema(String name, String value) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public void changeDbSchema(String name, String value) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public Map<String, String> getDbSchemas() throws CaMgmtException {
    return dbSchemas;
  }

  @Override
  public List<String> getCaNames() throws CaMgmtException {
    return caNames;
  }

  @Override
  public boolean deleteCa(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public List<String> getKeyPairGenNames() throws CaMgmtException {
    return keyPairGenNames;
  }

  @Override
  public boolean deleteKeyPairGen(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public List<String> getProfileNames() throws CaMgmtException {
    return profileNames;
  }

  @Override
  public boolean deleteProfile(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public List<String> getPublisherNames() throws CaMgmtException {
    return publisherNames;
  }

  @Override
  public boolean deletePublisher(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public List<String> getRequestorNames() throws CaMgmtException {
    return requestorNames;
  }

  @Override
  public boolean deleteRequestor(String name) throws CaMgmtException {
    throw readOnlyException;
  }

  @Override
  public List<String> getSignerNames() throws CaMgmtException {
    return signerNames;
  }

  @Override
  public boolean deleteSigner(String name) throws CaMgmtException {
    throw readOnlyException;
  }

}
