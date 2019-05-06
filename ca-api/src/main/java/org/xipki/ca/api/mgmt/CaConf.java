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

package org.xipki.ca.api.mgmt;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.Validity;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

public class CaConf {

  public static class GenSelfIssued {

    private final String profile;

    private final byte[] csr;

    private final BigInteger serialNumber;

    private final String certOutputFormat;

    public GenSelfIssued(String profile, byte[] csr, BigInteger serialNumber,
        String certOutputFormat) {
      this.profile = Args.notBlank(profile, "profile");
      this.csr = Args.notNull(csr, "csr");
      this.serialNumber = serialNumber;
      this.certOutputFormat = certOutputFormat;
    }

    public String getProfile() {
      return profile;
    }

    public byte[] getCsr() {
      return csr;
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public String getCertOutputFormat() {
      return certOutputFormat;
    }
  }

  public static class SingleCa {

    private final String name;

    private final GenSelfIssued genSelfIssued;

    private final MgmtEntry.Ca caEntry;

    private final List<String> aliases;

    private final List<String> profileNames;

    private final List<MgmtEntry.CaHasRequestor> requestors;

    private final List<MgmtEntry.CaHasUser> users;

    private final List<String> publisherNames;

    public SingleCa(String name, GenSelfIssued genSelfIssued, MgmtEntry.Ca caEntry,
        List<String> aliases, List<String> profileNames, List<MgmtEntry.CaHasRequestor> requestors,
        List<MgmtEntry.CaHasUser> users, List<String> publisherNames) {
      this.name = Args.notBlank(name, "name");
      if (genSelfIssued != null) {
        if (caEntry == null) {
          throw new IllegalArgumentException(
              "caEntry may not be null if genSelfIssued is non-null");
        }

        if (caEntry instanceof MgmtEntry.Ca) {
          if (((MgmtEntry.Ca) caEntry).getCert() != null) {
            throw new IllegalArgumentException(
                "caEntry.cert may not be null if genSelfIssued is non-null");
          }
        }
      }

      this.genSelfIssued = genSelfIssued;
      this.caEntry = caEntry;
      this.aliases = aliases;
      this.profileNames = profileNames;
      this.requestors = requestors;
      this.users = users;
      this.publisherNames = publisherNames;
    }

    public String getName() {
      return name;
    }

    public MgmtEntry.Ca getCaEntry() {
      return caEntry;
    }

    public List<String> getAliases() {
      return aliases;
    }

    public GenSelfIssued getGenSelfIssued() {
      return genSelfIssued;
    }

    public List<String> getProfileNames() {
      return profileNames;
    }

    public List<MgmtEntry.CaHasRequestor> getRequestors() {
      return requestors;
    }

    public List<MgmtEntry.CaHasUser> getUsers() {
      return users;
    }

    public List<String> getPublisherNames() {
      return publisherNames;
    }

  }

  private static final Logger LOG = LoggerFactory.getLogger(CaConf.class);

  private final Map<String, String> properties = new HashMap<>();

  private final Map<String, MgmtEntry.Signer> signers = new HashMap<>();

  private final Map<String, MgmtEntry.Requestor> requestors = new HashMap<>();

  private final Map<String, Object> users = new HashMap<>();

  private final Map<String, MgmtEntry.Publisher> publishers = new HashMap<>();

  private final Map<String, MgmtEntry.Certprofile> certprofiles = new HashMap<>();

  private final Map<String, SingleCa> cas = new HashMap<>();

  public CaConf(File confFile, SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException {
    Args.notNull(securityFactory, "securityFactory");
    confFile = IoUtil.expandFilepath(Args.notNull(confFile, "confFile"));

    init(Files.newInputStream(confFile.toPath()), securityFactory);
  }

  public CaConf(InputStream confFileZipStream, SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException {
    Args.notNull(confFileZipStream, "confFileZipStream");
    Args.notNull(securityFactory, "securityFactory");
    init(confFileZipStream, securityFactory);
  }

  private final void init(InputStream zipFileStream, SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException {
    ZipInputStream zipStream = new ZipInputStream(zipFileStream);

    try {
      Map<String, byte[]> zipEntries = new HashMap<>();

      ZipEntry zipEntry;
      while ((zipEntry = zipStream.getNextEntry()) != null) {
        byte[] zipEntryBytes = read(zipStream);
        zipEntries.put(zipEntry.getName(), zipEntryBytes);
      }

      CaConfType.CaSystem root =
          JSON.parseObject(zipEntries.get("caconf.json"), CaConfType.CaSystem.class);
      root.validate();
      init0(root, zipEntries, securityFactory);
    } finally {
      try {
        zipFileStream.close();
      } catch (IOException ex) {
        LOG.info("could not clonse zipFileStream", ex.getMessage());
      }

      try {
        zipStream.close();
      } catch (IOException ex) {
        LOG.info("could not clonse zipStream", ex.getMessage());
      }
    }
  }

  private final void init0(CaConfType.CaSystem root, Map<String, byte[]> zipEntries,
      SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException {
    if (root.getProperties() != null) {
      properties.putAll(root.getProperties());
    }

    // Signers
    if (root.getSigners() != null) {
      for (CaConfType.Signer m : root.getSigners()) {
        MgmtEntry.Signer en = new MgmtEntry.Signer(m.getName(), expandConf(m.getType()),
            getValue(m.getConf(), zipEntries), getBase64Binary(m.getCert(), zipEntries));
        addSigner(en);
      }
    }

    // Requestors
    if (root.getRequestors() != null) {
      for (CaConfType.Requestor m : root.getRequestors()) {
        String conf;
        if (m.getConf() != null) {
          conf = getValue(m.getConf(), zipEntries);
        } else {
          conf = getBase64Binary(m.getBinaryConf(), zipEntries);
        }

        MgmtEntry.Requestor en =
            new MgmtEntry.Requestor(new NameId(null, m.getName()), m.getType(), conf);
        addRequestor(en);
      }
    }

    // Users
    if (root.getUsers() != null) {
      for (CaConfType.User m : root.getUsers()) {
        boolean active = m.isActive();
        String password = m.getPassword();
        if (password != null) {
          MgmtEntry.AddUser en =
              new MgmtEntry.AddUser(new NameId(null, m.getName()), active, password);
          addUser(en);
        } else {
          MgmtEntry.User en = new MgmtEntry.User(new NameId(null, m.getName()), active,
              m.getHashedPassword());
          addUser(en);
        }
      }
    }

    // Publishers
    if (root.getPublishers() != null) {
      for (CaConfType.NameTypeConf m : root.getPublishers()) {
        MgmtEntry.Publisher en = new MgmtEntry.Publisher(new NameId(null, m.getName()),
            expandConf(m.getType()), getValue(m.getConf(), zipEntries));
        addPublisher(en);
      }
    }

    // Profiles
    if (root.getProfiles() != null) {
      for (CaConfType.NameTypeConf m : root.getProfiles()) {
        MgmtEntry.Certprofile en = new MgmtEntry.Certprofile(new NameId(null, m.getName()),
            expandConf(m.getType()), getValue(m.getConf(), zipEntries));
        addProfile(en);
      }
    }

    // CAs
    if (root.getCas() != null) {
      for (CaConfType.Ca m : root.getCas()) {
        String name = m.getName();
        GenSelfIssued genSelfIssued = null;
        MgmtEntry.Ca caEntry = null;

        if (m.getCaInfo() != null) {
          CaConfType.CaInfo ci = m.getCaInfo();
          if (ci.getGenSelfIssued() != null) {
            if (ci.getCert() != null) {
              throw new InvalidConfException("cert.file of CA " + name + " may not be set");
            }
            byte[] csr = getBinary(ci.getGenSelfIssued().getCsr(), zipEntries);
            BigInteger serialNumber = null;
            String str = ci.getGenSelfIssued().getSerialNumber();
            if (str != null) {
              if (str.startsWith("0x") || str.startsWith("0X")) {
                serialNumber = new BigInteger(str.substring(2), 16);
              } else {
                serialNumber = new BigInteger(str);
              }
            }

            genSelfIssued = new GenSelfIssued(ci.getGenSelfIssued().getProfile(),
                csr, serialNumber, ci.getGenSelfIssued().getCertOutform());
          }

          CaUris caUris;
          if (ci.getCaUris() == null) {
            caUris = CaUris.EMPTY_INSTANCE;
          } else {
            CaConfType.CaUris uris = ci.getCaUris();
            caUris = new CaUris(uris.getCacertUris(), uris.getOcspUris(),
                uris.getCrlUris(), uris.getDeltacrlUris());
          }

          int exprirationPeriod = (ci.getExpirationPeriod() == null) ? 365
              : ci.getExpirationPeriod().intValue();

          int numCrls = (ci.getNumCrls() == null) ? 30 : ci.getNumCrls().intValue();

          caEntry = new MgmtEntry.Ca(new NameId(null, name), ci.getSnSize(), ci.getNextCrlNo(),
              expandConf(ci.getSignerType()), getValue(ci.getSignerConf(), zipEntries), caUris,
              numCrls, exprirationPeriod);

          if (CollectionUtil.isNonEmpty(ci.getCmpControl())) {
            caEntry.setCmpControl(new CmpControl(
                    new ConfPairs(ci.getCmpControl()).getEncoded()));
          }

          if (ci.getCrlControl() != null) {
            caEntry.setCrlControl(new CrlControl(
                new ConfPairs(ci.getCrlControl()).getEncoded()));
          }

          if (ci.getScepControl() != null) {
            caEntry.setScepControl(new ScepControl(
                new ConfPairs(ci.getScepControl()).getEncoded()));
          }

          if (ci.getCtLogControl() != null) {
            caEntry.setCtLogControl(new CtLogControl(
                new ConfPairs(ci.getCtLogControl()).getEncoded()));
          }

          caEntry.setCmpResponderName(ci.getCmpResponderName());
          caEntry.setScepResponderName(ci.getScepResponderName());
          caEntry.setCrlSignerName(ci.getCrlSignerName());

          caEntry.setDuplicateKeyPermitted(ci.isDuplicateKey());
          caEntry.setDuplicateSubjectPermitted(ci.isDuplicateSubject());
          if (ci.getExtraControl() != null) {
            caEntry.setExtraControl(new ConfPairs(ci.getExtraControl()).unmodifiable());
          }

          int keepExpiredCertDays = (ci.getKeepExpiredCertDays() == null) ? -1
              : ci.getKeepExpiredCertDays().intValue();
          caEntry.setKeepExpiredCertInDays(keepExpiredCertDays);

          caEntry.setMaxValidity(Validity.getInstance(ci.getMaxValidity()));
          caEntry.setPermission(getIntPermission(ci.getPermissions()));

          if (ci.getProtocolSupport() != null) {
            caEntry.setProtocolSupport(new ProtocolSupport(ci.getProtocolSupport()));
          }

          if (ci.getDhpocControl() != null) {
            caEntry.setDhpocControl(getValue(ci.getDhpocControl(), zipEntries));
          }

          caEntry.setSaveRequest(ci.isSaveReq());
          caEntry.setStatus(CaStatus.forName(ci.getStatus()));

          if (ci.getValidityMode() != null) {
            caEntry.setValidityMode(ValidityMode.forName(ci.getValidityMode()));
          }

          if (ci.getGenSelfIssued() == null) {
            X509Certificate caCert;

            if (ci.getCert() != null) {
              byte[] bytes = getBinary(ci.getCert(), zipEntries);
              try {
                caCert = X509Util.parseCert(bytes);
              } catch (CertificateException ex) {
                throw new InvalidConfException("invalid certificate of CA " + name, ex);
              }
            } else {
              // extract from the signer configuration
              ConcurrentContentSigner signer;
              try {
                List<String[]> signerConfs = MgmtEntry.Ca.splitCaSignerConfs(
                    getValue(ci.getSignerConf(), zipEntries));
                SignerConf signerConf = new SignerConf(signerConfs.get(0)[1]);

                signer = securityFactory.createSigner(expandConf(ci.getSignerType()), signerConf,
                    (X509Certificate) null);
              } catch (ObjectCreationException | XiSecurityException ex) {
                throw new InvalidConfException("could not create CA signer for CA " + name, ex);
              }
              caCert = signer.getCertificate();
            }

            caEntry.setCert(caCert);

            // certchain
            if (CollectionUtil.isNonEmpty(ci.getCertchain())) {
              List<X509Certificate> certchain = new LinkedList<>();
              for (FileOrBinary cc : ci.getCertchain()) {
                byte[] bytes = getBinary(cc, zipEntries);
                try {
                  certchain.add(X509Util.parseCert(bytes));
                } catch (CertificateException ex) {
                  throw new InvalidConfException("invalid certchain for CA " + name, ex);
                }
              }

              caEntry.setCertchain(certchain);
            }
          }
        }

        List<MgmtEntry.CaHasRequestor> caHasRequestors = null;
        if (m.getRequestors() != null) {
          caHasRequestors = new LinkedList<>();
          for (CaConfType.CaHasRequestor req : m.getRequestors()) {
            MgmtEntry.CaHasRequestor en =
                new MgmtEntry.CaHasRequestor(new NameId(null, req.getRequestorName()));
            en.setRa(req.isRa());

            if (req.getProfiles() != null && !req.getProfiles().isEmpty()) {
              en.setProfiles(new HashSet<>(req.getProfiles()));
            }

            en.setPermission(getIntPermission(req.getPermissions()));
            caHasRequestors.add(en);
          }
        }

        List<MgmtEntry.CaHasUser> caHasUsers = null;
        if (m.getUsers() != null) {
          caHasUsers = new LinkedList<>();
          for (CaConfType.CaHasUser req : m.getUsers()) {
            MgmtEntry.CaHasUser en = new MgmtEntry.CaHasUser(new NameId(null, req.getUserName()));
            en.setPermission(getIntPermission(req.getPermissions()));
            if (req.getProfiles() != null && !req.getProfiles().isEmpty()) {
              en.setProfiles(new HashSet<>(req.getProfiles()));
            }
            caHasUsers.add(en);
          }
        }

        List<String> aliases = null;
        if (m.getAliases() != null && !m.getAliases().isEmpty()) {
          aliases = m.getAliases();
        }
        List<String> profileNames = null;
        if (m.getProfiles() != null && !m.getProfiles().isEmpty()) {
          profileNames = m.getProfiles();
        }

        List<String> publisherNames = null;
        if (m.getPublishers() != null && !m.getPublishers().isEmpty()) {
          publisherNames = m.getPublishers();
        }

        SingleCa singleCa = new SingleCa(name, genSelfIssued, caEntry, aliases,
            profileNames, caHasRequestors, caHasUsers, publisherNames);
        addSingleCa(singleCa);
      }
    }

  }

  public void addSigner(MgmtEntry.Signer signer) {
    Args.notNull(signer, "signer");
    this.signers.put(signer.getName(), signer);
  }

  public Set<String> getSignerNames() {
    return Collections.unmodifiableSet(signers.keySet());
  }

  public MgmtEntry.Signer getSigner(String name) {
    return signers.get(Args.notNull(name, "name"));
  }

  public void addRequestor(MgmtEntry.Requestor requestor) {
    Args.notNull(requestor, "requestor");
    this.requestors.put(requestor.getIdent().getName(), requestor);
  }

  public void addUser(MgmtEntry.User user) {
    Args.notNull(user, "user");
    this.users.put(user.getIdent().getName(), user);
  }

  public void addUser(MgmtEntry.AddUser user) {
    Args.notNull(user, "user");
    this.users.put(user.getIdent().getName(), user);
  }

  public Set<String> getRequestorNames() {
    return Collections.unmodifiableSet(requestors.keySet());
  }

  public MgmtEntry.Requestor getRequestor(String name) {
    return requestors.get(Args.notNull(name, "name"));
  }

  public Set<String> getUserNames() {
    return Collections.unmodifiableSet(users.keySet());
  }

  public Object getUser(String name) {
    return users.get(Args.notNull(name, "name"));
  }

  public void addPublisher(MgmtEntry.Publisher publisher) {
    Args.notNull(publisher, "publisher");
    this.publishers.put(publisher.getIdent().getName(), publisher);
  }

  public Set<String> getPublisherNames() {
    return Collections.unmodifiableSet(publishers.keySet());
  }

  public MgmtEntry.Publisher getPublisher(String name) {
    return publishers.get(Args.notNull(name, "name"));
  }

  public void addProfile(MgmtEntry.Certprofile profile) {
    Args.notNull(profile, "profile");
    this.certprofiles.put(profile.getIdent().getName(), profile);
  }

  public Set<String> getCertprofileNames() {
    return Collections.unmodifiableSet(certprofiles.keySet());
  }

  public MgmtEntry.Certprofile getCertprofile(String name) {
    return certprofiles.get(Args.notNull(name, "name"));
  }

  public void addSingleCa(SingleCa singleCa) {
    Args.notNull(singleCa, "singleCa");
    this.cas.put(singleCa.getName(), singleCa);
  }

  public Set<String> getCaNames() {
    return Collections.unmodifiableSet(cas.keySet());
  }

  public SingleCa getCa(String name) {
    return cas.get(Args.notNull(name, "name"));
  }

  private String getValue(FileOrValue fileOrValue, Map<String, byte[]> zipEntries)
      throws IOException {
    if (fileOrValue == null) {
      return null;
    }

    if (fileOrValue.getValue() != null) {
      return expandConf(fileOrValue.getValue());
    }

    String fileName = fileOrValue.getFile();
    byte[] binary = zipEntries.get(fileName);
    if (binary == null) {
      throw new IOException("could not find ZIP entry " + fileName);
    }

    return expandConf(new String(binary, "UTF-8"));
  }

  private String getBase64Binary(FileOrBinary fileOrBinary, Map<String, byte[]> zipEntries)
      throws IOException {
    byte[] binary = getBinary(fileOrBinary, zipEntries);
    return (binary == null) ? null : Base64.encodeToString(binary);
  }

  private static byte[] read(InputStream in) throws IOException {
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    int readed = 0;
    byte[] buffer = new byte[2048];
    while ((readed = in.read(buffer)) != -1) {
      bout.write(buffer, 0, readed);
    }

    return bout.toByteArray();
  }

  private byte[] getBinary(FileOrBinary fileOrBinary, Map<String, byte[]> zipEntries)
      throws IOException {
    if (fileOrBinary == null) {
      return null;
    }

    if (fileOrBinary.getBinary() != null) {
      return fileOrBinary.getBinary();
    }

    String fileName = fileOrBinary.getFile();
    byte[] binary = zipEntries.get(fileName);
    if (binary == null) {
      throw new IOException("could not find ZIP entry " + fileName);
    }

    return binary;
  }

  private String expandConf(String confStr) {
    if (confStr == null || !confStr.contains("${") || confStr.indexOf('}') == -1) {
      return confStr;
    }

    for (String name : properties.keySet()) {
      String placeHolder = "${" + name + "}";
      while (confStr.contains(placeHolder)) {
        confStr = confStr.replace(placeHolder, properties.get(name));
      }
    }

    return confStr;
  }

  private static int getIntPermission(List<String> permissions) throws InvalidConfException {
    int ret = 0;
    for (String permission : permissions) {
      Integer ii = PermissionConstants.getPermissionForText(permission);
      if (ii == null) {
        throw new InvalidConfException("invalid permission " + permission);
      }
      ret |= ii;
    }
    return ret;
  }

}
