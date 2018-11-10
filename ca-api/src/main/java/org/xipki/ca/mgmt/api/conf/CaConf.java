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

package org.xipki.ca.mgmt.api.conf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.mgmt.api.AddUserEntry;
import org.xipki.ca.mgmt.api.CaEntry;
import org.xipki.ca.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.mgmt.api.CaHasUserEntry;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.ca.mgmt.api.CaStatus;
import org.xipki.ca.mgmt.api.CertprofileEntry;
import org.xipki.ca.mgmt.api.CmpControl;
import org.xipki.ca.mgmt.api.CrlControl;
import org.xipki.ca.mgmt.api.PermissionConstants;
import org.xipki.ca.mgmt.api.ProtocolSupport;
import org.xipki.ca.mgmt.api.PublisherEntry;
import org.xipki.ca.mgmt.api.RequestorEntry;
import org.xipki.ca.mgmt.api.ScepControl;
import org.xipki.ca.mgmt.api.SignerEntry;
import org.xipki.ca.mgmt.api.UserEntry;
import org.xipki.ca.mgmt.api.ValidityMode;
import org.xipki.ca.mgmt.api.conf.jaxb.CaHasRequestorType;
import org.xipki.ca.mgmt.api.conf.jaxb.CaHasUserType;
import org.xipki.ca.mgmt.api.conf.jaxb.CaInfoType;
import org.xipki.ca.mgmt.api.conf.jaxb.CaType;
import org.xipki.ca.mgmt.api.conf.jaxb.CaUrisType;
import org.xipki.ca.mgmt.api.conf.jaxb.CaconfType;
import org.xipki.ca.mgmt.api.conf.jaxb.FileOrBinaryType;
import org.xipki.ca.mgmt.api.conf.jaxb.FileOrValueType;
import org.xipki.ca.mgmt.api.conf.jaxb.NameValueType;
import org.xipki.ca.mgmt.api.conf.jaxb.ObjectFactory;
import org.xipki.ca.mgmt.api.conf.jaxb.PermissionsType;
import org.xipki.ca.mgmt.api.conf.jaxb.ProfileType;
import org.xipki.ca.mgmt.api.conf.jaxb.PublisherType;
import org.xipki.ca.mgmt.api.conf.jaxb.RequestorType;
import org.xipki.ca.mgmt.api.conf.jaxb.SignerType;
import org.xipki.ca.mgmt.api.conf.jaxb.UrisType;
import org.xipki.ca.mgmt.api.conf.jaxb.UserType;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.ConfPairs;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ParamUtil;
import org.xipki.util.XmlUtil;
import org.xml.sax.SAXException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

public class CaConf {
  private static final Logger LOG = LoggerFactory.getLogger(CaConf.class);

  private final Map<String, String> properties = new HashMap<>();

  private final Map<String, SignerEntry> signers = new HashMap<>();

  private final Map<String, RequestorEntry> requestors = new HashMap<>();

  private final Map<String, Object> users = new HashMap<>();

  private final Map<String, PublisherEntry> publishers = new HashMap<>();

  private final Map<String, CertprofileEntry> certprofiles = new HashMap<>();

  private final Map<String, SingleCaConf> cas = new HashMap<>();

  public CaConf(File confFile, SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException, JAXBException, SAXException {
    ParamUtil.requireNonNull("confFile", confFile);
    ParamUtil.requireNonNull("securityFactory", securityFactory);
    confFile = IoUtil.expandFilepath(confFile);

    init(Files.newInputStream(confFile.toPath()), securityFactory);
  }

  public CaConf(InputStream confFileZipStream, SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException, JAXBException, SAXException {
    ParamUtil.requireNonNull("confFileZipStream", confFileZipStream);
    ParamUtil.requireNonNull("securityFactory", securityFactory);

    init(confFileZipStream, securityFactory);
  }

  private final void init(InputStream zipFileStream, SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException, JAXBException, SAXException {
    ZipInputStream zipStream = new ZipInputStream(zipFileStream);

    try {
      Map<String, byte[]> zipEntries = new HashMap<>();

      ZipEntry zipEntry;
      while ((zipEntry = zipStream.getNextEntry()) != null) {
        byte[] zipEntryBytes = read(zipStream);
        zipEntries.put(zipEntry.getName(), zipEntryBytes);
      }

      JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);

      SchemaFactory schemaFact = SchemaFactory.newInstance(
          javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
      URL url = CaConf.class.getResource("/xsd/caconf.xsd");
      Unmarshaller jaxbUnmarshaller = context.createUnmarshaller();
      jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));

      CaconfType root = (CaconfType) ((JAXBElement<?>)
          jaxbUnmarshaller.unmarshal(new ByteArrayInputStream(zipEntries.get("caconf.xml"))))
          .getValue();

      init0(root, zipEntries, securityFactory);
    } catch (JAXBException ex) {
      throw XmlUtil.convert(ex);
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

  private final void init0(CaconfType jaxb, Map<String, byte[]> zipEntries,
      SecurityFactory securityFactory)
      throws IOException, InvalidConfException, CaMgmtException {
    if (jaxb.getProperties() != null) {
      for (NameValueType m : jaxb.getProperties().getProperty()) {
        String name = m.getName();
        if (properties.containsKey(name)) {
          throw new InvalidConfException("Property " + name + " already defined");
        }
        properties.put(name, m.getValue());
      }
    }

    // Signers
    if (jaxb.getSigners() != null) {
      for (SignerType m : jaxb.getSigners().getSigner()) {
        SignerEntry en = new SignerEntry(m.getName(), expandConf(m.getType()),
            getValue(m.getConf(), zipEntries), getBase64Binary(m.getCert(), zipEntries));
        addSigner(en);
      }
    }

    // Requestors
    if (jaxb.getRequestors() != null) {
      for (RequestorType m : jaxb.getRequestors().getRequestor()) {
        String conf;
        if (m.getConf() != null) {
          conf = getValue(m.getConf(), zipEntries);
        } else {
          conf = getBase64Binary(m.getBinaryConf(), zipEntries);
        }

        RequestorEntry en = new RequestorEntry(new NameId(null, m.getName()), m.getType(), conf);
        addRequestor(en);
      }
    }

    // Users
    if (jaxb.getUsers() != null) {
      for (UserType m : jaxb.getUsers().getUser()) {
        boolean active = (m.isActive() != null) ? m.isActive() : true;
        String password = m.getPassword();
        if (password != null) {
          AddUserEntry en = new AddUserEntry(new NameId(null, m.getName()), active, password);
          addUser(en);
        } else {
          UserEntry en = new UserEntry(new NameId(null, m.getName()), active,
              m.getHashedPassword());
          addUser(en);
        }
      }
    }

    // Publishers
    if (jaxb.getPublishers() != null) {
      for (PublisherType m : jaxb.getPublishers().getPublisher()) {
        PublisherEntry en = new PublisherEntry(new NameId(null, m.getName()),
            expandConf(m.getType()), getValue(m.getConf(), zipEntries));
        addPublisher(en);
      }
    }

    // Profiles
    if (jaxb.getProfiles() != null) {
      for (ProfileType m : jaxb.getProfiles().getProfile()) {
        CertprofileEntry en = new CertprofileEntry(new NameId(null, m.getName()),
            expandConf(m.getType()), getValue(m.getConf(), zipEntries));
        addProfile(en);
      }
    }

    // CAs
    if (jaxb.getCas() != null) {
      for (CaType m : jaxb.getCas().getCa()) {
        String name = m.getName();
        GenSelfIssued genSelfIssued = null;
        CaEntry caEntry = null;

        if (m.getCaInfo() != null) {
          CaInfoType ci = m.getCaInfo();
          if (ci.getGenSelfIssued() != null) {
            if (ci.getCert() != null) {
              throw new InvalidConfException("cert.file of CA " + name + " must not be set");
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
            CaUrisType uris = ci.getCaUris();
            caUris = new CaUris(getUris(uris.getCacertUris()), getUris(uris.getOcspUris()),
                getUris(uris.getCrlUris()), getUris(uris.getDeltacrlUris()));
          }

          int exprirationPeriod = (ci.getExpirationPeriod() == null) ? 365
              : ci.getExpirationPeriod().intValue();

          int numCrls = (ci.getNumCrls() == null) ? 30 : ci.getNumCrls().intValue();

          caEntry = new CaEntry(new NameId(null, name), ci.getSnSize(), ci.getNextCrlNo(),
              expandConf(ci.getSignerType()), getValue(ci.getSignerConf(), zipEntries), caUris,
              numCrls, exprirationPeriod);

          if (ci.getCmpControl() != null) {
            caEntry.setCmpControl(new CmpControl(ci.getCmpControl()));
          }

          if (ci.getCrlControl() != null) {
            caEntry.setCrlControl(new CrlControl(ci.getCrlControl()));
          }

          if (ci.getScepControl() != null) {
            caEntry.setScepControl(new ScepControl(ci.getScepControl()));
          }

          caEntry.setCmpResponderName(ci.getCmpResponderName());
          caEntry.setScepResponderName(ci.getScepResponderName());
          caEntry.setCrlSignerName(ci.getCrlSignerName());

          caEntry.setDuplicateKeyPermitted(ci.isDuplicateKey());
          caEntry.setDuplicateSubjectPermitted(ci.isDuplicateSubject());
          if (ci.getExtraControl() != null) {
            String value = getValue(ci.getExtraControl(), zipEntries);
            if (value != null) {
              caEntry.setExtraControl(new ConfPairs(value).unmodifiable());
            }
          }

          int keepExpiredCertDays = (ci.getKeepExpiredCertDays() == null) ? -1
              : ci.getKeepExpiredCertDays().intValue();
          caEntry.setKeepExpiredCertInDays(keepExpiredCertDays);

          caEntry.setMaxValidity(CertValidity.getInstance(ci.getMaxValidity()));
          caEntry.setPermission(getIntPermission(ci.getPermissions()));

          if (ci.getProtocolSupport() != null) {
            caEntry.setProtocolSupport(new ProtocolSupport(ci.getProtocolSupport()));
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
                List<String[]> signerConfs = CaEntry.splitCaSignerConfs(
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
          }
        }

        List<CaHasRequestorEntry> caHasRequestors = null;
        if (m.getRequestors() != null) {
          caHasRequestors = new LinkedList<>();
          for (CaHasRequestorType req : m.getRequestors().getRequestor()) {
            CaHasRequestorEntry en =
                new CaHasRequestorEntry(new NameId(null, req.getRequestorName()));
            en.setRa(req.isRa());

            if (req.getProfiles() != null && !req.getProfiles().getProfile().isEmpty()) {
              en.setProfiles(new HashSet<>(req.getProfiles().getProfile()));
            }

            en.setPermission(getIntPermission(req.getPermissions()));
            caHasRequestors.add(en);
          }
        }

        List<CaHasUserEntry> caHasUsers = null;
        if (m.getUsers() != null) {
          caHasUsers = new LinkedList<>();
          for (CaHasUserType req : m.getUsers().getUser()) {
            CaHasUserEntry en = new CaHasUserEntry(new NameId(null, req.getUserName()));
            en.setPermission(getIntPermission(req.getPermissions()));
            if (req.getProfiles() != null && !req.getProfiles().getProfile().isEmpty()) {
              en.setProfiles(new HashSet<>(req.getProfiles().getProfile()));
            }
            caHasUsers.add(en);
          }
        }

        List<String> aliases = null;
        if (m.getAliases() != null && !m.getAliases().getAlias().isEmpty()) {
          aliases = m.getAliases().getAlias();
        }
        List<String> profileNames = null;
        if (m.getProfiles() != null && !m.getProfiles().getProfile().isEmpty()) {
          profileNames = m.getProfiles().getProfile();
        }

        List<String> publisherNames = null;
        if (m.getPublishers() != null && !m.getPublishers().getPublisher().isEmpty()) {
          publisherNames = m.getPublishers().getPublisher();
        }

        SingleCaConf singleCa = new SingleCaConf(name, genSelfIssued, caEntry, aliases,
            profileNames, caHasRequestors, caHasUsers, publisherNames);
        addSingleCa(singleCa);
      }
    }

  }

  public void addSigner(SignerEntry signer) {
    ParamUtil.requireNonNull("signer", signer);
    this.signers.put(signer.getName(), signer);
  }

  public Set<String> getSignerNames() {
    return Collections.unmodifiableSet(signers.keySet());
  }

  public SignerEntry getSigner(String name) {
    return signers.get(ParamUtil.requireNonNull("name", name));
  }

  public void addRequestor(RequestorEntry requestor) {
    ParamUtil.requireNonNull("requestor", requestor);
    this.requestors.put(requestor.getIdent().getName(), requestor);
  }

  public void addUser(UserEntry user) {
    ParamUtil.requireNonNull("user", user);
    this.users.put(user.getIdent().getName(), user);
  }

  public void addUser(AddUserEntry user) {
    ParamUtil.requireNonNull("user", user);
    this.users.put(user.getIdent().getName(), user);
  }

  public Set<String> getRequestorNames() {
    return Collections.unmodifiableSet(requestors.keySet());
  }

  public RequestorEntry getRequestor(String name) {
    return requestors.get(ParamUtil.requireNonNull("name", name));
  }

  public Set<String> getUserNames() {
    return Collections.unmodifiableSet(users.keySet());
  }

  public Object getUser(String name) {
    return users.get(ParamUtil.requireNonNull("name", name));
  }

  public void addPublisher(PublisherEntry publisher) {
    ParamUtil.requireNonNull("publisher", publisher);
    this.publishers.put(publisher.getIdent().getName(), publisher);
  }

  public Set<String> getPublisherNames() {
    return Collections.unmodifiableSet(publishers.keySet());
  }

  public PublisherEntry getPublisher(String name) {
    return publishers.get(ParamUtil.requireNonNull("name", name));
  }

  public void addProfile(CertprofileEntry profile) {
    ParamUtil.requireNonNull("profile", profile);
    this.certprofiles.put(profile.getIdent().getName(), profile);
  }

  public Set<String> getCertprofileNames() {
    return Collections.unmodifiableSet(certprofiles.keySet());
  }

  public CertprofileEntry getCertprofile(String name) {
    return certprofiles.get(ParamUtil.requireNonNull("name", name));
  }

  public void addSingleCa(SingleCaConf singleCa) {
    ParamUtil.requireNonNull("singleCa", singleCa);
    this.cas.put(singleCa.getName(), singleCa);
  }

  public Set<String> getCaNames() {
    return Collections.unmodifiableSet(cas.keySet());
  }

  public SingleCaConf getCa(String name) {
    return cas.get(ParamUtil.requireNonNull("name", name));
  }

  private String getValue(FileOrValueType fileOrValue, Map<String, byte[]> zipEntries)
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

  private String getBase64Binary(FileOrBinaryType fileOrBinary, Map<String, byte[]> zipEntries)
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

  private byte[] getBinary(FileOrBinaryType fileOrBinary, Map<String, byte[]> zipEntries)
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

  private List<String> getUris(UrisType jaxb) {
    if (jaxb == null) {
      return null;
    }

    List<String> ret = new ArrayList<>(jaxb.getUri().size());
    for (String m : jaxb.getUri()) {
      ret.add(expandConf(m));
    }
    return ret;
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

  private static int getIntPermission(PermissionsType type) throws InvalidConfException {
    int ret = 0;
    for (String permission : type.getPermission()) {
      Integer ii = PermissionConstants.getPermissionForText(permission);
      if (ii == null) {
        throw new InvalidConfException("invalid permission " + type);
      }
      ret |= ii;
    }
    return ret;
  }

}
