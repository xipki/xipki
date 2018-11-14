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

package org.xipki.qa.ca;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.qa.ca.jaxb.CertprofileType;
import org.xipki.qa.ca.jaxb.FileOrValueType;
import org.xipki.qa.ca.jaxb.IssuerType;
import org.xipki.qa.ca.jaxb.ObjectFactory;
import org.xipki.qa.ca.jaxb.QaconfType;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;
import org.xml.sax.SAXException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaQaSystemManagerImpl implements CaQaSystemManager {

  private static final Logger LOG = LoggerFactory.getLogger(CaQaSystemManagerImpl.class);

  private final Unmarshaller jaxbUnmarshaller;

  private String confFile;

  private Map<String, CertprofileQa> x509ProfileMap = new HashMap<>();

  private Map<String, IssuerInfo> x509IssuerInfoMap = new HashMap<>();

  private AtomicBoolean initialized = new AtomicBoolean(false);

  public CaQaSystemManagerImpl() throws JAXBException, SAXException {
    JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
    jaxbUnmarshaller = context.createUnmarshaller();

    final SchemaFactory schemaFact = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    URL url = CaQaSystemManagerImpl.class.getResource("/xsd/caqa-conf.xsd");
    jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
  }

  public String getConfFile() {
    return confFile;
  }

  public void setConfFile(String confFile) {
    this.confFile = Args.notBlank(confFile, "confFile");
  }

  @Override
  public boolean init() {
    if (StringUtil.isBlank(confFile)) {
      throw new IllegalStateException("confFile must not be null and empty");
    }

    LOG.info("initializing ...");
    initialized.set(false);
    x509IssuerInfoMap.clear();
    x509IssuerInfoMap.clear();

    QaconfType qaConf;
    try {
      InputStream issuerConfStream = Files.newInputStream(Paths.get(confFile));
      qaConf = parseQaConf(issuerConfStream);
    } catch (IOException | JAXBException | SAXException ex) {
      final String message = "could not parse the QA configuration";
      LogUtil.error(LOG, ex, message);
      return false;
    }

    if (qaConf.getIssuers() != null) {
      List<IssuerType> issuerTypes = qaConf.getIssuers().getIssuer();
      for (IssuerType issuerType : issuerTypes) {
        byte[] certBytes;
        try {
          certBytes = readData(issuerType.getCert());
        } catch (IOException ex) {
          LogUtil.error(LOG, ex, "could not read the certificate bytes of issuer "
              + issuerType.getName());
          continue;
        }

        String str = issuerType.getValidityMode();
        boolean cutoffNotAfter;
        if (StringUtil.isBlank(str) || "CUTOFF".equalsIgnoreCase(str)) {
          cutoffNotAfter = true;
        } else if ("LAX".equalsIgnoreCase(str)) {
          cutoffNotAfter = false;
        } else {
          LOG.error("invalid validityMode {}", str);
          return false;
        }

        IssuerInfo issuerInfo;
        try {
          issuerInfo = new IssuerInfo(issuerType.getCaIssuerUrl(),
              issuerType.getOcspUrl(), issuerType.getCrlUrl(),
              issuerType.getDeltaCrlUrl(), certBytes, cutoffNotAfter);
        } catch (CertificateException ex) {
          LogUtil.error(LOG, ex, "could not parse certificate of issuer " + issuerType.getName());
          continue;
        }

        x509IssuerInfoMap.put(issuerType.getName(), issuerInfo);
        LOG.info("configured X509 issuer {}", issuerType.getName());
      }
    }

    if (qaConf.getCertprofiles() != null) {
      List<CertprofileType> certprofileTypes = qaConf.getCertprofiles().getCertprofile();
      for (CertprofileType type : certprofileTypes) {
        String name = type.getName();
        try {
          byte[] content = readData(type);
          x509ProfileMap.put(name, new CertprofileQa(content));
          LOG.info("configured X509 certificate profile {}", name);
        } catch (IOException | CertprofileException ex) {
          LogUtil.error(LOG, ex, "could not parse QA certificate profile " + name);
          continue;
        }
      }
    }

    initialized.set(true);
    LOG.info("initialized");

    return true;
  } // method init

  @Override
  public void close() {
  }

  @Override
  public Set<String> getIssuerNames() {
    assertInitialized();
    return Collections.unmodifiableSet(x509IssuerInfoMap.keySet());
  }

  @Override
  public IssuerInfo getIssuer(String issuerName) {
    assertInitialized();
    return x509IssuerInfoMap.get(Args.notNull(issuerName, "issuerName"));
  }

  @Override
  public Set<String> getCertprofileNames() {
    assertInitialized();
    return Collections.unmodifiableSet(x509ProfileMap.keySet());
  }

  @Override
  public CertprofileQa getCertprofile(String certprofileName) {
    assertInitialized();
    return x509ProfileMap.get(Args.notNull(certprofileName, "certprofileName"));
  }

  private QaconfType parseQaConf(InputStream confStream)
      throws IOException, JAXBException, SAXException {
    JAXBElement<?> rootElement;
    try {
      rootElement = (JAXBElement<?>) jaxbUnmarshaller.unmarshal(confStream);
    } finally {
      confStream.close();
    }

    Object rootType = rootElement.getValue();
    if (rootType instanceof QaconfType) {
      return (QaconfType) rootElement.getValue();
    } else {
      throw new SAXException("invalid root element type");
    }
  }

  private void assertInitialized() {
    if (!initialized.get()) {
      throw new IllegalStateException("CaQaSystemManager is not started yet");
    }
  }

  private static byte[] readData(FileOrValueType fileOrValue) throws IOException {
    byte[] data = fileOrValue.getValue();
    if (data == null) {
      data = IoUtil.read(fileOrValue.getFile());
    }
    return data;
  }

}
