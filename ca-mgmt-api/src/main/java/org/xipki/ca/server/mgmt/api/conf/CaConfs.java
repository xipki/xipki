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

package org.xipki.ca.server.mgmt.api.conf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaInfoType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.CaconfType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.FileOrBinaryType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.FileOrValueType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.NameValueType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ObjectFactory;
import org.xipki.ca.server.mgmt.api.conf.jaxb.ProfileType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.PublisherType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.RequestorType;
import org.xipki.ca.server.mgmt.api.conf.jaxb.SignerType;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.util.Base64;
import org.xipki.util.ConfPairs;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.XmlUtil;
import org.xml.sax.SAXException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

public class CaConfs {
  private static final Logger LOG = LoggerFactory.getLogger(CaConfs.class);

  private static final String APP_DIR = "APP_DIR";

  private CaConfs() {
  }

  public static void marshal(CaconfType jaxb, OutputStream out)
      throws JAXBException, SAXException {
    ParamUtil.requireNonNull("jaxb", jaxb);
    ParamUtil.requireNonNull("out", out);

    try {
      JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);

      SchemaFactory schemaFact = SchemaFactory.newInstance(
          javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
      URL url = CaConf.class.getResource("/xsd/caconf.xsd");
      Marshaller jaxbMarshaller = context.createMarshaller();
      jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
      jaxbMarshaller.setSchema(schemaFact.newSchema(url));

      jaxbMarshaller.marshal(new ObjectFactory().createCaconf(jaxb), out);
    } catch (JAXBException ex) {
      throw XmlUtil.convert(ex);
    }
  }

  public static InputStream convertFileConfToZip(String confFilename)
      throws IOException, JAXBException, InvalidConfException, SAXException {
    ParamUtil.requireNonNull("confFilename", confFilename);

    ByteArrayOutputStream bytesStream = new ByteArrayOutputStream(1048576); // initial 1M
    ZipOutputStream zipStream = new ZipOutputStream(bytesStream);
    zipStream.setLevel(Deflater.BEST_SPEED);

    File confFile = new File(confFilename);
    confFile = IoUtil.expandFilepath(confFile);

    InputStream caConfStream = null;
    String baseDir = null;

    try {
      caConfStream = Files.newInputStream(confFile.toPath());

      JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);

      SchemaFactory schemaFact = SchemaFactory.newInstance(
          javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
      URL url = CaConfs.class.getResource("/xsd/caconf.xsd");
      Unmarshaller jaxbUnmarshaller = context.createUnmarshaller();
      jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));

      CaconfType jaxb = (CaconfType) ((JAXBElement<?>)
          jaxbUnmarshaller.unmarshal(caConfStream)).getValue();

      baseDir = jaxb.getBasedir();
      if (StringUtil.isBlank(baseDir)) {
        File confFileParent = confFile.getParentFile();
        baseDir = (confFileParent == null) ? "." : confFileParent.getPath();
      } else if (APP_DIR.equalsIgnoreCase(baseDir)) {
        baseDir = ".";
      }
      // clear the baseDir in ZIP file
      jaxb.setBasedir(null);

      final Map<String, String> properties = new HashMap<>();

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
          String name = m.getName();

          if (m.getConf() != null) {
            String conf = convertSignerConf(m.getConf(), properties, baseDir);
            if (conf.length() > 200) {
              String zipEntryName = "files/signer-" + name + ".conf";
              createFileOrValue(zipStream, conf, zipEntryName);
              m.getConf().setFile(zipEntryName);
              m.getConf().setValue(null);
            } else {
              m.getConf().setFile(null);
              m.getConf().setValue(conf);
            }
          }

          if (m.getCert() != null && m.getCert().getFile() != null) {
            String zipEntryName = "files/signer-" + name + ".crt";
            byte[] value = getBinary(m.getConf().getFile(), properties, baseDir);
            createFileOrBinary(zipStream, value, zipEntryName);
            m.getCert().setFile(zipEntryName);
          }
        }
      }

      // Requestors
      if (jaxb.getRequestors() != null) {
        for (RequestorType m : jaxb.getRequestors().getRequestor()) {
          String name = m.getName();

          if (m.getConf() != null && m.getConf().getFile() != null) {
            String zipEntryName = "files/requestor-" + name + ".conf";
            String value = getValue(m.getConf().getFile(), properties, baseDir);
            createFileOrValue(zipStream, value, zipEntryName);
            m.getConf().setFile(zipEntryName);
          }

          if (m.getBinaryConf() != null && m.getBinaryConf().getFile() != null) {
            String zipEntryName = "files/requestor-" + name + ".bin";
            byte[] value = getBinary(m.getBinaryConf().getFile(), properties, baseDir);
            createFileOrBinary(zipStream, value, zipEntryName);
            m.getBinaryConf().setFile(zipEntryName);
          }
        }
      }

      // Publishers
      if (jaxb.getPublishers() != null) {
        for (PublisherType m : jaxb.getPublishers().getPublisher()) {
          String name = m.getName();

          if (m.getConf() != null && m.getConf().getFile() != null) {
            String zipEntryName = "files/publisher-" + name + ".conf";
            String value = getValue(m.getConf().getFile(), properties, baseDir);
            createFileOrValue(zipStream, value, zipEntryName);
            m.getConf().setFile(zipEntryName);
          }
        }
      }

      // Profiles
      if (jaxb.getProfiles() != null) {
        for (ProfileType m : jaxb.getProfiles().getProfile()) {
          String name = m.getName();

          if (m.getConf() != null && m.getConf().getFile() != null) {
            String zipEntryName = "files/certprofile-" + name + ".conf";
            String value = getValue(m.getConf().getFile(), properties, baseDir);
            createFileOrValue(zipStream, value, zipEntryName);
            m.getConf().setFile(zipEntryName);
          }
        }
      }

      // CAs
      if (jaxb.getCas() != null) {
        for (CaType m : jaxb.getCas().getCa()) {
          String name = m.getName();

          if (m.getCaInfo() != null) {
            CaInfoType ci = m.getCaInfo();

            if (ci.getSignerConf() != null) {
              String conf = convertSignerConf(ci.getSignerConf(), properties, baseDir);
              if (conf.length() > 200) {
                String zipEntryName = "files/ca-" + name + "-signer.conf";
                createFileOrValue(zipStream, conf, zipEntryName);
                ci.getSignerConf().setFile(zipEntryName);
                ci.getSignerConf().setValue(null);
              } else {
                ci.getSignerConf().setFile(null);
                ci.getSignerConf().setValue(conf);
              }
            }

            if (ci.getExtraControl() != null && ci.getExtraControl().getFile() != null) {
              String zipEntryName = "files/ca-" + name + "-extracontrol.conf";
              String value = getValue(ci.getExtraControl().getFile(), properties, baseDir);
              createFileOrValue(zipStream, value, zipEntryName);
              ci.getExtraControl().setFile(zipEntryName);
            }

            if (ci.getGenSelfIssued() == null) {
              if (ci.getCert() != null && ci.getCert().getFile() != null) {
                String zipEntryName = "files/ca-" + name + ".crt";
                byte[] value = getBinary(ci.getCert().getFile(), properties, baseDir);
                createFileOrBinary(zipStream, value, zipEntryName);
                ci.getCert().setFile(zipEntryName);
              }
            } else {
              if (ci.getCert() != null) {
                throw new InvalidConfException("cert of CA " + name + " must not be set");
              }

              FileOrBinaryType csrFb = ci.getGenSelfIssued().getCsr();
              if (csrFb != null && csrFb.getFile() != null) {
                String zipEntryName = "files/ca-" + name + "-csr.p10";
                byte[] value = getBinary(csrFb.getFile(), properties, baseDir);
                createFileOrBinary(zipStream, value, zipEntryName);
                csrFb.setFile(zipEntryName);
              }
            }
          }
        }
      }

      // add the CAConf XML file
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      try {
        CaConfs.marshal(jaxb, bout);
      } finally {
        bout.flush();
      }

      zipStream.putNextEntry(new ZipEntry("caconf.xml"));
      try {
        zipStream.write(bout.toByteArray());
      } finally {
        zipStream.closeEntry();
      }

    } catch (JAXBException ex) {
      throw XmlUtil.convert(ex);
    } finally {
      if (caConfStream != null) {
        try {
          caConfStream.close();
        } catch (IOException ex) {
          LOG.info("could not clonse caConfStream", ex.getMessage());
        }
      }

      zipStream.close();
      bytesStream.flush();
    }

    return new ByteArrayInputStream(bytesStream.toByteArray());
  }

  private static void createFileOrValue(ZipOutputStream zipStream, String content, String fileName)
      throws IOException {
    ZipEntry certZipEntry = new ZipEntry(fileName);
    zipStream.putNextEntry(certZipEntry);
    try {
      zipStream.write(content.getBytes("UTF-8"));
    } finally {
      zipStream.closeEntry();
    }
  }

  private static void createFileOrBinary(ZipOutputStream zipStream, byte[] content, String fileName)
      throws IOException {
    ZipEntry certZipEntry = new ZipEntry(fileName);
    zipStream.putNextEntry(certZipEntry);
    try {
      zipStream.write(content);
    } finally {
      zipStream.closeEntry();
    }
  }

  private static String getValue(String fileName, Map<String, String> properties, String baseDir)
      throws IOException {
    byte[] binary = getBinary(fileName, properties, baseDir);
    return new String(binary, "UTF-8");
  }

  private static byte[] getBinary(String fileName, Map<String, String> properties, String baseDir)
      throws IOException {
    fileName = expandConf(fileName, properties);

    InputStream is = Files.newInputStream(Paths.get(resolveFilePath(fileName, baseDir)));

    return IoUtil.read(is);
  }

  private static String expandConf(String confStr, Map<String, String> properties) {
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

  private static String resolveFilePath(String filePath, String baseDir) {
    File file = new File(filePath);
    return file.isAbsolute() ? filePath : new File(baseDir, filePath).getPath();
  }

  private static String convertSignerConf(FileOrValueType confFv, Map<String, String> properties,
      String baseDir) throws IOException {

    String conf;
    if (confFv.getValue() != null) {
      conf = confFv.getValue();
    } else {
      conf = getValue(confFv.getFile(), properties, baseDir);
    }

    conf = expandConf(conf, properties);
    if (!conf.contains("file:")) {
      return conf;
    }

    ConfPairs confPairs = new ConfPairs(conf);
    boolean changed = false;

    for (String name : confPairs.names()) {
      String value = confPairs.value(name);
      if (!value.startsWith("file:")) {
        continue;
      }

      changed = true;
      String fileName = value.substring("file:".length());
      byte[] binValue = getBinary(fileName, properties, baseDir);
      confPairs.putPair(name, "base64:" + Base64.encodeToString(binValue));
    }

    return changed ? confPairs.getEncoded() : conf;
  }

  public static void main(String[] args) {
    try {
      /*InputStream is = convertFileConfToZip(
          "/home/lliao/source/xipki/assemblies/xipki-console/target/xipki-console-4.0.1-SNAPSHOT/"
          + "xipki/ca-setup/cacert-none/ca-conf.xml");
      Files.copy(is, Paths.get("dummy.zip"), StandardCopyOption.REPLACE_EXISTING);
      */
      InputStream is2 = Files.newInputStream(Paths.get("dummy.zip"));
      new CaConf(is2, new SecurityFactoryImpl());
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

}
