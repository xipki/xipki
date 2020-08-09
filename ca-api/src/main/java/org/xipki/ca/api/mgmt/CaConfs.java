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

package org.xipki.ca.api.mgmt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

/**
 * Helper class to convert the CA configuration.
 *
 * @author Lijun Liao
 * @since 2.1.0
 */

public class CaConfs {
  private static final Logger LOG = LoggerFactory.getLogger(CaConfs.class);

  private static final String APP_DIR = "APP_DIR";

  private CaConfs() {
  }

  public static void marshal(CaConfType.CaSystem root, OutputStream out)
      throws InvalidConfException, IOException {
    Args.notNull(root, "root");
    Args.notNull(out, "out");
    root.validate();
    JSON.writeJSONString(out, Charset.forName("UTF8"), root, SerializerFeature.PrettyFormat);
  } // method marshal

  public static InputStream convertFileConfToZip(String confFilename)
      throws IOException, InvalidConfException {
    Args.notNull(confFilename, "confFilename");

    ByteArrayOutputStream bytesStream = new ByteArrayOutputStream(1048576); // initial 1M
    ZipOutputStream zipStream = new ZipOutputStream(bytesStream);
    zipStream.setLevel(Deflater.BEST_SPEED);

    File confFile = new File(confFilename);
    confFile = IoUtil.expandFilepath(confFile);

    InputStream caConfStream = null;
    String baseDir = null;

    try {
      caConfStream = Files.newInputStream(confFile.toPath());
      CaConfType.CaSystem root = JSON.parseObject(caConfStream, CaConfType.CaSystem.class);

      baseDir = root.getBasedir();
      if (StringUtil.isBlank(baseDir)) {
        File confFileParent = confFile.getParentFile();
        baseDir = (confFileParent == null) ? "." : confFileParent.getPath();
      } else if (APP_DIR.equalsIgnoreCase(baseDir)) {
        baseDir = ".";
      }
      // clear the baseDir in ZIP file
      root.setBasedir(null);

      final Map<String, String> properties = new HashMap<>();

      if (root.getProperties() != null) {
        properties.putAll(root.getProperties());
      }

      // Signers
      if (root.getSigners() != null) {
        for (CaConfType.Signer m : root.getSigners()) {
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
      if (root.getRequestors() != null) {
        for (CaConfType.Requestor m : root.getRequestors()) {
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
      if (root.getPublishers() != null) {
        for (CaConfType.NameTypeConf m : root.getPublishers()) {
          if (m.getConf() != null && m.getConf().getFile() != null) {
            String name = m.getName();
            String zipEntryName = "files/publisher-" + name + ".conf";
            String value = getValue(m.getConf().getFile(), properties, baseDir);
            createFileOrValue(zipStream, value, zipEntryName);
            m.getConf().setFile(zipEntryName);
          }
        }
      }

      // Profiles
      if (root.getProfiles() != null) {
        for (CaConfType.NameTypeConf m : root.getProfiles()) {
          if (m.getConf() != null && m.getConf().getFile() != null) {
            String name = m.getName();
            String zipEntryName = "files/certprofile-" + name + ".conf";
            String value = getValue(m.getConf().getFile(), properties, baseDir);
            createFileOrValue(zipStream, value, zipEntryName);
            m.getConf().setFile(zipEntryName);
          }
        }
      }

      // CAs
      if (root.getCas() != null) {
        for (CaConfType.Ca m : root.getCas()) {
          if (m.getCaInfo() != null) {
            String name = m.getName();
            CaConfType.CaInfo ci = m.getCaInfo();

            // SignerInfo
            if (ci.getSignerConf() != null) {
              FileOrValue fv = ci.getSignerConf();
              String conf = convertSignerConf(fv, properties, baseDir);
              if (conf.length() > 200) {
                String zipEntryName = "files/ca-" + name + "-signer.conf";
                createFileOrValue(zipStream, conf, zipEntryName);
                fv.setFile(zipEntryName);
                fv.setValue(null);
              } else {
                fv.setFile(null);
                fv.setValue(conf);
              }
            }

            // DHPoc Control
            if (ci.getDhpocControl() != null) {
              FileOrValue fv = ci.getDhpocControl();
              String conf = convertSignerConf(fv, properties, baseDir);
              if (conf.length() > 200) {
                String zipEntryName = "files/ca-" + name + "-dhpoc.conf";
                createFileOrValue(zipStream, conf, zipEntryName);
                fv.setFile(zipEntryName);
                fv.setValue(null);
              } else {
                fv.setFile(null);
                fv.setValue(conf);
              }
            }

            // Cert and Certchain
            if (ci.getGenSelfIssued() == null) {
              if (ci.getCert() != null && ci.getCert().getFile() != null) {
                String zipEntryName = "files/ca-" + name + ".crt";
                byte[] value = getBinary(ci.getCert().getFile(), properties, baseDir);
                createFileOrBinary(zipStream, value, zipEntryName);
                ci.getCert().setFile(zipEntryName);
              }

              if (CollectionUtil.isNotEmpty(ci.getCertchain())) {
                for (int i = 0; i < ci.getCertchain().size(); i++) {
                  FileOrBinary fi = ci.getCertchain().get(i);
                  if (fi.getFile() != null) {
                    String zipEntryName = "files/cacertchain-" + name + "-" + i + ".crt";
                    byte[] value = getBinary(fi.getFile(), properties, baseDir);
                    createFileOrBinary(zipStream, value, zipEntryName);
                    fi.setFile(zipEntryName);
                  }
                }
              }
            } else {
              if (ci.getCert() != null) {
                throw new InvalidConfException("cert of CA " + name + " may not be set");
              }

              FileOrBinary csrFb = ci.getGenSelfIssued().getCsr();
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
        marshal(root, bout);
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
  } // method convertFileConfToZip

  private static void createFileOrValue(ZipOutputStream zipStream, String content, String fileName)
      throws IOException {
    ZipEntry certZipEntry = new ZipEntry(fileName);
    zipStream.putNextEntry(certZipEntry);
    try {
      zipStream.write(StringUtil.toUtf8Bytes(content));
    } finally {
      zipStream.closeEntry();
    }
  } // method createFileOrValue

  private static void createFileOrBinary(ZipOutputStream zipStream, byte[] content, String fileName)
      throws IOException {
    ZipEntry certZipEntry = new ZipEntry(fileName);
    zipStream.putNextEntry(certZipEntry);
    try {
      zipStream.write(content);
    } finally {
      zipStream.closeEntry();
    }
  } // method createFileOrBinary

  private static String getValue(String fileName, Map<String, String> properties, String baseDir)
      throws IOException {
    byte[] binary = getBinary(fileName, properties, baseDir);
    return new String(binary, "UTF-8");
  } // method getValue

  private static byte[] getBinary(String fileName, Map<String, String> properties, String baseDir)
      throws IOException {
    fileName = expandConf(fileName, properties);

    InputStream is = Files.newInputStream(Paths.get(resolveFilePath(fileName, baseDir)));

    return IoUtil.read(is);
  } // method getBinary

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
  } // method expandConf

  private static String resolveFilePath(String filePath, String baseDir) {
    File file = new File(filePath);
    return file.isAbsolute() ? filePath : new File(baseDir, filePath).getPath();
  } // method resolveFilePath

  private static String convertSignerConf(FileOrValue confFv, Map<String, String> properties,
      String baseDir)
          throws IOException {

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
  } // method convertSignerConf

}
