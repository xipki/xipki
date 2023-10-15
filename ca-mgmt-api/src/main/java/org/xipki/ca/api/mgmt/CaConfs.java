// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.security.util.JSON;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;

import java.io.*;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Helper class to convert the CA configuration.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public class CaConfs {

  private static final String APP_DIR = "APP_DIR";

  private CaConfs() {
  }

  /**
   * Serialize a {#CaConfType.CaSystem} object to the output stream.
   * The specified stream remains open after this method returns.
   * @param root the object to be serialized.
   * @param out the output stream.
   * @throws InvalidConfException if the configuration is not valid.
   */
  public static void marshal(CaConfType.CaSystem root, OutputStream out)
      throws InvalidConfException {
    Args.notNull(root, "root");
    Args.notNull(out, "out");
    root.validate();
    JSON.writePrettyJSON(root, out);
  } // method marshal

  public static InputStream convertFileConfToZip(String confFilename)
      throws IOException, InvalidConfException {
    Args.notNull(confFilename, "confFilename");

    ByteArrayOutputStream bytesStream = new ByteArrayOutputStream(1048576); // initial 1M
    String baseDir;

    try (ZipOutputStream zipStream = new ZipOutputStream(bytesStream)) {
      zipStream.setLevel(Deflater.BEST_SPEED);

      File confFile = new File(confFilename);
      confFile = IoUtil.expandFilepath(confFile, false);

      CaConfType.CaSystem root = JSON.parseObject(confFile, CaConfType.CaSystem.class);

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
                    String zipEntryName = "files/cacerts-" + name + "-" + i + ".crt";
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
            }
          }
        }
      }

      // add the CAConf XML file
      byte[] bytes;
      try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
        marshal(root, bout);
        bytes = bout.toByteArray();
      }

      zipStream.putNextEntry(new ZipEntry("caconf.json"));
      try {
        zipStream.write(bytes);
      } finally {
        zipStream.closeEntry();
      }
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
    return StringUtil.toUtf8String(binary);
  } // method getValue

  private static byte[] getBinary(String fileName, Map<String, String> properties, String baseDir)
      throws IOException {
    fileName = expandConf(fileName, properties);
    return IoUtil.read(Paths.get(resolveFilePath(fileName, baseDir)).toFile());
  } // method getBinary

  private static String expandConf(String confStr, Map<String, String> properties) {
    if (confStr == null || !confStr.contains("${") || confStr.indexOf('}') == -1) {
      return confStr;
    }

    for (Entry<String, String> entry : properties.entrySet()) {
      String name = entry.getKey();
      String placeHolder = "${" + name + "}";
      while (confStr.contains(placeHolder)) {
        confStr = confStr.replace(placeHolder, entry.getValue());
      }
    }

    return confStr;
  } // method expandConf

  private static String resolveFilePath(String filePath, String baseDir) {
    File file = new File(filePath);
    return file.isAbsolute() ? filePath : new File(baseDir, filePath).getPath();
  } // method resolveFilePath

  private static String convertSignerConf(FileOrValue confFv, Map<String, String> properties, String baseDir)
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

  public static void checkName(String param, String paramName) throws InvalidConfException {
    if (param == null || param.isEmpty()) {
      throw new InvalidConfException(paramName + " must not be blank");
    }

    for (int i = 0; i < param.length(); i++) {
      char c = param.charAt(i);
      if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
          || (c == '-') || (c == '_') || (c == '.')) {
        continue;
      }

      throw new InvalidConfException("invalid char '" + c + "' in " + paramName);
    }
  }

}
