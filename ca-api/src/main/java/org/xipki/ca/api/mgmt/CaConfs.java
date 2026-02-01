// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.io.FileOrBinary;
import org.xipki.util.io.FileOrValue;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
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
   * @throws IOException if IO error occurs while writing to the output stream.
   */
  public static void marshal(CaConfType.CaSystem root, OutputStream out)
      throws IOException {
    Args.notNull(root, "root");
    Args.notNull(out, "out");

    String jsonText = JsonBuilder.toPrettyJson(root.toCodec());
    out.write(jsonText.getBytes(StandardCharsets.UTF_8));
  } // method marshal

  public static InputStream convertFileConfToZip(String confFilename)
      throws IOException, InvalidConfException {
    Args.notNull(confFilename, "confFilename");

    ByteArrayOutputStream bytesStream =
        new ByteArrayOutputStream(1048576); // initial 1M
    String baseDir;

    try (ZipOutputStream zipStream = new ZipOutputStream(bytesStream)) {
      zipStream.setLevel(Deflater.BEST_SPEED);

      File confFile = new File(confFilename);
      confFile = IoUtil.expandFilepath(confFile, false);

      CaConfType.CaSystem root = CaConfType.CaSystem.parse(confFile.toPath());

      baseDir = root.basedir();
      if (StringUtil.isBlank(baseDir)) {
        File confFileParent = confFile.getParentFile();
        baseDir = (confFileParent == null) ? "." : confFileParent.getPath();
      } else if (APP_DIR.equalsIgnoreCase(baseDir)) {
        baseDir = ".";
      }
      // clear the baseDir in ZIP file
      root.setBasedir(null);

      final Map<String, String> properties = new HashMap<>();

      if (root.properties() != null) {
        properties.putAll(root.properties());
      }

      // Signers
      if (root.signers() != null) {
        for (CaConfType.Signer m : root.signers()) {
          String name = m.name();

          if (m.conf() != null) {
            String conf = convertSignerConf(m.conf(), properties, baseDir);
            if (conf.length() > 200) {
              String zipEntryName = "files/signer-" + name + ".conf";
              createFileOrValue(zipStream, conf, zipEntryName);
              m.conf().setFile(zipEntryName);
            } else {
              m.conf().setValue(conf);
            }
          }

          if (m.cert() != null && m.cert().file() != null) {
            String zipEntryName = "files/signer-" + name + ".crt";
            byte[] value = getBinary(m.conf().file(),
                            properties, baseDir);
            createFileOrBinary(zipStream, value, zipEntryName);
            m.cert().setFile(zipEntryName);
          }
        }
      }

      // Requestors
      if (root.requestors() != null) {
        for (CaConfType.Requestor m : root.requestors()) {
          String name = m.name();

          if (m.conf() != null && m.conf().file() != null) {
            String zipEntryName = "files/requestor-" + name + ".conf";
            String value = getValue(m.conf().file(), properties, baseDir);
            createFileOrValue(zipStream, value, zipEntryName);
            m.conf().setFile(zipEntryName);
          }

          if (m.binaryConf() != null
              && m.binaryConf().file() != null) {
            String zipEntryName = "files/requestor-" + name + ".bin";
            byte[] value = getBinary(m.binaryConf().file(),
                            properties, baseDir);
            createFileOrBinary(zipStream, value, zipEntryName);
            m.binaryConf().setFile(zipEntryName);
          }
        }
      }

      // Publishers
      if (root.publishers() != null) {
        for (CaConfType.NameTypeConf m : root.publishers()) {
          if (m.conf() != null && m.conf().file() != null) {
            String name = m.name();
            String zipEntryName = "files/publisher-" + name + ".conf";
            String value = getValue(m.conf().file(), properties, baseDir);
            createFileOrValue(zipStream, value, zipEntryName);
            m.conf().setFile(zipEntryName);
          }
        }
      }

      // Profiles
      if (root.profiles() != null) {
        for (CaConfType.NameTypeConf m : root.profiles()) {
          if (m.conf() != null && m.conf().file() != null) {
            String name = m.name();
            String zipEntryName = "files/certprofile-" + name + ".conf";
            String value = getValue(m.conf().file(), properties, baseDir);
            createFileOrValue(zipStream, value, zipEntryName);
            m.conf().setFile(zipEntryName);
          }
        }
      }

      // CAs
      if (root.cas() != null) {
        for (CaConfType.Ca m : root.cas()) {
          if (m.caInfo() != null) {
            String name = m.name();
            CaConfType.CaInfo ci = m.caInfo();

            // SignerInfo
            if (ci.signerConf() != null) {
              FileOrValue fv = ci.signerConf();
              String conf = convertSignerConf(fv, properties, baseDir);
              if (conf.length() > 200) {
                String zipEntryName = "files/ca-" + name + "-signer.conf";
                createFileOrValue(zipStream, conf, zipEntryName);
                fv.setFile(zipEntryName);
              } else {
                fv.setValue(conf);
              }
            }

            // Cert and Certchain
            if (ci.genSelfIssued() == null) {
              if (ci.cert() != null && ci.cert().file() != null) {
                String zipEntryName = "files/ca-" + name + ".crt";
                byte[] value = getBinary(ci.cert().file(),
                                properties, baseDir);
                createFileOrBinary(zipStream, value, zipEntryName);
                ci.cert().setFile(zipEntryName);
              }

              if (CollectionUtil.isNotEmpty(ci.getCertchain())) {
                for (int i = 0; i < ci.getCertchain().size(); i++) {
                  FileOrBinary fi = ci.getCertchain().get(i);
                  if (fi.file() != null) {
                    String zipEntryName =
                        "files/cacerts-" + name + "-" + i + ".crt";
                    byte[] value = getBinary(fi.file(), properties, baseDir);
                    createFileOrBinary(zipStream, value, zipEntryName);
                    fi.setFile(zipEntryName);
                  }
                }
              }
            } else {
              if (ci.cert() != null) {
                throw new InvalidConfException(
                    "cert of CA " + name + " may not be set");
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

  private static void createFileOrValue(
      ZipOutputStream zipStream, String content, String fileName)
      throws IOException {
    ZipEntry certZipEntry = new ZipEntry(fileName);
    zipStream.putNextEntry(certZipEntry);
    try {
      zipStream.write(StringUtil.toUtf8Bytes(content));
    } finally {
      zipStream.closeEntry();
    }
  } // method createFileOrValue

  private static void createFileOrBinary(
      ZipOutputStream zipStream, byte[] content, String fileName)
      throws IOException {
    ZipEntry certZipEntry = new ZipEntry(fileName);
    zipStream.putNextEntry(certZipEntry);
    try {
      zipStream.write(content);
    } finally {
      zipStream.closeEntry();
    }
  } // method createFileOrBinary

  public static String getValue(
      String fileName, Map<String, String> properties, String baseDir)
      throws IOException {
    byte[] binary = getBinary(fileName, properties, baseDir);
    return StringUtil.toUtf8String(binary);
  } // method getValue

  public static byte[] getBinary(
      String fileName, Map<String, String> properties, String baseDir)
      throws IOException {
    fileName = expandConf(fileName, properties);
    return IoUtil.read(
        Paths.get(resolveFilePath(fileName, baseDir)).toFile());
  } // method getBinary

  private static String expandConf(
      String confStr, Map<String, String> properties) {
    if (confStr == null || !confStr.contains("${")
        || confStr.indexOf('}') == -1) {
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

  public static String convertSignerConf(
      FileOrValue confFv, Map<String, String> properties, String baseDir)
      throws IOException {
    String conf;
    if (confFv.value() != null) {
      conf = confFv.value();
    } else {
      conf = getValue(confFv.file(), properties, baseDir);
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

  public static void checkName(String param, String paramName)
      throws InvalidConfException {
    if (param == null || param.isEmpty()) {
      throw new InvalidConfException(paramName + " must not be blank");
    }

    for (int i = 0; i < param.length(); i++) {
      char c = param.charAt(i);
      if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
          || (c >= 'A' && c <= 'Z')
          || (c == '-') || (c == '_') || (c == '.')) {
        continue;
      }

      throw new InvalidConfException(
          "invalid char '" + c + "' in " + paramName);
    }
  }

}
