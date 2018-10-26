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

package org.xipki.audits;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.xipki.audit.AuditServiceRegister;
import org.xipki.audit.internal.AuditServiceRegisterImpl;
import org.xipki.audit.syslog.SyslogAuditService;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Audits implements Closeable {

  private static final String DFLT_AUDIT_CFG = "xipki/etc/org.xipki.audit.cfg";

  private static final String DFLT_AUDIT_SYSLOG_CFG = "xipki/etc/org.xipki.audit.syslog.cfg";

  private String auditCfg;

  private AuditServiceRegisterImpl auditServiceRegister;

  public void setAuditCfg(String file) {
    this.auditCfg = file;
  }

  public AuditServiceRegister getAuditServiceRegister() {
    return auditServiceRegister;
  }

  public void init() throws IOException {
    auditServiceRegister = new AuditServiceRegisterImpl();

    Properties auditProps = loadProperties(auditCfg, DFLT_AUDIT_CFG);
    String auditType = getString(auditProps, "audit.type", "embed");
    if ("embed".equalsIgnoreCase(auditType)) {
      // do nothing
    } else if ("syslog".equalsIgnoreCase(auditType)) {
      String cfgFile = getString(auditProps, "audit.syslog.conf",
          DFLT_AUDIT_SYSLOG_CFG);
      SyslogAuditService service = new SyslogAuditService();
      Properties props = loadProperties(cfgFile);

      service.setFacility(
          getString(props, "facility", "user"));
      service.setHost(
          getString(props, "host", "127.0.0.1"));

      service.setPrefix(
          getString(props, "prefix", "xipki"));

      String localname = props.getProperty("localname");
      if (localname != null) {
        service.setLocalname(localname);
      }

      service.setMaxMessageLength(
          getInt(props, "maxMessageLength", 1024));

      service.setPort(
          getInt(props, "port", 514));

      service.setProtocol(
          getString(props, "protocol", "udp"));

      service.setWriteRetries(
          getInt(props, "writeRetries", 2));

      service.setSsl(
          getBoolean(props, "ssl", false));

      service.setMessageFormat(
          getString(props, "messageFormat", "rfc_5424"));

      auditServiceRegister.registService(service);
    } else {
      throw new IOException("invalid audit type '" + auditType + "'");
    }
  }

  @Override
  public void close() {
    auditServiceRegister = null;
  }

  public static Properties loadProperties(String path, String dfltPath) throws IOException {
    return loadProperties(path == null ? dfltPath : path);
  }

  public static Properties loadProperties(String path) throws IOException {
    Path realPath = Paths.get(path);
    if (Files.exists(realPath)) {
      Properties props = new Properties();
      try (InputStream is = Files.newInputStream(realPath)) {
        props.load(is);
      }
      return props;
    } else {
      return null;
    }
  }

  public static String getString(Properties props, String key, String dfltValue) {
    if (props == null) {
      return dfltValue;
    } else {
      String value = props.getProperty(key);
      return value == null ? dfltValue : value;
    }
  }

  public static int getInt(Properties props, String key, int dfltValue) {
    if (props == null) {
      return dfltValue;
    } else {
      String value = props.getProperty(key);
      return value == null ? dfltValue : Integer.parseInt(value);
    }
  }

  public static boolean getBoolean(Properties props, String key, boolean dfltValue) {
    if (props == null) {
      return dfltValue;
    } else {
      String value = props.getProperty(key);
      return value == null ? dfltValue : Boolean.parseBoolean(value);
    }
  }

}
