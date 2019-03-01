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

package org.xipki.audit;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.xipki.audit.services.EmbedAuditService;
import org.xipki.audit.services.SyslogAuditService;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Audits {

  private static final String DFLT_AUDIT_CFG = "xipki/etc/org.xipki.audit.cfg";

  private static final String DFLT_AUDIT_SYSLOG_CFG = "xipki/etc/org.xipki.audit.syslog.cfg";

  private static AuditService auditService;

  private static AuditServiceRuntimeException initializationException;

  private Audits() {
  }

  public static AuditService getAuditService() {
    if (auditService != null) {
      return auditService;
    }

    if (initializationException != null) {
      throw initializationException;
    } else {
      throw new IllegalStateException("Please call Audits.init() first.");
    }
  }

  public static void init(String auditCfg)  {
    try {
      Properties auditProps = loadProperties(auditCfg == null ? DFLT_AUDIT_CFG : auditCfg);
      String auditType = getString(auditProps, "audit.type", "embed");
      String auditConf = getString(auditProps, "audit.conf", DFLT_AUDIT_SYSLOG_CFG);

      AuditService service;
      if ("embed".equalsIgnoreCase(auditType)) {
        service = new EmbedAuditService();
      } else if ("syslog".equalsIgnoreCase(auditType)) {
        service = new SyslogAuditService();
      } else  if (auditType.startsWith("java:")) {
        String className = auditType.substring("java:".length());
        try {
          Class<?> clazz = Class.forName(className);
          service = (AuditService) clazz.newInstance();
        } catch (ClassCastException | ClassNotFoundException | IllegalAccessException
            | InstantiationException ex) {
          throw new AuditServiceRuntimeException(
              "error caught while initializing AuditService " + auditType
              + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
      } else {
        throw new AuditServiceRuntimeException("invalid Audit.Type '" + auditType
            + "'. Valid values are 'embed', 'syslog' or java:<name of class that implements "
            + AuditService.class.getName() + ">");
      }

      service.init(auditConf);
      auditService = service;
    } catch (AuditServiceRuntimeException ex) {
      initializationException = ex;
    } catch (RuntimeException ex) {
      initializationException = new AuditServiceRuntimeException(ex.getMessage(), ex);
    }
  }

  private static Properties loadProperties(String path) throws AuditServiceRuntimeException {
    Path realPath = Paths.get(path);
    if (Files.exists(realPath)) {
      Properties props = new Properties();
      try {
        try (InputStream is = Files.newInputStream(realPath)) {
          props.load(is);
        }
      } catch (IOException ex) {
        throw new AuditServiceRuntimeException("could not load properties from file " + path, ex);
      }
      return props;
    } else {
      throw new AuditServiceRuntimeException("the file " + path + " does not exist");
    }
  }

  private static String getString(Properties props, String key, String dfltValue) {
    if (props == null) {
      return dfltValue;
    } else {
      String value = props.getProperty(key);
      return value == null ? dfltValue : value;
    }
  }
}
