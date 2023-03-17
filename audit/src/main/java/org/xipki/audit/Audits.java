// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit;

import org.xipki.audit.services.EmbedAuditService;
import org.xipki.audit.services.FileMacAuditService;
import org.xipki.audit.services.NoopAuditService;
import org.xipki.password.PasswordResolver;

import java.lang.reflect.InvocationTargetException;

/**
 * Helper class to configure and initialize the Audit.
 *
 * @author Lijun Liao (xipki)
 */

public class Audits {

  public static class AuditConf {

    /**
     * valid values are:
     *   embed: use the embedded slf4j logging
     *   java:&lt;name of class that implements org.xipki.audit.AuditService&gt;
     */
    private String type;

    private String conf;

    public static AuditConf DEFAULT = new AuditConf();

    public String getType() {
      return type == null || type.isEmpty() ? "embed" : type;
    }

    public void setType(String type) {
      this.type = type;
    }

    public String getConf() {
      return conf;
    }

    public void setConf(String conf) {
      this.conf = conf;
    }

  }

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
  } // method getAuditService

  public static void init(String auditType, String auditConf, PasswordResolver passwordResolver) {
    try {
      AuditService service;
      if ("embed".equalsIgnoreCase(auditType)) {
        service = new EmbedAuditService();
      } else if ("noop".equalsIgnoreCase(auditType)) {
        service = new NoopAuditService();
      } else if ("file-mac".equals(auditType)) {
        service = new FileMacAuditService();
      } else {
        String className;

        if (auditType.startsWith("java:")) {
          className = auditType.substring("java:".length());
        } else if ("database-mac".equals(auditType)) {
          className = "org.xipki.audit.extra.DatabaseMacAuditService";
        } else {
          throw new AuditServiceRuntimeException("invalid Audit.Type '" + auditType
                  + "'. Valid values are 'embed' or java:<name of class that implements "
                  + AuditService.class.getName() + ">");
        }

        try {
          Class<?> clazz = Class.forName(className);
          service = (AuditService) clazz.getDeclaredConstructor().newInstance();
        } catch (ClassCastException | ClassNotFoundException | NoSuchMethodException
                | IllegalAccessException | InstantiationException | InvocationTargetException ex) {
          throw new AuditServiceRuntimeException(
                  "error caught while initializing AuditService " + auditType
                          + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
      }

      service.init(auditConf, passwordResolver);
      auditService = service;
    } catch (AuditServiceRuntimeException ex) {
      initializationException = ex;
    } catch (Exception ex) {
      initializationException = new AuditServiceRuntimeException(ex.getMessage(), ex);
    }
  } // method init

}
