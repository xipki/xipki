// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.audit;

import org.xipki.codec.exception.CodecException;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.ConfPairs;
import org.xipki.codec.util.ReflectiveUtil;
import org.xipki.util.audit.services.DatabaseMacAuditService;
import org.xipki.util.audit.services.EmbedAuditService;
import org.xipki.util.audit.services.FileMacAuditService;
import org.xipki.util.audit.services.NoopAuditService;

/**
 * Audits.
 *
 * @author Lijun Liao (xipki)
 */
public class Audits {

  /**
   * Audit configuration.
   */
  public static class AuditConf {

    /**
     * valid values are:
     *   embed: use the embedded slf4j logging
     *   java:&lt;name of class that implements org.xipki.util.audit.AuditService&gt;
     */
    private final String type;

    private final ConfPairs conf;

    public static final AuditConf DEFAULT = new AuditConf(null, null);

    public AuditConf(String type, ConfPairs conf) {
      this.type = type;
      this.conf = conf;
    }

    public String type() {
      return type == null || type.isEmpty() ? "embed" : type;
    }

    public ConfPairs conf() {
      return conf;
    }

    public static AuditConf parse(JsonMap json) throws CodecException {
      return new AuditConf(json.getString("type"), ConfPairs.parse(json.getMap("conf")));
    }

  }

  private static AuditService auditService;

  private static RuntimeException initializationException;

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

  public static void init(String auditType, ConfPairs auditConf) {
    try {
      AuditService service;
      if ("embed".equalsIgnoreCase(auditType)) {
        service = new EmbedAuditService();
      } else if ("noop".equalsIgnoreCase(auditType)) {
        service = new NoopAuditService();
      } else if ("file-mac".equalsIgnoreCase(auditType)) {
        service = new FileMacAuditService();
      } else if (  "db-mac".equalsIgnoreCase(auditType)
          || "database-mac".equalsIgnoreCase(auditType)) {
        service = new DatabaseMacAuditService();
      } else {
        String className = getClassName(auditType);
        service = ReflectiveUtil.newInstance(className);
      }

      service.init(auditConf);
      auditService = service;
    } catch (RuntimeException ex) {
      initializationException = ex;
    } catch (Exception ex) {
      initializationException = new IllegalStateException(ex.getMessage(), ex);
    }
  } // method init

  private static String getClassName(String auditType) {
    if (auditType.startsWith("java:")) {
      return auditType.substring("java:".length());
    } else {
      throw new IllegalArgumentException("invalid Audit.Type '"
          + auditType + "'. Valid values are 'embed' or "
          + "java:<name of class that implements "
          + AuditService.class.getName() + ">");
    }
  }

}
