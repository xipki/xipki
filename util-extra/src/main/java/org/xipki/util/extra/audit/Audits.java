// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.audit;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.audit.services.DatabaseMacAuditService;
import org.xipki.util.extra.audit.services.EmbedAuditService;
import org.xipki.util.extra.audit.services.FileMacAuditService;
import org.xipki.util.extra.audit.services.NoopAuditService;
import org.xipki.util.extra.misc.ReflectiveUtil;

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
    private final String type;

    private final ConfPairs conf;

    public static final AuditConf DEFAULT = new AuditConf(null, null);

    public AuditConf(String type, ConfPairs conf) {
      this.type = type;
      this.conf = conf;
    }

    public String getType() {
      return type == null || type.isEmpty() ? "embed" : type;
    }

    public ConfPairs getConf() {
      return conf;
    }

    public static AuditConf parse(JsonMap json) throws CodecException {
      return new AuditConf(json.getString("type"),
          ConfPairs.parse(json.getMap("conf")));
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

  public static void init(String auditType, ConfPairs auditConf) {
    try {
      AuditService service;
      if ("embed".equalsIgnoreCase(auditType)) {
        service = new EmbedAuditService();
      } else if ("noop".equalsIgnoreCase(auditType)) {
        service = new NoopAuditService();
      } else if ("file-mac".equalsIgnoreCase(auditType)) {
        service = new FileMacAuditService();
      } else if ("db-mac".equalsIgnoreCase(auditType)
          || "database-mac".equalsIgnoreCase(auditType)) {
        service = new DatabaseMacAuditService();
      } else {
        String className = getClassName(auditType);
        service = ReflectiveUtil.newInstance(className);
      }

      service.init(auditConf);
      auditService = service;
    } catch (AuditServiceRuntimeException ex) {
      initializationException = ex;
    } catch (Exception ex) {
      initializationException =
          new AuditServiceRuntimeException(ex.getMessage(), ex);
    }
  } // method init

  private static String getClassName(String auditType) {
    if (auditType.startsWith("java:")) {
      return auditType.substring("java:".length());
    } else {
      throw new AuditServiceRuntimeException("invalid Audit.Type '"
          + auditType + "'. Valid values are 'embed' or "
          + "java:<name of class that implements "
          + AuditService.class.getName() + ">");
    }
  }

}
