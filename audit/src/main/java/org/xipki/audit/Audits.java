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

package org.xipki.audit;

import org.xipki.audit.services.EmbedAuditService;

import java.lang.reflect.InvocationTargetException;

/**
 * Helper class to configure and initialize the Audit.
 *
 * @author Lijun Liao
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

  public static void init(String auditType, String auditConf)  {
    try {
      AuditService service;
      if ("embed".equalsIgnoreCase(auditType)) {
        service = new EmbedAuditService();
      } else  if (auditType.startsWith("java:")) {
        String className = auditType.substring("java:".length());
        try {
          Class<?> clazz = Class.forName(className);
          service = (AuditService) clazz.getDeclaredConstructor().newInstance();
        } catch (ClassCastException | ClassNotFoundException | NoSuchMethodException
            | IllegalAccessException | InstantiationException | InvocationTargetException ex) {
          throw new AuditServiceRuntimeException(
              "error caught while initializing AuditService " + auditType
              + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
      } else {
        throw new AuditServiceRuntimeException("invalid Audit.Type '" + auditType
            + "'. Valid values are 'embed' or java:<name of class that implements "
            + AuditService.class.getName() + ">");
      }

      service.init(auditConf);
      auditService = service;
    } catch (AuditServiceRuntimeException ex) {
      initializationException = ex;
    } catch (RuntimeException ex) {
      initializationException = new AuditServiceRuntimeException(ex.getMessage(), ex);
    }
  } // method init

}
