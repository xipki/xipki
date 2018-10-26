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

package org.xipki.ca.server.servlet;

import org.xipki.audit.AuditServiceRegister;
import org.xipki.ca.server.api.ResponderManager;

/**
 * TODO.
 * @author Lijun Liao
 */
public class ServletHelper {

  private static AuditServiceRegister auditServiceRegister;

  private static ResponderManager responderManager;

  public ServletHelper() {
  }

  public void setResponderManager(ResponderManager paramResponderManager) {
    responderManager = paramResponderManager;
  }

  public void setAuditServiceRegister(AuditServiceRegister paramAuditServiceRegister) {
    auditServiceRegister = paramAuditServiceRegister;
  }

  public static AuditServiceRegister getAuditServiceRegister() {
    return auditServiceRegister;
  }

  public static ResponderManager getResponderManager() {
    return responderManager;
  }

}
