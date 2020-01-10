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

package org.xipki.ca.servlet;

import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.util.Args;

/**
 * Response Audit Exception.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpRespAuditException extends Exception {

  private static final long serialVersionUID = 1L;

  private final int httpStatus;

  private final String httpErrorMessage;

  private final String auditMessage;

  private final AuditLevel auditLevel;

  private AuditStatus auditStatus;

  public HttpRespAuditException(int httpStatus, String auditMessage,
      AuditLevel auditLevel, AuditStatus auditStatus) {
    this(httpStatus, null, auditMessage, auditLevel, auditStatus);
  }

  public HttpRespAuditException(int httpStatus, String httpErrorMessage,
      String auditMessage, AuditLevel auditLevel, AuditStatus auditStatus) {
    this.httpStatus = httpStatus;
    this.httpErrorMessage = httpErrorMessage;
    this.auditMessage = Args.notBlank(auditMessage, "auditMessage");
    this.auditLevel = Args.notNull(auditLevel, "auditLevel");
    this.auditStatus = Args.notNull(auditStatus, "auditStatus");
  }

  public int getHttpStatus() {
    return httpStatus;
  }

  public String getHttpErrorMessage() {
    return httpErrorMessage;
  }

  public String getAuditMessage() {
    return auditMessage;
  }

  public AuditLevel getAuditLevel() {
    return auditLevel;
  }

  public AuditStatus getAuditStatus() {
    return auditStatus;
  }

}
