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

/**
 * Audit service interface.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface AuditService extends AutoCloseable {

  int AUDIT_EVENT = 1;

  int PCI_AUDIT_EVENT = 2;

  void init(String conf);

  /**
   * Log audit event.
   * @param event
   *          Audit event. Must not be {@code null}-
   */
  void logEvent(AuditEvent event);

  /**
   * Log PCI audit event.
   *
   * @param event
   *          Audit event. Must not be {@code null}-
   */
  void logEvent(PciAuditEvent event);

}
