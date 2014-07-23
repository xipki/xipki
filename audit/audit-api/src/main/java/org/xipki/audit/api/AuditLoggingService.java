/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.audit.api;

/**
 * @author Lijun Liao
 */

public interface AuditLoggingService
{
    void logEvent(AuditEvent event);

    /**
     * Logging an PCI audit event.
     *
     * @param event
     *            The event.
     */
    void logEvent(PCIAuditEvent event);
}
