package org.xipki.audit.api;


public interface AuditLoggingService
{
    void logEvent(AuditEvent event);
}
