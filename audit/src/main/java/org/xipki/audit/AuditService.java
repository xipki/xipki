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

package org.xipki.audit;

import java.util.List;
import java.util.Objects;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class AuditService {

    protected abstract void logEvent0(AuditEvent event);

    protected abstract void logEvent0(PciAuditEvent event);

    /**
     *
     * @param event
     *          Audit event. Must not be {@code null}-
     */
    public final void logEvent(AuditEvent event) {
        Objects.requireNonNull(event, "event must not be null");

        /*
        switch (event.getLevel()) {
        case DEBUG:
            if (LOG.isDebugEnabled()) {
                LOG.debug("AuditEvent {}", createMessage(event));
            }
            break;
        default:
            if (LOG.isInfoEnabled()) {
                LOG.info("AuditEvent {}", createMessage(event));
            }
            break;
        } // end switch
        */

        logEvent0(event);
    }

    /**
     *
     * @param event
     *          Audit event. Must not be {@code null}-
     */
    public final void logEvent(PciAuditEvent event) {
        Objects.requireNonNull(event, "event must not be null");

        /*
        CharArrayWriter msg = event.toCharArrayWriter("");
        AuditLevel al = event.getLevel();
        switch (al) {
        case DEBUG:
            if (LOG.isDebugEnabled()) {
                LOG.debug("PciAuditEvent {} | {}", al.getAlignedText(), msg);
            }
            break;
        default:
            if (LOG.isInfoEnabled()) {
                LOG.info("PciAuditEvent {} | {}", al.getAlignedText(), msg);
            }
            break;
        } // end switch
        */

        logEvent0(event);
    }

    protected static String createMessage(final AuditEvent event) {
        Objects.requireNonNull(event, "event must not be null");
        String applicationName = event.applicationName();
        if (applicationName == null) {
            applicationName = "undefined";
        }

        String name = event.name();
        if (name == null) {
            name = "undefined";
        }

        StringBuilder sb = new StringBuilder(150);

        sb.append(event.level().alignedText()).append(" | ");
        sb.append(applicationName).append(" - ").append(name);

        AuditStatus status = event.status();
        if (status == null) {
            status = AuditStatus.UNDEFINED;
        }
        sb.append(":\tstatus: ").append(status.name());
        List<AuditEventData> eventDataArray = event.eventDatas();

        long duration = event.duration();
        if (duration >= 0) {
            sb.append("\tduration: ").append(duration);
        }

        if ((eventDataArray != null) && (eventDataArray.size() > 0)) {
            for (AuditEventData m : eventDataArray) {
                if (duration >= 0 && "duration".equalsIgnoreCase(m.name())) {
                    continue;
                }

                sb.append("\t").append(m.name()).append(": ").append(m.value());
            }
        }

        return sb.toString();
    }

}
