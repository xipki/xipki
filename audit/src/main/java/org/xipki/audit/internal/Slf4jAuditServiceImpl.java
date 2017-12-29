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

package org.xipki.audit.internal;

import java.io.CharArrayWriter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.PciAuditEvent;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Slf4jAuditServiceImpl extends AuditService {

    private static final Logger LOG = LoggerFactory.getLogger("xipki.audit.slf4j");

    public Slf4jAuditServiceImpl() {
    }

    @Override
    protected void logEvent0(AuditEvent event) {
        switch (event.level()) {
        case DEBUG:
            if (LOG.isDebugEnabled()) {
                LOG.debug("{}", createMessage(event));
            }
            break;
        default:
            if (LOG.isInfoEnabled()) {
                LOG.info("{}", createMessage(event));
            }
            break;
        } // end switch
    }

    @Override
    protected void logEvent0(PciAuditEvent event) {
        CharArrayWriter msg = event.toCharArrayWriter("");
        AuditLevel al = event.level();
        switch (al) {
        case DEBUG:
            if (LOG.isDebugEnabled()) {
                LOG.debug("{} | {}", al.alignedText(), msg);
            }
            break;
        default:
            if (LOG.isInfoEnabled()) {
                LOG.info("{} | {}", al.alignedText(), msg);
            }
            break;
        } // end switch
    }

}
