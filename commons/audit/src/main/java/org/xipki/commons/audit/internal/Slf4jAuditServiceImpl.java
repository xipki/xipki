/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.audit.internal;

import java.io.CharArrayWriter;

import org.eclipse.jdt.annotation.NonNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.audit.AuditEvent;
import org.xipki.commons.audit.AuditLevel;
import org.xipki.commons.audit.AuditService;
import org.xipki.commons.audit.PciAuditEvent;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Slf4jAuditServiceImpl extends AuditService {

    private static final Logger LOG = LoggerFactory.getLogger("xipki.audit.slf4j");

    public Slf4jAuditServiceImpl() {
    }

    @Override
    public void doLogEvent(@NonNull final AuditEvent event) {
        switch (event.getLevel()) {
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
    public void doLogEvent(@NonNull final PciAuditEvent event) {
        CharArrayWriter msg = event.toCharArrayWriter("");
        AuditLevel al = event.getLevel();
        switch (al) {
        case DEBUG:
            if (LOG.isDebugEnabled()) {
                LOG.debug("{} | {}", al.getAlignedText(), msg);
            }
            break;
        default:
            if (LOG.isInfoEnabled()) {
                LOG.info("{} | {}", al.getAlignedText(), msg);
            }
            break;
        } // end switch
    }

}
