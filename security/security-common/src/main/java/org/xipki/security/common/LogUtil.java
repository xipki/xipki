/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security.common;

import org.slf4j.Logger;

/**
 * @author Lijun Liao
 */

public class LogUtil
{
    public static void logErrorThrowable(Logger log, String message, Throwable t)
    {
        if(log.isErrorEnabled())
        {
            String msg = (message == null || message.isEmpty()) ? "{}: {}" : message + ", {}: {}";
            log.error(msg, t.getClass().getName(), t.getMessage());
        }
        log.debug(message == null ? "error" : message, t);
    }

    public static void logWarnThrowable(Logger log, String message, Throwable t)
    {
        if(log.isWarnEnabled())
        {
            String msg = (message == null || message.isEmpty()) ? "{}: {}" : message + ", {}: {}";
            log.warn(msg, t.getClass().getName(), t.getMessage());
        }
        log.debug(message == null ? "error" : message, t);
    }

}
