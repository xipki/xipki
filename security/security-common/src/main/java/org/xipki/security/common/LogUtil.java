/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
