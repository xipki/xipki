/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

/**
 * @author Lijun Liao
 */

public class LogUtil
{

    public static String buildExceptionLogFormat(String message)
    {
        return (message == null || message.isEmpty()) ? "{}: {}" : message + ", {}: {}";
    }

}
