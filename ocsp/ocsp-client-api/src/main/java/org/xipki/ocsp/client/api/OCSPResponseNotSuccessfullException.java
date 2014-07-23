/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.api;

/**
 * @author Lijun Liao
 */

public class OCSPResponseNotSuccessfullException extends OCSPRequestorException
{

    private static final long serialVersionUID = 1L;
    private final int statusCode;
    private final String statusText;

    public OCSPResponseNotSuccessfullException(int statusCode)
    {
        super("OCSPResponse with status " + statusCode + " (" + getOCSPResponseStatus(statusCode) + ")");
        this.statusCode = statusCode;
        this.statusText = getOCSPResponseStatus(statusCode);
    }

    public int getStatusCode()
    {
        return statusCode;
    }

    public String getStatusText()
    {
        return statusText;
    }

    private static String getOCSPResponseStatus(int statusCode)
    {
        switch(statusCode)
        {
        case 0:
            return "successfull";
        case 1:
            return "malformedRequest";
        case 2:
            return "internalError";
        case 3:
            return "tryLater";
        case 5:
            return "sigRequired";
        case 6:
            return "unauthorized";
        default:
            return "undefined";
        }
    }

}
