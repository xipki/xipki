/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.remotep11.server;

import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Lijun Liao
 */

public class Rfc6712Servlet extends HttpServlet
{
    private static final Logger LOG = LoggerFactory.getLogger(Rfc6712Servlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_REQUEST  = "application/pkixcmp";
    private static final String CT_RESPONSE = "application/pkixcmp";

    private final CmpResponder responder;
    private LocalP11CryptService localP11CryptService;

    public Rfc6712Servlet()
    {
        responder = new CmpResponder();
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
    {
        try
        {
            if(localP11CryptService == null)
            {
                LOG.error("localP11CryptService in servlet not configured");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);
                return;
            }

            if (CT_REQUEST.equalsIgnoreCase(request.getContentType()) == false)
            {
                response.setContentLength(0);
                response.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
                response.flushBuffer();
                return;
            }

            PKIMessage pkiReq = generatePKIMessage(request.getInputStream());

            PKIHeader reqHeader = pkiReq.getHeader();
            ASN1OctetString tid = reqHeader.getTransactionID();

            PKIHeaderBuilder respHeader = new PKIHeaderBuilder(reqHeader.getPvno().getValue().intValue(),
                    reqHeader.getRecipient(), reqHeader.getSender());
            respHeader.setTransactionID(tid);

            PKIMessage pkiResp = responder.processPKIMessage(localP11CryptService, pkiReq);
            byte[] pkiRespBytes = pkiResp.getEncoded("DER");

            response.setContentType(Rfc6712Servlet.CT_RESPONSE);
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentLength(pkiRespBytes.length);
            response.getOutputStream().write(pkiRespBytes);

        }catch(Throwable t)
        {
            LOG.error("Throwable thrown, this should not happen. {}: {}", t.getClass().getName(), t.getMessage());
            LOG.debug("Throwable thrown, this should not happen.", t);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        }

        response.flushBuffer();
    }

    protected PKIMessage generatePKIMessage(InputStream is)
    throws IOException
    {
        ASN1InputStream asn1Stream = new ASN1InputStream(is);

        try
        {
            return PKIMessage.getInstance(asn1Stream.readObject());
        }finally
        {
            try
            {
                asn1Stream.close();
            }catch(IOException e)
            {
            }
        }
    }

    public void setLocalP11CryptService(LocalP11CryptService localP11CryptService)
    {
        this.localP11CryptService = localP11CryptService;
    }
}
