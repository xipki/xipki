/*
 * Copyright 2014 xipki.org
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

package org.xipki.ocsp;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Rfc2560Servlet extends HttpServlet
{
    private final Logger LOG = LoggerFactory.getLogger(Rfc2560Servlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_REQUEST  = "application/ocsp-request";
    private static final String CT_RESPONSE = "application/ocsp-response";

    private int maxRequestLength = 4096;

    private OcspResponder responder;
    public Rfc2560Servlet()
    {
    }

    public void setResponder(OcspResponder responder)
    {
        this.responder = responder;
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException
    {
        try{
            if(responder == null)
            {
                LOG.error("responder in servlet not configured");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);
                return;
            }

            // accept only "application/ocsp-request" as content type
            if (! CT_REQUEST.equalsIgnoreCase(request.getContentType()))
            {
                response.setContentLength(0);
                response.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
                response.flushBuffer();
                return;
            }

            // request too long
            if(request.getContentLength() > maxRequestLength)
            {
                response.setContentLength(0);
                response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
                response.flushBuffer();
                return;
            }

            ServletInputStream in = request.getInputStream();
            ASN1StreamParser parser = new ASN1StreamParser(in);
            OCSPRequest ocspRequest = OCSPRequest.getInstance(parser.readObject());
            OCSPReq ocspReq = new OCSPReq(ocspRequest);

            response.setContentType(Rfc2560Servlet.CT_RESPONSE);

            OCSPResp ocspResp = responder.answer(ocspReq);
            if (ocspResp == null)
            {
                LOG.error("processRequest returned null, this should not happen!");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);
            }
            else
            {
                byte[] encodedOcspResp = ocspResp.getEncoded();
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentLength(encodedOcspResp.length);
                response.getOutputStream().write(encodedOcspResp);
            }
        }catch(Throwable t)
        {
            LOG.error("Throwable. {}: {}", t.getClass().getName(), t.getMessage());
            LOG.debug("Throwable", t);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        }

        response.flushBuffer();
    }

    public int getMaxRequestLength() {
        return maxRequestLength;
    }

    public void setMaxRequestLength(int maxRequestLength) {
        this.maxRequestLength = maxRequestLength;
    }

}
