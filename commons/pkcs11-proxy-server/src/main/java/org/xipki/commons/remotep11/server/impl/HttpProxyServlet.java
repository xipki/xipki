/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.commons.remotep11.server.impl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.pkcs11proxy.common.ServerCaps;
import org.xipki.commons.security.api.BadAsn1ObjectException;
import org.xipki.commons.security.api.p11.P11CryptServiceFactory;
import org.xipki.commons.security.api.p11.P11TokenException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HttpProxyServlet extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(HttpProxyServlet.class);

    private static final long serialVersionUID = 1L;

    private static final String CT_REQUEST = "application/pkixcmp";

    private static final String CT_RESPONSE = "application/pkixcmp";

    private final CmpResponder responder;

    private LocalP11CryptServicePool localP11CryptServicePool;

    public HttpProxyServlet() {
        responder = new CmpResponder();
    }

    @Override
    public void doGet(
            final HttpServletRequest request,
            final HttpServletResponse response)
    throws ServletException, IOException {
        String operation = request.getParameter("operation");
        try {
            if (!"GetCaps".equalsIgnoreCase(operation)) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
            } else {
                if (localP11CryptServicePool == null) {
                    LOG.error("localP11CryptService in servlet not configured");
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    response.setContentLength(0);
                    return;
                }

                String moduleName = extractModuleName(request);
                if (moduleName == null) {
                    response.sendError(HttpServletResponse.SC_NOT_FOUND);
                    return;
                }

                boolean readOnly;
                try {
                    readOnly = localP11CryptServicePool.getP11CryptService(moduleName).getModule()
                            .isReadOnly();
                } catch (P11TokenException ex) {
                    LOG.error("localP11CryptService in servlet not configured");
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    return;
                }
                ServerCaps serverCaps = new ServerCaps(readOnly, CmpResponder.getVersions());
                String respText = serverCaps.getCaps();
                response.setStatus(HttpServletResponse.SC_OK);
                response.getOutputStream().write(respText.getBytes());
                response.getOutputStream().flush();
            }
        } finally {
            response.flushBuffer();
        }
    }

    @Override
    public void doPost(
            final HttpServletRequest request,
            final HttpServletResponse response)
    throws ServletException, IOException {
        try {
            String moduleName = extractModuleName(request);
            if (moduleName == null) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            if (localP11CryptServicePool == null) {
                LOG.error("localP11CryptService in servlet not configured");
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentLength(0);
                return;
            }

            if (!CT_REQUEST.equalsIgnoreCase(request.getContentType())) {
                response.setContentLength(0);
                response.sendError(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
                response.flushBuffer();
                return;
            }

            PKIMessage pkiReq;
            try {
                pkiReq = generatePkiMessage(request.getInputStream());
            } catch (Exception ex) {
                response.setContentLength(0);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                final String message = "could not parse the request (PKIMessage)";
                LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
                LOG.debug(message, ex);
                return;
            }

            PKIMessage pkiResp = responder.processPkiMessage(localP11CryptServicePool,
                    moduleName, pkiReq);

            response.setContentType(CT_RESPONSE);
            response.setStatus(HttpServletResponse.SC_OK);
            ASN1OutputStream asn1Out = new ASN1OutputStream(response.getOutputStream());
            asn1Out.writeObject(pkiResp);
            asn1Out.flush();
        } catch (EOFException ex) {
            final String message = "connection reset by peer";
            if (LOG.isWarnEnabled()) {
                LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
            }
            LOG.debug(message, ex);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        } catch (Throwable th) {
            String msg = "Throwable thrown, this should not happen.";
            LOG.error(LogUtil.getErrorLog(msg), th.getClass().getName(), th.getMessage());
            LOG.debug(msg, th);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        } finally {
            response.flushBuffer();
        }
    } // method doPost

    protected PKIMessage generatePkiMessage(
            final InputStream is)
    throws BadAsn1ObjectException {
        ParamUtil.requireNonNull("is", is);
        ASN1InputStream asn1Stream = new ASN1InputStream(is);

        try {
            return PKIMessage.getInstance(asn1Stream.readObject());
        } catch (IOException | IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("could not parse PKIMessage: " + ex.getMessage(), ex);
        } finally {
            try {
                asn1Stream.close();
            } catch (IOException ex) {
                LOG.error("could not close ASN1Stream: {}", ex.getMessage());
            }
        }
    }

    public void setLocalP11CryptServicePool(
            final LocalP11CryptServicePool localP11CryptServicePool) {
        this.localP11CryptServicePool = localP11CryptServicePool;
    }

    private static String extractModuleName(
            final HttpServletRequest request)
    throws UnsupportedEncodingException {
        String moduleName = null;
        String encodedUrl = request.getRequestURI();
        String constructedPath = null;
        if (encodedUrl != null) {
            constructedPath = URLDecoder.decode(encodedUrl, "UTF-8");
            String servletPath = request.getServletPath();
            if (!servletPath.endsWith("/")) {
                servletPath += "/";
                if (servletPath.startsWith(constructedPath)) {
                    moduleName = P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;
                }
            }

            int indexOf = constructedPath.indexOf(servletPath);
            if (indexOf >= 0) {
                constructedPath = constructedPath.substring(indexOf + servletPath.length());
            }
        }

        if (moduleName == null) {
            int moduleNameEndIndex = constructedPath.indexOf('/');
            moduleName = (moduleNameEndIndex == -1)
                    ? constructedPath
                    : constructedPath.substring(0, moduleNameEndIndex);
        }

        return moduleName;
    }
}
