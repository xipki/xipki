/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.commons.remotep11.server;

import java.io.EOFException;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HttpProxyServlet extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(HttpProxyServlet.class);

    private static final long serialVersionUID = 1L;

    private static final String REQUEST_MIMETYPE = "application/x-xipki-pkcs11";

    private static final String RESPONSE_MIMETYPE = "application/x-xipki-pkcs11";

    private final P11ProxyResponder responder;
    
    private LocalP11CryptServicePool localP11CryptServicePool;

    public HttpProxyServlet() {
        responder = new P11ProxyResponder();
    }

    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        try {
            boolean success = true;

            if (success && !REQUEST_MIMETYPE.equalsIgnoreCase(request.getContentType())) {
                success = false;
                response.sendError(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
            }

            if (success && localP11CryptServicePool == null) {
                success = false;
                LOG.error("localP11CryptService in servlet not configured");
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }

            if (success) {
                byte[] requestBytes = IoUtil.read(request.getInputStream());
                byte[] responseBytes = responder.processRequest(localP11CryptServicePool,
                        requestBytes);

                response.setContentType(RESPONSE_MIMETYPE);
                response.setStatus(HttpServletResponse.SC_OK);
                response.getOutputStream().write(responseBytes);
            }
        } catch (EOFException ex) {
            LogUtil.warn(LOG, ex, "connection reset by peer");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        } catch (Throwable th) {
            LogUtil.error(LOG, th, "Throwable thrown, this should not happen.");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentLength(0);
        } finally {
            response.flushBuffer();
        }
    } // method doPost

    public void setLocalP11CryptServicePool(
            final LocalP11CryptServicePool localP11CryptServicePool) {
        this.localP11CryptServicePool = localP11CryptServicePool;
    }

}
