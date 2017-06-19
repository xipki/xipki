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

package org.xipki.pki.scep.serveremulator;

import java.util.Arrays;
import java.util.List;

import org.xipki.common.util.ParamUtil;
import org.xipki.http.server.HttpServer;
import org.xipki.http.server.ServletListener;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepServerContainer {

    private HttpServer server;

    public ScepServerContainer(final int port, final ScepServer scepServer) throws Exception {
        this(port, Arrays.asList(ParamUtil.requireNonNull("scepServer", scepServer)));
    }

    public ScepServerContainer(final int port, final List<ScepServer> scepServers)
            throws Exception {
        ParamUtil.requireNonEmpty("scepServers", scepServers);
        HttpServer tmpServer = new HttpServer(null, port, 1);

        ServletListener servletListener = new ServletListener();
        tmpServer.setServletListener(servletListener);
        for (ScepServer m : scepServers) {
            String alias = "/" + m.name() + "/pkiclient.exe";
            ScepServlet servlet = m.getServlet();
            servletListener.register(servlet, alias);
        }

        this.server = tmpServer;
    }

    public void start() throws Exception {
        try {
            server.start();
        } catch (Exception ex) {
            server.shutdown();
            throw ex;
        }
    }

    public void stop() throws Exception {
        server.shutdown();
    }

}
