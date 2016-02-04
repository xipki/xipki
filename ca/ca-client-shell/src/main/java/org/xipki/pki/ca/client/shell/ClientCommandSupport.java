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

package org.xipki.pki.ca.client.shell;

import java.io.IOException;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.commons.common.RequestResponseDebug;
import org.xipki.commons.common.RequestResponsePair;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.console.karaf.XipkiCommandSupport;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.pki.ca.client.api.CAClient;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class ClientCommandSupport extends XipkiCommandSupport {

    @Reference
    protected CAClient caClient;

    @Option(name = "--req-out",
            description = "where to save the request")
    @Completion(FilePathCompleter.class)
    private String reqout;

    @Option(name = "--resp-out",
            description = "where to save the response")
    @Completion(FilePathCompleter.class)
    private String respout;

    protected RequestResponseDebug getRequestResponseDebug() {
        boolean saveReq = isNotBlank(reqout);
        boolean saveResp = isNotBlank(respout);
        if (saveReq || saveResp) {
            return new RequestResponseDebug();
        }
        return null;
    }

    protected void saveRequestResponse(
            final RequestResponseDebug debug) {
        boolean saveReq = isNotBlank(reqout);
        boolean saveResp = isNotBlank(respout);
        if (!saveReq && !saveResp) {
            return;
        }

        if (debug == null || debug.size() == 0) {
            return;
        }

        final int n = debug.size();
        for (int i = 0; i < n; i++) {
            RequestResponsePair reqResp = debug.get(i);
            if (saveReq) {
                byte[] bytes = reqResp.getRequest();
                if (bytes != null) {
                    String fn = (n == 1)
                            ? reqout
                            : appendIndex(reqout, i);
                    try {
                        IoUtil.save(fn, bytes);
                    } catch (IOException ex) {
                        System.err.println("IOException: " + ex.getMessage());
                    }
                }
            }

            if (saveResp) {
                byte[] bytes = reqResp.getResponse();
                if (bytes != null) {
                    String fn = (n == 1)
                            ? respout
                            : appendIndex(respout, i);
                    try {
                        IoUtil.save(fn, bytes);
                    } catch (IOException ex) {
                        System.err.println("IOException: " + ex.getMessage());
                    }
                }
            }
        }
    } // method saveRequestResponse

    private static String appendIndex(
            final String filename,
            final int index) {
        int idx = filename.lastIndexOf('.');
        if (idx == -1 || idx == filename.length() - 1) {
            return filename + "-" + index;
        }

        StringBuilder sb = new StringBuilder(filename);
        sb.insert(idx, index);
        sb.insert(idx, '-');
        return sb.toString();
    }

}
