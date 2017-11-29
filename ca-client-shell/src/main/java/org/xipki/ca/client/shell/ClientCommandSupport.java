/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.client.shell;

import java.io.IOException;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.ca.client.api.CaClient;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.RequestResponsePair;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.XipkiCommandSupport;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class ClientCommandSupport extends XipkiCommandSupport {

    @Reference
    protected CaClient caClient;

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

    protected void saveRequestResponse(final RequestResponseDebug debug) {
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
                byte[] bytes = reqResp.request();
                if (bytes != null) {
                    String fn = (n == 1) ? reqout : appendIndex(reqout, i);
                    try {
                        IoUtil.save(fn, bytes);
                    } catch (IOException ex) {
                        System.err.println("IOException: " + ex.getMessage());
                    }
                }
            }

            if (saveResp) {
                byte[] bytes = reqResp.response();
                if (bytes != null) {
                    String fn = (n == 1) ? respout : appendIndex(respout, i);
                    try {
                        IoUtil.save(fn, bytes);
                    } catch (IOException ex) {
                        System.err.println("IOException: " + ex.getMessage());
                    }
                }
            }
        }
    } // method saveRequestResponse

    private static String appendIndex(final String filename, final int index) {
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
