/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.commons.console.karaf.command;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.XipkiCommandSupport;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

@Command(scope = "xipki-cmd", name = "curl",
        description = "Transfer a URL")
@Service
public class CurlCmd extends XipkiCommandSupport {

    @Argument(index = 0, name = "url",
            required = true,
            description = "URL\n"
                    + "(required)")
    private String url;

    @Option(name = "--verbose", aliases = "-v",
            description = "show response verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(name = "--post", aliases = "-p",
            description = "send the request via HTTP POST")
    private Boolean usePost;

    @Option(name = "--data", aliases = "-d",
            description = "data to be sent in a POST request")
    private String postData;

    @Option(name = "--data-charset", aliases = "-c",
            description = "charset of data")
    private String postDataCharSet = "UTF-8";

    @Option(name = "--data-file",
            description = "file contains the data to be sent in a POST request")
    private String postDataFile;

    @Option(name = "--out",
            description = "where to save the response")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Option(name = "--header", aliases = "-h",
            multiValued = true,
            description = "header in request")
    @Completion(FilePathCompleter.class)
    private List<String> headers;

    @Option(name = "--user", aliases = "-u",
            description = "<user:password>")
    private String userPassword;

    @Override
    protected Object doExecute() throws Exception {

        byte[] dataBytes = null;
        if (postData != null) {
            dataBytes = postData.getBytes(postDataCharSet);
        } else if (postDataFile != null) {
            dataBytes = IoUtil.read(postDataFile);
        }

        if (dataBytes != null) {
            usePost = Boolean.TRUE;
        } else if (usePost == null) {
            usePost = Boolean.TRUE;
        }

        URL newUrl = new URL(url);
        HttpURLConnection httpConn = IoUtil.openHttpConn(newUrl);;

        try {
            httpConn.setRequestMethod(usePost ? "POST" : "GET");
            httpConn.setUseCaches(false);

            if (headers != null) {
                for (String header : headers) {
                    int idx = header.indexOf(':');
                    if (idx == -1 || idx == header.length() - 1) {
                        throw new IllegalCmdParamException("invalid HTTP header: '" + header + "'");
                    }

                    String key = header.substring(0, idx);
                    String value = header.substring(idx + 1).trim();

                    httpConn.setRequestProperty(key, value);
                }
            }

            if (userPassword != null) {
                int idx = userPassword.indexOf(':');
                if (idx == -1 || idx == userPassword.length() - 1) {
                    throw new IllegalCmdParamException("invalid user");
                }

                httpConn.setRequestProperty("Authorization",
                        "Basic " + Base64.toBase64String(userPassword.getBytes()));
            }

            Map<String, List<String>> properties;

            if (dataBytes == null) {
                properties = httpConn.getRequestProperties();
            } else {
                httpConn.setDoOutput(true);
                httpConn.setRequestProperty("Content-Length", Integer.toString(dataBytes.length));
                properties = httpConn.getRequestProperties();

                OutputStream outputstream = httpConn.getOutputStream();
                outputstream.write(dataBytes);
                outputstream.flush();
            }

            // show the request headers
            if (verbose) {
                println("request:\n========");
                println("  HTTP method: " + httpConn.getRequestMethod());
                for (String key : properties.keySet()) {
                    List<String> values = properties.get(key);
                    for (String value : values) {
                        println("  " + key + ": " + value);
                    }
                }
            }

            // read the response
            int respCode = httpConn.getResponseCode();
            if (verbose) {
                println("response:\n========");
                println("  reponse code: " + respCode + " " + httpConn.getResponseMessage());
                properties = httpConn.getHeaderFields();
                for (String key : properties.keySet()) {
                    List<String> values = properties.get(key);
                    for (String value : values) {
                        println("  " + key + ": " + value);
                    }
                }
            }

            InputStream inputstream = httpConn.getInputStream();
            if (respCode != HttpURLConnection.HTTP_OK) {
                inputstream.close();
                println("ERROR: bad response: " + httpConn.getResponseCode() + "    "
                        + httpConn.getResponseMessage());
                return null;
            }

            byte[] respContentBytes = IoUtil.read(inputstream);
            if (respContentBytes == null || respContentBytes.length == 0) {
                println("NO response content");
                return null;
            }

            if (outFile != null) {
                saveVerbose("saved response to", new File(outFile), respContentBytes);
            } else {
                println(new String(respContentBytes, "UTF-8"));
            }
        } finally {
            // httpConn.disconnect();
        }

        return null;
    }

}
