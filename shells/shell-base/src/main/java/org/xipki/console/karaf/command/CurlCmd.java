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

package org.xipki.console.karaf.command;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.XiAction;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

@Command(scope = "xi", name = "curl",
        description = "transfer a URL")
@Service
public class CurlCmd extends XiAction {

    @Argument(index = 0, name = "url",
            required = true,
            description = "URL\n"
                    + "(required)")
    private String url;

    @Option(name = "--verbose", aliases = "-v",
            description = "show request and response verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(name = "--post", aliases = "-p",
            description = "send the request via HTTP POST")
    private Boolean usePost = Boolean.FALSE;

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
            description = "User and password of the form user:password")
    private String userPassword;

    @Override
    protected Object execute0() throws Exception {

        byte[] dataBytes = null;
        if (postData != null) {
            dataBytes = postData.getBytes(postDataCharSet);
        } else if (postDataFile != null) {
            dataBytes = IoUtil.read(postDataFile);
        }

        if (dataBytes != null) {
            usePost = Boolean.TRUE;
        }

        URL newUrl = new URL(url);
        HttpURLConnection httpConn = IoUtil.openHttpConn(newUrl);

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
                        "Basic " + Base64.encodeToString(userPassword.getBytes()));
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
                println("=====request=====");
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
                println("=====response=====");
                println("  response code: " + respCode + " " + httpConn.getResponseMessage());
                properties = httpConn.getHeaderFields();
                for (String key : properties.keySet()) {
                    if (key == null) {
                        continue;
                    }
                    List<String> values = properties.get(key);
                    for (String value : values) {
                        println("  " + key + ": " + value);
                    }
                }
                println("=====response content=====");
            } else {
                if (respCode != HttpURLConnection.HTTP_OK) {
                    println("ERROR: bad response: " + httpConn.getResponseCode() + "    "
                            + httpConn.getResponseMessage());
                }
            }

            InputStream inputStream = null;
            InputStream errorStream = null;

            try {
                inputStream = httpConn.getInputStream();
            } catch (IOException ex) {
                errorStream = httpConn.getErrorStream();
            }

            byte[] respContentBytes;
            if (inputStream != null) {
                respContentBytes = IoUtil.read(inputStream);
            } else if (errorStream != null) {
                respContentBytes = IoUtil.read(errorStream);
            } else {
                respContentBytes = null;
            }

            if (respContentBytes == null || respContentBytes.length == 0) {
                println("NO response content");
                return null;
            }

            if (outFile != null) {
                String fn = (errorStream != null) ? "error-" + outFile : outFile;
                saveVerbose("saved response to file", new File(fn), respContentBytes);
            } else {
                String ct = httpConn.getHeaderField("Content-Type");
                String charset = getCharset(ct);
                if (charset == null) {
                    charset = "UTF-8";
                }
                if (errorStream != null) {
                    println("ERROR: ");
                }
                println(new String(respContentBytes, charset));
            }
        } finally {
            httpConn.disconnect();
        }

        return null;
    }

    private static String getCharset(final String contentType) {
        if (StringUtil.isBlank(contentType) || contentType.indexOf(';') == -1) {
            return null;
        }

        StringTokenizer st = new StringTokenizer(contentType, ";");
        st.nextToken();

        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            int idx = token.indexOf('=');
            if (idx == -1) {
                continue;
            }

            String paramName = token.substring(0, idx).trim();
            if ("charset".equalsIgnoreCase(paramName)) {
                return token.substring(idx + 1, token.length());
            }
        }

        return null;
    }

}
