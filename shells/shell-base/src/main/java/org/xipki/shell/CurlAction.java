/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.shell;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.http.curl.Curl;
import org.xipki.util.http.curl.CurlResult;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

@Command(scope = "xi", name = "curl", description = "transfer a URL")
@Service
public class CurlAction extends XiAction {

  @Argument(index = 0, name = "url", required = true, description = "URL")
  private String url;

  @Option(name = "--verbose", aliases = "-v", description = "show request and response verbosely")
  private Boolean verbose = Boolean.FALSE;

  @Option(name = "--post", aliases = "-p", description = "send the request via HTTP POST")
  private Boolean usePost = Boolean.FALSE;

  @Option(name = "--data", aliases = "-d", description = "data to be sent in a POST request")
  private String postData;

  @Option(name = "--data-charset", aliases = "-c", description = "charset of data")
  private String postDataCharSet = "UTF-8";

  @Option(name = "--data-file", description = "file contains the data to be sent in a POST request")
  @Completion(FileCompleter.class)
  private String postDataFile;

  @Option(name = "--out", description = "where to save the response")
  @Completion(FileCompleter.class)
  private String outFile;

  @Option(name = "--header", aliases = "-h", multiValued = true, description = "header in request")
  private List<String> headers;

  @Option(name = "--user", aliases = "-u",
      description = "User and password of the form user:password")
  private String userPassword;

  @Reference
  private Curl curl;

  @Override
  protected Object execute0() throws Exception {
    byte[] content = null;
    if (postData != null) {
      content = postData.getBytes(postDataCharSet);
    } else if (postDataFile != null) {
      content = IoUtil.read(postDataFile);
    }

    if (content != null) {
      usePost = Boolean.TRUE;
    }

    Map<String, String> headerNameValues = null;
    if (headers != null) {
      headerNameValues = new HashMap<>();
      for (String header : headers) {
        int idx = header.indexOf(':');
        if (idx == -1 || idx == header.length() - 1) {
          throw new IllegalCmdParamException("invalid HTTP header: '" + header + "'");
        }

        String key = header.substring(0, idx);
        String value = header.substring(idx + 1).trim();
        headerNameValues.put(key, value);
      }
    }

    CurlResult result;
    if (usePost) {
      result = curl.curlPost(url, verbose, headerNameValues, userPassword, content);
    } else {
      result = curl.curlGet(url, verbose, headerNameValues, userPassword);
    }

    if (result.getContent() == null && result.getErrorContent() == null) {
      println("NO response content");
      return null;
    }

    if (outFile != null) {
      if (result.getContent() != null) {
        saveVerbose("saved response to file", outFile, result.getContent());
      } else {
        saveVerbose("saved (error) response to file", "error-" + outFile, result.getErrorContent());
      }
    } else {
      String ct = result.getContentType();
      String charset = getCharset(ct);
      if (charset == null) {
        charset = "UTF-8";
      }

      if (result.getContent() != null) {
        println(new String(result.getContent(), charset));
      } else {
        println("ERROR: ");
        println(new String(result.getContent(), charset));
      }
    }

    return null;
  }

  private static String getCharset(String contentType) {
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
