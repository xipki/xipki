/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.util;

import java.io.File;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * XIPKI_BASE utility class.
 *
 * @author Lijun Liao
 */
public class XipkiBaseDir {

  private static final Logger LOG = LoggerFactory.getLogger(XipkiBaseDir.class);

  private static final String PROP_XIPKI_BASE = "XIPKI_BASE";

  private static String basedir = null;

  public static synchronized void init() {
    if (basedir != null) {
      return;
    }

    String str = System.getProperty(PROP_XIPKI_BASE);

    String workingDir;
    try {
      workingDir = new File(".").getCanonicalPath();
    } catch (IOException ex) {
      workingDir = new File(".").getAbsolutePath();
    }

    LOG.info("working dir is {}", workingDir);

    if (StringUtil.isBlank(str)) {
      String os = System.getProperty("os.name");
      boolean windows = os.toLowerCase().contains("windows");
      if (windows) {
        basedir = "C:\\Program Files\\xipki";
      } else {
        basedir = "/opt/xipki";
      }
      LOG.info("use default basedir '{}', can be specified via the property '{}'",
          basedir, PROP_XIPKI_BASE);
    } else {
      if (str.startsWith("~")) {
        str = IoUtil.USER_HOME + str.substring(1);
      }

      try {
        basedir = new File(str).getCanonicalPath();
      } catch (IOException ex) {
        throw new IllegalStateException("error getCanonicalPath of " + str);
      }
      LOG.info("use basedir '{}', ", basedir);
    }
  }

  private XipkiBaseDir() {
  }

  public static final String basedir() {
    return basedir;
  }

}
