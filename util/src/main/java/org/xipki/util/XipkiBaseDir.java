// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

/**
 * XIPKI_BASE utility class.
 *
 * @author Lijun Liao (xipki)
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
      basedir = new File("xipki").getAbsolutePath();
      LOG.info("use default basedir '{}', can be specified via the property '{}'", basedir, PROP_XIPKI_BASE);
    } else {
      if (str.startsWith("~")) {
        str = IoUtil.USER_HOME + str.substring(1);
      }

      basedir = new File(IoUtil.expandFilepath(str)).getAbsolutePath();
      LOG.info("use basedir '{}', ", basedir);
    }
  }

  private XipkiBaseDir() {
  }

  public static String basedir() {
    return basedir;
  }

}
