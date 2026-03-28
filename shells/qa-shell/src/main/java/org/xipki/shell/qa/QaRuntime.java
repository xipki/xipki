// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.qa;

import org.xipki.qa.ca.CaQaSystemManager;
import org.xipki.qa.ca.CaQaSystemManagerImpl;
import org.xipki.shell.ShellUtil;

/**
 * Qa Runtime.
 *
 * @author Lijun Liao (xipki)
 */
public class QaRuntime {

  private static final String DEFAULT_QA_CONF = "xipki/ca-qa/qa-certcheck-conf.json";

  private static CaQaSystemManager caQaManager;

  private QaRuntime() {
  }

  /**
   * Returns the lazily initialized QA system manager.
   *
   * @return QA system manager
   */
  public synchronized static CaQaSystemManager getCaQaManager() {
    if (caQaManager != null) {
      return caQaManager;
    }

    String confFile = ShellUtil.resolveRequired(DEFAULT_QA_CONF);
    caQaManager = newCaQaManager(confFile);
    return caQaManager;
  }

  private static CaQaSystemManager newCaQaManager(String confFile) {
    CaQaSystemManagerImpl manager = new CaQaSystemManagerImpl();
    manager.setConfFile(confFile);
    return manager;
  }

}
