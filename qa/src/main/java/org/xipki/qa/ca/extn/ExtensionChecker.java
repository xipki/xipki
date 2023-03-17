// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca.extn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;

/**
 * Extension checker.
 * @author Lijun Liao
 */
class ExtensionChecker {

  protected final Logger log;

  protected final ExtensionsChecker caller;

  ExtensionChecker(ExtensionsChecker caller) {
    this.caller = caller;
    this.log = LoggerFactory.getLogger(getClass());
  }

  protected XijsonCertprofile getCertprofile() {
    return caller.getCertprofile();
  }
}
