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

package org.xipki.ca.server.mgmt.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.shell.ProfileUpdateCmd;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.CmdFailure;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "profile-check",
    description = "check information of profiles (QA)")
@Service
public class ProfileCheckCmd extends ProfileUpdateCmd {

  @Override
  protected Object execute0() throws Exception {
    println("checking profile " + name);

    if (type == null && conf == null && confFile == null) {
      System.out.println("nothing to update");
      return null;
    }

    if (conf == null && confFile != null) {
      conf = new String(IoUtil.read(confFile));
    }

    CertprofileEntry cp = caManager.getCertprofile(name);
    if (cp == null) {
      throw new CmdFailure("certificate profile named '" + name + "' is not configured");
    }

    if (cp.getType() != null) {
      MgmtQaShellUtil.assertTypeEquals("type", type, cp.getType());
    }

    MgmtQaShellUtil.assertEquals("conf", conf, cp.getConf());

    println(" checked profile " + name);
    return null;
  }

}
