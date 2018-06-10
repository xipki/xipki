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

package org.xipki.ca.server.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.shell.completer.ProfileTypeCompleter;
import org.xipki.shell.CmdFailure;
import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "profile-add", description = "add certificate profile")
@Service
public class ProfileAddAction extends CaAction {

  @Option(name = "--name", aliases = "-n", required = true, description = "profile name")
  private String name;

  @Option(name = "--type", required = true, description = "profile type")
  @Completion(ProfileTypeCompleter.class)
  private String type;

  @Option(name = "--conf", description = "certificate profile configuration")
  private String conf;

  @Option(name = "--conf-file", description = "certificate profile configuration file")
  @Completion(FileCompleter.class)
  private String confFile;

  @Override
  protected Object execute0() throws Exception {
    if (conf == null && confFile != null) {
      conf = new String(IoUtil.read(confFile));
    }

    CertprofileEntry entry = new CertprofileEntry(new NameId(null, name), type, conf);
    String msg = "certificate profile " + name;
    try {
      caManager.addCertprofile(entry);
      println("added " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
