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
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.shell.completer.PublisherNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.PublisherTypeCompleter;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "publisher-up", description = "update publisher")
@Service
public class PublisherUpdateAction extends CaAction {

  @Option(name = "--name", aliases = "-n", required = true, description = "publisher name")
  @Completion(PublisherNameCompleter.class)
  protected String name;

  @Option(name = "--type", description = "publisher type")
  @Completion(PublisherTypeCompleter.class)
  protected String type;

  @Option(name = "--conf", description = "publisher configuration or 'null'")
  protected String conf;

  @Option(name = "--conf-file", description = "profile configuration file")
  @Completion(FileCompleter.class)
  protected String confFile;

  @Override
  protected Object execute0() throws Exception {
    if (type == null && conf == null && confFile == null) {
      throw new IllegalCmdParamException("nothing to update");
    }

    if (conf == null && confFile != null) {
      conf = new String(IoUtil.read(confFile));
    }

    String msg = "publisher " + name;
    try {
      caManager.changePublisher(name, type, conf);
      println("updated " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
