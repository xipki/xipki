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

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.api.NameId;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.ca.mgmt.api.PublisherEntry;
import org.xipki.shell.CmdFailure;
import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "publisher-add", description = "add publisher")
@Service
public class PublisherAddAction extends CaAction {

  @Option(name = "--name", aliases = "-n", required = true, description = "publisher Name")
  private String name;

  @Option(name = "--type", required = true, description = "publisher type")
  @Completion(CaCompleters.PublisherTypeCompleter.class)
  private String type;

  @Option(name = "--conf", description = "publisher configuration")
  private String conf;

  @Option(name = "--conf-file", description = "publisher configuration file")
  @Completion(FileCompleter.class)
  private String confFile;

  @Override
  protected Object execute0() throws Exception {
    if (conf == null && confFile != null) {
      conf = new String(IoUtil.read(confFile));
    }

    PublisherEntry entry = new PublisherEntry(new NameId(null, name), type, conf);
    String msg = "publisher " + name;
    try {
      caManager.addPublisher(entry);
      println("added " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
