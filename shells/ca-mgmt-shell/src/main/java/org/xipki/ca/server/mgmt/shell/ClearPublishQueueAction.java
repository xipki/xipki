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

import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.shell.completer.CaNamePlusAllCompleter;
import org.xipki.ca.server.mgmt.shell.completer.PublisherNamePlusAllCompleter;
import org.xipki.shell.CmdFailure;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "clear-publishqueue", description = "clear publish queue")
@Service
public class ClearPublishQueueAction extends CaAction {

  @Option(name = "--ca", required = true, description = "CA name or 'all' for all CAs")
  @Completion(CaNamePlusAllCompleter.class)
  private String caName;

  @Option(name = "--publisher", required = true, multiValued = true,
      description = "publisher name or 'all' for all publishers")
  @Completion(PublisherNamePlusAllCompleter.class)
  private List<String> publisherNames;

  @Override
  protected Object execute0() throws Exception {
    if (publisherNames == null) {
      throw new IllegalStateException("should not reach here");
    }
    boolean allPublishers = false;
    for (String publisherName : publisherNames) {
      if ("all".equalsIgnoreCase(publisherName)) {
        allPublishers = true;
        break;
      }
    }

    if (allPublishers) {
      publisherNames = null;
    }

    if ("all".equalsIgnoreCase(caName)) {
      caName = null;
    }

    String msg = "publish queue of CA " + caName + " for publishers " + toString(publisherNames);
    try {
      caManager.clearPublishQueue(caName, publisherNames);
      println("cleared " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not clear " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
