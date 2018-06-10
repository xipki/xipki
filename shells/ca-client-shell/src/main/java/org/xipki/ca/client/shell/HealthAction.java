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

package org.xipki.ca.client.shell;

import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.client.shell.completer.CaNameCompleter;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "cmp-health", description = "check healty status of CA")
@Service
public class HealthAction extends ClientAction {

  @Option(name = "--ca", description = "CA name\n(required if multiple CAs are configured)")
  @Completion(CaNameCompleter.class)
  private String caName;

  @Option(name = "--verbose", aliases = "-v", description = "show status verbosely")
  private Boolean verbose = Boolean.FALSE;

  @Override
  protected Object execute0() throws Exception {
    if (caName != null) {
      caName = caName.toLowerCase();
    }

    Set<String> caNames = caClient.getCaNames();
    if (isEmpty(caNames)) {
      throw new IllegalCmdParamException("no CA is configured");
    }

    if (caName != null && !caNames.contains(caName)) {
      throw new IllegalCmdParamException("CA " + caName + " is not within the configured CAs "
          + caNames);
    }

    if (caName == null) {
      if (caNames.size() == 1) {
        caName = caNames.iterator().next();
      } else {
        throw new IllegalCmdParamException("no CA is specified, one of " + caNames
            + " is required");
      }
    }

    HealthCheckResult healthResult = caClient.getHealthCheckResult(caName);
    String str = StringUtil.concat("healthy status for CA ", caName, ": ",
        (healthResult.isHealthy() ? "healthy" : "not healthy"));
    if (verbose) {
      str = StringUtil.concat(str, "\n", healthResult.toJsonMessage(true));
    }
    System.out.println(str);
    return null;
  } // method execute0

}
