/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.CaCommandSupport;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "caalias-check",
        description = "check CA aliases (QA)")
@Service
public class CaAliasCheckCmd extends CaCommandSupport {

    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--alias",
            required = true,
            description = "alias name\n"
                    + "(required)")
    private String aliasName;

    @Override
    protected Object execute0() throws Exception {
        println("checking CA alias='" + aliasName + "', CA='" + caName + "'");
        String tmpCaName = caManager.getCaNameForAlias(aliasName);
        if (tmpCaName == null) {
            throw new CmdFailure("alias '" + aliasName + "' is not configured");
        }

        MgmtQaShellUtil.assertEquals("CA name", caName, tmpCaName);
        println(" checked CA alias='" + aliasName + "', CA='" + caName + "'");
        return null;
    }

}
