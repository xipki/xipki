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

package org.xipki.ca.server.mgmt.shell;

import java.io.File;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "profile-export",
        description = "export certificate profile configuration")
@Service
public class ProfileExportCmd extends CaAction {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "profile name\n"
                    + "(required)")
    private String name;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the profile configuration\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
        CertprofileEntry entry = caManager.getCertprofile(name);
        if (entry == null) {
            throw new IllegalCmdParamException(
                    "no certificate profile named " + name + " is defined");
        }

        if (StringUtil.isBlank(entry.conf())) {
            println("cert profile does not have conf");
        } else {
            saveVerbose("saved cert profile configuration to", new File(confFile),
                    entry.conf().getBytes("UTF-8"));
        }
        return null;
    }

}
