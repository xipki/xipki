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

import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.CaCommandSupport;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ProfileNameCompleter;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "caprofile-check",
        description = "check information of certificate profiles in given CA (QA)")
@Service
public class CaProfileCheckCmd extends CaCommandSupport {

    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--profile",
            required = true,
            description = "profile name\n"
                + "(required)")
    @Completion(ProfileNameCompleter.class)
    private String profileName;

    @Override
    protected Object execute0() throws Exception {
        println("checking CA profile CA='" + caName + "', profile='" + profileName + "'");

        if (caManager.getCa(caName) == null) {
            throw new CmdFailure("could not find CA '" + caName + "'");
        }

        Set<String> entries = caManager.getCertprofilesForCa(caName);
        if (!entries.contains(profileName.toUpperCase())) {
            throw new CmdFailure("CA is not associated with profile '" + profileName + "'");
        }

        println(" checked CA profile CA='" + caName + "', profile='" + profileName + "'");
        return null;
    }

}
