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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.completer.ProfileNameCompleter;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "profile-up",
        description = "update certificate profile")
@Service
public class ProfileUpdateCmd extends CaCommandSupport {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "profile name\n"
                    + "(required)")
    @Completion(ProfileNameCompleter.class)
    protected String name;

    @Option(name = "--type",
            description = "profile type")
    protected String type;

    @Option(name = "--conf",
            description = "certificate profile configuration or 'NULL'")
    protected String conf;

    @Option(name = "--conf-file",
            description = "certificate profile configuration file")
    @Completion(FilePathCompleter.class)
    protected String confFile;

    @Override
    protected Object execute0() throws Exception {
        if (type == null && conf == null && confFile == null) {
            throw new IllegalCmdParamException("nothing to update");
        }

        if (conf == null && confFile != null) {
            conf = new String(IoUtil.read(confFile));
        }

        boolean bo = caManager.changeCertprofile(name, type, conf);
        output(bo, "updated", "could not update", "certificate profile " + name);
        return null;
    }

}
