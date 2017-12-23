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

import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "export-conf",
        description = "export configuration to zip file")
@Service
public class ExportConfCmd extends CaAction {

    @Option(name = "--conf-file",
            required = true,
            description = "zip file that saves the exported configuration")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Option(name = "--ca", multiValued = true,
            description = "CAs whose configuration should be exported."
            + " Empty list means all CAs\n(multi-valued)")
    @Completion(CaNameCompleter.class)
    private List<String> caNames;

    @Override
    protected Object execute0() throws Exception {
        boolean bo = caManager.exportConf(confFile, caNames);
        output(bo, "exported", "could not export", "configuration to file " + confFile);
        return null;
    }

}
