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

import java.io.File;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.shell.completer.PublisherNameCompleter;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "publisher-export",
        description = "export publisher configuration")
@Service
public class PublisherExportCmd extends CaAction {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "publisher name\n"
                    + "(required)")
    @Completion(PublisherNameCompleter.class)
    private String name;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the publisher configuration\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
        PublisherEntry entry = caManager.getPublisher(name);
        if (entry == null) {
            throw new IllegalCmdParamException("no publisher named " + name + " is defined");
        }

        if (StringUtil.isBlank(entry.conf())) {
            println("publisher does not have conf");
        } else {
            saveVerbose("saved publisher configuration to", new File(confFile),
                    entry.conf().getBytes("UTF-8"));
        }
        return null;
    }

}
