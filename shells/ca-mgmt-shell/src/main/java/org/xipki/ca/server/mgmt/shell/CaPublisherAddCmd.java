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
import org.xipki.ca.server.mgmt.shell.completer.PublisherNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "capub-add",
        description = "add publisher to CA")
@Service
public class CaPublisherAddCmd extends CaAction {

    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--publisher",
        required = true, multiValued = true,
        description = "publisher name\n"
                + "(required, multi-valued)")
    @Completion(PublisherNameCompleter.class)
    private List<String> publisherNames;

    @Override
    protected Object execute0() throws Exception {
        for (String publisherName : publisherNames) {
            boolean bo = caManager.addPublisherToCa(publisherName, caName);
            output(bo, "added", "could not add", "publisher " + publisherName + " to CA " + caName);
        }
        return null;
    }

}
