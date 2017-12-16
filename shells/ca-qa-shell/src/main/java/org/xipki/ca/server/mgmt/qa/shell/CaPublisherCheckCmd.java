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

import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.shell.CaCommandSupport;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.PublisherNameCompleter;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "capub-check",
        description = "check information of publishers in given CA (QA)")
@Service
public class CaPublisherCheckCmd extends CaCommandSupport {

    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--publisher",
            required = true,
            description = "publisher name\n"
                    + "(required)")
    @Completion(PublisherNameCompleter.class)
    private String publisherName;

    @Override
    protected Object execute0() throws Exception {
        println("checking CA publisher CA='" + caName + "', publisher='" + publisherName + "'");

        if (caManager.getCa(caName) == null) {
            throw new CmdFailure("could not find CA '" + caName + "'");
        }

        List<PublisherEntry> entries = caManager.getPublishersForCa(caName);

        String upPublisherName = publisherName.toUpperCase();
        for (PublisherEntry m : entries) {
            if (m.ident().name().equals(upPublisherName)) {
                println(" checked CA publisher CA='" + caName + "', publisher='" + publisherName
                        + "'");
                return null;
            }
        }

        throw new CmdFailure("CA is not associated with publisher '" + publisherName + "'");
    }

}
