/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.PublisherEntry;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "publisher-list", description="List publishers")
public class PublisherListCommand extends CaCommand
{

    @Option(name = "-name",
            description = "Publisher Name",
            required = false, multiValued = false)
    protected String name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        StringBuilder sb = new StringBuilder();

        if(name == null)
        {
            Set<String> names = caManager.getPublisherNames();
            int n = names.size();

            if(n == 0 || n == 1)
            {
                sb.append(((n == 0) ? "no" : "1") + " publisher is configured\n");
            }
            else
            {
                sb.append(n + " publishers are configured:\n");
            }

            List<String> sorted = new ArrayList<>(names);
            Collections.sort(sorted);

            for(String name : sorted)
            {
                sb.append("\t").append(name).append("\n");
            }
        }
        else
        {
            PublisherEntry entry = caManager.getPublisher(name);
            if(entry != null)
            {
                sb.append(entry.toString());
            }
        }

        System.out.println(sb.toString());

        return null;
    }
}
