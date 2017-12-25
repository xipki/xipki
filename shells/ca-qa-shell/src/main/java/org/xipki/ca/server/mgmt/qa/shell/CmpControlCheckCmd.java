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

package org.xipki.ca.server.mgmt.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.ca.server.mgmt.shell.CmpControlUpdateCmd;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "cmpcontrol-check",
        description = "show information of CMP control (QA)")
@Service
public class CmpControlCheckCmd extends CmpControlUpdateCmd {

    @Override
    protected Object execute0() throws Exception {
        println("checking CMP control " + name);

        CmpControlEntry ce = caManager.getCmpControl(name);
        if (ce == null) {
            throw new CmdFailure("no CMP control named '" + name + "' is configured");
        }

        String is = ce.conf();
        String ex = new CmpControl(new CmpControlEntry(name, conf)).dbEntry().conf();
        MgmtQaShellUtil.assertEquals("CMP control", ex, is);

        println(" checked CMP control " + name);
        return null;
    }

}
