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

package org.xipki.ca.server.mgmt.shell.completer;

import org.xipki.ca.server.mgmt.DuplicationMode;
import org.xipki.console.karaf.EnumCompleter;

/**
 * @author Lijun Liao
 */

public class DuplicationModeCompleter extends EnumCompleter
{
    public DuplicationModeCompleter()
    {
        StringBuilder enums = new StringBuilder();
        for(DuplicationMode mode : DuplicationMode.values())
        {
            enums.append(Integer.toString(mode.getMode())).append(",");
            enums.append(mode.getDescription()).append(",");
        }
        enums.deleteCharAt(enums.length() - 1);
        setTokens(enums.toString());
    }

}
