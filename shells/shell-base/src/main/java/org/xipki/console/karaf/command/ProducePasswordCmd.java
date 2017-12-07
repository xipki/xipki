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

package org.xipki.console.karaf.command;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.XipkiCommandSupport;
import org.xipki.console.karaf.completer.PasswordNameCompleter;
import org.xipki.password.PasswordProducer;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "produce-password",
        description = "produce password")
@Service
public class ProducePasswordCmd extends XipkiCommandSupport {

    @Option(name = "--name", required = true, description = "name of the password")
    @Completion(PasswordNameCompleter.class)
    private String name;

    @Option(name = "-k", description = "quorum of the password parts")
    private Integer quorum = 1;

    @Override
    protected Object execute0() throws Exception {
        if (!PasswordProducer.needsPassword(name)) {
            throw new IllegalCmdParamException("password named '" + name
                    + "' will not be requested");
        }

        while (PasswordProducer.needsPassword(name)) {
            char[] password;
            if (quorum == 1) {
                password = readPassword("Password");
            } else {
                char[][] parts = new char[quorum][];
                for (int i = 0; i < quorum; i++) {
                    parts[i] = readPassword("Password (part " + (i + 1) + "/" + quorum + ")");
                }
                password = StringUtil.merge(parts);
            }
            PasswordProducer.putPassword(name, password);

            final int n = 10;
            for (int i = 0; i < n; i++) {
                Thread.sleep(500);
                Boolean correct = PasswordProducer.removePasswordCorrect(name);
                if (correct != null) {
                    println("\rthe given password is "
                            + (correct ? "correct            " : "not correct        "));
                    break;
                } else {
                    println("\rthe given password is still under process");
                }
            }
        }
        return null;
    }

}
