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

package org.xipki.security.speed.p11.cmd;

import java.util.LinkedList;
import java.util.Queue;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.LoadExecutor;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.speed.cmd.RSAControl;
import org.xipki.security.speed.cmd.completer.RSASigAlgCompleter;
import org.xipki.security.speed.p11.P11RSASignLoadTest;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "bspeed-rsa-sign-p11",
        description = "performance test of PKCS#11 RSA signature creation (batch)")
@Service
// CHECKSTYLE:SKIP
public class BSpeedP11RSASignCmd extends BSpeedP11Action {

    @Option(name = "--sig-algo", required = true,
            description = "signature algorithm\n(required)")
    @Completion(RSASigAlgCompleter.class)
    private String sigAlgo;

    private final Queue<RSAControl> queue = new LinkedList<>();

    public BSpeedP11RSASignCmd() {
        queue.add(new RSAControl(1024));
        queue.add(new RSAControl(2048));
        queue.add(new RSAControl(3072));
        queue.add(new RSAControl(4096));
    }

    @Override
    protected LoadExecutor nextTester() throws Exception {
        RSAControl control = queue.poll();
        if (control == null) {
            return null;
        }

        P11Slot slot = getSlot();
        return new P11RSASignLoadTest(securityFactory, slot, sigAlgo, control.modulusLen(),
                                toBigInt("0x10001"));
    }

}
