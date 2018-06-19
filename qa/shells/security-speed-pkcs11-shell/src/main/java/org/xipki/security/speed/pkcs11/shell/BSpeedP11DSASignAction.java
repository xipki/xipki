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

package org.xipki.security.speed.pkcs11.shell;

import java.util.LinkedList;
import java.util.Queue;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.qa.BenchmarkExecutor;
import org.xipki.security.speed.pkcs11.P11DSASignSpeed;
import org.xipki.security.speed.shell.DSAControl;
import org.xipki.security.speed.shell.completer.DSASigAlgCompleter;
import org.xipki.shell.IllegalCmdParamException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "bspeed-dsa-sign-p11",
    description = "performance test of PKCS#11 DSA signature creation (batch)")
@Service
// CHECKSTYLE:SKIP
public class BSpeedP11DSASignAction extends BSpeedP11Action {

  @Option(name = "--sig-algo", required = true, description = "signature algorithm")
  @Completion(DSASigAlgCompleter.class)
  private String sigAlgo;

  private final Queue<DSAControl> queue = new LinkedList<>();

  public BSpeedP11DSASignAction() {
    queue.add(new DSAControl(1024, 160));
    queue.add(new DSAControl(2048, 224));
    queue.add(new DSAControl(2048, 256));
    queue.add(new DSAControl(3072, 256));
  }

  @Override
  protected BenchmarkExecutor nextTester() throws Exception {
    DSAControl control = queue.poll();
    if (control == null) {
      return null;
    }

    if (control.plen() == 1024) {
      if (!"SHA1withDSA".equalsIgnoreCase(sigAlgo)) {
        throw new IllegalCmdParamException("only SHA1withDSA is permitted for DSA with 1024 bit");
      }
    }

    return new P11DSASignSpeed(securityFactory, getSlot(), getKeyId(), sigAlgo,
        control.plen(), control.qlen());
  }

}
