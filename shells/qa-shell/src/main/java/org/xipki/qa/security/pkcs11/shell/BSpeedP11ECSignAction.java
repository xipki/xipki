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

package org.xipki.qa.security.pkcs11.shell;

import java.util.LinkedList;
import java.util.Queue;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.qa.security.pkcs11.P11ECSignSpeed;
import org.xipki.qa.security.shell.ECControl;
import org.xipki.qa.security.shell.completer.ECDSASigAlgCompleter;
import org.xipki.util.BenchmarkExecutor;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "bspeed-ec-sign-p11",
    description = "performance test of PKCS#11 EC signature creation (batch)")
@Service
// CHECKSTYLE:SKIP
public class BSpeedP11ECSignAction extends BSpeedP11Action {

  @Option(name = "--sig-algo", required = true, description = "signature algorithm")
  @Completion(ECDSASigAlgCompleter.class)
  private String sigAlgo;

  private final Queue<ECControl> queue = new LinkedList<>();

  public BSpeedP11ECSignAction() {
    for (String curveName : getECCurveNames()) {
      queue.add(new ECControl(curveName));
    }
  }

  @Override
  protected BenchmarkExecutor nextTester() throws Exception {
    ECControl control = queue.poll();
    if (control == null) {
      return null;
    }

    return new P11ECSignSpeed(securityFactory, getSlot(), getKeyId(), sigAlgo, getNumThreads(),
        control.curveName());
  }

}
