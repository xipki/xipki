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

package org.xipki.security.speed.pkcs12.cmd;

import java.util.LinkedList;
import java.util.Queue;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.qa.BenchmarkExecutor;
import org.xipki.security.speed.cmd.ECControl;
import org.xipki.security.speed.pkcs12.P12ECSignSpeed;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "bspeed-ec-sign-p12",
    description = "performance test of PKCS#12 EC signature creation (batch)")
@Service
// CHECKSTYLE:SKIP
public class BSpeedP12ECSignAction extends BSpeedP12SignAction {

  private final Queue<ECControl> queue = new LinkedList<>();

  public BSpeedP12ECSignAction() {
    for (String curveName : getECCurveNames()) {
      queue.add(new ECControl(curveName));
    }
  }

  @Override
  protected BenchmarkExecutor nextTester() throws Exception {
    ECControl control = queue.poll();
    return (control == null) ? null
        : new P12ECSignSpeed(securityFactory, sigAlgo, control.curveName());
  }

}
