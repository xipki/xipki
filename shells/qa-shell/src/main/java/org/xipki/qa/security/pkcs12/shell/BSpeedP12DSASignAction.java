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

package org.xipki.qa.security.pkcs12.shell;

import java.util.LinkedList;
import java.util.Queue;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.qa.security.benchmark.pkcs12.P12DSASignSpeed;
import org.xipki.qa.security.shell.DSAControl;
import org.xipki.util.BenchmarkExecutor;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "bspeed-dsa-sign-p12",
    description = "performance test of PKCS#12 DSA signature creation")
@Service
// CHECKSTYLE:SKIP
public class BSpeedP12DSASignAction extends BSpeedP12SignAction {

  private final Queue<DSAControl> queue = new LinkedList<>();

  public BSpeedP12DSASignAction() {
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
      sigAlgo = "SHA1withDSA";
    }

    return new P12DSASignSpeed(securityFactory, sigAlgo, getNumThreads(),
        control.plen(), control.qlen());
  }

}
