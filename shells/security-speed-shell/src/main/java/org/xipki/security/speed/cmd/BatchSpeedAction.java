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

package org.xipki.security.speed.cmd;

import java.util.List;

import org.apache.karaf.shell.api.action.Option;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.BenchmarkExecutor;
import org.xipki.common.util.LogUtil;
import org.xipki.security.util.AlgorithmUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class BatchSpeedAction extends SecurityAction {

  private static final Logger LOG = LoggerFactory.getLogger(BatchSpeedAction.class);

  @Option(name = "--duration", description = "duration for each test case")
  private String duration = "10s";

  @Option(name = "--thread", description = "number of threads")
  private Integer numThreads = 5;

  protected abstract BenchmarkExecutor nextTester() throws Exception;

  @Override
  protected Object execute0() throws InterruptedException {
    while (true) {
      println("============================================");
      BenchmarkExecutor tester;
      try {
        tester = nextTester();
      } catch (Exception ex) {
        String msg = "could not get nextTester";
        LogUtil.error(LOG, ex, msg);
        println(msg + ": " + ex.getMessage());
        continue;
      }

      if (tester == null) {
        break;
      }

      tester.setDuration(duration);
      tester.setThreads(Math.min(20, numThreads));
      tester.execute();
      if (tester.isInterrupted()) {
        throw new InterruptedException("cancelled by the user");
      }
    }
    return null;
  }

  // CHECKSTYLE:SKIP
  protected List<String> getECCurveNames() {
    return AlgorithmUtil.getECCurveNames();
  }

}
