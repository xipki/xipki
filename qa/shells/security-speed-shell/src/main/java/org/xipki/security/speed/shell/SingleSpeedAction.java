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

package org.xipki.security.speed.shell;

import org.apache.karaf.shell.api.action.Option;
import org.xipki.common.qa.BenchmarkExecutor;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class SingleSpeedAction extends SecurityAction {

  @Option(name = "--duration", description = "duration")
  private String duration = "30s";

  @Option(name = "--thread", description = "number of threads")
  private Integer numThreads = 5;

  protected abstract BenchmarkExecutor getTester() throws Exception;

  @Override
  protected Object execute0() throws Exception {
    BenchmarkExecutor tester = getTester();
    tester.setDuration(duration);
    tester.setThreads(getNumThreads(numThreads));

    tester.execute();
    return null;
  }

  protected int getNumThreads(int numThreads) {
    return numThreads;
  }

}
