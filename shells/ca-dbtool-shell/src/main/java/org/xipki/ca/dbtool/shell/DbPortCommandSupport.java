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

package org.xipki.ca.dbtool.shell;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.ca.dbtool.port.DbPortWorker;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.XipkiCommandSupport;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.password.PasswordResolver;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class DbPortCommandSupport extends XipkiCommandSupport {

    protected DataSourceFactory datasourceFactory;

    @Reference
    protected PasswordResolver passwordResolver;

    public DbPortCommandSupport() {
        datasourceFactory = new DataSourceFactory();
    }

    protected abstract DbPortWorker getDbPortWorker() throws Exception;

    protected Object execute0() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(1);
        DbPortWorker myRun = getDbPortWorker();
        executor.execute(myRun);

        executor.shutdown();
        while (true) {
            try {
                boolean terminated = executor.awaitTermination(1, TimeUnit.SECONDS);
                if (terminated) {
                    break;
                }
            } catch (InterruptedException ex) {
                myRun.setStopMe(true);
            }
        }

        Exception ex = myRun.exception();
        if (ex != null) {
            String errMsg = ex.getMessage();
            if (StringUtil.isBlank(errMsg)) {
                errMsg = "ERROR";
            }

            System.err.println(errMsg);
        }

        return null;
    }

}
