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

package org.xipki.ca.client.shell.loadtest;

import java.io.FileInputStream;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.client.shell.loadtest.jaxb.EnrollTemplateType;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xiqa", name = "cmp-benchmark-template-enroll",
        description = "CA client template enroll load test")
@Service
public class CaLoadTestTemplateEnrollCmd extends CaLoadTestCommandSupport {

    @Option(name = "--template", aliases = "-t",
            required = true,
            description = "template file. Note the contained profiles must allow duplication of"
                    + " public key \n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String templateFile;

    @Option(name = "--duration",
            description = "duration")
    private String duration = "30s";

    @Option(name = "--thread",
            description = "number of threads")
    private Integer numThreads = 5;

    @Option(name = "--max-num",
            description = "maximal number of requests\n"
                    + "0 for unlimited")
    private Integer maxRequests = 0;

    @Override
    protected Object execute0() throws Exception {
        if (numThreads < 1) {
            throw new IllegalCmdParamException("invalid number of threads " + numThreads);
        }

        EnrollTemplateType template = CaLoadTestTemplateEnroll.parse(
                new FileInputStream(templateFile));
        int size = template.getEnrollCert().size();

        StringBuilder description = new StringBuilder(200);
        description.append("template: ").append(templateFile).append("\n");
        description.append("maxRequests: ").append(maxRequests).append("\n");
        description.append("unit: ").append(size).append(" certificate");
        if (size > 1) {
            description.append("s");
        }
        description.append("\n");

        CaLoadTestTemplateEnroll loadTest = new CaLoadTestTemplateEnroll(caClient, template,
                maxRequests, description.toString());
        loadTest.setDuration(duration);
        loadTest.setThreads(numThreads);
        loadTest.test();

        return null;
    } // method execute0

}
