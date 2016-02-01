/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.client.shell;

import java.io.FileInputStream;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.pki.ca.client.shell.internal.loadtest.CALoadTestTemplateEnroll;
import org.xipki.pki.ca.client.shell.internal.loadtest.jaxb.EnrollTemplateType;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-cli", name = "loadtest-template-enroll",
        description = "CA Client Template Enroll Load test")
@Service
public class CALoadTestTemplateEnrollCmd extends CALoadTestCommandSupport {

    @Option(name = "--template", aliases = "-t",
            required = true,
            description = "template file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String templateFile;

    @Option(name = "--duration",
            description = "duration in seconds")
    private Integer durationInSecond = 30;

    @Option(name = "--thread",
            description = "number of threads")
    private Integer numThreads = 5;

    @Override
    protected Object doExecute()
    throws Exception {
        if (numThreads < 1) {
            throw new IllegalCmdParamException("invalid number of threads " + numThreads);
        }

        if (durationInSecond < 1) {
            throw new IllegalCmdParamException("invalid duration " + durationInSecond);
        }

        EnrollTemplateType template = CALoadTestTemplateEnroll.parse(
                new FileInputStream(templateFile));
        int n = template.getEnrollCert().size();

        StringBuilder description = new StringBuilder();
        description.append("template: ").append(templateFile).append("\n");
        description.append("#certs/req: ").append(n).append("\n");
        description.append("unit: ").append(n).append(" certificate");
        if (n > 1) {
            description.append("s");
        }
        description.append("\n");

        CALoadTestTemplateEnroll loadTest = new CALoadTestTemplateEnroll(caClient,
                template, description.toString());
        loadTest.setDuration(durationInSecond);
        loadTest.setThreads(numThreads);
        loadTest.test();

        return null;
    } // method doExecute

}
