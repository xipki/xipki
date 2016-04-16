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
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.commons.security.speed.cmd;

import java.util.List;

import org.apache.karaf.shell.api.action.Option;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.LoadExecutor;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.security.api.p11.P11CryptServiceFactory;
import org.xipki.commons.security.api.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class BatchSpeedCommandSupport extends SecurityCommandSupport {

    private static final Logger LOG = LoggerFactory.getLogger(BatchSpeedCommandSupport.class);

    protected static final String DEFAULT_P11MODULE_NAME =
            P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

    @Option(name = "--duration",
            description = "duration in seconds for each test case")
    private Integer durationInSecond = 10;

    @Option(name = "--thread",
            description = "number of threads")
    private Integer numThreads = 5;

    protected abstract LoadExecutor nextTester()
    throws Exception;

    @Override
    protected Object doExecute()
    throws InterruptedException {
        while (true) {
            println("============================================");
            LoadExecutor tester;
            try {
                tester = nextTester();
            } catch (Exception ex) {
                String msg = "ERROR while getting nextTester";
                LOG.error(LogUtil.getErrorLog(msg), ex.getClass(), ex.getMessage());
                LOG.debug(msg, ex);
                println(msg + ": " + ex.getMessage());
                continue;
            }
            if (tester == null) {
                break;
            }

            tester.setDuration(durationInSecond);
            tester.setThreads(Math.min(20, numThreads));
            tester.test();
            if (tester.isInterrupted()) {
                throw new InterruptedException("cancelled by the user");
            }
        }
        return null;
    }

    protected List<String> getECCurveNames() { // CHECKSTYLE:SKIP
        return AlgorithmUtil.getECCurveNames();
    }

}
