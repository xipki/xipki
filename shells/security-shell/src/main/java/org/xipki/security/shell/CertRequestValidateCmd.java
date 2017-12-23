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

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "validate-csr",
        description = "validate CSR")
@Service
public class CertRequestValidateCmd extends SecurityAction {

    @Option(name = "--csr",
            required = true,
            description = "CSR file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Override
    protected Object execute0() throws Exception {
        CertificationRequest csr = CertificationRequest.getInstance(IoUtil.read(csrFile));
        String sigAlgo = AlgorithmUtil.getSignatureAlgoName(csr.getSignatureAlgorithm());
        boolean bo = securityFactory.verifyPopo(csr, null);
        String txt = bo ? "valid" : "invalid";
        println("The POP is " + txt + " (signature algorithm " + sigAlgo + ").");
        return null;
    }

}
