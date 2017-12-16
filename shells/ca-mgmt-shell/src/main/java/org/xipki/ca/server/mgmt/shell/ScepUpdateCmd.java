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

package org.xipki.ca.server.mgmt.shell;

import java.io.ByteArrayInputStream;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.ca.server.mgmt.api.x509.ChangeScepEntry;
import org.xipki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ProfileNameAndAllCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ScepNameCompleter;
import org.xipki.common.util.Base64;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.console.karaf.completer.SignerTypeCompleter;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "scep-up",
        description = "Update SCEP")
@Service
public class ScepUpdateCmd extends CaCommandSupport {

    @Option(name = "--name",
            required = true,
            description = "name\n"
                    + "(required)")
    @Completion(ScepNameCompleter.class)
    private String name;

    @Option(name = "--ca",
            description = "CA name")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--active",
            description = "activate this SCEP")
    private Boolean active;

    @Option(name = "--inactive",
            description = "deactivate this SCEP")
    private Boolean inactive;

    @Option(name = "--resp-type",
            description = "type of the responder")
    @Completion(SignerTypeCompleter.class)
    private String responderType;

    @Option(name = "--resp-conf",
            description = "conf of the responder")
    private String responderConf;

    @Option(name = "--resp-cert",
            description = "responder certificate file or 'NULL'")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(name = "--profile",
            multiValued = true,
            description = "profile name or 'ALL' for all profiles\n"
                    + "(multi-valued)")
    @Completion(ProfileNameAndAllCompleter.class)
    private Set<String> profiles;

    @Option(name = "--control",
            description = "SCEP control or 'NULL'")
    private String control;

    @Reference
    private PasswordResolver passwordResolver;

    private String getResponderConf() throws Exception {
        if (responderConf == null) {
            return responderConf;
        }
        String tmpRespType = responderType;
        if (tmpRespType == null) {
            ScepEntry entry = caManager.getScepEntry(name);
            if (entry == null) {
                throw new IllegalCmdParamException("please specify the responderType");
            }
            tmpRespType = entry.responderType();
        }

        return ShellUtil.canonicalizeSignerConf(tmpRespType, responderConf, passwordResolver,
                securityFactory);
    }

    @Override
    protected Object execute0() throws Exception {
        Boolean realActive;
        if (active != null) {
            if (inactive != null) {
                throw new IllegalCmdParamException(
                        "maximal one of --active and --inactive can be set");
            }
            realActive = Boolean.TRUE;
        } else if (inactive != null) {
            realActive = Boolean.FALSE;
        } else {
            realActive = null;
        }

        String certConf = null;
        if (CaManager.NULL.equalsIgnoreCase(certFile)) {
            certConf = CaManager.NULL;
        } else if (certFile != null) {
            byte[] certBytes = IoUtil.read(certFile);
            X509Util.parseCert(new ByteArrayInputStream(certBytes));
            certConf = Base64.encodeToString(certBytes);
        }

        ChangeScepEntry entry = new ChangeScepEntry(name);
        if (realActive != null) {
            entry.setActive(realActive);
        }

        if (caName != null) {
            entry.setCa(new NameId(null, caName));
        }

        if (responderType != null) {
            entry.setResponderType(responderType);
        }

        String conf = getResponderConf();
        if (conf != null) {
            entry.setResponderConf(conf);
        }

        if (certConf != null) {
            entry.setBase64Cert(certConf);
        }

        if (CollectionUtil.isNonEmpty(profiles)) {
            if (profiles.contains("NONE")) {
                profiles.clear();
            }
        }

        if (control != null) {
            entry.setControl(control);
        }

        boolean bo = caManager.changeScep(entry);
        output(bo, "updated", "could not update", "SCEP responder " + name);
        return null;
    } // method execute0

}
