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

package org.xipki.pki.ca.server.mgmt.api;

import java.io.Serializable;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 */

public class CertprofileEntry implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;

    private final String type;

    private final String conf;

    private boolean faulty;

    public CertprofileEntry(
            final String name,
            final String type,
            final String conf) {
        ParamUtil.assertNotBlank("name", name);
        ParamUtil.assertNotBlank("type", type);

        if ("all".equalsIgnoreCase(name) || "null".equalsIgnoreCase(name)) {
            throw new IllegalArgumentException(
                    "certificate profile name could not be 'all' and 'null'");
        }
        this.name = name;
        this.type = type;
        this.conf = conf;
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public String getConf() {
        return conf;
    }

    public boolean isFaulty() {
        return faulty;
    }

    public void setFaulty(
            final boolean faulty) {
        this.faulty = faulty;
    }

    @Override
    public String toString() {
        return toString(false);
    }

    public String toString(
            final boolean verbose) {
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        sb.append("faulty: ").append(faulty).append('\n');
        sb.append("type: ").append(type).append('\n');
        sb.append("conf: ");
        if (verbose || conf == null || conf.length() < 301) {
            sb.append(conf);
        } else {
            sb.append(conf.substring(0, 297)).append("...");
        }
        return sb.toString();
    }

}
