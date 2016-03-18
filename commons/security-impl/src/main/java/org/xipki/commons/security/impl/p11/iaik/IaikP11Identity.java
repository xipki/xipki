/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.impl.p11.iaik;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11UnsupportedMechanismException;
import org.xipki.commons.security.api.p11.parameters.P11Params;

import iaik.pkcs.pkcs11.objects.PrivateKey;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class IaikP11Identity extends P11Identity {
    private final String moduleName;

    private final PrivateKey privateKey;

    IaikP11Identity(
            final String moduleName,
            final P11EntityIdentifier entityId,
            final PrivateKey privateKey,
            final X509Certificate[] certificateChain,
            final PublicKey publicKey) {
        super(entityId, certificateChain, publicKey);
        this.moduleName = ParamUtil.requireNonBlank("moduleName", moduleName);
        this.privateKey = ParamUtil.requireNonNull("privateKey", privateKey);
    }

    private IaikP11Module getModule()
    throws P11TokenException {
        IaikP11Module module = IaikP11ModulePool.getInstance().getModule(moduleName);
        if (module == null) {
            throw new P11TokenException("could not find IaikP11Module '" + moduleName + "'");
        }
        return module;
    }

    @Override
    public byte[] sign(
            final long mechanism,
            final P11Params parameters,
            final byte[] content)
    throws P11TokenException {
        ParamUtil.requireNonNull("content", content);

        if (!supportsMechanism(mechanism, parameters)) {
            throw new P11UnsupportedMechanismException(mechanism, entityId);
        }

        IaikP11Module module = getModule();
        IaikP11Slot slot = (IaikP11Slot) module.getSlot(entityId.getSlotId());
        return slot.sign(mechanism, parameters, content, entityId.getKeyId());
    }

    PrivateKey getPrivateKey() {
        return privateKey;
    }

}
