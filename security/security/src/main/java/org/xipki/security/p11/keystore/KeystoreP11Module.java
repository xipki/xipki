/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.security.p11.keystore;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.IoCertUtil;
import org.xipki.common.ParamChecker;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11ModuleConf;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class KeystoreP11Module
{
    private static final Logger LOG = LoggerFactory.getLogger(KeystoreP11Module.class);

    private P11ModuleConf moduleConf;

    private Map<P11SlotIdentifier, KeystoreP11Slot> slots = new HashMap<>();
    private List<P11SlotIdentifier> slotIds;

    public KeystoreP11Module(P11ModuleConf moduleConf)
    {
        ParamChecker.assertNotNull("moduleConf", moduleConf);
        this.moduleConf = moduleConf;

        final String nativeLib = moduleConf.getNativeLibrary();

        File baseDir = new File(IoCertUtil.expandFilepath(nativeLib));
        File[] children = baseDir.listFiles();
        List<P11SlotIdentifier> allSlotIds = new LinkedList<>();

        for(File child : children)
        {
            if((child.isDirectory() && child.canRead() && child.exists()) == false)
            {
                LOG.warn("ignore path {}, it does not point to a readable exist directory", child.getPath());
                continue;
            }

            String filename = child.getName();
            String[] tokens = filename.split("-");
            if(tokens == null || tokens.length != 2)
            {
                LOG.warn("ignore dir {}, invalid filename syntax", child.getPath());
                continue;
            }

            int slotIndex;
            long slotId;
            try
            {
                slotIndex = Integer.parseInt(tokens[0]);
                slotId = Long.parseLong(tokens[1]);
            }catch(NumberFormatException e)
            {
                LOG.warn("ignore dir {}, invalid filename syntax", child.getPath());
                continue;
            }

            allSlotIds.add(new P11SlotIdentifier(slotIndex, slotId));
        }

        List<P11SlotIdentifier> tmpSlotIds = new LinkedList<>();
        for (P11SlotIdentifier slotId : allSlotIds)
        {
            if(moduleConf.isSlotIncluded(slotId))
            {
                tmpSlotIds.add(slotId);
            }
        }

        this.slotIds = Collections.unmodifiableList(tmpSlotIds);
    }

    public KeystoreP11Slot getSlot(P11SlotIdentifier slotId)
    throws SignerException
    {
        KeystoreP11Slot extSlot = slots.get(slotId);
        if(extSlot != null)
        {
            return extSlot;
        }

        P11SlotIdentifier _slotId = null;
        for(P11SlotIdentifier s : slotIds)
        {
            if(s.getSlotIndex() == slotId.getSlotIndex() ||
                s.getSlotId() == slotId.getSlotId())
            {
                _slotId = s;
                break;
            }
        }

        if(_slotId == null)
        {
            throw new SignerException("Could not find slot identified by " + slotId);
        }

        List<char[]> pwd;
        try
        {
            pwd = moduleConf.getPasswordRetriever().getPassword(_slotId);
        } catch (PasswordResolverException e)
        {
            throw new SignerException("PasswordResolverException: " + e.getMessage(), e);
        }

        File slotDir = new File(moduleConf.getNativeLibrary(), _slotId.getSlotIndex() + "-" + _slotId.getSlotId());

        extSlot = new KeystoreP11Slot(slotDir, _slotId, pwd);

        slots.put(slotId, extSlot);
        return extSlot;
    }

    public void destroySlot(long slotId)
    {
        slots.remove(slotId);
    }

    public void close()
    {
        slots.clear();
        LOG.info( "close", "close pkcs11 module: {}", moduleConf.getName());
    }

    public List<P11SlotIdentifier> getSlotIds()
    {
        return slotIds;
    }

}
