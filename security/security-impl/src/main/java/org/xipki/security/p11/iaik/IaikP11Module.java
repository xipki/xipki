/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.security.p11.iaik;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11Module;
import org.xipki.security.api.p11.P11ModuleConf;
import org.xipki.security.api.p11.P11SlotIdentifier;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.TokenException;

/**
 * @author Lijun Liao
 */

public class IaikP11Module implements P11Module
{
    private static final Logger LOG = LoggerFactory.getLogger(IaikP11Module.class);

    private Module module;
    private P11ModuleConf moduleConf;

    private Map<P11SlotIdentifier, IaikP11Slot> slots = new HashMap<>();
    private Map<P11SlotIdentifier, Slot> availableSlots = new HashMap<>();
    private List<P11SlotIdentifier> slotIds;

    public IaikP11Module(
            final Module module,
            final P11ModuleConf moduleConf)
    throws SignerException
    {
        ParamUtil.assertNotNull("module", module);
        ParamUtil.assertNotNull("moduleConf", moduleConf);

        this.module = module;
        this.moduleConf = moduleConf;

        Slot[] slotList;
        try
        {
            boolean cardPresent = true;
            slotList = module.getSlotList(cardPresent);
        } catch (Throwable t)
        {
            LOG.error("module.getSlotList(). {}: {}", t.getClass().getName(), t.getMessage());
            LOG.debug("module.getSlotList()", t);
            throw new SignerException("TokenException in module.getSlotList(): " + t.getMessage());
        }

        if(slotList == null || slotList.length == 0)
        {
            throw new SignerException("no slot with present card could be found");
        }

        List<P11SlotIdentifier> tmpSlotIds = new LinkedList<>();
        for (int i = 0; i < slotList.length; i++)
        {
            Slot slot = slotList[i];
            P11SlotIdentifier slotId = new P11SlotIdentifier(i, slot.getSlotID());
            availableSlots.put(slotId, slot);
            if(moduleConf.isSlotIncluded(slotId))
            {
                tmpSlotIds.add(slotId);
            }
        }

        this.slotIds = Collections.unmodifiableList(tmpSlotIds);

        if(LOG.isDebugEnabled())
        {
            try
            {
                StringBuilder msg = new StringBuilder();
                for (int i = 0; i < slotList.length; i++)
                {
                    Slot slot = slotList[i];
                    msg.append("------------------------Slot ")
                        .append(i + 1)
                        .append("-------------------------\n");
                    msg.append(slot.getSlotID()).append("\n");
                    try
                    {
                        msg.append(slot.getSlotInfo().toString()).append("\n");
                    } catch (TokenException e)
                    {
                        msg.append("error: " + e.getMessage());
                    }
                }
                LOG.debug("{}", msg);
            }catch(Throwable t)
            {
                final String message = "unexpected error";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                            t.getMessage());
                }
                LOG.debug(message, t);
            }
        }
    }

    @Override
    public IaikP11Slot getSlot(
            final P11SlotIdentifier slotId)
    throws SignerException
    {
        IaikP11Slot extSlot = slots.get(slotId);
        if(extSlot != null)
        {
            return extSlot;
        }

        Slot slot = null;
        P11SlotIdentifier _slotId = null;
        for(P11SlotIdentifier s : availableSlots.keySet())
        {
            if(s.getSlotIndex() == slotId.getSlotIndex()
                    || s.getSlotId() == slotId.getSlotId())
            {
                _slotId = s;
                slot = availableSlots.get(s);
                break;
            }
        }

        if(slot == null)
        {
            throw new SignerException("could not find slot identified by " + slotId);
        }

        List<char[]> pwd;
        try
        {
            pwd = moduleConf.getPasswordRetriever().getPassword(slotId);
        } catch (PasswordResolverException e)
        {
            throw new SignerException("PasswordResolverException: " + e.getMessage(), e);
        }
        extSlot = new IaikP11Slot(_slotId, slot, pwd);

        slots.put(slotId, extSlot);
        return extSlot;
    }

    public void destroySlot(
            final long slotId)
    {
        slots.remove(slotId);
    }

    public void close()
    {
        for(P11SlotIdentifier slotId : slots.keySet())
        {
            try
            {
                slots.get(slotId).close();
            }catch(Throwable t)
            {
            }

            availableSlots.remove(slotId);

        }
        slots.clear();
        slots = null;

        for(P11SlotIdentifier slotId : availableSlots.keySet())
        {
            try
            {
                availableSlots.get(slotId).getToken().closeAllSessions();
            }catch(Throwable t)
            {
            }
        }
        availableSlots.clear();
        availableSlots = null;

        LOG.info( "close", "close pkcs11 module: {}", module );
        try
        {
            module.finalize(null);
        }
        catch (Throwable t)
        {
            final String message = "error while module.finalize()";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                        t.getMessage());
            }
            LOG.debug(message, t);
        }

        module = null;
    }

    @Override
    public List<P11SlotIdentifier> getSlotIdentifiers()
    {
        return slotIds;
    }

}
