/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11.iaik;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.TokenException;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.LogUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IaikExtendedModule
{
    private static final Logger LOG = LoggerFactory.getLogger(IaikExtendedModule.class);

    private Module module;
    private Map<PKCS11SlotIdentifier, IaikExtendedSlot> slots = new HashMap<>();
    private Map<PKCS11SlotIdentifier, Slot> availableSlots = new HashMap<>();

    public IaikExtendedModule(Module module)
    throws SignerException
    {
        ParamChecker.assertNotNull("module", module);

        this.module = module;

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
            throw new SignerException("No slot with present card could be found");
        }

        for (int i = 0; i < slotList.length; i++)
        {
            Slot slot = slotList[i];
            PKCS11SlotIdentifier slotId = new PKCS11SlotIdentifier(i, slot.getSlotID());
            availableSlots.put(slotId, slot);
        }

        if(LOG.isDebugEnabled())
        {
            try
            {
                StringBuilder msg = new StringBuilder();
                for (int i = 0; i < slotList.length; i++)
                {
                    Slot slot = slotList[i];
                    msg.append("------------------------Slot ").append(i+1).append("-------------------------\n");
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
                LogUtil.logWarnThrowable(LOG, "Unexpected error", t);
            }
        }
    }

    public IaikExtendedSlot getSlot(PKCS11SlotIdentifier slotId, char[] password)
    throws SignerException
    {
        IaikExtendedSlot extSlot = slots.get(slotId);
        if(extSlot != null)
        {
            return extSlot;
        }

        Slot slot = null;
        for(PKCS11SlotIdentifier s : availableSlots.keySet())
        {
            if(s.getSlotIndex() == slotId.getSlotIndex() ||
                s.getSlotId() == slotId.getSlotId())
            {
                slot = availableSlots.get(s);
                break;
            }
        }

        if(slot == null)
        {
            throw new SignerException("Could not find slot identified by " + slotId);
        }

        extSlot = new IaikExtendedSlot(slot, password);

        slots.put(slotId, extSlot);
        return extSlot;
    }

    public void destroySlot(long slotId)
    {
        slots.remove(slotId);
    }

    public Module getModule()
    {
        return module;
    }

    public void close()
    {
        for(PKCS11SlotIdentifier slotId : slots.keySet())
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

        for(PKCS11SlotIdentifier slotId : availableSlots.keySet())
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
            LogUtil.logErrorThrowable(LOG, "error while module.finalize()", t);
        }

        module = null;
    }

    public Set<PKCS11SlotIdentifier> getAllSlotIds()
    {
        return availableSlots.keySet();
    }

}
