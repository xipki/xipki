/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Lijun Liao
 */

public class CmpControl implements Serializable
{
    private static final int DFLT_messageTimeBias = 300; // 300 seconds
    private static final int DFLT_confirmWaitTime = 300; // 300 seconds

    public static final String name = "default";
    private boolean requireConfirmCert;
    private boolean sendCaCert;

    private boolean messageTimeRequired = true;
    private boolean sendResponderCert = true;

    public boolean isMessageTimeRequired()
    {
        return messageTimeRequired;
    }

    public void setMessageTimeRequired(boolean messageTimeRequired)
    {
        this.messageTimeRequired = messageTimeRequired;
    }

    private int messageTimeBias = DFLT_messageTimeBias;
    private int confirmWaitTime = DFLT_confirmWaitTime;

    private static final CmpControl defaultInstance;
    static
    {
        defaultInstance = new CmpControl();
        defaultInstance.setRequireConfirmCert(false);
    }

    public static CmpControl getDefaultCmpControlEntry()
    {
        return defaultInstance;
    }

    public CmpControl()
    {
        this.serialVersion = SERIAL_VERSION;
    }

    public boolean isRequireConfirmCert()
    {
        return requireConfirmCert;
    }

    public void setRequireConfirmCert(boolean requireConfirmCert)
    {
        this.requireConfirmCert = requireConfirmCert;
    }

    public int getMessageTimeBias()
    {
        return messageTimeBias;
    }

    public void setMessageBias(int messageTimeBias)
    {
        this.messageTimeBias = messageTimeBias;
    }

    public int getConfirmWaitTime()
    {
        return confirmWaitTime;
    }

    public void setConfirmWaitTime(int confirmWaitTime)
    {
        this.confirmWaitTime = confirmWaitTime;
    }

    public boolean isSendCaCert()
    {
        return sendCaCert;
    }

    public void setSendCaCert(boolean sendCaCert)
    {
        this.sendCaCert = sendCaCert;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        sb.append("requireConfirmCert: ").append(requireConfirmCert ? "yes" : "no").append('\n');
        sb.append("sendCaCert: ").append(sendCaCert ? "yes" : "no").append("\n");
        sb.append("sendResponderCert: ").append(sendResponderCert ? "yes" : "no").append("\n");
        sb.append("messageTimeRequired: ").append(messageTimeRequired ? "yes" : "no").append("\n");
        sb.append("messageTimeBias: ").append(messageTimeBias).append(" s").append('\n');
        sb.append("confirmWaitTime: ").append(confirmWaitTime).append(" s");

        return sb.toString();
    }

    public boolean isSendResponderCert()
    {
        return sendResponderCert;
    }

    public void setSendResponderCert(boolean sendResponderCert)
    {
        this.sendResponderCert = sendResponderCert;
    }

    // ------------------------------------------------
    // Customized serialization
    // ------------------------------------------------
    private static final long serialVersionUID = 1L;

    private static final String SR_serialVersion = "serialVersion";
    private static final double SERIAL_VERSION = 1.0;

    private static final String SR_requireConfirmCert= "requireConfirmCert";
    private static final String SR_sendCaCert = "sendCaCert";
    private static final String SR_messageTimeRequired = "messageTimeRequired";
    private static final String SR_sendResponderCert = "sendResponderCert";
    private static final String SR_messageTimeBias = "messageTimeBias";
    private static final String SR_confirmWaitTime = "confirmWaitTime";

    private double serialVersion;

    private void writeObject(java.io.ObjectOutputStream out)
    throws IOException
    {
        final Map<String, Object> serialMap = new HashMap<String, Object>();

        serialMap.put(SR_serialVersion, serialVersion);
        serialMap.put(SR_requireConfirmCert, requireConfirmCert);
        serialMap.put(SR_sendCaCert, sendCaCert);
        serialMap.put(SR_messageTimeRequired, messageTimeRequired);
        serialMap.put(SR_sendResponderCert, sendResponderCert);
        serialMap.put(SR_messageTimeBias, messageTimeBias);
        serialMap.put(SR_confirmWaitTime, confirmWaitTime);

        out.writeObject(serialMap);
    }

    @SuppressWarnings("unchecked")
    private void readObject(java.io.ObjectInputStream in)
    throws IOException, ClassNotFoundException
    {
        final Map<String, Object> serialMap = (Map<String, Object>) in.readObject();
        serialVersion = (double) serialMap.get(SR_serialVersion);
        requireConfirmCert = (boolean) serialMap.get(SR_requireConfirmCert);
        sendCaCert = (boolean) serialMap.get(SR_sendCaCert);
        messageTimeRequired = (boolean) serialMap.get(SR_messageTimeRequired);
        sendResponderCert = (boolean) serialMap.get(SR_sendResponderCert);
        messageTimeBias = (int) serialMap.get(SR_messageTimeBias);
        confirmWaitTime = (int) serialMap.get(SR_confirmWaitTime);
    }
}
