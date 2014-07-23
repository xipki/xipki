/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.server;

/**
 * @author Lijun Liao
 */

public class CmpControl
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
}
