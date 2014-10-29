/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

/**
 * @author Lijun Liao
 */

class AddText
{
    private final Condition condition;
    private final String text;

    public AddText(Condition condition, String text)
    {
        this.condition = condition;
        this.text = text;
    }

    public Condition getCondition()
    {
        return condition;
    }

    public String getText()
    {
        return text;
    }

}
