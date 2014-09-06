/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common;

/**
 * @author Lijun Liao
 */

public enum CASystemStatus
{
    STARTED_AS_MASTER,
    STARTED_AS_SLAVE,
    NOT_INITED,
    INITIALIZING,
    LOCK_FAILED,
    ERROR;
}
