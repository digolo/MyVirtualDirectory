/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package net.sourceforge.myvd.protocol.ldap.mina.ldap.exception;


import javax.naming.InvalidNameException;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;


/**
 * A subclass of InvalidNameException designed to hold an unequivocal LDAP
 * result code.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 437007 $
 */
public class LdapInvalidNameException extends InvalidNameException implements LdapException
{
    static final long serialVersionUID = 1922458280238058561L;

    /** the LDAP resultCode this exception is associated with */
    private final ResultCodeEnum resultCode;


    /**
     * Creates an Eve NamingException.
     * 
     * @param resultCode
     *            the LDAP resultCode this exception is associated with
     */
    public LdapInvalidNameException(ResultCodeEnum resultCode)
    {
        this.resultCode = resultCode;
    }


    /**
     * Creates an Eve NamingException.
     * 
     * @param explanation
     *            an explanation for the failure
     * @param resultCode
     *            the LDAP resultCode this exception is associated with
     */
    public LdapInvalidNameException(String explanation, ResultCodeEnum resultCode)
    {
        super( explanation );
        this.resultCode = resultCode;
    }


    /**
     * Gets the LDAP resultCode this exception is associated with.
     * 
     * @return the LDAP resultCode this exception is associated with
     */
    public ResultCodeEnum getResultCode()
    {
        return resultCode;
    }
}
