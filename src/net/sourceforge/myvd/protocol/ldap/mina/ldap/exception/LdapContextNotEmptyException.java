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


import javax.naming.ContextNotEmptyException;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;


/**
 * A ContextNotEmptyException which contains an LDAP result code.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 477298 $
 */
public class LdapContextNotEmptyException extends ContextNotEmptyException implements LdapException
{
    static final long serialVersionUID = -2320797162018226278L;


    public LdapContextNotEmptyException()
    {
        super();
    }


    public LdapContextNotEmptyException(String explanation)
    {
        super( explanation );
    }


    /**
     * Gets the LDAP ResultCode for this exception type.
     * 
     * @return {@link ResultCodeEnum#NOTALLOWEDONNONLEAF} always
     */
    public ResultCodeEnum getResultCode()
    {
        return ResultCodeEnum.NOT_ALLOWED_ON_NON_LEAF;
    }
}
