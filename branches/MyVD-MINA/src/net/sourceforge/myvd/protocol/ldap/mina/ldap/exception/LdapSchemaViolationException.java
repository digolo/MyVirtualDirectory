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


import javax.naming.directory.SchemaViolationException;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;


/**
 * Makes a SchemaViolationException unambiguous with respect to the result code
 * it corresponds to by associating an LDAP specific result code with it.
 * 
 * @see <a
 *      href="http://java.sun.com/j2se/1.4.2/docs/guide/jndi/jndi-ldap-gl.html#EXCEPT">
 *      LDAP ResultCode to JNDI Exception Mappings</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 477298 $
 */
public class LdapSchemaViolationException extends SchemaViolationException implements LdapException
{
    static final long serialVersionUID = 5763624876999168014L;

    /** the LDAP resultCode this exception is associated with */
    private final ResultCodeEnum resultCode;


    /**
     * Creates an Ldap NamingException using a result code.
     * 
     * @param resultCode
     *            the LDAP resultCode this exception is associated with
     * @throws IllegalArgumentException
     *             if the resultCode argument is not
     *             ResultCodeEnum.OBJECTCLASSVIOLATION,
     *             ResultCodeEnum.NOTALLOWEDONRDN, or
     *             ResultCodeEnum.OBJECTCLASSMODSPROHIBITED
     */
    public LdapSchemaViolationException(ResultCodeEnum resultCode)
    {
        super();

        switch ( resultCode )
        {
            case OBJECT_CLASS_VIOLATION :

                break;

            case NOT_ALLOWED_ON_RDN :

                break;

            case OBJECT_CLASS_MODS_PROHIBITED :

                break;

            default:

                throw new IllegalArgumentException( resultCode + " is not an acceptable result code." );
        }

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
    public LdapSchemaViolationException(String explanation, ResultCodeEnum resultCode)
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
        return this.resultCode;
    }
}
