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

package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.AbstractContainer;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.IAsn1Container;


/**
 * A container for the StoredProcedureCall codec.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoredProcedureCallContainer extends AbstractContainer implements IAsn1Container
{
    // ~ Instance fields ------------------------------------------------------

    /** StoredProcedureCall */
    private StoredProcedureCall storedProcedureCall;


    // ~ Constructors ---------------------------------------------------------

    public StoredProcedureCallContainer()
    {
        super();
        stateStack = new int[1];
        grammar = StoredProcedureCallGrammar.getInstance();
        states = StoredProcedureCallStatesEnum.getInstance();
    }


    // ~ Methods
    // ------------------------------------------------------------------------------------
    /**
     * @return Returns the ldapMessage.
     */
    public StoredProcedureCall getStoredProcedureCall()
    {
        return storedProcedureCall;
    }


    /**
     * Set a StoredProcedureCall object into the container.
     * It will be completed by the ldapDecoder.
     * 
     * @param ldapMessage
     *            The ldapMessage to set.
     */
    public void setStoredProcedureCall( StoredProcedureCall storedProcedureCall )
    {
        this.storedProcedureCall = storedProcedureCall;
    }


    public void clean()
    {
        super.clean();

        storedProcedureCall = null;
    }
}
