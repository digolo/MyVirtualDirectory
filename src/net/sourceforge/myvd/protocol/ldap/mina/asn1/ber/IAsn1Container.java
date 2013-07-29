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
package net.sourceforge.myvd.protocol.ldap.mina.asn1.ber;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.grammar.IGrammar;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.grammar.IStates;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;


/**
 * Every ASN1 container must implement this interface.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface IAsn1Container
{
    // ~ Methods
    // ------------------------------------------------------------------------------------

    // State accessors
    /**
     * Get the current grammar state
     * 
     * @return Returns the current grammar state
     */
    int getState();


    /**
     * Set the new current state
     * 
     * @param state The new state
     */
    void setState( int state );


    /**
     * Set the current TLV
     * 
     * @param tlv The current TLV
     */
    public void setCurrentTLV( TLV tlv );


    /**
     * Get the currentTLV
     * 
     * @return Returns the current TLV being decoded
     */
    public TLV getCurrentTLV();


    /**
     * Get the grammar
     * 
     * @return Returns the grammar used to decode a LdapMessage.
     */
    public IGrammar getGrammar();


    /**
     * Get the transition
     * 
     * @return Returns the transition from the previous state to the new state
     */
    public int getTransition();


    /**
     * Update the transition from a state to another
     * 
     * @param transition The transition to set
     */
    public void setTransition( int transition );

    /**
     * @return Returns the states.
     */
    public IStates getStates();


    /**
     * @return get the parent TLV.
     */
    public TLV getParentTLV();


    /**
     * Set the parent TLV
     * 
     * @param The new parent TLV
     */
    public void setParentTLV( TLV parentTLV );


    /**
     * Check that we can have a end state after this transition
     * 
     * @return true if this can be the last transition
     */
    public boolean isGrammarEndAllowed();


    /**
     * Set the flag to allow a end transition
     * 
     * @param endAllowed true or false, depending on the next transition 
     * being an end or not.
     */
    public void grammarEndAllowed( boolean grammarEndAllowed );
    
    /**
     * Get a new TLV id
     * @return a unique value representing the current TLV id
     */
    public int getNewTlvId();

    /**
     * Get the current TLV id
     * @return a unique value representing the current TLV id
     */
    public int getTlvId();
}
