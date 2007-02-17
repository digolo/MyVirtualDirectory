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
package net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.grammar;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.grammar.IGrammar;


/**
 * This interface is used to store the different states of a grammar. While
 * tracing debugging information, the methods to dump the current state as a
 * string are called.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface IStates
{
    /** The initial state of every grammar */
    static int INIT_GRAMMAR_STATE = 0;

    /** The ending state for every grammars */
    static int GRAMMAR_END = -1;

    /** The END_STATE */
    static int END_STATE = -1;

    /** Get the current state */
    String getState( int state );

    /** Return the grammar name from a grammar */
    String getGrammarName( IGrammar grammar );

    /** Return the grammar name from a grammar number */
    String getGrammarName( int grammar );
}
