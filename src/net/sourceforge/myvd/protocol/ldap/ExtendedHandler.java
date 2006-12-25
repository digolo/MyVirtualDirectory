package net.sourceforge.myvd.protocol.ldap;

/*
 *   Copyright 2004 The Apache Software Foundation
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */



import java.util.HashMap;

import javax.naming.InvalidNameException;

import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Password;


import org.apache.directory.server.core.configuration.StartupConfiguration;
import org.apache.directory.server.ldap.support.LdapMessageHandler;
import org.apache.directory.shared.ldap.message.ExtendedRequest;
import org.apache.directory.shared.ldap.message.LdapResult;
import org.apache.directory.shared.ldap.message.ResultCodeEnum;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.apache.directory.shared.ldap.util.ExceptionUtils;
import org.apache.mina.common.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;


/**
 * A single reply handler for {@link org.apache.ldap.common.message.ExtendedRequest}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 161724 $
 */
public class ExtendedHandler implements LdapMessageHandler,LdapInfo
{
	
	 private static final Logger LOG = LoggerFactory.getLogger( ExtendedHandler.class );
		private Insert[] globalChain;
		private Router router;
		
    public void messageReceived( IoSession session, Object request )
    {
        ExtendedRequest req = (ExtendedRequest) request;
        LdapResult result = req.getResultResponse().getLdapResult();
        
HashMap userSession = null;
        
        
        
        try
        {
        	userSession = (HashMap) session.getAttribute("VLDAP_SESSION");
            DistinguishedName bindDN = (DistinguishedName) session.getAttribute("VLDAP_BINDDN");
            Password pass = (Password) session.getAttribute("VLDAP_BINDPASS");
            
            if (bindDN == null) {
            	bindDN = new DistinguishedName("");
            	pass = new Password();
            }
            
            ExetendedOperationInterceptorChain chain = new ExetendedOperationInterceptorChain(bindDN,pass,0,this.globalChain,userSession,new HashMap(),router);
            
            ExtendedOperation op = new ExtendedOperation(null, new LDAPExtendedOperation(req.getOid(),req.getPayload()));
            chain.nextExtendedOperations(op,new LDAPConstraints());
            
        }
        catch( LDAPException e )
        {
            String msg = "failed to delete entry " + "";

           /* if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( e );
            }*/

            ResultCodeEnum code;

           
           code = ResultCodeEnum.getResultCodeEnum(e.getResultCode());
           
            result.setResultCode( code );
            result.setErrorMessage( msg );

            if( e.getMatchedDN() != null )
            {
                try {
					result.setMatchedDn( new LdapDN(e.getMatchedDN().toString()) );
				} catch (InvalidNameException e1) {
					LOG.error("Error",e1);
				}
            }

            session.write( result );
            return;
        } catch (Throwable t) {
        	
            String msg = "failed to perform extended op "  + t.toString();

            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( t );
            }

            ResultCodeEnum code;

            
                code = ResultCodeEnum.OPERATIONSERROR;
            

            result.setResultCode( code );
            result.setErrorMessage( msg );
            

            session.write( result );
            return;
        
    }

        result.setResultCode( ResultCodeEnum.SUCCESS );
        try {
			result.setMatchedDn( new LdapDN("") );
		} catch (InvalidNameException e) {
			LOG.error("Error",e);
		}
        session.write( result );
    }

	public void setEnv(Insert[] globalChain, Router router) {
		this.globalChain = globalChain;
		this.router = router;
		
	}

	public void init(StartupConfiguration arg0) {
		// TODO Auto-generated method stub
		
	}
}
