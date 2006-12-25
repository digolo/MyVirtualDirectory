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



import java.util.ArrayList;
import java.util.HashMap;

import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.LdapContext;

import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;




import org.apache.directory.server.core.configuration.StartupConfiguration;
import org.apache.directory.server.ldap.support.LdapMessageHandler;
import org.apache.directory.shared.ldap.exception.LdapException;
import org.apache.directory.shared.ldap.message.LdapResult;
import org.apache.directory.shared.ldap.message.ModifyRequest;
import org.apache.directory.shared.ldap.message.ResultCodeEnum;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.apache.directory.shared.ldap.util.ExceptionUtils;
import org.apache.mina.common.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;


/**
 * A single reply handler for {@link org.apache.ldap.common.message.ModifyRequest}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 231083 $
 */
public class ModifyHandler implements LdapMessageHandler,LdapInfo
{
    private static final Logger LOG = LoggerFactory.getLogger( ModifyHandler.class );
    private static final ModificationItem[] EMPTY = new ModificationItem[0];
	private Insert[] globalChain;
	private Router router;


    public void messageReceived( IoSession session, Object request )
    {
        ModifyRequest req = ( ModifyRequest ) request;
        LdapResult result = req.getResultResponse().getLdapResult();

        HashMap userSession;
        try
        {
            
        	ModificationItem[] attribs = (ModificationItem[]) req.getModificationItems().toArray( EMPTY );
            
            ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>(attribs.length);
			
			for (int i=0,m=attribs.length;i<m;i++) {
				mods.add(this.createChange(attribs[i].getAttribute(),attribs[i].getModificationOp()));
			}
			
			userSession = (HashMap) session.getAttribute("VLDAP_SESSION");
            DistinguishedName bindDN = (DistinguishedName) session.getAttribute("VLDAP_BINDDN");
            Password pass = (Password) session.getAttribute("VLDAP_BINDPASS");
            
            if (bindDN == null) {
            	bindDN = new DistinguishedName("");
            	pass = new Password();
            
            }
            
            ModifyInterceptorChain chain = new ModifyInterceptorChain(bindDN,pass,0,this.globalChain,userSession,new HashMap(),this.router);
            chain.nextModify(new DistinguishedName(req.getName().toString()),mods,new LDAPConstraints());
            
            
        }
        catch ( LDAPException e )
        {
            String msg = "failed to modify entry " + req.getName();
	    
            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( e );
            }

            ResultCodeEnum code;
            code = ResultCodeEnum.getResultCodeEnum(e.getResultCode());
            

            result.setResultCode( code );
            result.setErrorMessage( msg );

            if ( e.getMatchedDN() != null )
            {
                try {
					result.setMatchedDn( new LdapDN(e.getMatchedDN()) );
				} catch (InvalidNameException e1) {
					LOG.error("Error",e1);
				}
            }

            session.write( result );
            return;
        }
        catch ( NamingException e )
        {
            String msg = "failed to modify entry " + req.getName();
	    
            if ( LOG.isDebugEnabled() )
            {
                msg += ":\n" + ExceptionUtils.getStackTrace( e );
            }

            ResultCodeEnum code;
            if ( e instanceof LdapException )
            {
                code = ( ( LdapException ) e ).getResultCode() ;
            }
            else
            {
                code = ResultCodeEnum.getBestEstimate( e, req.getType() );
            }

            result.setResultCode( code );
            result.setErrorMessage( msg );

            if ( e.getResolvedName() != null )
            {
                try {
					result.setMatchedDn( new LdapDN(e.getResolvedName().toString()) );
				} catch (InvalidNameException e1) {
					LOG.error("Error",e1);
				}
            }

            session.write( result );
            return;
        }catch (Throwable t) {
        	
            String msg = "failed to add entry " + req.getName() + "; " + t.toString();

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
        result.setMatchedDn( req.getName() );
        session.write( result );
        return;
    }
    
    private LDAPModification createChange(Attribute attrib,int type) throws NamingException {
		
    	if (type == 1) {
    		type = 0;
    	} else if (type == 3) {
    		type = 1;
    	}
    	
		LDAPAttribute ldapAttrib = new LDAPAttribute(attrib.getID());
		NamingEnumeration vals = attrib.getAll();
		while (vals.hasMore()) {
			ldapAttrib.addValue((String) vals.next());
		}
		
		
		LDAPModification newMod = new LDAPModification(type,ldapAttrib);
		System.err.println("Modification : " + type + ";" + newMod);
		return newMod;
	}


	public void setEnv(Insert[] globalChain, Router router) {
		this.globalChain = globalChain;
		this.router = router;
		
	}

	public void init(StartupConfiguration arg0) {
		// TODO Auto-generated method stub
		
	}
}

