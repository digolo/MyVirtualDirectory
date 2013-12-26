package net.sourceforge.myvd.server.apacheds;

import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.HashMap;

import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.SessionVariables;

import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.authn.AbstractAuthenticator;
import org.apache.mina.core.session.IoSession;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;

public class MyVDAuthenticator extends AbstractAuthenticator {

	InsertChain globalChain;
	Router router;
	SchemaManager schemaManager;
	
	public MyVDAuthenticator(InsertChain globalChain,Router router,SchemaManager schemaManager) {
		super(AuthenticationLevel.SIMPLE);
		this.globalChain = globalChain;
		this.router = router;
		this.schemaManager = schemaManager;
	}
	
	

	@Override
	public LdapPrincipal authenticate(BindOperationContext bindContext)
			throws Exception {
		
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = null;
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (bindContext.getSession() == null) {
			userSession = new HashMap<Object,Object>();
			bindContext.getIoSession().setAttribute("MYVD_USER_SESSION", userSession);
			
			bindDN = new DistinguishedName("");
			password = null;
			
		} else {
			userSession = bindContext.getSession().getUserSession();
			
			if (bindContext.getSession().isAnonymous()) {
				bindDN = new DistinguishedName("");
				password = null;
			} else {
				bindDN = new DistinguishedName(bindContext.getSession().getAuthenticatedPrincipal().getDn().getName());
				if (bindContext.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
					password = bindContext.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
				} else {
					password = null;
				}
			}
		}
		
		
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		}
		
		
		
		
		
		Password pass = new Password(password);
		
		StringBuffer sb = new StringBuffer();
		
		
		for (Rdn rdn : bindContext.getDn().getRdns()) {
			sb.append(rdn.getAva().getAttributeType().getNames().get(0)).append('=').append(rdn.getValue().getString()).append(',');
		}
		
		sb.setLength(sb.length() - 1);
		
		DistinguishedName newBindDN = new DistinguishedName(sb.toString());
        Password newPass = new Password(bindContext.getCredentials());
        
        try {
        	BindInterceptorChain chain = new BindInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,router);
        	chain.nextBind(newBindDN,newPass,new LDAPConstraints());
        } catch (LDAPException e) {
        	throw MyVDPartition.generateException(e);
        }
        
        userSession.put("MYVD_BINDDN",newBindDN);
        userSession.put("MYVD_BINDPASS",newPass);
        
        LdapPrincipal principal = new LdapPrincipal(this.schemaManager,bindContext.getDn(),AuthenticationLevel.SIMPLE,  bindContext.getCredentials());
        
        IoSession session = bindContext.getIoSession();

        if ( session != null )
        {
            SocketAddress clientAddress = session.getRemoteAddress();
            principal.setClientAddress( clientAddress );
            SocketAddress serverAddress = session.getServiceAddress();
            principal.setServerAddress( serverAddress );
        }
        
        return principal;
		
		
	}
	

}
