package net.sourceforge.myvd.protocol.ldap;

import java.util.ArrayList;
import java.util.HashMap;

import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.SessionVariables;



import org.apache.mina.common.IoSession;
import org.apache.mina.handler.demux.MessageHandler;

public abstract class LDAPOperation implements MessageHandler {

	Insert[] globalChain;
    Router router;
	
	public LDAPOperation() {
		super();
	}

	public void messageReceived(IoSession session, Object request) {
		HashMap userSession = null;
		
		userSession = (HashMap) session.getAttribute("MYVD_SESSION");
		if (userSession == null) {
			userSession = new HashMap();
			session.setAttribute("MYVD_SESSION", userSession);
		}
	    DistinguishedName bindDN = (DistinguishedName) session.getAttribute("MYVD_BINDDN");
	    Password pass = (Password) session.getAttribute("MYVD_BINDPASS");
	    
	    if (bindDN == null) {
	    	bindDN = new DistinguishedName("");
	    	pass = new Password();
	    	
	    	
	    	
	    	userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
	    	session.setAttribute("MYVD_BINDDN",new DistinguishedName(""));
	        session.setAttribute("MYVD_BINDPASS",new Password());
	       
	    }
	    
	    messageReceived(session,request,userSession,bindDN,pass);
	}

	
	public void setEnv(Insert[] globalChain,Router router) {
		this.globalChain = globalChain;
		this.router = router;
	}
	
	public abstract void messageReceived( IoSession session, Object request,HashMap userSession,DistinguishedName bindDN,Password pass );

}