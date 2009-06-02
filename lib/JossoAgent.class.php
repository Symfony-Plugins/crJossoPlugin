<?php
/**
 * JOSSO Agent class definition.
 *
 * @package org.josso.agent.php
 */

/**
JOSSO: Java Open Single Sign-On

Copyright 2004-2008, Atricore, Inc.

This is free software; you can redistribute it and/or modify it
under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation; either version 2.1 of
the License, or (at your option) any later version.

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this software; if not, write to the Free
Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
02110-1301 USA, or see the FSF site: http://www.fsf.org.

*/

/**
 * PHP Josso Agent implementation based on WS.
 *
 * @package  org.josso.agent.php
 *
 * @author Sebastian Gonzalez Oyuela <sgonzalez@josso.org>
 * @version $Id: class.jossoagent.php 613 2008-08-26 16:42:10Z sgonzalez $
 * @author <a href="mailto:sgonzalez@josso.org">Sebastian Gonzalez Oyuela</a>
 * @author Updated by Christian A. Rodriguez <car@cespi.unlp.edu.ar>
 * @author <a href="mailto:car@cespi.unlp.edu.ar">Christian A. Rodriguez</a>
 *
 */

class JossoAgent  {


	// ---------------------------------------
	// JOSSO Agent configuration : 
	// --------------------------------------- 
	
	/**
	 * WS End-point
	 * @var string
	 * @access private
	 */
	private $endpoint = 'http://localhost:8080';
	
	/**
	 * WS Proxy Settings
     * @var string
     * @access private
     */
	private $proxyhost = '';

	/**
     * @var string
     * @access private
     */
	private $proxyport = '';

	/**
     * @var string
     * @access private
     */
	private $proxyusername = '';

	/**
     * @var string
     * @access private
     */
	private $proxypassword = '';
	
	// Gateway
    /**
     * @var string
     * @access private
     */
	private $gatewayLoginUrl;

	/**
     * @var string
     * @access private
     */
	private $gatewayLogoutUrl;



	// ---------------------------------------
	// JOSSO Agent internal state : 
	// --------------------------------------- 

	/**
	 * SOAP Clienty for identity mgr.
     * @var string
     * @access private
     */
	private $identityMgrClient;


	/**
	 * SOAP Clienty for identity provider.
     * @var string
     * @access private
     */
	private $identityProviderClient;

	
	/**
	 * SOAP Clienty for session mgr.
     * @var string
     * @access private
     */
	private $sessionMgrClient;
	
	
	/**
	 * @return JossoAgent a new Josso PHP Agent instance.
	 */
	public static function getNewInstance() {
		// Get config variable values from josso.inc.
		$josso_gatewayLoginUrl=sfConfig::get('app_cr_josso_plugin_gateway_login_url');
		$josso_gatewayLogoutUrl=sfConfig::get('app_cr_josso_plugin_gateway_logout_url');
		$josso_endpoint=sfConfig::get('app_cr_josso_plugin_service_endpoint_url');
		$josso_proxyhost=sfConfig::get('app_cr_josso_plugin_proxy_host');
		$josso_proxyport=sfConfig::get('app_cr_josso_plugin_proxy_port');
		$josso_proxyusername=sfConfig::get('app_cr_josso_plugin_proxy_username');
		$josso_proxypassword=sfConfig::get('app_cr_josso_plugin_proxy_password');
		return new JossoAgent($josso_gatewayLoginUrl, 
							  $josso_gatewayLogoutUrl, 
							  $josso_endpoint, 
							  $josso_proxyhost, 
							  $josso_proxyport, 
							  $josso_proxyusername, 
							  $josso_proxypassword
            );
	}
	
	/**
	* constructor
	*
	* @access private
	*
	* @param    string $josso_gatewayLoginUrl 
	* @param    string $josso_gatewayLogoutUrl 
	* @param    string $josso_endpoint SOAP server
	* @param    string $josso_proxyhost
	* @param    string $josso_proxyport
	* @param    string $josso_proxyusername
	* @param    string $josso_proxypassword
	*/
	private function __construct($josso_gatewayLoginUrl, $josso_gatewayLogoutUrl, $josso_endpoint, 
						$josso_proxyhost, $josso_proxyport, $josso_proxyusername, $josso_proxypassword) {
	
		// WS Config
		$this->endpoint = $josso_endpoint;
		$this->proxyhost = $josso_proxyhost;
		$this->proxyport = $josso_proxyport;
		$this->proxyusername = $josso_proxyusername;
		$this->proxypassoword = $josso_proxypassword;
		
		// Agent config
		$this->gatewayLoginUrl = $josso_gatewayLoginUrl;
		$this->gatewayLogoutUrl = $josso_gatewayLogoutUrl;
										
	}
	
	/**
	* Gets the authenticated jossouser, if any.
	*
	* @return JossoUser the authenticated user information or null.
	* @access public
	*/
	public function getUserInSession() {
	
		$sessionId = $this->getSessionId();
		if (!isset($sessionId)) {
			return null;
		}
		// SOAP Invocation
		$identityMgr = $this->getIdentityMgrSoapClient();
    $params = new stdClass;
    $params->ssoSessionId=$sessionId;
    try{
      $response  = $identityMgr->FindUserInSession($params);
      return $this->newUser($response->SSOUser);
    }catch(SoapFault $e){
      return null;
    }
	}
	
	/**
	* Returns all roles associated to the current sessionId
	*
	* @return JossoRole[] an array with all JossoRole instances
	* @access public
	*/
	public function getRoles () {
	
		// SOAP Invocation
    $sessionId=$this->getSessionId();
		$identityMgr = $this->getIdentityMgrSoapClient();
    $params = new stdClass;
    $params->ssoSessionId=$sessionId;
    try{
      $response = $identityMgr->FindRolesBySSOSessionId($params);
    }catch(SoapFault $e)
    {
      throw new sfException("Can't get Josso Roles from WebService for current user: ".$e->getMessage());
    }
    // Build array of roles
    $i = 0;
    $result = $response->roles;
    $roles=array();

    foreach($result as $roledata) {
      $roles[$i] = $this->newRole($roledata);
      $i++;
    }
    return $roles;
		
	}
	
	/**
	 * Sends a keep-alive notification to the SSO server so that SSO sesison is not lost.
	 * @access public
	 */
	public function accessSession() {
	
		// Check if a session ID is pressent.
		$sessionId = $this->getSessionid();
		if (!isset($sessionId ) || $sessionId == '') {
			return null;
		}

		// Check last access time :
		// $lastAccessTime = $_SESSION['JOSSO_LAST_ACCESS_TIME'];
		// $now = time();

    try{
        $sessionMgr = $this->getSessionMgrSoapClient();
        $params = new stdClass;
        $params->ssoSessionId=$sessionId;
        $response=$sessionMgr->AccessSession($params);
        return $response->ssoSessionId;
    }catch(SoapFault $e){
      return null;
    }
	}
	
	/**
	 * Returns the URL where the user should be redireted to authenticate.
	 *
	 * @return string the configured login url.
	 *
	 * @access public
	 */
	public function getGatewayLoginUrl() {
		return $this->gatewayLoginUrl;
	}

	/**
	 * Returns the SSO Session ID given an assertion id.
	 *
	 * @param string $assertionId
	 *
	 * @return string, the SSO Session associated with the given assertion.
	 *
	 * @access public
	 */
	public function resolveAuthenticationAssertion($assertionId) {
		// SOAP Invocation
		$identityProvider = $this->getIdentityProvdierSoapClient();
    $params = new stdClass;
    $params->assertionId=$assertionId;
    $resolveAuthenticationAssertionResponse = $identityProvider->resolveAuthenticationAssertion($params);
	  return $resolveAuthenticationAssertionResponse->ssoSessionId;
	}
	
	/**
	 * Returns the URL where the user should be redireted to logout.
	 *
     * @return string the configured logout url.
     *
     * @access public
	 */
	public function getGatewayLogoutUrl() {
		return $this->gatewayLogoutUrl;
	}


	
	//----------------------------------------------------------------------------------------
	// Protected methods intended to be invoked only within this class or subclasses.
	//----------------------------------------------------------------------------------------
	
	/**
	 * Gets current JOSSO session id, if any.
	 *
	 * @access private
	 */
	private function getSessionId() {
	    if (isset($_COOKIE['JOSSO_SESSIONID']))
		    return $_COOKIE['JOSSO_SESSIONID'];
	}
	
	/**
	 * Factory method to build a user from soap data.
	 *
	 * @param JossoUser as received from WS.
	 * @return jossouser a new jossouser instance.
	 *
	 * @access private
	 */
	private function newUser($user) {
		// Build a new jossouser 
		$username = $user->name;
		$properties = $user->properties;
    $roles=$this->getRoles();
		$user = new JossoUser($username, $properties,$roles);
		
		return $user;
	}
	
	/**
	 * Factory method to build a role from soap data.
	 *
	 * @param array role information as received from WS.
	 * @return jossorole a new jossorole instance
	 *
	 * @access private
	 */
	private function newRole($data) {
		// Build a new jossouser 
		$rolename = $data->name;
		$role = new JossoRole($rolename);
		return $role;
	}
	
	
	/**
	 * Gets the soap client to access identity service.
	 *
	 * @access private
	 */
	private function getIdentityMgrSoapClient() {
		// Lazy load the propper soap client
		if (!isset($this->identityMgrClient)) {
      $wsdl=$this->endpoint . '/josso/services/SSOIdentityManager?wsdl';
      $options=array(
        "proxy_host"      =>  $this->proxyhost, 
        "proxy_port"      =>  $this->proxyport, 
        "proxy_login"     =>  $this->proxyusername, 
        "proxy_password"  =>  $this->proxypassword,
        "exceptions"      =>  true,
        "encoding"        =>  "UTF-8",
      ); 
			$this->identityMgrClient = new Soapclient($wsdl,$options);
		}
		return $this->identityMgrClient;
	}

	/**
	 * Gets the soap client to access identity provider.
	 *
	 * @access private
	 */
	private function getIdentityProvdierSoapClient() {
		// Lazy load the propper soap client
		if (!isset($this->identityProviderClient)) {
      $wsdl=$this->endpoint . '/josso/services/SSOIdentityProvider?wsdl';
      $options=array(
        "proxy_host"      =>  $this->proxyhost, 
        "proxy_port"      =>  $this->proxyport, 
        "proxy_login"     =>  $this->proxyusername, 
        "proxy_password"  =>  $this->proxypassword,
        "exceptions"      =>  true,
        "tarce"           =>  true,
        "encoding"        =>  "UTF-8",
      ); 
			$this->identityProviderClient = new Soapclient($wsdl,$options);
		}
		return $this->identityProviderClient;
	}

	
	/**
	 * Gets the soap client to access session service.
	 *
	 * @access private
	 */
	function getSessionMgrSoapClient() {
		// Lazy load the propper soap client
		if (!isset($this->sessionMgrClient)) {
			// SSOSessionManager SOAP Client
      $wsdl=$this->endpoint . '/josso/services/SSOSessionManager?wsdl';
      $options=array(
        "proxy_host"      =>  $this->proxyhost, 
        "proxy_port"      =>  $this->proxyport, 
        "proxy_login"     =>  $this->proxyusername, 
        "proxy_password"  =>  $this->proxypassword,
        "exceptions"      =>  true,
        "encoding"        =>  "UTF-8",
      ); 
			$this->sessionMgrClient = new Soapclient($wsdl,$options);
		}
		return $this->sessionMgrClient;

	}

}
?>
