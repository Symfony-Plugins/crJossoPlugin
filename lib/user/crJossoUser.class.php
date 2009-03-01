<?php

/**
 * PHP Josso User implementation for symfony
 *
 * @author Christian A. Rodriguez <car@cespi.unlp.edu.ar>
 */

class crJossoUser extends sfBasicSecurityUser {
  

	/**
	* Implements the actionless of user signin, populating current object
  * with important data of JossoUser
	*
	* @access public
  *
	* @param    string $aSession SSO Session ID
	*/
  public function signIn($aSession)
  {
    $this->setAttribute('crJossoPluginSessionId',$aSession);
    $this->setAuthenticated(true);
    $this->loadJossoCredentials();
  }


	/**
	* Checks if the SSO Session ID has changed with our own session
	*
	* @return boolean
  *
	* @access public
	*/
  public function haveToRelogin($aSession)
  {
    return $aSession!=$this->getAttribute('crJossoPluginSessionId','-1');
  }

	/**
	* Returns a JossoUser Object
	*
	* @return JossoUser or null if it can't retrieve it.
  *
	* @access public
	*/
  public function getJossoUser()
  {
    $agent=JossoAgent::getNewInstance();
    try{
      return $agent->getUserInSession();
    }catch(SoapFault $e){
      return null;
    }
  }

	/**
	* Implements the actionless of user signout, cleaning the context
	*
	* @access public
	*/
  public function signOut()
  {
    $this->setAuthenticated(false);
  }

	/**
	* Gives current symfony user all credentials taken from 
	* JOSSO User
  *
	* @access protected
	*/
  protected function loadJossoCredentials()
  {
    $user=$this->getJossoUser();
    if (is_null($user))return;
    foreach($user->getRoles() as $role){
      $this->addCredential($role->getName());
    }
  }

  
}
