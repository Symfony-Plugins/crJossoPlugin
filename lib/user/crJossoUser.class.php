<?php

/**
 * PHP Josso User implementation for symfony
 *
 * @author Christian A. Rodriguez <car@cespi.unlp.edu.ar>
 */

class crJossoUser extends sfBasicSecurityUser {
  
	/**
	 * User instance of JossoUser
	 * @var JossoUser
	 * @access private
	 */
  private $user=null;

	/**
	* Implements the actionless of user signin, populating current object
  * with important data of JossoUser
	*
	* @access public
  *
	* @param    JossoUser $user
	*/
  public function signIn(JossoUser $user)
  {
    $this->setAuthenticated(true);
    $this->user=$user;
    $this->loadJossoCredentials();
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
    if (is_null($this->user))
    {
      $agent=JossoAgent::getNewInstance();
      try{
        $this->signin($agent->getUserInSession());
      }catch(SoapFault $e){
      }
      if (!$this->user)
        $this->signOut();
    }
    return $this->user;
  }

	/**
	* Implements the actionless of user signout, cleaning the context
	*
	* @access public
	*/
  public function signOut()
  {
    $this->setAuthenticated(false);
    $this->user=null;
  }

	/**
	* Gives current symfony user all credentials taken from 
	* JOSSO User
  *
	* @access protected
	*/
  protected function loadJossoCredentials()
  {
    if (is_null($this->user))return;
    foreach($this->user->getRoles() as $role){
      $this->addCredential($role->getName());
    }
  }

  
}
