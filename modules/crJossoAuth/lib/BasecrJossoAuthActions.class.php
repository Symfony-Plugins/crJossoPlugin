<?php
/*
 * Real implementation of crJossoAuth actions
 *
 * @author Lic. Christian A. Rodriguez <car@cespi.unlp.edu.ar>
 */

class BasecrJossoAuthActions extends sfActions
{
  /**
  * Signin action
  * This action in any other application must be responsable of showing
  * the login form and authenticatin user.
  * In this case every job is delegated to JOSSO
  *
  * @access public
  *
  */
  public function executeSignin()
  {
    $agent=JossoAgent::getNewInstance();
    $josso_user=$agent->getUserInSession();
    if (!is_null($josso_user)){
      $this->getUser()->signIn($agent->accessSession());
      $this->redirect('@homepage');
    }else{
      $this->forwardToLoginAction();
    }
  }
  
  /**
  * Signout action
  * This action in any other application must be responsable of cleainig
  * session objects
  * In this case every job is delegated to JOSSO and same cleaning is done
  *
  * @access public
  *
  */
  public function executeSignout()
  {
    sfLoader::loadHelpers(array('Url'));

    $josso_agent = JossoAgent::getNewInstance();

    $sign_out_url=sfConfig::get('app_cr_josso_plugin_success_signout_url');
    $sign_out_url=!empty($sign_out_url)?$sign_out_url:'@homepage';

    $logoutUrl = $josso_agent->getGatewayLogoutUrl(). '?josso_back_to=' . url_for($sign_out_url,true);

    $logoutUrl = $logoutUrl . $this->createFrontChannelParams();
    setcookie("JOSSO_SESSIONID", '', 0, "/"); // Clear session cookie ...

    $this->getUser()->signOut();

    $this->redirect($logoutUrl);
  }

  /**
  * This function is used by crJossoSecurityFilter to complement its work
  * checking if JOSSO session is still active or not.
  * The trick is all inside a cookie
  *
  * @access public
  *
  */
  public function executeSecurityCheck()
  {
    $agent=JossoAgent::getNewInstance();
    try{
      $assertionId=$this->getRequestParameter('josso_assertion_id');
      $this->forward404Unless($assertionId);
      $ssoSessionId = $agent->resolveAuthenticationAssertion($assertionId);
      setcookie("JOSSO_SESSIONID", $ssoSessionId, 0, "/"); // session cookie ...
      $sign_in_url=sfConfig::get('app_cr_josso_plugin_success_signin_url');
      $sign_in_url=!empty($sign_in_url)?$sign_in_url:'@homepage';
      $this->redirect($sign_in_url);
    }catch(SoapFault $e){
      setcookie("JOSSO_SESSIONID",'', 0, "/"); // session cookie ...
      $this->redirect('@cr_josso_signin');
    }
  }

  /**
  * It builds login URL and redirects the request
  *
  * @access private
  *
  */
  private function forwardToLoginAction()
  {
    sfLoader::loadHelpers(array('Url'));

    //$this->getUser()->setAttribute('JOSSO_ORIGINAL_URL',$currentUrl);
    $agent=JossoAgent::getNewInstance();
    $securityCheckUrl=url_for(
            sfConfig::get('app_cr_josso_plugin_security_check_module')."/".
            sfConfig::get('app_cr_josso_plugin_security_check_action'),true);
    $loginUrl = $agent->getGatewayLoginUrl(). '?josso_back_to=' . $securityCheckUrl;
    $loginUrl = $loginUrl . $this->createFrontChannelParams();
    $this->redirect($loginUrl);
  }

  private function createFrontChannelParams() {
    // Add some request parameters like host name
    $host = $_SERVER['HTTP_HOST'];
    $params = '&josso_partnerapp_host=' . $host;
    return $params;
    // TODO : Support josso_partnerapp_ctx param too ?

  }

}
