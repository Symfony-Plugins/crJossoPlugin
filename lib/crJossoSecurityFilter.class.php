<?php
/**
 * PHP Josso Symfony Security Filter 
 *
 * @author Lic. Christian A. Rodriguez <car@cespi.unlp.edu.ar>
 */


class crJossoSecurityFilter extends sfBasicSecurityFilter
{
  /**
   * Executes this filter.
   *
   * @param sfFilterChain $filterChain A sfFilterChain instance
   */
  public function execute($filterChain)
  {
    $agent=JossoAgent::getNewInstance();
    $aSession=$agent->accessSession(); //Sends keep alive to WS.

    /* Disable security on josso security checks */
    if (
      (sfConfig::get('app_cr_josso_plugin_security_check_module') == $this->context->getModuleName()) && 
      (sfConfig::get('app_cr_josso_plugin_security_check_action') == $this->context->getActionName())
    ){
      $filterChain->execute();
      return;
    }else{
      //Check if user authenticated is also authenticated in SSO Identity Manager
      if ($this->context->getUser()->isAuthenticated()&&is_null($aSession))
      {
          // the user is not authenticated against SSO Identity Manager...
          $this->context->getUser()->setAuthenticated(false);
          // Then we need to relogin on JOSSO Server
          $this->forwardToLoginAction();
      }

    }
    parent::execute($filterChain);
  }
}
