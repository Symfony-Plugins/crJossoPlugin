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
      //Check if user authenticated 
      if ($this->context->getUser()->isAuthenticated())
      {
        // if it is not authenticated in SSO Identity Manager then force login
        // or
        // if shall we relogin because SSO Session changed
        if (  is_null($aSession)  ||
              $this->context->getUser()->haveToRelogin($aSession)
            ){
          $this->context->getUser()->setAuthenticated(false);
          // Then we need to relogin on JOSSO Server
          $this->forwardToLoginAction();
        }
      }

    }
    parent::execute($filterChain);
  }
}
