<?php
// This file is part of miniOrange moodle plugin
//
// This plugin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * This library is miniOrange SAML Login handler.
 *
 * Redirect here for saml request and response purpose
 *
 * @copyright   2017  miniOrange
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     auth_mo_login
 */
// @codingStandardsIgnoreLine
require_once(__DIR__ . '/../../config.php');

require_once('responseauthmologin.php');
require_once('auth_mo_login_utilities.php');
require_once('assertionauthmologin.php');
require_once('functions.php');
global $CFG, $USER, $SESSION;

$wantsurl = optional_param('wantsurl', '', PARAM_LOCALURL);




$pluginconfig = get_config('auth_mo_login');
// This condition showing the request for the saml.
// If SAMLResponse is not set or testConfig requested means it will consruct saml request.

if (!isset($_POST['SAMLResponse']) || (isset($_REQUEST['option'])&& $_REQUEST['option'] == 'testConfig')) {

    if (array_key_exists('option', $_REQUEST) && $_REQUEST['option'] == 'testConfig' ) {
        $sendrelaystate = 'testValidate';
        // Checking the purpose of saml request.
    } else if ( isset( $_REQUEST['redirect_to'])) {
        $sendrelaystate = required_param('redirect_to', PARAM_URL);
    } else {
        $sendrelaystate = $CFG->wwwroot.'/auth/mo_login/index.php';
        // Sendrelaystate set above.
    }

    $ssourl = $pluginconfig->login_url;
    // Saml login url.
    $acsurl = $CFG->wwwroot.'/auth/mo_login/index.php';
    // Acs for the plugin.
    $issuer = $CFG->wwwroot;
    // Plugin base url.
    $forceauthn = 'false';
    // Disabled forceauthn.
    $samlrequest = auth_mo_login_create_authn_request($acsurl, $issuer, $forceauthn);
    // Calling method presentin functions.php for consructing saml request.
    $redirect = $ssourl;
    if (strpos($ssourl, '?') !== false) {
        $redirect .= '&';
    } else {
        $redirect .= '?';
    }
    $redirect .= 'SAMLRequest=' . $samlrequest . '&RelayState=' . urlencode($sendrelaystate);
    // Requested attributes are included.
    header('Location: '.$redirect);
    // Redirecting the login page to IdP login page.
    exit();
}
if ( array_key_exists('SAMLResponse', $_POST) && !empty($_POST['SAMLResponse'])) {
    // Reading saml response and extracting useful data.


    $response = required_param('SAMLResponse', PARAM_RAW);
    $relaystate = optional_param('RelayState', '', PARAM_URL);

    $response = base64_decode($response);

    $document = new DOMDocument();
    $document->loadXML($response);
    $samlresponsexml = $document->firstChild;

    $certfromplugin = get_config('auth_mo_login', 'x509certificate');

    $certfpfromplugin = xml_security_key::get_raw_thumbprint($certfromplugin);
    $acsurl = $CFG->wwwroot.'/auth/mo_login/index.php';
    $samlresponse = new auth_mo_login_saml_response_class($samlresponsexml);
    $responsesignaturedata = $samlresponse->get_signature_data();
    $assertionsignaturedata = current($samlresponse->get_assertions())->get_signature_data();
    $certfpfromplugin = iconv('UTF-8', "CP1252//IGNORE", $certfpfromplugin);
    $certfpfromplugin = preg_replace('/\s+/', '', $certfpfromplugin);


    if (!empty($responsesignaturedata)) {

        $validsignature = auth_mo_login_utilities::process_response
        ($acsurl, $certfpfromplugin, $responsesignaturedata, $samlresponse);
        if ($validsignature === false) {
            echo 'Invalid signature in the SAML Response.';
            exit;
        }
    }
    if (!empty($assertionsignaturedata)) {
        $validsignature = auth_mo_login_utilities::
        process_response($acsurl, $certfpfromplugin, $assertionsignaturedata, $samlresponse);
        if ($validsignature === false) {
            echo 'Invalid signature in the SAML Assertion.';
            exit;
        }
    }
    $issuer = $pluginconfig->entity_id;
    $spentityid = $CFG->wwwroot;
    auth_mo_login_utilities::validate_issuer_and_audience($samlresponse, $spentityid, $issuer);
    $ssoemail = current(current($samlresponse->get_assertions())->get_name_id());
    $attrs = current($samlresponse->get_assertions())->get_attributes();


    $attrs['NameID'] = $ssoemail;
    $sessionindex = current($samlresponse->get_assertions())->get_session_index();
    $SESSION->mo_login_attributes = $attrs;
    $SESSION->mo_login_nameID = $ssoemail;
    $SESSION->mo_login_sessionIndex = $sessionindex;
    $pluginconfig = get_config('auth_mo_login');

    if ($relaystate == 'testValidate') {
        auth_mo_login_checkmapping($attrs, $relaystate, $sessionindex);

    } else {
        // This part doing login in moodle via reading, assigning and updating saml user attributes.
        $samlplugin = get_auth_plugin('mo_login');

        $pluginconfig = get_config('auth_mo_login');

        $samluser = $samlplugin->get_userinfo($ssoemail);

        $USER = auth_mo_login_authenticate_user_login('email', $samluser, 'true', 'true');
        // This function present in functions.php which basic purpose to return moodle user.
        // If it returns false means moodle user not created.
        if ($USER != false) {
            $USER->loggedin = true;
            $USER->site = $CFG->wwwroot;
            $USER = get_complete_user_data('id', $USER->id);

            // Everywhere we can access user by its id.
            complete_user_login($USER);
            // Here user get login with its all field assigned.
            $SESSION->isSAMLSessionControlled = true;
            // Work of saml response is done here.
            if (isset($wantsurl)) {
                // Need to set wantsurl, where we redirect.
                $urltogo = $wantsurl;
            } else {
                $urltogo = $CFG->wwwroot.'/';
            }
            if (!$urltogo || $urltogo == '') {
                $urltogo = $CFG->wwwroot.'/';
            }
            unset($SESSION->wantsurl);
            redirect($urltogo, 0);
        } else {
            // This block executed only when user is not created.
            print_error('USER is not created.');
        }
    }
}