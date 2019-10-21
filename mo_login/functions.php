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
 * This library is miniOrange Authentication Service.
 *
 * Gives result of saml response.
 *
 * @copyright   2017  miniOrange
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     auth_mo_login
 */
// @codingStandardsIgnoreLine
require_once(__DIR__ . '/../../config.php');
defined('MOODLE_INTERNAL') || die();
$config = get_config('auth/mo_login');
// Config provide access to all data saved in database of mld_config table.
/**
 * Show test result
 * @param String $useremail String
 * @param String $attrs String
 */
function auth_mo_login_show_test_result($useremail, $attrs) {
    ob_end_clean();
    echo '<div style="font-family:Calibri;padding:0 3%;">';
    if (!empty($useremail)) {
        echo '<div >TEST SUCCESSFUL</div>
                <div ></div>';
    }
        echo '<span style="font-size:14pt;">
                <b>Hello</b>, '.$useremail.'</span><br/>
                <p >ATTRIBUTES RECEIVED:</p>
                <table >
                <tr ><td >ATTRIBUTE NAME</td><td>ATTRIBUTE VALUE</td></tr>';
    if (!empty($attrs)) {
        foreach ($attrs as $key => $value) {
            $value = is_array($value) ? $value : array(0 => $value);
            echo "
            <tr><td>" .$key . "</td>
                <td> " .implode("<hr/>" , $value). " </td></tr> ";
        }
    } else {
        echo "No Attributes Received.";
    }
    echo '</table></div>';
    echo '<div ><input type="button" value="Done" onClick="self.close();"></div>';
    exit;
}

/**
 * Create authn Request
 * @param String $acsurl String
 * @param String $issuer String
 * @param string $forceauthn AUtn URL
 * @return string
 */
function auth_mo_login_create_authn_request($acsurl, $issuer, $forceauthn = 'false') {

    $requestxmlstr = '<?xml version="1.0" encoding="UTF-8"?>' .
                    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="' . auth_mo_login_generate_id() .
                    '" Version="2.0" IssueInstant="' . auth_mo_login_generate_timestamp() . '"';
    if ( $forceauthn == 'true') {
        $requestxmlstr .= ' ForceAuthn="true"';
    }
    $requestxmlstr .= ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="' . $acsurl .
                    '" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' . $issuer . '</saml:Issuer>
                    </samlp:AuthnRequest>';
    $deflatedstr = gzdeflate($requestxmlstr);
    $baseencodedstr = base64_encode($deflatedstr);
    $urlencoded = urlencode($baseencodedstr);
    return $urlencoded;
}

/**
 * Login User
 * @param String $accountmatcher String
 * @param String $userssaml String
 * @param bool $samlcreate Create
 * @param bool $samlupdate Update
 * @return bool|mixed|stdClass|void
 * @throws dml_exception
 * @throws moodle_exception
 */
function auth_mo_login_authenticate_user_login($accountmatcher, $userssaml, $samlcreate=false, $samlupdate=false) {
    global $CFG, $DB;
    $authsenabled = get_enabled_auth_plugins();
    $password = auth_mo_login_get_random_password();
    $created = false;
    if ($user = get_complete_user_data($accountmatcher, $userssaml[$accountmatcher])) {
        if ($user->auth == 'manual') {
            $samlupdate = 'false';
        }
        $auth = empty($user->auth) ? 'manual' : $user->auth;
        if ($auth == 'nologin' or !is_enabled_auth($auth)) {
            $errormsg = '[client '.getremoteaddr().'] '.$CFG->wwwroot.'  --->  DISABLED_LOGIN: '.$userssaml[$accountmatcher];
            print_error($errormsg);
            return false;
        }
    } else {
        // If account matcher queryconditions detected 1 get_field of user and id return true means user already logedin.
        $queryconditions[$accountmatcher] = $userssaml[$accountmatcher];
        $queryconditions['deleted'] = 1;
        if ($DB->get_field('user', 'id', $queryconditions)) {
            $errormsg = '[client '.$_SERVER['REMOTE_ADDR'].'] '.  $CFG->wwwroot.'  --->  ALREADY LOGEDIN:
            '.$userssaml[$accountmatcher];
            print_error($errormsg);
            return false;
        }

        $auths = $authsenabled;
        $user = new stdClass();
        $user->id = 0;
    }
    // Selecting our mo_login plugin for updating user data.
    $auth = 'mo_login';
    $authplugin = get_auth_plugin($auth);
    if (!$authplugin->user_login($userssaml[$accountmatcher], $password)) {
        return;
    }
    if (!$user->id) {
        // For non existing user we create account here and make $created true.
        if ($samlcreate) {
            $user = create_user_record($userssaml['username'], $password, $auth);
            $authplugin->sync_roles($user);
            // Synchronizing the role of user here.
            $created = true;
        }
    }

    if ($user->id && !$created) {
        if (empty($user->auth)) {
            $queryconditions['id'] = $user->id;
            $DB->set_field('user', 'auth', $auth, $queryconditions);
            $user->auth = $auth;
        }
        if ($samlupdate && $user->auth == 'mo_login') {
            $queryconditions['id'] = $user->id;

            // Updating the attributes data coming into SAML response. If $samlupdate is true. only for idp user.
            if (empty($user->firstaccess)) {
                $queryconditions['id'] = $user->id;
                $DB->set_field('user', 'firstaccess', $user->timemodified, $queryconditions);
                $user->firstaccess = $user->timemodified;
            }
            foreach (auth_plugin_mo_login::ATTRIBUTES as $attribute) {
                if (array_key_exists($attribute, $userssaml)) {
                    $queryconditions['id'] = $user->id;
                    $DB->set_field('user', $attribute, $userssaml[$attribute], $queryconditions);
                    $user->username = $userssaml['username'];
                }
            }

        }

        $authplugin->sync_roles($user);

    }

    foreach ($authsenabled as $authe) {
        $authes = get_auth_plugin($authe);
        $authes->user_authenticated_hook($user, $userssaml[$accountmatcher], $password);
    }
    if (!$user->id && !$samlcreate) {
        print_error("New coming User ". ' "'. $userssaml[$accountmatcher] . '" '
        . "not exists in moodle and auto-create is disabled");
        return false;
    }

    return $user;
}

/**
 * Get Random Password
 * @return string
 */
function auth_mo_login_get_random_password() {
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
    $pass = array();
    $alphalength = strlen($alphabet) - 1;
    for ($i = 0; $i < 7; $i++) {
        $n = rand(0, $alphalength);
        $pass[] = $alphabet[$n];
    }
    return implode($pass);
}
// Timestamp for instant issuer.
/**
 * Generate Timestamp
 * @param null $instant Instant
 * @return false|string
 */
function auth_mo_login_generate_timestamp($instant = null) {
    if ($instant === null) {
        $instant = time();
    }
    return gmdate('Y-m-d\TH:i:s\Z', $instant);
}
// Id for saml request.
/**
 * Generate ID
 * @return string
 */
function auth_mo_login_generate_id() {
    return '_' .auth_mo_login_string_to_hex(auth_mo_login_generate_random_bytes(21));
}
// Value conversion method for string_to_hex.
/**
 * String to HEX
 * @param String $bytes Bytes
 * @return string
 */
function auth_mo_login_string_to_hex($bytes) {
    $ret = '';
    for ($i = 0; $i < strlen($bytes); $i++) {
        $ret .= sprintf('%02x', ord($bytes[$i]));
    }
    return $ret;
}
// Generate_random_bytes produce random bytes of given length.
/**
 * Generate Random bytes
 * @param Length $length Length
 * @param bool $fallback Fallback
 * @return string
 */
function auth_mo_login_generate_random_bytes($length, $fallback = true) {
    return openssl_random_pseudo_bytes($length);
}
// Here we are checking Mapping attributes in plugin to coming saml attributes.
/**
 * Check mapping
 * @param Attribute $attrs Attribvutes
 * @param String $relaystate Go to URL
 * @param int $sessionindex Index
 */
function auth_mo_login_checkmapping($attrs, $relaystate, $sessionindex) {
    try {

        // Attribute mapping.
        // Check if Match or Create user is by username or email.
        if (!empty($attrs)) {

            if (!empty($emailattribute) && array_key_exists($emailattribute, $attrs)) {
                $useremail = $attrs[$emailattribute][0];
            } else {
                $useremail = $attrs['NameID'][0];
            }

            auth_mo_login_show_test_result($useremail,  $attrs);
            // It will change with version.
        }
    } catch (Exception $e) {
        echo sprintf('An error occurred while processing the SAML Response.');
        exit;
    }
}