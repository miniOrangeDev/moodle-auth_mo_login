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
 * This library is contain overridden moodle method.
 *
 * Contains authentication method.
 *
 * @copyright   2017  miniOrange
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     auth_mo_login
 */
// @codingStandardsIgnoreLine
require_once(__DIR__ . '/../../config.php');
global $CFG;
require_once('functions.php');
require_once($CFG->libdir.'/authlib.php');
/**
 * This class contains authentication plugin method
 *
 * @package    auth_mo_login
 * @copyright  2017 miniOrange
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class auth_plugin_mo_login extends auth_plugin_base {

    /**
     *
     */
    const PLUGIN_NAME = 'auth/mo_login';
    /**
     *
     */
    const ATTRIBUTES = array('firstname', 'lastname');
    // Constructor which has authtype, roleauth, and config variable initialized.

    /**
     * auth_plugin_mo_login constructor.
     * @throws dml_exception
     */
    public function __construct() {
        $this->authtype = 'mo_login';
        $this->roleauth = 'auth_mo_login';
        $this->config = get_config('auth/mo_login');
    }

    // User login return boolean value after checking username and password combination.

    /**
     * User Login
     * @param string $username Username
     * @param string $password Password
     * @return bool
     */
    public function user_login($username, $password) {
        global $SESSION;
        if (isset($SESSION->mo_login_attributes)) {
            return true;
        }
        return false;
    }
    /*
    *function get_userinfo() called from index.php
    *Its purpose to rectify attributes coming froms saml with mapped attributes.
    *$samlattributes variable assigned by $SESSION->mo_login_attributes which priviously saved in SESSION variable in index.php
    *get_attributes() method called to get all attributes variable mapped in plugin.
    *It will return $user array in which all attributes value according to mapped value.
    */
    /**
     * Get User INfo
     * @param null $username String
     * @return array|mixed
     * @throws dml_exception
     */
    public function get_userinfo($username = null) {
        global $SESSION;

        $user = array();
        $pluginconfig = get_config('auth_mo_login');
        $mosamlattributes = $SESSION->mo_login_attributes;
        $user['email'] = $mosamlattributes['NameID'];
        $user['username'] = $mosamlattributes['NameID'];
        foreach (self::ATTRIBUTES as $attribute) {
            $attributevalue = $pluginconfig->{$attribute};
            if ($attributevalue && array_key_exists($attributevalue, $mosamlattributes)) {
                if ((is_array($mosamlattributes[$attributevalue]) && count($mosamlattributes[$attributevalue]) == 1)) {
                    $user[$attribute] = $mosamlattributes[$attributevalue][0];
                } else if (!is_array($mosamlattributes[$attributevalue])) {
                    $user[$attribute] = $mosamlattributes[$attributevalue];
                }
            }
        }

        return $user;
    }


    /**
     * Get custom attributes
     * @return array
     */
    public function get_custom_attributes_mapping() {
        $customattributemapping = array();
        $customattributecount = array_key_exists('mo_login_custom_attribute_mapping_count', $this->config) ?
            $this->config->mo_login_custom_attribute_mapping_count : '';
        for ($i = 1; $i <= $customattributecount; $i++) {
            $idpattributename = "mo_login_idp_custom_attribute_".$i;
            $customattributename = "mo_login_custom_attribute_".$i;
            if (isset($this->config->custom_attribute_name) && isset($this->config->idp_attribute_name)) {
                $customattributemapping[$this->config->custom_attribute_name] = $this->config->idp_attribute_name;
            }
        }
        return $customattributemapping;
    }
    // Here we are assigning  role to user which is selected in role mapping.

    /**
     * Obtain Roles
     * @return string
     */
    public function obtain_roles() {
        global $SESSION;
        $roles = 'Manager';

        if (!empty($this->config->default_role_map) && isset($this->config->default_role_map)) {
            $roles = $this->config->default_role_map;
        }
        return $roles;
    }


    // Sync roles assigne the role for new user if role mapping done in default role.

    /**
     * Sync ROles
     * @param object $user User
     * @throws coding_exception
     * @throws dml_exception
     */
    public function sync_roles($user) {
        global $CFG, $DB, $SESSION;
        $defaultrole = get_config('auth_mo_login', 'default_role_map');
        $syscontext = context_system::instance();

        $rolesavailableobj = $DB->get_records_select('role',  false, null,  false, 'id,shortname');
        $pluginroleconfig = get_config('auth_mo_login', 'role');
        role_assign($defaultrole, $user->id, $syscontext);
        if (array_key_exists($pluginroleconfig, $SESSION->mo_login_attributes)) {
            $rolefromidps = $SESSION->mo_login_attributes[$pluginroleconfig][0];

            $checkrole = false;

            foreach ($rolesavailableobj as $roleobj) {
                $rolestobeassigned = get_config('auth_mo_login', $roleobj->shortname);
                if ($roleobj->shortname === $defaultrole) {
                    role_assign($roleobj->id, $user->id, $syscontext);
                }
                if ($rolestobeassigned) {
                    $rolestobeassigned = explode($rolestobeassigned, ';');
                    foreach ($rolestobeassigned as $roletoassigned) {

                        if ($rolefromidps === $roletoassigned) {
                            role_assign($roleobj->id, $user->id, $syscontext);
                        }
                    }
                }

            }
        }
    }
    // Returns true if this authentication plugin is internal.
    // Internal plugins use password hashes from Moodle user table for authentication.
    /**
     * Is Internal
     * @return bool
     */
    public function is_internal() {
        return false;
    }
    // Indicates if password hashes should be stored in local moodle database.
    // This function automatically returns the opposite boolean of what is_internal() returns.
    // Returning true means MD5 password hashes will be stored in the user table.
    // Returning false means flag 'not_cached' will be stored there instead.
    /**
     * Prevent Local passwords
     * @return bool
     */
    public function prevent_local_passwords() {
        return true;
    }
    // Returns true if this authentication plugin can change users' password.

    /**
     * Can CHange Password
     * @return bool
     */
    public function can_change_password() {
        return false;
    }
    // Returns true if this authentication plugin can edit the users' profile.

    /**
     * Can edit profile
     * @return bool
     */
    public function can_edit_profile() {
        return true;
    }
    // Hook for overriding behaviour of login page.

    /**
     * Login Page Hook
     * @throws moodle_exception
     */
    public function loginpage_hook() {
        global $CFG;
        $CFG->nolastloggedin = true;

        $getsamlsso = array_key_exists("saml_sso", $_GET) ? required_param('saml_sso', PARAM_RAW) : "";
        $postusername = array_key_exists("username", $_GET) ? required_param('username', PARAM_RAW) : "";
        $postpassword = array_key_exists("password", $_GET) ? required_param('password',  PARAM_RAW) : "";
        if (array_key_exists('enablebackdoor', $this->config) && $this->config->enablebackdoor === 'true') {
            if (!isset($getsamlsso) && ($postusername) && empty($postpassword)) {
                $initssourl = $CFG->wwwroot.'/auth/mo_login/index.php';
                redirect($initssourl);
            }
        } else {
            ?>
            <script>$(document).ready(function(){
              $('<a class = "btn btn-primary btn-block m-t-1" href="<?php echo $CFG->wwwroot.'/auth/mo_login/index.php';
                ?>">Login with <?php echo($this->config->identityname); ?> </a>').insertAfter('#loginbtn')
            });</script>
            <?php
        }
    }
    // Hook for overriding behaviour of logout page.

    /**
     * Logout Page Hook
     * @throws moodle_exception
     */
    public function logoutpage_hook() {
        global  $CFG;
        $logouturl = $CFG->wwwroot.'/login/index.php?saml_sso=false';
        require_logout();
        set_moodle_cookie('nobody');
        redirect($logouturl);
    }

    /**
     * Sanitize certificate
     * @param String $certificate String
     * @return mixed|string|string[]|null
     */
    public function sanitize_certificate($certificate ) {
        $certificate = preg_replace("/[\r\n]+/", '', $certificate);
        $certificate = str_replace( "-", '', $certificate );
        $certificate = str_replace( "BEGIN CERTIFICATE", '', $certificate );
        $certificate = str_replace( "END CERTIFICATE", '', $certificate );
        $certificate = str_replace( " ", '', $certificate );
        $certificate = chunk_split($certificate, 64, "\r\n");
        $certificate = "-----BEGIN CERTIFICATE-----\r\n" . $certificate . "-----END CERTIFICATE-----";
        return $certificate;
    }
    // Getting customer which is already created at host for login purpose.
    // The page show in test configuration page.
    /**
     * Test Setttings
     */
    public function test_settings() {
        global $CFG;?>

        <script>

            window.open("<?php echo $CFG->wwwroot."/auth/mo_login/index.php".'/?option=testConfig'; ?>",
        "TEST SAML IDP", "scrollbars=1 width=800, height=600");

    </script>
<?php
    }

    /**
     * Login Page IDP list
     * @param string $wantsurl List of URLS
     * @return array
     */
    public function loginpage_idp_list($wantsurl) {
        global $CFG;
        $idplist[] = [
            'url'  => $CFG->wwwroot.'/auth/mo_login/index.php',
            'icon' => new pix_icon('i/user', 'Login'),
            'name' => 'Login with miniOrange',
        ];
        return $idplist;
    }
}