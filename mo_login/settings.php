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
 * Contains version related information.
 *
 * @copyright   2017  miniOrange
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     auth_mo_login
 */
// @codingStandardsIgnoreLine
require_once(__DIR__ . '/../../config.php');
if ($ADMIN->fulltree) {

    global $CFG;
    $settings->add(new admin_setting_heading('auth_mo_login/pluginname', '',
        ''));


    $html = '<table border="1"
            style="background-color:#FFFFFF; border:1px solid #CCCCCC; padding:0px 0px 0px 10px;
            margin:2px; border-collapse: collapse; width:98%">
                <tr>
                    <td style="width:40%; padding: 15px;"><b>SP-EntityID / Issuer</b></td>
                                            <td style="width:60%; padding: 15px;">' . $CFG->wwwroot . '</td>
                </tr>
                <tr>
                    <td style="width:40%; padding: 15px;"><b>ACS (AssertionConsumerService) URL</b></td>
                                                <td style="width:60%;  padding: 15px;">
                                                ' . $CFG->wwwroot . "/auth/mo_login/index.php" . '</td>
                </tr>
                <tr>
                    <td style="width:40%; padding: 15px;"><b>Audience URI</b></td>
                                            <td style="width:60%; padding: 15px;">
                                            ' . $CFG->wwwroot . '</td>
                </tr>
                <tr>
                    <td style="width:40%; padding: 15px;"><b>NameID format</b></td>
                                            <td style="width:60%; padding: 15px;">
                                            urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</td>
                </tr>
            </table>';
    $settings->add(new admin_setting_heading('auth_mo_login/serviceprovider', 'Service Provider Information', $html));

    $settings->add(new admin_setting_heading('auth_mo_login/spsetting',  'Configure Service Provider',  ''
    ));

    $settings->add(new admin_setting_configtext(
        'auth_mo_login/entity_id',
        get_string('entity_id', 'auth_mo_login'),
        get_string('entity_id_desc', 'auth_mo_login'),
        '',
        PARAM_TEXT));

    $settings->add(new admin_setting_configtext(
        'auth_mo_login/login_url',
        get_string('login_url', 'auth_mo_login'),
        get_string('login_url_desc', 'auth_mo_login'),
        '',
        PARAM_TEXT));

    $settings->add(new admin_setting_configtextarea(
        'auth_mo_login/x509certificate',
        get_string('x509certificate', 'auth_mo_login'),
        get_string('x509certificate_desc', 'auth_mo_login'),
        '',
        PARAM_RAW,
        80,
        5));

    $settings->add(new admin_setting_heading('auth_mo_login/attribute_mapping_heading',
        'Attribute Mapping', ''
        ));

    $settings->add(new admin_setting_configtext(
        'auth_mo_login/email',
        'Email',
        'SAML attribute for Email',
        'NameID',
        PARAM_TEXT));

    $settings->add(new admin_setting_configtext(
        'auth_mo_login/username',
        'User Name',
        'SAML attribute for User Name',
        'NameID',
        PARAM_TEXT));


    $settings->add(new admin_setting_configtext(
        'auth_mo_login/firstname',
        'First Name',
        'SAML attribute for First Name',
        '',
        PARAM_TEXT));

    $settings->add(new admin_setting_configtext(
        'auth_mo_login/lastname',
        'Surname',
        'SAML attribute for Surname',
        '',
        PARAM_TEXT));

    $settings->add(new admin_setting_configtext(
        'auth_mo_login/role',
        'Role',
        'SAML Attribute for Group/Role',
        '',
        PARAM_TEXT));

    $rolesavailableobj = $DB->get_records_select('role', false, null, false, 'id,shortname,description');
    $rolesavailable = array();
    foreach ($rolesavailableobj as $role) {
        $rolesavailable[$role->id] = $role->shortname;
    }

    $settings->add(new admin_setting_heading('auth_mo_login/role_mapping_heading',
        'Role Mapping', ''
    ));

    $settings->add(new admin_setting_configselect('auth_mo_login/default_role_map',
        'Default Role Mapping' , 'Role assigned if the user is not mapped'
        , 1, $rolesavailable));


    foreach ($rolesavailableobj as $role) {

        $settings->add(new admin_setting_configtext(
            'auth_mo_login/'.$role->shortname,
            $role->shortname,
            $role->description.' Enter semi-colon(;) separated roles',
            '',
            PARAM_TEXT));
    }
}
