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
 * Contains validation of saml element.
 *
 * @copyright   2017  miniOrange
 * @category    authentication
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     mo_login
 */
defined('MOODLE_INTERNAL') || die();
require_once('assertion.php');
/**
 * Class for SAML2 Response messages.
 *
 */
/**
 * Auth external functions
 *
 * @package    mo_login
 * @category   response
 * @copyright  2017 miniOrange
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class saml_response_class {
    /**
     * The assertions in this response.
     */
    private $assertions;

    /**
     * The destination URL in this response.
     */
    private $destination;

    private $certificates;
    private $signaturedata;

    /**
     * Constructor for SAML 2 response messages.
     *
     * @param DOMElement|null $xml The input message.
     */
    public function __construct(DOMElement $xml = null) {

        $this->assertions = array();
        $this->certificates = array();

        if ($xml === null) {
            return;
        }

        $sig = utilities::validate_element($xml);
        if ($sig !== false) {
            $this->certificates = $sig['Certificates'];
            $this->signaturedata = $sig;
        }

        // Set the destination from saml response.
        if ($xml->hasAttribute('Destination')) {
            $this->destination = $xml->getAttribute('Destination');
        }

        for ($node = $xml->firstChild; $node !== null; $node = $node->nextSibling) {
            if ($node->namespaceURI !== 'urn:oasis:names:tc:SAML:2.0:assertion') {
                continue;
            }

            if ($node->localName === 'Assertion' || $node->localName === 'EncryptedAssertion') {
                $this->assertions[] = new saml_assertion_class($node);
            }

        }
    }

    /**
     * Retrieve the assertions in this response.
     *
     * @return saml_assertion_class[]|SAML2_EncryptedAssertion[]
     */
    public function get_assertions() {
        return $this->assertions;
    }

    /**
     * Set the assertions that should be included in this response.
     *
     * @param saml_assertion_class[]|SAML2_EncryptedAssertion[] The assertions.
     */
    public function set_assertions(array $assertions) {
        $this->assertions = $assertions;
    }

    public function get_destination() {
        return $this->destination;
    }

    /**
     * Convert the response message to an XML element.
     *
     * @return DOMElement This response.
     */
    public function to_unsigned_xml() {
        $root = parent::to_unsigned_xml();
        // Var saml_assertion_class|SAML2_EncryptedAssertion $assertion.
        foreach ($this->assertions as $assertion) {
            $assertion->to_xml($root);
        }

        return $root;
    }

    public function get_certificates() {
        return $this->certificates;
    }

    public function get_signature_data() {
        return $this->signaturedata;
    }
}
