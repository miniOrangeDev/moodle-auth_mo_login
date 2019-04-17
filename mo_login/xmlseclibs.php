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
 * xmlseclibs.php
 *
 * Copyright (c) 2007-2013, Robert Richards <rrichards@cdatazone.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Robert Richards nor the names of his
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @author     Robert Richards <rrichards@cdatazone.org>
 * @copyright  2007-2013 Robert Richards <rrichards@cdatazone.org>
 * @license    http://www.opensource.org/licenses/bsd-license.php  BSD License
 */
defined('MOODLE_INTERNAL') || die();
/**
 * Sort and Add Attributes
 * @package auth_mo_login
 * @param Node $element Element
 * @param array $aratts Attributes
 */
function sort_and_add_attrs($element, $aratts) {
    $newatts = array();
    foreach ($aratts as $attnode) {
        $newatts[$attnode->nodeName] = $attnode;
    }
    ksort($newatts);
    foreach ($newatts as $attnode) {
        $element->setAttribute($attnode->nodeName, $attnode->nodeValue);
    }
}
/**
 * Find Canonical
 * @param Node $tree Tree
 * @param Node $element Element
 * @package auth_mo_login
 * @param String $withcomments comments
 */
function canonical($tree, $element, $withcomments) {
    if ($tree->nodeType != XML_DOCUMENT_NODE) {
        $dom = $tree->ownerDocument;
    } else {
        $dom = $tree;
    }
    if ($element->nodeType != XML_ELEMENT_NODE) {
        if ($element->nodeType == XML_DOCUMENT_NODE) {
            foreach ($element->childNodes as $node) {
                canonical($dom, $node, $withcomments);
            }
            return;
        }
        if ($element->nodeType == XML_COMMENT_NODE && ! $withcomments) {
            return;
        }
        $tree->appendChild($dom->importNode($element, true));
        return;
    }
    $arnss = array();
    if ($element->namespaceURI != "") {
        if ($element->prefix == "") {
            $elecopy = $dom->createElementNS($element->namespaceURI, $element->nodeName);
        } else {
            $prefix = $tree->lookupPrefix($element->namespaceURI);
            if ($prefix == $element->prefix) {
                $elecopy = $dom->createElementNS($element->namespaceURI, $element->nodeName);
            } else {
                $elecopy = $dom->createElement($element->nodeName);
                $arnss[$element->namespaceURI] = $element->prefix;
            }
        }
    } else {
        $elecopy = $dom->createElement($element->nodeName);
    }
    $tree->appendChild($elecopy);

    $xxpath = new DOMXPath($element->ownerDocument);

    $aratts = $xxpath->query('attribute::*[namespace-uri(.) != ""]', $element);

    foreach ($aratts as $attnode) {
        if (array_key_exists($attnode->namespaceURI, $arnss) &&
            ($arnss[$attnode->namespaceURI] == $attnode->prefix)) {
            continue;
        }
        $prefix = $tree->lookupPrefix($attnode->namespaceURI);
        if ($prefix != $attnode->prefix) {
            $arnss[$attnode->namespaceURI] = $attnode->prefix;
        } else {
            $arnss[$attnode->namespaceURI] = null;
        }
    }
    if (count($arnss) > 0) {
        asort($arnss);
    }

    foreach ($arnss as $namespaceuri => $prefix) {
        if ($prefix != null) {
            $elecopy->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:".$prefix, $namespaceuri);
        }
    }
    if (count($arnss) > 0) {
        ksort($arnss);
    }

    $aratts = $xxpath->query('attribute::*[namespace-uri(.) = ""]', $element);
    sort_and_add_attrs($elecopy, $aratts);

    foreach ($arnss as $nssuri => $prefix) {
        $aratts = $xxpath->query('attribute::*[namespace-uri(.) = "'.$nssuri.'"]', $element);
        sort_and_add_attrs($elecopy, $aratts);
    }

    foreach ($element->childNodes as $node) {
        canonical($elecopy, $node, $withcomments);
    }
}
/**
 * Get Fortn general
 * @package auth_mo_login
 * @param String $element Element
 * @param bool $exclusive
 * @param bool $withcomments
 * @return string|null
 * @throws Exception
 */
function cfortnngeneral($element, $exclusive=false, $withcomments=false) {
    $phpversion = explode('.', PHP_VERSION);
    if (($phpversion[0] > 5) || ($phpversion[0] == 5 && $phpversion[1] >= 2) ) {
        return $element->C14N($exclusive, $withcomments);
    }

    if (! $element instanceof DOMElement && ! $element instanceof DOMDocument) {
        return null;
    }
    if ($exclusive == false) {
        throw new Exception("Only exclusive canonicalization is supported in this version of PHP");
    }

    $copyydoc = new DOMDocument();
    canonical($copyydoc, $element, $withcomments);
    return $copyydoc->saveXML($copyydoc->documentElement, LIBXML_NOEMPTYTAG);
}
/**
 * Auth external functions
 * @copyright  2017 miniOrange
 * @package auth_mo_login
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class xml_security_key {
    /**
     *
     */
    const TRIPLEDES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
    /**
     *
     */
    const AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
    /**
     *
     */
    const AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
    /**
     *
     */
    const AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
    /**
     *
     */
    const RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
    /**
     *
     */
    const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
    /**
     *
     */
    const DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
    /**
     *
     */
    const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    /**
     *
     */
    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    /**
     *
     */
    const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    /**
     *
     */
    const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    /**
     * @var array
     */
    private $crypttparams = array();
    /**
     * @var int
     */
    public $type = 0;
    /**
     * @var null
     */
    public $key = null;
    /**
     * @var string
     */
    public $passphrase = "";
    /**
     * @var null
     */
    public $iv = null;
    /**
     * @var null
     */
    public $name = null;
    /**
     * @var null
     */
    public $keychain = null;
    /**
     * @var bool
     */
    public $issencrypted = false;
    /**
     * @var null
     */
    public $encryptedctx = null;
    /**
     * @var null
     */
    public $guid = null;

    /**
     * @var null
     * This variable contains the certificate as a string if this key represents an X509-certificate.
     * If this key doesn't represent a certificate, this will be null.
     */
    private $xxcertificate = null;

    // This variable contains the certificate thunbprint if we have loaded an X509-certificate.
    /**
     * @var null
     */
    private $xxthumbprint = null;

    /**
     * xml_security_key constructor.
     * @param Type $type Type
     * @param null $params Params
     * @throws Exception
     */
    public function __construct($type, $params=null) {
        srand();
        switch ($type) {
            case (self::TRIPLEDES_CBC):
                $this->crypttparams['library'] = 'openssl';
                $this->crypttparams['cipher'] = 'des-ede3-cbc';
                $this->crypttparams['type'] = 'symmetric';
                $this->crypttparams['method'] = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
                $this->crypttparams['keysize'] = 24;
                $this->crypttparams['blocksize'] = 8;
                break;
            case (self::AES128_CBC):
                $this->crypttparams['library'] = 'openssl';
                $this->crypttparams['cipher'] = 'aes-128-cbc';
                $this->crypttparams['type'] = 'symmetric';
                $this->crypttparams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
                $this->crypttparams['keysize'] = 16;
                $this->crypttparams['blocksize'] = 16;
                break;
            case (self::AES192_CBC):
                $this->crypttparams['library'] = 'openssl';
                $this->crypttparams['cipher'] = 'aes-192-cbc';
                $this->crypttparams['type'] = 'symmetric';
                $this->crypttparams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
                $this->crypttparams['keysize'] = 24;
                $this->crypttparams['blocksize'] = 16;
                break;
            case (self::AES256_CBC):
                $this->crypttparams['library'] = 'openssl';
                $this->crypttparams['cipher'] = 'aes-256-cbc';
                $this->crypttparams['type'] = 'symmetric';
                $this->crypttparams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
                $this->crypttparams['keysize'] = 32;
                $this->crypttparams['blocksize'] = 16;
                break;
            case (self::RSA_1_5):
                $this->crypttparams['library'] = 'openssl';
                $this->crypttparams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->crypttparams['method'] = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->crypttparams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
                return;
            case (self::RSA_OAEP_MGF1P):
                $this->crypttparams['library'] = 'openssl';
                $this->crypttparams['padding'] = OPENSSL_PKCS1_OAEP_PADDING;
                $this->crypttparams['method'] = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
                $this->crypttparams['hash'] = null;
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->crypttparams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
                return;
            case (self::RSA_SHA1):
                $this->crypttparams['library'] = 'openssl';
                $this->crypttparams['method'] = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
                $this->crypttparams['padding'] = OPENSSL_PKCS1_PADDING;
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->crypttparams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
                break;
            case (self::RSA_SHA256):
                $this->crypttparams['library'] = 'openssl';
                $this->crypttparams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
                $this->crypttparams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->crypttparams['digest'] = 'SHA256';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->crypttparams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
                break;
            case (self::RSA_SHA384):
                $this->crypttparams['library'] = 'openssl';
                $this->crypttparams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
                $this->crypttparams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->crypttparams['digest'] = 'SHA384';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->crypttparams['type'] = $params['type'];
                        break;
                    }
                }
            case (self::RSA_SHA512):
                $this->crypttparams['library'] = 'openssl';
                $this->crypttparams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
                $this->crypttparams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->crypttparams['digest'] = 'SHA512';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->crypttparams['type'] = $params['type'];
                        break;
                    }
                }
            default:
                throw new Exception('Invalid Key Type');
                return;
        }
        $this->type = $type;
    }

    /**
     * Retrieve the key size for the symmetric encryption algorithm..
     *
     * If the key size is unknown, or this isn't a symmetric encryption algorithm,
     * null is returned.
     *
     * @return int|null  The number of bytes in the key.
     */
    public function get_symmetric_key_size() {
        if (! isset($this->crypttparams['keysize'])) {
            return null;
        }
        return $this->crypttparams['keysize'];
    }

    /**
     * Generates Session Key
     * @return string
     * @throws Exception
     */
    public function generate_session_key() {
        if (!isset($this->crypttparams['keysize'])) {
            throw new Exception('Unknown key size for type "' . $this->type . '".');
        }
        $keysize = $this->crypttparams['keysize'];
        $key = openssl_random_pseudo_bytes($keysize);
        if ($this->type === self::TRIPLEDES_CBC) {
            /* Make sure that the generated key has the proper parity bits set.
             * Mcrypt doesn't care about the parity bits, but others may care.
            */
            for ($i = 0; $i < strlen($key); $i++) {
                $byte = ord($key[$i]) & 0xfe;
                $parity = 1;
                for ($j = 1; $j < 8; $j++) {
                    $parity ^= ($byte >> $j) & 1;
                }
                $byte |= $parity;
                $key[$i] = chr($byte);
            }
        }

        $this->key = $key;
        return $key;
    }

    /**
     * Get Raw thubprint
     * @param String $cert Certificate
     * @return string|null
     */
    public static function get_raw_thumbprint($cert) {

        $arrcert = explode("\n", $cert);
        $data = '';
        $inndata = false;

        foreach ($arrcert as $currdata) {
            if (! $inndata) {
                if (strncmp($currdata, '-----BEGIN CERTIFICATE', 22) == 0) {
                    $inndata = true;
                }
            } else {
                if (strncmp($currdata, '-----END CERTIFICATE', 20) == 0) {
                    $inndata = false;
                    break;
                }
                $data .= trim($currdata);
            }
        }

        if (! empty($data)) {
            return strtolower(sha1(base64_decode($data)));
        }
        return null;
    }

    /**
     * Load Key
     * @param String $key Key
     * @param bool $issfile Is a FIle
     * @param bool $isscert Is a Certi
     */
    public function load_key($key, $issfile=false, $isscert = false) {
        if ($issfile) {
            $this->key = file_get_contents($key);
        } else {
            $this->key = $key;
        }

        if ($isscert) {
            $this->key = openssl_x509_read($this->key);
            openssl_x509_export($this->key, $strrcert);
            $this->xxcertificate = $strrcert;
            $this->key = $strrcert;
        } else {
            $this->xxcertificate = null;
        }
        if ($this->crypttparams['library'] == 'openssl') {
            if ($this->crypttparams['type'] == 'public') {
                if ($isscert) {
                    // Load the thumbprint if this is an X509 certificate.
                    $this->xxthumbprint = self::get_raw_thumbprint($this->key);
                }
                $this->key = openssl_get_publickey($this->key);
            } else {
                $this->key = openssl_get_privatekey($this->key, $this->passphrase);
            }
        }
    }


    /**
     * Encrypt Openssl
     * @param String $data Data
     * @throws Exception
     */
    private function encrypt_openssl($data) {
        if ($this->crypttparams['type'] == 'public') {
            if (! openssl_public_encrypt($data, $encryptedddata, $this->key, $this->crypttparams['padding'])) {
                throw new Exception('Failure encrypting Data');
                return;
            }
        } else {
            if (! openssl_private_encrypt($data, $encryptedddata, $this->key, $this->crypttparams['padding'])) {
                throw new Exception('Failure encrypting Data');
                return;
            }
        }
        return $encryptedddata;
    }

    /**
     * Decrypt openssl
     * @param String $data Data
     * @throws Exception
     */
    private function decrypt_openssl($data) {
        if ($this->crypttparams['type'] == 'public') {
            if (! openssl_public_decrypt($data, $decrypted, $this->key, $this->crypttparams['padding'])) {
                throw new Exception('Failure decrypting Data');
                return;
            }
        } else {
            if (! openssl_private_decrypt($data, $decrypted, $this->key, $this->crypttparams['padding'])) {
                throw new Exception('Failure decrypting Data');
                return;
            }
        }
        return $decrypted;
    }

    /**
     * Sign openssl
     * @param String $data data
     * @throws Exception
     */
    private function sign_openssl($data) {
        $algo = OPENSSL_ALGO_SHA1;
        if (! empty($this->crypttparams['digest'])) {
            $algo = $this->crypttparams['digest'];
        }
        if (! openssl_sign ($data, $signature, $this->key, $algo)) {
            throw new Exception('Failure Signing Data: ' . openssl_error_string() . ' - ' . $algo);
            return;
        }
        return $signature;
    }

    /**
     * Cerify openssl
     * @param String $data Data
     * @param String $signature Sgnature
     * @return int
     */
    private function verify_openssl($data, $signature) {
        $algo = OPENSSL_ALGO_SHA1;
        if (! empty($this->crypttparams['digest'])) {
            $algo = $this->crypttparams['digest'];
        }
        return openssl_verify ($data, $signature, $this->key, $algo);
    }

    /**
     * Encrypt data
     * @param String $data Data
     * @throws Exception
     */
    public function encrypt_data($data) {
        switch ($this->crypttparams['library']) {

            case 'openssl':
                return $this->encrypt_openssl($data);
                break;
        }
    }

    /**
     * Decrypt data
     * @param String $data Data
     * @throws Exception
     */
    public function decrypt_data($data) {
        switch ($this->crypttparams['library']) {

            case 'openssl':
                return $this->decrypt_openssl($data);
                break;
        }
    }

    /**
     * Sign data
     * @param String $data Data
     * @throws Exception
     */
    public function sign_data($data) {
        switch ($this->crypttparams['library']) {
            case 'openssl':
                return $this->sign_openssl($data);
                break;
        }
    }

    /**
     * Verify signature
     * @param String $data Data
     * @param String $signature Data
     * @return int
     */
    public function verify_signature($data, $signature) {
        switch ($this->crypttparams['library']) {
            case 'openssl':
                return $this->verify_openssl($data, $signature);
                break;
        }
    }

    /**
     * Get Algorithm
     * @return mixed
     */
    public function get_algorith() {
        return $this->crypttparams['method'];
    }

    /**
     * Make segment
     * @param String $type Type
     * @param String $string String
     * @return string|null
     */
    public static function make_asn_segment($type, $string) {
        switch ($type){
            case 0x02:
                if (ord($string) > 0x7f) {
                    $string = chr(0).$string;
                }
                break;
            case 0x03:
                $string = chr(0).$string;
                break;
        }

        $length = strlen($string);

        if ($length < 128) {
            $output = sprintf("%c%c%s", $type, $length, $string);
        } else if ($length < 0x0100) {
            $output = sprintf("%c%c%c%s", $type, 0x81, $length, $string);
        } else if ($length < 0x010000) {
            $output = sprintf("%c%c%c%c%s", $type, 0x82, $length / 0x0100, $length % 0x0100, $string);
        } else {
            $output = null;
        }
        return($output);
    }

    // Modulus and Exponent must already be base64 decoded.

    /**
     * Convert to RSA
     * @param String $modulus Mod
     * @param String $exponent Exp
     * @return string
     */
    public static function convert_rsa($modulus, $exponent) {
        // Make an ASN publickeyinfo.
        $exponentencoding = self::make_asn_segment(0x02, $exponent);
        $modulusencoding = self::make_asn_segment(0x02, $modulus);
        $sequenceencoding = self::make_asn_segment(0x30, $modulusencoding.$exponentencoding);
        $bitstringencoding = self::make_asn_segment(0x03, $sequenceencoding);
        $rsaalgorithmidentifier = pack("H*", "300D06092A864886F70D0101010500");
        $publickeyinfo = self::make_asn_segment (0x30, $rsaalgorithmidentifier.$bitstringencoding);

        // Encode the publickeyinfo in base64 and add PEM brackets.
        $publickeyinfobase64 = base64_encode($publickeyinfo);
        $encoding = "-----BEGIN PUBLIC KEY-----\n";
        $offset = 0;
        while ($segment = substr($publickeyinfobase64, $offset, 64)) {
            $encoding = $encoding.$segment."\n";
            $offset += 64;
        }
        return $encoding."-----END PUBLIC KEY-----\n";
    }

    /**
     * Serilize key
     * @param Parent $parent Parent
     */
    public function serialize_key($parent) {

    }



    /**
     * Get X509 Cert Retrieve the X509 certificate this key represents.
     *
     * Will return the X509 certificate in PEM-format if this key represents
     * an X509 certificate.
     *
     * @return  The X509 certificate or null if this key doesn't represent an X509-certificate.
     */
    public function get_xxcertificate() {
        return $this->xxcertificate;
    }

    /* Get the thumbprint of this X509 certificate.
     *
     * Returns:
     *  The thumbprint as a lowercase 40-character hexadecimal number, or null
     *  if this isn't a X509 certificate.
     */
    /**
     * Get Thumbprint
     * @return null
     */
    public function get_xxthumbprint() {
        return $this->xxthumbprint;
    }


    /**
     * Create key from an EncryptedKey-element.
     *
     * @param DOMElement $element  The EncryptedKey-element.
     * @return xml_security_key  The new key.
     */
    public static function from_encrypted_key_element(DOMElement $element) {

        $objenc = new xml_sec_enc();
        $objenc->set_node($element);
        if (! $objjkey = $objenc->locate_key()) {
            throw new Exception("Unable to locate algorithm for this Encrypted Key");
        }
        $objjkey->issencrypted = true;
        $objjkey->encryptedctx = $objenc;
        xml_sec_enc::static_locate_key_info($objjkey, $element);
        return $objjkey;
    }

}
/**
 * Auth external functions
 * @package auth_mo_login
 * @copyright  2017 miniOrange
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class xml_security_dsig {
    /**
     *
     */
    const XMLDSIGNS = 'http://www.w3.org/2000/09/xmldsig#';
    /**
     *
     */
    const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    /**
     *
     */
    const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    /**
     *
     */
    const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    /**
     *
     */
    const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
    /**
     *
     */
    const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

    /**
     *
     */
    const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    /**
     *
     */
    const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    /**
     *
     */
    const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    /**
     *
     */
    const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
    /**
     *
     */
    const TEMPLATE = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:SignatureMethod />
  </ds:SignedInfo>
</ds:Signature>';

    /**
     * @var DOMElement|null
     */
    public $signode = null;
    /**
     * @var array
     */
    public $idkeys = array();
    /**
     * @var array
     */
    public $idns = array();
    /**
     * @var null
     */
    private $signedinfo = null;
    /**
     * @var null
     */
    private $xpathctx = null;
    /**
     * @var null
     */
    private $canonicalmethod = null;
    /**
     * @var string
     */
    private $prefix = 'ds';
    /**
     * @var string
     */
    private $searchpfx = 'secdsig';

    // This variable contains an associative array of validated nodes.
    /**
     * @var null
     */
    private $validatednodes = null;

    /**
     * xml_security_dsig constructor.
     */
    public function __construct() {
        $sigdoc = new DOMDocument();
        $sigdoc->loadXML(self::TEMPLATE);
        $this->signode = $sigdoc->documentElement;
    }

    /**
     * Reset X-PAth
     */
    private function reset_x_path_obj() {
        $this->xpathctx = null;
    }

    /**
     * Get xpath
     * @return DOMXPath|null
     */
    private function get_x_path_obj() {
        if (empty($this->xpathctx) && ! empty($this->signode)) {
            $xpath = new DOMXPath($this->signode->ownerDocument);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
            $this->xpathctx = $xpath;
        }
        return $this->xpathctx;
    }

    /**
     * generate guide
     * @param string $prefix
     * @return string
     */
    public static function generate_guid($prefix = 'pfx') {
        $uuid = md5(uniqid(rand(), true));
        $guid = $prefix.substr($uuid, 0, 8)."-".
                substr($uuid, 8, 4)."-".
                substr($uuid, 12, 4)."-".
                substr($uuid, 16, 4)."-".
                substr($uuid, 20, 12);
        return $guid;
    }

    /**
     * locate signature
     * @param DOMDocument $objjdoc Doc
     * @return DOMElement|DOMNode|null
     */
    public function locate_signature($objjdoc) {
        if ($objjdoc instanceof DOMDocument) {
            $doc = $objjdoc;
        } else {
            $doc = $objjdoc->ownerDocument;
        }
        if ($doc) {
            $xpath = new DOMXPath($doc);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
            $query = ".//secdsig:Signature";
            $nodeset = $xpath->query($query, $objjdoc);
            $this->signode = $nodeset->item(0);
            return $this->signode;
        }
        return null;
    }

    /**
     * Create new sign node
     * @param String $name name
     * @param null $value Value
     * @return DOMElement
     */
    public function create_new_sign_node($name, $value=null) {
        $doc = $this->signode->ownerDocument;
        if (! is_null($value)) {
            $node = $doc->createElementNS(self::XMLDSIGNS, $this->prefix.':'.$name, $value);
        } else {
            $node = $doc->createElementNS(self::XMLDSIGNS, $this->prefix.':'.$name);
        }
        return $node;
    }

    /**
     * Set canonical method
     * @param String $method Encp Method
     * @throws Exception
     */
    public function set_canonical_method($method) {
        switch ($method) {
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
            case 'http://www.w3.org/2001/10/xml-exc-c14n#':
            case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':
                $this->canonicalmethod = $method;
                break;
            default:
                throw new Exception('Invalid Canonical Method');
        }
        if ($xpath = $this->get_x_path_obj()) {
            $query = './'.$this->searchpfx.':SignedInfo';
            $nodeset = $xpath->query($query, $this->signode);
            if ($sinfo = $nodeset->item(0)) {
                $query = './'.$this->searchpfx.'CanonicalizationMethod';
                $nodeset = $xpath->query($query, $sinfo);
                if (! ($canonnode = $nodeset->item(0))) {
                    $canonnode = $this->create_new_sign_node('CanonicalizationMethod');
                    $sinfo->insertBefore($canonnode, $sinfo->firstChild);
                }
                $canonnode->setAttribute('Algorithm', $this->canonicalmethod);
            }
        }
    }

    /**
     * Canacolize method
     * @param DomNode $node nide
     * @param String $canonicalmethod String
     * @param null $arxxpath ARxxpath
     * @param null $prefixlist prefixlist
     * @return string|null
     * @throws Exception
     */
    private function canonicalize_data($node, $canonicalmethod, $arxxpath=null, $prefixlist=null) {
        $exclusive = false;
        $withcomments = false;
        switch ($canonicalmethod) {
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
                $exclusive = false;
                $withcomments = false;
                break;
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
                $withcomments = true;
                break;
            case 'http://www.w3.org/2001/10/xml-exc-c14n#':
                $exclusive = true;
                break;
            case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':
                $exclusive = true;
                $withcomments = true;
                break;
        }
        // Support PHP versions < 5.2 not containing C14N methods in DOM extension.
        $phpversion = explode('.', PHP_VERSION);
        if (($phpversion[0] < 5) || ($phpversion[0] == 5 && $phpversion[1] < 2) ) {
            if (! is_null($arxxpath)) {
                throw new Exception("PHP 5.2.0 or higher is required to perform XPath Transformations");
            }
            return cfortnngeneral($node, $exclusive, $withcomments);
        }
        $element = $node;
        if ($node instanceof DOMNode && $node->ownerDocument !== null && $node->isSameNode($node->ownerDocument->documentElement)) {
            $element = $node->ownerDocument;
        }
        return $element->C14N($exclusive, $withcomments, $arxxpath, $prefixlist);
    }

    /**
     * Canocalize signed info
     * @return string|null
     * @throws Exception
     */
    public function canonicalize_signed_info() {

        $doc = $this->signode->ownerDocument;
        $canonicalmethod = null;
        if ($doc) {
            $xpath = $this->get_x_path_obj();
            $query = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->signode);
            if ($signinfonode = $nodeset->item(0)) {
                $query = "./secdsig:CanonicalizationMethod";
                $nodeset = $xpath->query($query, $signinfonode);
                if ($canonnode = $nodeset->item(0)) {
                    $canonicalmethod = $canonnode->getAttribute('Algorithm');
                }
                $this->signedinfo = $this->canonicalize_data($signinfonode, $canonicalmethod);
                return $this->signedinfo;
            }
        }
        return null;
    }

    /**
     * Cal digest
     * @param String $digestalgorithm Algo
     * @param String $data Data
     * @return string
     * @throws Exception
     */
    public function calculate_digest ($digestalgorithm, $data) {
        switch ($digestalgorithm) {
            case self::SHA1:
                $alg = 'sha1';
                break;
            case self::SHA256:
                $alg = 'sha256';
                break;
            case self::SHA384:
                $alg = 'sha384';
                break;
            case self::SHA512:
                $alg = 'sha512';
                break;
            case self::RIPEMD160:
                $alg = 'ripemd160';
                break;
            default:
                throw new Exception("Cannot validate digest: Unsupported Algorith <$digestalgorithm>");
        }
        if (function_exists('hash')) {
            return base64_encode(hash($alg, $data, true));
        } else if (function_exists('mhash')) {
            $alg = "MHASH_" . strtoupper($alg);
            return base64_encode(mhash(constant($alg), $data));
        } else if ($alg === 'sha1') {
            return base64_encode(sha1($data, true));
        } else {
            throw new Exception('xmlseclibs is unable to calculate a digest. Maybe you need the mhash library?');
        }
    }

    /**
     * Validate digest
     * @param Node $reffnode Node
     * @param String $data Data
     * @return bool
     * @throws Exception
     */
    public function validate_digest($reffnode, $data) {
        $xpath = new DOMXPath($reffnode->ownerDocument);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        $query = 'string(./secdsig:DigestMethod/@Algorithm)';
        $digestalgorithm = $xpath->evaluate($query, $reffnode);
        $diggvalue = $this->calculate_digest($digestalgorithm, $data);
        $query = 'string(./secdsig:DigestValue)';
        $digesttvalue = $xpath->evaluate($query, $reffnode);
        return ($diggvalue == $digesttvalue);
    }

    /**
     * Process reffnode
     * @param String $reffnode String
     * @param Objdata $objjdata Objdata
     * @param bool $includecommentnodes Comments
     * @return string|null
     * @throws Exception
     */
    public function process_transforms($reffnode, $objjdata, $includecommentnodes = true) {
        $data = $objjdata;
        $xpath = new DOMXPath($reffnode->ownerDocument);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        $query = './secdsig:Transforms/secdsig:Transform';
        $nodelist = $xpath->query($query, $reffnode);
        $canonicalmethod = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
        $arxxpath = null;
        $prefixlist = null;
        foreach ($nodelist as $transform) {
            $algorithm = $transform->getAttribute("Algorithm");
            switch ($algorithm) {
                case 'http://www.w3.org/2001/10/xml-exc-c14n#':
                case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':

                    if (!$includecommentnodes) {
                        /* We remove comment nodes by forcing it to use a canonicalization
                         * without comments.
                         */
                        $canonicalmethod = 'http://www.w3.org/2001/10/xml-exc-c14n#';
                    } else {
                        $canonicalmethod = $algorithm;
                    }

                    $node = $transform->firstChild;
                    while ($node) {
                        if ($node->localName == 'InclusiveNamespaces') {
                            if ($pfx = $node->getAttribute('PrefixList')) {
                                $arpfx = array();
                                $pfxlist = explode(" ", $pfx);
                                foreach ($pfxlist as $pfx) {
                                    $val = trim($pfx);
                                    if (! empty($val)) {
                                        $arpfx[] = $val;
                                    }
                                }
                                if (count($arpfx) > 0) {
                                    $prefixlist = $arpfx;
                                }
                            }
                            break;
                        }
                        $node = $node->nextSibling;
                    }
            break;
                case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
                case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
                    if (!$includecommentnodes) {
                        /* We remove comment nodes by forcing it to use a canonicalization
                         * without comments.
                         */
                        $canonicalmethod = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
                    } else {
                        $canonicalmethod = $algorithm;
                    }

                    break;
                case 'http://www.w3.org/TR/1999/REC-xpath-19991116':
                    $node = $transform->firstChild;
                    while ($node) {
                        if ($node->localName == 'XPath') {
                            $arxxpath = array();
                            $arxxpath['query'] = '(.//. | .//@* | .//namespace::*)['.$node->nodeValue.']';
                            $arrxpath['namespaces'] = array();
                            // Variable confussion.
                            $nslist = $xpath->query('./namespace::*', $node);
                            foreach ($nslist as $nsnode) {
                                if ($nsnode->localName != "xml") {
                                    $arxxpath['namespaces'][$nsnode->localName] = $nsnode->nodeValue;
                                }
                            }
                            break;
                        }
                        $node = $node->nextSibling;
                    }
                    break;
            }
        }
        if ($data instanceof DOMNode) {
            $data = $this->canonicalize_data($objjdata, $canonicalmethod, $arxxpath, $prefixlist);
        }
        return $data;
    }

    /**
     * Process reffnode
     * @param String $reffnode Node
     * @return bool
     * @throws Exception
     */
    public function process_ref_node($reffnode) {
        $dataaobject = null;

        /*
         * Depending on the URI, we may not want to include comments in the result
         * See: http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel
         */
        $includecommentnodes = true;

        if ($uri = $reffnode->getAttribute("URI")) {
            $arrurl = parse_url($uri);
            if (empty($arrurl['path'])) {
                if ($identifier = $arrurl['fragment']) {

                    /* This reference identifies a node with the given id by using
                     * a URI on the form "#identifier". This should not include comments.
                     */
                    $includecommentnodes = false;

                    $xxpath = new DOMXPath($reffnode->ownerDocument);
                    if ($this->idns && is_array($this->idns)) {
                        foreach ($this->idns as $nspf => $ns) {
                            $xxpath->registerNamespace($nspf, $ns);
                        }
                    }
                    $idlist = '@Id="'.$identifier.'"';
                    if (is_array($this->idkeys)) {
                        foreach ($this->idkeys as $idkey) {
                            $idlist .= " or @$idkey='$identifier'";
                        }
                    }
                    $query = '//*['.$idlist.']';
                    $dataaobject = $xxpath->query($query)->item(0);
                } else {
                    $dataaobject = $reffnode->ownerDocument;
                }
            } else {
                $dataaobject = file_get_contents($arrurl);
            }
        } else {
            /* This reference identifies the root node with an empty URI. This should
             * not include comments.
             */
            $includecommentnodes = false;

            $dataaobject = $reffnode->ownerDocument;
        }
        $data = $this->process_transforms($reffnode, $dataaobject, $includecommentnodes);
        if (!$this->validate_digest($reffnode, $data)) {
            return false;
        }

        if ($dataaobject instanceof DOMNode) {
            // Add this node to the list of validated nodes.
            if (! empty($identifier)) {
                $this->validatednodes[$identifier] = $dataaobject;
            } else {
                $this->validatednodes[] = $dataaobject;
            }
        }

        return true;
    }

    /**
     * Get Ref node id
     * @param null $reffnode ReferenceNode
     * @return mixed|null
     */
    public function get_ref_node_id($reffnode) {
        if ($uri = $reffnode->getAttribute("URI")) {
            $arrurl = parse_url($uri);
            if (empty($arrurl['path'])) {
                if ($identifier = $arrurl['fragment']) {
                    return $identifier;
                }
            }
        }
        return null;
    }

    /**
     * Get ID
     * @return array
     * @throws Exception
     */
    public function get_ref_ids() {
        $refids = array();
        $doc = $this->signode->ownerDocument;

        $xpath = $this->get_x_path_obj();
        $query = "./secdsig:SignedInfo/secdsig:Reference";
        $nodeset = $xpath->query($query, $this->signode);
        if ($nodeset->length == 0) {
            throw new Exception("Reference nodes not found");
        }
        foreach ($nodeset as $reffnode) {
            $refids[] = $this->get_ref_node_id($reffnode);
        }
        return $refids;
    }

    /**
     * Validate reference
     * @return bool
     * @throws Exception
     */
    public function validate_reference() {
        $doc = $this->signode->ownerDocument;
        if (! $doc->isSameNode($this->signode)) {
            $this->signode->parentNode->removeChild($this->signode);
        }
        $xpath = $this->get_x_path_obj();
        $query = "./secdsig:SignedInfo/secdsig:Reference";
        $nodeset = $xpath->query($query, $this->signode);
        if ($nodeset->length == 0) {
            throw new Exception("Reference nodes not found");
        }

        // Initialize/reset the list of validated nodes.
        $this->validatednodes = array();

        foreach ($nodeset as $reffnode) {
            if (! $this->process_ref_node($reffnode)) {
                // Clear the list of validated nodes.
                $this->validatednodes = null;
                throw new Exception("Reference validation failed");
            }
        }
        return true;
    }

    /**
     * Add external ref
     * @param Node $sinfonode Signnode
     * @param Node $node Node
     * @param String $algorithm StringAlgo
     * @param null $arrtransforms Transforms
     * @param null $options Options
     * @throws Exception
     */
    private function add_ref_internal($sinfonode, $node, $algorithm, $arrtransforms=null, $options=null) {
        $prefix = null;
        $prefixxns = null;
        $iddname = 'Id';
        $overwriteeid  = true;
        $forceeuri = false;

        if (is_array($options)) {
            $prefix = empty($options['prefix']) ? null : $options['prefix'];
            $prefixxns = empty($options['prefixxns']) ? null : $options['prefixxns'];
            $iddname = empty($options['iddname']) ? 'Id' : $options['iddname'];
            $overwriteeid = !isset($options['overwrite']) ? true : (bool)$options['overwrite'];
            $forceeuri = !isset($options['forceeuri']) ? false : (bool)$options['forceeuri'];
        }

        $attname = $iddname;
        if (! empty($prefix)) {
            $attname = $prefix.':'.$attname;
        }

        $reffnode = $this->create_new_sign_node('Reference');
        $sinfonode->appendChild($reffnode);

        if (! $node instanceof DOMDocument) {
            $uri = null;
            if (! $overwriteeid) {
                $uri = $node->getAttributeNS($prefixxns, $iddname);
            }
            if (empty($uri)) {
                $uri = self::generate_guid();
                $node->setAttributeNS($prefixxns, $attname, $uri);
            }
            $reffnode->setAttribute("URI", '#'.$uri);
        } else if ($forceeuri) {
            $reffnode->setAttribute("URI", '');
        }

        $transnodes = $this->create_new_sign_node('Transforms');
        $reffnode->appendChild($transnodes);

        if (is_array($arrtransforms)) {
            foreach ($arrtransforms as $transform) {
                $transnode = $this->create_new_sign_node('Transform');
                $transnodes->appendChild($transnode);
                if (is_array($transform) &&
                    (! empty($transform['http://www.w3.org/TR/1999/REC-xpath-19991116'])) &&
                    (! empty($transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['query']))) {
                    $transnode->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
                    $xpathnode = $this->create_new_sign_node('XPath',
                                        $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['query']);
                    $transnode->appendChild($xpathnode);
                    if (! empty($transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['namespaces'])) {
                        $ulcs = $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['namespaces'];
                        foreach ($ulcs as $prefix => $namespace) {
                            $xpathnode->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:$prefix", $namespace);
                        }
                    }
                } else {
                    $transnode->setAttribute('Algorithm', $transform);
                }
            }
        } else if (! empty($this->canonicalmethod)) {
            $transnode = $this->create_new_sign_node('Transform');
            $transnodes->appendChild($transnode);
            $transnode->setAttribute('Algorithm', $this->canonicalmethod);
        }

        $canonicaldata = $this->process_transforms($reffnode, $node);
        $diggvalue = $this->calculate_digest($algorithm, $canonicaldata);

        $digestmethod = $this->create_new_sign_node('DigestMethod');
        $reffnode->appendChild($digestmethod);
        $digestmethod->setAttribute('Algorithm', $algorithm);

        $digesttvalue = $this->create_new_sign_node('DigestValue', $diggvalue);
        $reffnode->appendChild($digesttvalue);
    }

    /**
     * Add Refernce
     * @param Node $node Node
     * @param String $algorithm Algorithm
     * @param null $arrtransforms Transforms
     * @param null $options Options
     * @throws Exception
     */
    public function add_reference($node, $algorithm, $arrtransforms=null, $options=null) {
        if ($xpath = $this->get_x_path_obj()) {
            $query = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->signode);
            if ($sinfo = $nodeset->item(0)) {
                $this->add_ref_internal($sinfo, $node, $algorithm, $arrtransforms, $options);
            }
        }
    }

    /**
     * Add refernce list
     * @param Arnodes $arnodes Nodes
     * @param Algorithm $algorithm Algo
     * @param null $arrtransforms Transform
     * @param null $options Options
     * @throws Exception
     */
    public function add_reference_list($arnodes, $algorithm, $arrtransforms=null, $options=null) {
        if ($xpath = $this->get_x_path_obj()) {
            $query = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->signode);
            if ($sinfo = $nodeset->item(0)) {
                foreach ($arnodes as $node) {
                    $this->add_ref_internal($sinfo, $node, $algorithm, $arrtransforms, $options);
                }
            }
        }
    }

    /**
     * Add objects
     * @param String $data String
     * @param null $mimetype MimType
     * @param null $encoding Encoding
     * @return DOMElement
     */
    public function add_object($data, $mimetype=null, $encoding=null) {
        $objnode = $this->create_new_sign_node('Object');
        $this->signode->appendChild($objnode);
        if (! empty($mimetype)) {
            $objnode->setAtribute('MimeType', $mimetype);
        }
        if (! empty($encoding)) {
            $objnode->setAttribute('Encoding', $encoding);
        }

        if ($data instanceof DOMElement) {
            $newdata = $this->signode->ownerDocument->importNode($data, true);
        } else {
            $newdata = $this->signode->ownerDocument->createTextNode($data);
        }
        $objnode->appendChild($newdata);

        return $objnode;
    }

    /**
     * Add locate key
     * @param null $node Node
     * @return xml_security_key|null
     */
    public function locate_key($node=null) {
        if (empty($node)) {
            $node = $this->signode;
        }
        if (! $node instanceof DOMNode) {
            return null;
        }
        if ($doc = $node->ownerDocument) {
            $xpath = new DOMXPath($doc);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
            $query = "string(./secdsig:SignedInfo/secdsig:SignatureMethod/@Algorithm)";
            $algorithm = $xpath->evaluate($query, $node);
            if ($algorithm) {
                try {
                    $objjkey = new xml_security_key($algorithm, array('type' => 'public'));
                } catch (Exception $e) {
                    return null;
                }
                return $objjkey;
            }
        }
        return null;
    }

    /**
     * Verify
     * @param Key $objjkey Objkey
     * @return mixed
     * @throws Exception
     */
    public function verify($objjkey) {
        $doc = $this->signode->ownerDocument;
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        $query = "string(./secdsig:SignatureValue)";
        $sigvalue = $xpath->evaluate($query, $this->signode);
        if (empty($sigvalue)) {
            throw new Exception("Unable to locate SignatureValue");
        }
        return $objjkey->verify_signature($this->signedinfo, base64_decode($sigvalue));
    }

    /**
     * Sign data
     * @param Key $objjkey ObjKey
     * @param String $data String
     * @return mixed
     */
    public function sign_data($objjkey, $data) {
        return $objjkey->sign_data($data);
    }

    /**
     * Sign objkey
     * @param Objkey $objjkey ObjKey
     * @param null $appendtonode AppendNode
     * @throws Exception
     */
    public function sign($objjkey, $appendtonode = null) {
        // If we have a parent node append it now so C14N properly works.
        if ($appendtonode != null) {
            $this->reset_x_path_obj();
            $this->append_signature($appendtonode);
            $this->signode = $appendtonode->lastChild;
        }
        if ($xpath = $this->get_x_path_obj()) {
            $query = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->signode);
            if ($sinfo = $nodeset->item(0)) {
                $query = "./secdsig:SignatureMethod";
                $nodeset = $xpath->query($query, $sinfo);
                $smethod = $nodeset->item(0);
                $smethod->setAttribute('Algorithm', $objjkey->type);
                $data = $this->canonicalize_data($sinfo, $this->canonicalmethod);
                $sigvalue = base64_encode($this->sign_data($objjkey, $data));
                $sigvaluenode = $this->create_new_sign_node('SignatureValue', $sigvalue);
                if ($infosibling = $sinfo->nextSibling) {
                    $infosibling->parentNode->insertBefore($sigvaluenode, $infosibling);
                } else {
                    $this->signode->appendChild($sigvaluenode);
                }
            }
        }
    }

    /**
     * Appenc cert
     *
     */
    public function append_cert() {

    }

    /**
     * Append objkey
     * @param Key $objjkey Objkey
     * @param null $parent Parent
     */
    public function append_key($objjkey, $parent=null) {
        $objjkey->serialize_key($parent);
    }


    /**
     * This function inserts the signature element.
     *
     * The signature element will be appended to the element, unless $beforenode is specified. If $beforenode
     * is specified, the signature element will be inserted as the last element before $beforenode.
     *
     * @param DomNode $node  The node the signature element should be inserted into.
     * @param DOMNode $beforenode  The node the signature element should be located before.
     *
     * @return DOMNode The signature element node
     */
    public function insert_signature($node, $beforenode = null) {

        $document = $node->ownerDocument;
        $signatureelement = $document->importNode($this->signode, true);

        if ($beforenode == null) {
            return $node->insertBefore($signatureelement);
        } else {
            return $node->insertBefore($signatureelement, $beforenode);
        }
    }

    /**
     * Append signature
     * @param DOMNode $parentnode Node
     * @param bool $insertbefore Node
     * @return DOMNode
     */
    public function append_signature($parentnode, $insertbefore = false) {
        $beforenode = $insertbefore ? $parentnode->firstChild : null;
        return $this->insert_signature($parentnode, $beforenode);
    }

    /**
     * Get x509 cert
     * @param String $cert Certificate
     * @param bool $ispemformat Pemcert
     * @return mixed|string
     */
    public static function get_509x_cert($cert, $ispemformat=true) {
        $certs = self::static_get_x509_xcerts($cert, $ispemformat);
        if (! empty($certs)) {
            return $certs[0];
        }
        return '';
    }

    /**
     * Static get x509 cert
     * @param String $certs Certificate
     * @param bool $ispemformat Is Correct
     * @return array
     */
    public static function static_get_x509_xcerts($certs, $ispemformat=true) {
        if ($ispemformat) {
            $data = '';
            $certlist = array();
            $arrcert = explode("\n", $certs);
            $inndata = false;
            foreach ($arrcert as $currdata) {
                if (! $inndata) {
                    if (strncmp($currdata, '-----BEGIN CERTIFICATE', 22) == 0) {
                        $inndata = true;
                    }
                } else {
                    if (strncmp($currdata, '-----END CERTIFICATE', 20) == 0) {
                        $inndata = false;
                        $certlist[] = $data;
                        $data = '';
                        continue;
                    }
                    $data .= trim($currdata);
                }
            }
            return $certlist;
        } else {
            return array($certs);
        }
    }

    /**
     * Add certificate
     * @param String $parentref Parent Ref
     * @param Certificate $cert Cert
     * @param bool $ispemformat IsPemFormat
     * @param bool $isurl Is URL
     * @param null $xpath XPATH
     * @param null $options Options
     * @throws Exception
     */
    public static function static_add509_cert($parentref, $cert, $ispemformat=true, $isurl=false, $xpath=null, $options=null) {
        if ($isurl) {
            $cert = file_get_contents($cert);
        }
        if (! $parentref instanceof DOMElement) {
            throw new Exception('Invalid parent Node parameter');
        }
        $basedoc = $parentref->ownerDocument;

        if (empty($xpath)) {
            $xpath = new DOMXPath($parentref->ownerDocument);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        }

        $query = "./secdsig:KeyInfo";
        $nodeset = $xpath->query($query, $parentref);
        $keyinfo = $nodeset->item(0);
        if (! $keyinfo) {
            $inserted = false;
            $keyinfo = $basedoc->createElementNS(self::XMLDSIGNS, 'ds:KeyInfo');

            $query = "./secdsig:Object";
            $nodeset = $xpath->query($query, $parentref);
            if ($sobject = $nodeset->item(0)) {
                $sobject->parentNode->insertBefore($keyinfo, $sobject);
                $inserted = true;
            }

            if (! $inserted) {
                $parentref->appendChild($keyinfo);
            }
        }

        // Add all certs if there are more than one.
        $certs = self::static_get_x509_xcerts($cert, $ispemformat);

        // Attach X509 data node.
        $x509datanode = $basedoc->createElementNS(self::XMLDSIGNS, 'ds:X509Data');
        $keyinfo->appendChild($x509datanode);

        $issuerserial = false;
        $subjectname = false;
        if (is_array($options)) {
            if (! empty($options['issuerserial'])) {
                $issuerserial = true;
            }
        }

        // Attach all certificate nodes and any additional data.
        foreach ($certs as $x509cert) {
            if ($issuerserial) {
                if ($certdata = openssl_x509_parse("-----BEGIN CERTIFICATE-----\n"
                                .chunk_split($x509cert, 64, "\n")."-----END CERTIFICATE-----\n")) {
                    if ($issuerserial && ! empty($certdata['issuer']) && ! empty($certdata['serialNumber'])) {
                        if (is_array($certdata['issuer'])) {
                            $parts = array();
                            foreach ($certdata['issuer'] as $key => $value) {
                                array_unshift($parts, "$key=$value" . $issuer);
                            }
                            $issuername = implode(',', $parts);
                        } else {
                            $issuername = $certdata['issuer'];
                        }

                        $x509issuernode = $basedoc->createElementNS(self::XMLDSIGNS, 'ds:X509IssuerSerial');
                        $x509datanode->appendChild($x509issuernode);

                        $x509node = $basedoc->createElementNS(self::XMLDSIGNS, 'ds:X509IssuerName', $issuername);
                        $x509issuernode->appendChild($x509node);
                        $x509node = $basedoc->createElementNS(self::XMLDSIGNS, 'ds:X509SerialNumber', $certdata['serialNumber']);
                        $x509issuernode->appendChild($x509node);
                    }
                }

            }
            $x509certnode = $basedoc->createElementNS(self::XMLDSIGNS, 'ds:X509Certificate', $x509cert);
            $x509datanode->appendChild($x509certnode);
        }
    }

    /**
     * Add x509 certificate
     * @param String $cert Certificate
     * @param bool $ispemformat IsPemcert
     * @param bool $isurl IsURL
     * @param null $options Options
     * @throws Exception
     */
    public function add_x509_cert($cert, $ispemformat=true, $isurl=false, $options=null) {
        if ($xpath = $this->get_x_path_obj()) {
            self::static_add509_cert($this->signode, $cert, $ispemformat, $isurl, $xpath, $options);
        }
    }


    /**
     * This function retrieves an associative array of the validated nodes.
     * @return null
     */
    public function get_validated_nodes() {
        return $this->validatednodes;
    }
}
/**
 * Auth external functions
 * @package auth_mo_login
 * @copyright  2017 miniOrange
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class xml_sec_enc {
    /**
     *
     */
    const TEMPLATE = "<xenc:EncryptedData xmlns:xenc='http://www.w3.org/2001/04/xmlenc#'>
   <xenc:CipherData>
      <xenc:CipherValue></xenc:CipherValue>
   </xenc:CipherData>
</xenc:EncryptedData>";

    /**
     *
     */
    const ELEMENT = 'http://www.w3.org/2001/04/xmlenc#Element';
    /**
     *
     */
    const CONTENT = 'http://www.w3.org/2001/04/xmlenc#Content';
    /**
     *
     */
    const URI = 3;
    /**
     *
     */
    const XMLENCNS = 'http://www.w3.org/2001/04/xmlenc#';

    /**
     * @var null
     */
    private $encdoc = null;
    /**
     * @var null
     */
    private $rawnode = null;
    /**
     * @var null
     */
    public $type = null;
    /**
     * @var null
     */
    public $enckey = null;
    /**
     * @var array
     */
    private $references = array();

    /**
     * xml_sec_enc constructor.
     */
    public function __construct() {
        $this->_reset_template();
    }

    /**
     * Rest template
     *
     */
    private function _reset_template() {
        $this->encdoc = new DOMDocument();
        $this->encdoc->loadXML(self::TEMPLATE);
    }

    /**
     * Add reference
     * @param String $name Name
     * @param DOMNode $node Node
     * @param Type $type Type
     * @throws Exception
     */
    public function add_reference($name, $node, $type) {
        if (! $node instanceOf DOMNode) {
            throw new Exception('$node is not of type DOMNode');
        }
        $curencdoc = $this->encdoc;
        $this->_reset_template();
        $encdoc = $this->encdoc;
        $this->encdoc = $curencdoc;
        $refuri = xml_security_dsig::generate_guid();
        $element = $encdoc->documentElement;
        $element->setAttribute("Id", $refuri);
        $this->references[$name] = array("node" => $node, "type" => $type, "encnode" => $encdoc, "refuri" => $refuri);
    }

    /**
     * Set Node
     * @param DOMNode $node Node
     */
    public function set_node($node) {
        $this->rawnode = $node;
    }

    /**
     * Encrypt the selected node with the given key.
     *
     * @param xml_security_key $objjkey  The encryption key and algorithm.
     * @param bool $replace  Whether the encrypted node should be replaced in the original tree. Default is true.
     * @return DOMElement  The <xenc:EncryptedData>-element.
     */
    public function encrypt_node($objjkey, $replace=true) {
        $data = '';
        if (empty($this->rawnode)) {
            throw new Exception('Node to encrypt has not been set');
        }
        if (! $objjkey instanceof xml_security_key) {
            throw new Exception('Invalid Key');
        }
        $doc = $this->rawnode->ownerDocument;
        $xxpath = new DOMXPath($this->encdoc);
        $objlist = $xxpath->query('/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue');
        $ciphervalue = $objlist->item(0);
        if ($ciphervalue == null) {
            throw new Exception('Error locating CipherValue element within TEMPLATE');
        }
        switch ($this->type) {
            case (self::ELEMENT ):
                $data = $doc->saveXML($this->rawnode);
                $this->encdoc->documentElement->setAttribute('Type', self::ELEMENT );
                break;
            case (self::CONTENT):
                $children = $this->rawnode->childNodes;
                foreach ($children as $child) {
                    $data .= $doc->saveXML($child);
                }
                $this->encdoc->documentElement->setAttribute('Type', self::CONTENT);
                break;
            default:
                throw new Exception('Type is currently not supported');
                return;
        }

        $encmethod = $this->encdoc->documentElement->appendChild(
        $this->encdoc->createElementNS(self::XMLENCNS, 'xenc:EncryptionMethod'));
        $encmethod->setAttribute('Algorithm', $objjkey->get_algorith());
        $ciphervalue->parentNode->parentNode->insertBefore($encmethod, $ciphervalue->parentNode->parentNode->firstChild);

        $strencrypt = base64_encode($objjkey->encrypt_data($data));
        $value = $this->encdoc->createTextNode($strencrypt);
        $ciphervalue->appendChild($value);

        if ($replace) {
            switch ($this->type) {
                case (self::ELEMENT ):
                    if ($this->rawnode->nodeType == XML_DOCUMENT_NODE) {
                        return $this->encdoc;
                    }
                    $importenc = $this->rawnode->ownerDocument->importNode($this->encdoc->documentElement, true);
                    $this->rawnode->parentNode->replaceChild($importenc, $this->rawnode);
                    return $importenc;
                    break;
                case (self::CONTENT):
                    $importenc = $this->rawnode->ownerDocument->importNode($this->encdoc->documentElement, true);
                    while ($this->rawnode->firstChild) {
                        $this->rawnode->removeChild($this->rawnode->firstChild);
                    }
                    $this->rawnode->appendChild($importenc);
                    return $importenc;
                    break;
            }
        } else {
            return $this->encdoc->documentElement;
        }
    }

    /**
     * Encryot node
     * @param Key $objjkey ObjKey
     * @throws Exception
     */
    public function encrypt_references($objjkey) {
        $currawnode = $this->rawnode;
        $curtype = $this->type;
        foreach ($this->references as $name => $reference) {
            $this->encdoc = $reference["encnode"];
            $this->rawnode = $reference["node"];
            $this->type = $reference["type"];
            try {
                $encnode = $this->encrypt_node($objjkey);
                $this->references[$name]["encnode"] = $encnode;
            } catch (Exception $e) {
                $this->rawnode = $currawnode;
                $this->type = $curtype;
                throw $e;
            }
        }
        $this->rawnode = $currawnode;
        $this->type = $curtype;
    }

    /**
     * Retrieve the CipherValue text from this encrypted node.
     *
     * @return string|null  The Ciphervalue text, or null if no CipherValue is found.
     */
    public function get_cipher_value() {
        if (empty($this->rawnode)) {
            throw new Exception('Node to decrypt has not been set');
        }

        $doc = $this->rawnode->ownerDocument;
        $xxpath = new DOMXPath($doc);
        $xxpath->registerNamespace('xmlencr', self::XMLENCNS);
        // Only handles embedded content right now and not a reference.
        $query = "./xmlencr:CipherData/xmlencr:CipherValue";
        $nodeset = $xxpath->query($query, $this->rawnode);
        $node = $nodeset->item(0);

        if (!$node) {
            return null;
        }

        return base64_decode($node->nodeValue);
    }

    /**
     * Decrypt this encrypted node.
     *
     * The behaviour of this function depends on the value of $replace.
     * If $replace is false, we will return the decrypted data as a string.
     * If $replace is true, we will insert the decrypted element(s) into the
     * document, and return the decrypted element(s).
     *
     * @param xml_security_key $objjkey  The decryption key that should be used when decrypting the node.
     * @param boolean $replace  Whether we should replace the encrypted node in the XML document with the decrypted data.
     * @return string|DOMElement  The decrypted data.
     */
    public function decrypt_node($objjkey, $replace=true) {
        if (! $objjkey instanceof xml_security_key) {
            throw new Exception('Invalid Key');
        }

        $encrypteddata = $this->get_cipher_value();
        if ($encrypteddata) {
            $decrypted = $objjkey->decrypt_data($encrypteddata);
            if ($replace) {
                switch ($this->type) {
                    case (self::ELEMENT):
                        $newdoc = new DOMDocument();
                        $newdoc->loadXML($decrypted);
                        if ($this->rawnode->nodeType == XML_DOCUMENT_NODE) {
                            return $newdoc;
                        }
                        $importenc = $this->rawnode->ownerDocument->importNode($newdoc->documentElement, true);
                        $this->rawnode->parentNode->replaceChild($importenc, $this->rawnode);
                        return $importenc;
                        break;
                    case (self::CONTENT):
                        if ($this->rawnode->nodeType == XML_DOCUMENT_NODE) {
                            $doc = $this->rawnode;
                        } else {
                            $doc = $this->rawnode->ownerDocument;
                        }
                        $newfrag = $doc->createDocumentFragment();
                        $newfrag->appendXML($decrypted);
                        $parent = $this->rawnode->parentNode;
                        $parent->replaceChild($newfrag, $this->rawnode);
                        return $parent;
                        break;
                    default:
                        return $decrypted;
                }
            } else {
                return $decrypted;
            }
        } else {
            throw new Exception("Cannot locate encrypted data");
        }
    }

    /**
     * Encryot key
     * @param String $srckey Key
     * @param String $rawkey Key
     * @param bool $append Append
     * @throws Exception
     */
    public function encrypt_key($srckey, $rawkey, $append=true) {
        if ((! $srckey instanceof xml_security_key) || (! $rawkey instanceof xml_security_key)) {
            throw new Exception('Invalid Key');
        }
        $strenckey = base64_encode($srckey->encrypt_data($rawkey->key));
        $root = $this->encdoc->documentElement;
        $enckey = $this->encdoc->createElementNS(self::XMLENCNS, 'xenc:EncryptedKey');
        if ($append) {
            $keyinfo = $root->insertBefore(
            $this->encdoc->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'dsig:KeyInfo'), $root->firstChild);
            $keyinfo->appendChild($enckey);
        } else {
            $this->enckey = $enckey;
        }
        $encmethod = $enckey->appendChild($this->encdoc->createElementNS(self::XMLENCNS, 'xenc:EncryptionMethod'));
        $encmethod->setAttribute('Algorithm', $srckey->get_algorith());
        if (! empty($srckey->name)) {
            $keyinfo = $enckey->appendChild($this->encdoc->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'dsig:KeyInfo'));
            $keyinfo->appendChild(
            $this->encdoc->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'dsig:KeyName', $srckey->name));
        }
        $cipherdata = $enckey->appendChild($this->encdoc->createElementNS(self::XMLENCNS, 'xenc:CipherData'));
        $cipherdata->appendChild($this->encdoc->createElementNS(self::XMLENCNS, 'xenc:CipherValue', $strenckey));
        if (is_array($this->references) && count($this->references) > 0) {
            $reflist = $enckey->appendChild($this->encdoc->createElementNS(self::XMLENCNS, 'xenc:ReferenceList'));
            foreach ($this->references as $name => $reference) {
                $refuri = $reference["refuri"];
                $dataref = $reflist->appendChild($this->encdoc->createElementNS(self::XMLENCNS, 'xenc:DataReference'));
                $dataref->setAttribute("URI", '#' . $refuri);
            }
        }
        return;
    }

    /**
     * Decrypt key
     * @param String $enckey Enckey
     * @return DOMElement|string
     * @throws Exception
     */
    public function decrypt_key($enckey) {
        if (! $enckey->issencrypted) {
            throw new Exception("Key is not Encrypted");
        }
        if (empty($enckey->key)) {
            throw new Exception("Key is missing data to perform the decryption");
        }
        return $this->decrypt_node($enckey, false);
    }

    /**
     * Locate Encrypted Data
     * @param Element $element Element
     * @return DOMNode|null
     */
    public function locate_encrypted_data($element) {
        if ($element instanceof DOMDocument) {
            $doc = $element;
        } else {
            $doc = $element->ownerDocument;
        }
        if ($doc) {
            $xpath = new DOMXPath($doc);
            $query = "//*[local-name()='EncryptedData' and namespace-uri()='".self::XMLENCNS."']";
            $nodeset = $xpath->query($query);
            return $nodeset->item(0);
        }
        return null;
    }

    /**
     * Locate Key
     * @param null $node Node
     * @return xml_security_key|null
     */
    public function locate_key($node=null) {
        if (empty($node)) {
            $node = $this->rawnode;
        }
        if (! $node instanceof DOMNode) {
            return null;
        }
        if ($doc = $node->ownerDocument) {
            $xpath = new DOMXPath($doc);
            $xpath->registerNamespace('xml_sec_enc', self::XMLENCNS);
            $query = ".//self:EncryptionMethod";
            $nodeset = $xpath->query($query, $node);
            if ($encmeth = $nodeset->item(0)) {
                   $attralgorithm = $encmeth->getAttribute("Algorithm");
                try {
                    $objjkey = new xml_security_key($attralgorithm, array('type' => 'private'));
                } catch (Exception $e) {
                    return null;
                }
                return $objjkey;
            }
        }
        return null;
    }

    /**
     * Static locate key
     * @param null $objbasekey ObjKey
     * @param null $node Node
     * @return xml_security_key|null
     * @throws Exception
     */
    public static function static_locate_key_info($objbasekey=null, $node=null) {
        if (empty($node) || (! $node instanceof DOMNode)) {
            return null;
        }
        $doc = $node->ownerDocument;
        if (!$doc) {
            return null;
        }

        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('xml_sec_enc', self::XMLENCNS);
        $xpath->registerNamespace('xmlsecdsig', xml_security_dsig::XMLDSIGNS);
        $query = "./xmlsecdsig:KeyInfo";
        $nodeset = $xpath->query($query, $node);
        $encmeth = $nodeset->item(0);
        if (!$encmeth) {
            // No KeyInfo in EncryptedData / EncryptedKey.
            return $objbasekey;
        }

        foreach ($encmeth->childNodes as $child) {
            switch ($child->localName) {
                case 'KeyName':
                    if (! empty($objbasekey)) {
                        $objbasekey->name = $child->nodeValue;
                    }
                    break;
                case 'KeyValue':
                    foreach ($child->childNodes as $keyval) {
                        switch ($keyval->localName) {
                            case 'DSAKeyValue':
                                throw new Exception("DSAKeyValue currently not supported");
                                break;
                            case 'RSAKeyValue':
                                $modulus = null;
                                $exponent = null;
                                if ($modulusnode = $keyval->getElementsByTagName('Modulus')->item(0)) {
                                    $modulus = base64_decode($modulusnode->nodeValue);
                                }
                                if ($exponentnode = $keyval->getElementsByTagName('Exponent')->item(0)) {
                                    $exponent = base64_decode($exponentnode->nodeValue);
                                }
                                if (empty($modulus) || empty($exponent)) {
                                    throw new Exception("Missing Modulus or Exponent");
                                }
                                $publickey = xml_security_key::convert_rsa($modulus, $exponent);
                                $objbasekey->load_key($publickey);
                                break;
                        }
                    }
                    break;
                case 'RetrievalMethod':
                    $type = $child->getAttribute('Type');
                    if ($type !== 'http://www.w3.org/2001/04/xmlenc#EncryptedKey') {
                        // Unsupported key type.
                        break;
                    }
                    $uri = $child->getAttribute('URI');
                    if ($uri[0] !== '#') {
                        // URI not a reference - unsupported.
                        break;
                    }
                    $id = substr($uri, 1);

                    $query = "//xml_sec_enc:EncryptedKey[@Id='$id']";
                    $keyelement = $xpath->query($query)->item(0);
                    if (!$keyelement) {
                        throw new Exception("Unable to locate EncryptedKey with @Id='$id'.");
                    }

                    return xml_security_key::from_encrypted_key_element($keyelement);
                case 'EncryptedKey':
                    return xml_security_key::from_encrypted_key_element($child);
                case 'X509Data':
                    if ($x509certnodes = $child->getElementsByTagName('X509Certificate')) {
                        if ($x509certnodes->length > 0) {
                            $x509cert = $x509certnodes->item(0)->textContent;
                            $x509cert = str_replace(array("\r", "\n"), "", $x509cert);
                            $x509cert = "-----BEGIN CERTIFICATE-----\n"
                                        .chunk_split($x509cert, 64, "\n")."-----END CERTIFICATE-----\n";
                            $objbasekey->load_key($x509cert, false, true);
                        }
                    }
                    break;
            }
        }
        return $objbasekey;
    }

    /**
     * Localte Key info
     * @param null $objbasekey
     * @param null $node
     * @return xml_security_key|null
     * @throws Exception
     */
    public function locate_key_info($objbasekey=null, $node=null) {
        if (empty($node)) {
            $node = $this->rawnode;
        }
        return self::static_locate_key_info($objbasekey, $node);
    }
}
