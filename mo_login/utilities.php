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
 * @copyright 2017  miniOrange
 * @category  authentication
 * @license   http://www.gnu.org/copyleft/gpl.html GNU/GPL, see license.txt
 * @package   mo_login
 */
// @codingStandardsIgnoreLine
require_once('../../config.php');
require_once('xmlseclibs.php');
/**
 * Auth external functions
 *
 * @package   mo_login
 * @category  utilities
 * @copyright 2017 miniOrange
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class utilities
{

    public static function generate_id() {
        return '_' . self::string_to_hex(self::generate_random_bytes(21));
    }

    public static function string_to_hex($bytes) {
        $ret = '';
        for ($i = 0; $i < strlen($bytes); $i++) {
            $ret .= sprintf('%02x', ord($bytes[$i]));
        }
        return $ret;
    }

    public static function generate_random_bytes($length, $fallback = true) {
        return openssl_random_pseudo_bytes($length);
    }

    public static function create_authn_request($acsurl, $issuer, $forceauthn = 'false') {
        $requestxmlstr = '<?xml version="1.0" encoding="UTF-8"?>' .
                        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="' . self::generate_id() .
                        '" Version="2.0" IssueInstant="' . self::generate_timestamp() . '"';
        if ($forceauthn == 'true') {
            $requestxmlstr .= ' ForceAuthn="true"';
        }
        $requestxmlstr .= ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="'
        . $acsurl .
         '" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        . $issuer . '</saml:Issuer></samlp:AuthnRequest>';
        $deflatedstr = gzdeflate($requestxmlstr);
        $baseencodedstr = base64_encode($deflatedstr);
        $urlencoded = urlencode($baseencodedstr);
        return $urlencoded;
    }

    public static function generate_timestamp($instant = null) {
        if ($instant === null) {
            $instant = time();
        }
        return gmdate('Y-m-d\TH:i:s\Z', $instant);
    }

    public static function xpquery(DOMNode $node, $query) {
        static $xpcache = null;

        if ($node instanceof DOMDocument) {
            $doc = $node;
        } else {
            $doc = $node->ownerDocument;
        }

        if ($xpcache === null || !$xpcache->document->isSameNode($doc)) {
            $xpcache = new DOMXPath($doc);
            $xpcache->registerNamespace('soap-env', 'http://schemas.xmlsoap.org/soap/envelope/');
            $xpcache->registerNamespace('saml_protocol', 'urn:oasis:names:tc:SAML:2.0:protocol');
            $xpcache->registerNamespace('saml_assertion', 'urn:oasis:names:tc:SAML:2.0:assertion');
            $xpcache->registerNamespace('saml_metadata', 'urn:oasis:names:tc:SAML:2.0:metadata');
            $xpcache->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
            $xpcache->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        }

        $results = $xpcache->query($query, $node);
        $ret = array();
        for ($i = 0; $i < $results->length; $i++) {
            $ret[$i] = $results->item($i);
        }

        return $ret;
    }

    public static function parse_name_id(DOMElement $xml) {
        $ret = array('Value' => trim($xml->textContent));

        foreach (array('NameQualifier', 'SPNameQualifier', 'Format') as $attr) {
            if ($xml->hasAttribute($attr)) {
                $ret[$attr] = $xml->getAttribute($attr);
            }
        }

        return $ret;
    }

    public static function xs_date_time_to_timestamp($time) {
        $matches = array();

        // We use a very strict regex to parse the timestamp.
        $regex = '/^(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.\\d+)?Z$/D';
        if (preg_match($regex, $time, $matches) == 0) {
            echo sprintf('nvalid SAML2 timestamp passed to xs_date_time_to_timestamp: '.$time);
            exit;
        }

        // Extract the different components of the time from the  matches in the regex.
        // Intval will ignore leading zeroes in the string.
        $year   = intval($matches[1]);
        $month  = intval($matches[2]);
        $day    = intval($matches[3]);
        $hour   = intval($matches[4]);
        $minute = intval($matches[5]);
        $second = intval($matches[6]);

        // We use gmmktime because the timestamp will always be given in UTC.
        $ts = gmmktime($hour, $minute, $second, $month, $day, $year);

        return $ts;
    }

    public static function extract_strings(DOMElement $parent, $namespaceuri, $localname) {

        $ret = array();
        for ($node = $parent->firstChild; $node !== null; $node = $node->nextSibling) {
            if ($node->namespaceURI !== $namespaceuri || $node->localName !== $localname) {
                continue;
            }
            $ret[] = trim($node->textContent);
        }

        return $ret;
    }

    public static function validate_element(DOMElement $root) {

        // Create an XML security object.
        $objxmlsecdsig = new xml_security_dsig();

        // Both SAML messages and SAML assertions use the 'ID' attribute.
        $objxmlsecdsig->idkeys[] = 'ID';
        // Locate the XMLDSig Signature element to be used.
        $signatureelement = self::xpquery($root, './ds:Signature');
        if (count($signatureelement) === 0) {
            // We don't have a signature element to validate.
            return false;
        } else if (count($signatureelement) > 1) {
            echo sprintf('XMLSec: more than one signature element in root.');
            exit;
        }
        // Removed code.
        $signatureelement = $signatureelement[0];
        $objxmlsecdsig->signode = $signatureelement;

        // Canonicalize the XMLDSig SignedInfo element in the message.
        $objxmlsecdsig->canonicalize_signed_info();

        // Validate referenced xml nodes.
        if (!$objxmlsecdsig->validate_reference()) {
            echo sprintf('XMLsec: digest validation failed');
            exit;
        }

        // Check that $root is one of the signed nodes.
        $rootsigned = false;
        foreach ($objxmlsecdsig->get_validated_nodes() as $signednode) {
            if ($signednode->isSameNode($root)) {
                $rootsigned = true;
                break;
            } else if ($root->parentNode instanceof DOMDocument && $signednode->isSameNode($root->ownerDocument)) {
                $rootsigned = true;
                break;
            }
        }

        if (!$rootsigned) {
            echo sprintf('XMLSec: The root element is not signed.');
            exit;
        }

        // Now we extract all available X509 certificates in the signature element.
        $certificates = array();
        foreach (self::xpquery($signatureelement, './ds:KeyInfo/ds:X509Data/ds:X509Certificate') as $certnode) {
            $certdata = trim($certnode->textContent);
            $certdata = str_replace(array("\r", "\n", "\t", ' '), '', $certdata);
            $certificates[] = $certdata;
        }

        $ret = array(
            'Signature' => $objxmlsecdsig,
            'Certificates' => $certificates,
            );
        return $ret;
    }
    public static function validate_signature(array $info, xml_security_key $key) {
        $objxmlsecdsig = $info['Signature'];

        $sigmethod = self::xpquery($objxmlsecdsig->signode, './ds:SignedInfo/ds:SignatureMethod');
        if (empty($sigmethod)) {
            echo sprintf('Missing SignatureMethod element');
            exit();
        }
        $sigmethod = $sigmethod[0];
        if (!$sigmethod->hasAttribute('Algorithm')) {
            echo sprintf('Missing Algorithm-attribute on SignatureMethod element.');
            exit;
        }
        $algo = $sigmethod->getAttribute('Algorithm');

        if ($key->type === xml_security_key::RSA_SHA1 && $algo !== $key->type) {
            $key = self::cast_key($key, $algo);
        }

        // Check the signature.
        if (! $objxmlsecdsig->verify($key)) {
            echo sprintf('Unable to validate Sgnature');
            exit;
        }
    }

    public static function cast_key(xml_security_key $key, $algorithm, $type = 'public') {

        // Do nothing if algorithm is already the type of the key.
        if ($key->type === $algorithm) {
            return $key;
        }

        $keyinfo = openssl_pkey_get_details($key->key);
        if ($keyinfo === false) {
            echo sprintf('Unable to get key details from xml_security_key.');
            exit;
        }
        if (!isset($keyinfo['key'])) {
            echo sprintf('Missing key in public key details.');
            exit;
        }

        $newkey = new xml_security_key($algorithm, array('type' => $type));
        $newkey->load_key($keyinfo['key']);
        return $newkey;
    }

    public static function process_response($currenturl, $certfingerprint, $signaturedata,
        saml_response_class $response
    ) {

        $assertion = current($response->get_assertions());

        $notbefore = $assertion->get_not_before();
        if ($notbefore !== null && $notbefore > time() + 60) {
            die('Received an assertion that is valid in the future. Check clock synchronization on IdP and SP.');
        }

        $notonorafter = $assertion->get_not_onor_after();
        if ($notonorafter !== null && $notonorafter <= time() - 60) {
            die('Received an assertion that has expired. Check clock synchronization on IdP and SP.');
        }

        $sessionnotonorafter = $assertion->get_session_not_onor_after();
        if ($sessionnotonorafter !== null && $sessionnotonorafter <= time() - 60) {
            die('Received an assertion with a session that has expired. Check clock synchronization on IdP and SP.');
        }

        // Validate Response-element destination.
        $msgdestination = $response->get_destination();
        if (substr($msgdestination, -1) == '/') {
            $msgdestination = substr($msgdestination, 0, -1);
        }
        if (substr($currenturl, -1) == '/') {
            $currenturl = substr($currenturl, 0, -1);
        }

        if ($msgdestination !== null && $msgdestination !== $currenturl) {
            echo sprintf(
                'Destination in response doesn\'t match the current URL. Destination is "' .
                $msgdestination . '", current URL is "' . $currenturl . '".'
            );
            exit;
        }

        $responsesigned = self::check_sign($certfingerprint, $signaturedata);

        // Returning boolean $responsesigned.
        return $responsesigned;
    }

    public static function check_sign($certfingerprint, $signaturedata) {
        $certificates = $signaturedata['Certificates'];

        if (count($certificates) === 0) {
            return false;
        }

        $fparray = array();
        $fparray[] = $certfingerprint;

        $pemcert = self::find_certificate($fparray, $certificates);

        $lastexception = null;
        $key = new xml_security_key(xml_security_key::RSA_SHA1, array('type' => 'public'));
        $key->load_key($pemcert);

        try {
            /*
             * Make sure that we have a valid signature
             */
            self::validate_signature($signaturedata, $key);
            return true;
        } catch (Exception $e) {
            $lastexception = $e;
        }
        // We were unable to validate the signature with any of our keys.
        if ($lastexception !== null) {
            throw $lastexception;
        } else {
            return false;
        }

    }

    public static function validate_issuer_and_audience($samlresponse, $spentityid, $issuertovalidateagainst) {
        $issuer = current($samlresponse->get_assertions())->get_issuer();
        $assertion = current($samlresponse->get_assertions());
        $audiences = $assertion->get_valid_audiences();
        if (strcmp($issuertovalidateagainst, $issuer) === 0) {
            if (!empty($audiences)) {
                if (in_array($spentityid, $audiences, true)) {
                    return true;
                } else {
                    echo sprintf('Invalid Audience URI. Expected one of the Audiences to be: '. $spentityid);
                    exit;
                }
            }
        } else {
            echo sprintf('Issuer cannot be verified.');
            exit;
        }
    }

    private static function find_certificate(array $certfingerprints, array $certificates) {

        $candidates = array();

        foreach ($certificates as $cert) {
            $fp = strtolower(sha1(base64_decode($cert)));
            if (!in_array($fp, $certfingerprints, true)) {
                $candidates[] = $fp;
                continue;
            }

            // We have found a matching fingerprint.
            $pem = "-----BEGIN CERTIFICATE-----\n" .
                chunk_split($cert, 64) .
                "-----END CERTIFICATE-----\n";

            return $pem;
        }

        echo sprintf('Unable to find a certificate matching the configured fingerprint.');
        exit;
    }

        /**
         * Decrypt an encrypted element.
         *
         * This is an internal helper function.
         *
         * @param  DOMElement       $encrypteddata The encrypted data.
         * @param  xml_security_key $inputkey      The decryption key.
         * @param  array            &$blacklist    Blacklisted decryption algorithms.
         * @return DOMElement     The decrypted element.
         * @throws Exception
         */
    private static function do_decrypt_element(DOMElement $encrypteddata, xml_security_key $inputkey, array &$blacklist) {
        $enc = new xml_sec_enc();
        $enc->set_node($encrypteddata);

        $enc->type = $encrypteddata->getAttribute('Type');
        $symmetrickey = $enc->locate_key($encrypteddata);
        if (!$symmetrickey) {
            echo sprintf('Could not locate key algorithm in encrypted data.');
            exit;
        }

        $symmetrickeyinfo = $enc->locate_key_info($symmetrickey);
        if (!$symmetrickeyinfo) {
            echo sprintf('Could not locate <dsig:KeyInfo> for the encrypted key.');
            exit;
        }
        $inputkeyalgo = $inputkey->get_algorith();
        if ($symmetrickeyinfo->issencrypted) {
            $symkeyinfoalgo = $symmetrickeyinfo->get_algorith();
            if (in_array($symkeyinfoalgo, $blacklist, true)) {
                echo sprintf('Algorithm disabled: ' . var_export($symkeyinfoalgo, true));
                exit;
            }
            if ($symkeyinfoalgo === xml_security_key::RSA_OAEP_MGF1P && $inputkeyalgo === xml_security_key::RSA_1_5) {
                /*
                 * The RSA key formats are equal, so loading an RSA_1_5 key
                 * into an RSA_OAEP_MGF1P key can be done without problems.
                 * We therefore pretend that the input key is an
                 * RSA_OAEP_MGF1P key.
                 */
                $inputkeyalgo = xml_security_key::RSA_OAEP_MGF1P;
            }
            // Make sure that the input key format is the same as the one used to encrypt the key.
            if ($inputkeyalgo !== $symkeyinfoalgo) {
                echo sprintf(
                    'Algorithm mismatch between input key and key used to encrypt ' .
                    ' the symmetric key for the message. Key was: ' .
                    var_export($inputkeyalgo, true) . '; message was: ' .
                    var_export($symkeyinfoalgo, true)
                );
                exit;
            }
                       $enckey = $symmetrickeyinfo->encryptedctx;
            $symmetrickeyinfo->key = $inputkey->key;
            $keysize = $symmetrickey->get_symmetric_key_size();
            if ($keysize === null) {
                /* To protect against key oracle attacks, we need to be able to create a
                 * symmetric key, and for that we need to know the key size.
                 */
                echo sprintf('Unknown key size for encryption algorithm: ' . var_export($symmetrickey->type, true));
                exit;
            }
            try {
                $key = $enckey->decrypt_key($symmetrickeyinfo);
                if (strlen($key) != $keysize) {
                    echo sprintf(
                        'Unexpected key size (' . strlen($key) * 8 . 'bits) for encryption algorithm: ' .
                        var_export($symmetrickey->type, true)
                    );
                    exit;
                }
            } catch (Exception $e) {
                // We failed to decrypt this key. Log it, and substitute a random key.

                // Create a replacement key, so that it looks like we fail in the same way as if the key was correctly padded.
                /* We base the symmetric key on the encrypted key and private key, so that we always behave the
                 * same way for a given input key.
                 */
                $encryptedkey = $enckey->get_cipher_value();
                $pkey = openssl_pkey_get_details($symmetrickeyinfo->key);
                $pkey = sha1(serialize($pkey), true);
                $key = sha1($encryptedkey . $pkey, true);
                // Make sure that the key has the correct length.
                if (strlen($key) > $keysize) {
                    $key = substr($key, 0, $keysize);
                } else if (strlen($key) < $keysize) {
                    $key = str_pad($key, $keysize);
                }
            }
            $symmetrickey->loadkey($key);
        } else {
            $symkeyalgo = $symmetrickey->get_algorith();
            // Make sure that the input key has the correct format.
            if ($inputkeyalgo !== $symkeyalgo) {
                echo sprintf(
                    'Algorithm mismatch between input key and key in message. ' .
                    'Key was: ' . var_export($inputkeyalgo, true) . '; message was: ' .
                    var_export($symkeyalgo, true)
                );
                exit;
            }
            $symmetrickey = $inputkey;
        }
        $algorithm = $symmetrickey->get_algorith();
        if (in_array($algorithm, $blacklist, true)) {
            echo sprintf('Algorithm disabled: ' . var_export($algorithm, true));
            exit;
        }
        $decrypted = $enc->decrypt_node($symmetrickey, false);

        $xml = '<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '.
                     'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' .
            $decrypted .
            '</root>';
        $newdoc = new DOMDocument();
        if (!@$newdoc->loadXML($xml)) {
            echo sprintf('Failed to parse decrypted XML. Maybe the wrong sharedkey was used?');
            throw new Exception('Failed to parse decrypted XML. Maybe the wrong sharedkey was used?');
        }
        $decryptedelement = $newdoc->firstChild->firstChild;
        if ($decryptedelement === null) {
            echo sprintf('Missing encrypted element.');
            throw new Exception('Missing encrypted element.');
        }

        if (!($decryptedelement instanceof DOMElement)) {
            echo sprintf('Decrypted element was not actually a DOMElement.');
        }

        return $decryptedelement;
    }
    /**
     * Decrypt an encrypted element.
     *
     * @param  DOMElement       $encrypteddata The encrypted data.
     * @param  xml_security_key $inputkey      The decryption key.
     * @param  array            $blacklist     Blacklisted decryption algorithms.
     * @return DOMElement     The decrypted element.
     * @throws Exception
     */
    public static function decrypt_element(DOMElement $encrypteddata,
        xml_security_key $inputkey,
        array $blacklist = array(),
        xml_security_key $alternatekey = null
    ) {
        try {
            return self::do_decrypt_element($encrypteddata, $inputkey, $blacklist);
        } catch (Exception $e) {
            // Try with alternate key.
            try {
                return self::do_decrypt_element($encrypteddata, $alternatekey, $blacklist);
            } catch (Exception $t) {
                echo sprintf('Failed to decrypt XML element.');
            }
            /*
             * Something went wrong during decryption, but for security
             * reasons we cannot tell the user what failed.
             */
            echo sprintf('Failed to decrypt XML element.');
            exit;
        }
    }

    /**
     * Generates the metadata of the SP based on the settings
     *
     * @param string    $sp            The SP data
     * @param string    $authnsign     authnRequestsSigned attribute
     * @param string    $wsign         wantAssertionsSigned attribute
     * @param DateTime  $validUntil    Metadata's valid time
     * @param Timestamp $cacheDuration Duration of the cache in seconds
     * @param array     $contacts      Contacts info
     * @param array     $organization  Organization ingo
     *
     * @return string SAML Metadata XML
     */
    public static function metadata_builder($siteurl) {
        $xml = new DOMDocument();
        $url = plugins_url().'/miniorange-saml-20-single-sign-on/sp-metadata.xml';

        $xml->load($url);

        $xpath = new DOMXPath($xml);
        $elements = $xpath->query(
            '//md:EntityDescriptor[@entityID="http://{path-to-your-site}/wp-content/plugins/miniorange-saml-20-single-sign-on/"]'
        );
        if ($elements->length >= 1) {
            $element = $elements->item(0);
            $element->setAttribute('entityID', $siteurl.'/wp-content/plugins/miniorange-saml-20-single-sign-on/');
        }

        $elements = $xpath->query('//md:AssertionConsumerService[@Location="http://{path-to-your-site}"]');
        if ($elements->length >= 1) {
            $element = $elements->item(0);
            $element->setAttribute('Location', $siteurl.'/');
        }

        // Re-save.
        $xml->save(plugins_url()."/miniorange-saml-20-single-sign-on/sp-metadata.xml");
    }

    public static function get_mapped_groups($samlparams, $samlgroups) {
            $groups = array();

        if (!empty($samlgroups)) {
            $samlmappedgroups = array();
            $i = 1;
            while ($i < 10) {
                $samlmappedgroupsvalue = $samlparams->get('group'.$i.'_map');

                $samlmappedgroups[$i] = explode(';', $samlmappedgroupsvalue);
                $i++;
            }
        }

        foreach ($samlgroups as $samlgroup) {
            if (!empty($samlgroup)) {
                $i = 0;
                $found = false;

                while ($i < 9 && !$found) {
                    if (!empty($samlmappedgroups[$i]) && in_array($samlgroup, $samlmappedgroups[$i], true)) {
                        $groups[] = $samlparams->get('group'.$i);
                        $found = true;
                    }
                    $i++;
                }
            }
        }

        return array_unique($groups);
    }


    public static function get_encryption_algorithm($method) {
        switch($method) {
            case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
            return xml_security_key::TRIPLEDES_CBC;
                break;

            case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
            return xml_security_key::AES128_CBC;

            case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
            return xml_security_key::AES192_CBC;
                break;

            case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
            return xml_security_key::AES256_CBC;
                break;

            case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
            return xml_security_key::RSA_1_5;
                break;

            case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
            return xml_security_key::RSA_OAEP_MGF1P;
                break;

            case 'http://www.w3.org/2000/09/xmldsig#dsa-sha1':
            return xml_security_key::DSA_SHA1;
                break;

            case 'http://www.w3.org/2000/09/xmldsig#rsa-sha1':
            return xml_security_key::RSA_SHA1;
                break;

            case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256':
            return xml_security_key::RSA_SHA256;
                break;

            case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384':
            return xml_security_key::RSA_SHA384;
                break;

            case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512':
            return xml_security_key::RSA_SHA512;
                break;

            default:
                echo sprintf('Invalid Encryption Method: '.$method);
            exit;
                break;
        }
    }

    public static function sanitize_certificate( $certificate ) {
        $certificate = preg_replace("/[\r\n]+/", "", $certificate);
        $certificate = str_replace("-", "", $certificate);
        $certificate = str_replace("BEGIN CERTIFICATE", "", $certificate);
        $certificate = str_replace("END CERTIFICATE", "", $certificate);
        $certificate = str_replace(" ", "", $certificate);
        $certificate = chunk_split($certificate, 64, "\r\n");
        $certificate = "-----BEGIN CERTIFICATE-----\r\n" . $certificate . "-----END CERTIFICATE-----";
        return $certificate;
    }

    public static function desanitize_certificate( $certificate ) {
        $certificate = preg_replace("/[\r\n]+/", "", $certificate);
        $certificate = str_replace("-----BEGIN CERTIFICATE-----", "", $certificate);
        $certificate = str_replace("-----END CERTIFICATE-----", "", $certificate);
        $certificate = str_replace(" ", "", $certificate);
        return $certificate;
    }
}