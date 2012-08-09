<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project.
 *
 * PHP version 5.2
 *
 * LICENSE: This source file is subject to the New BSD license.  You should read
 * and accept the LICENSE before you use, modify, and/or redistribute this
 * software.
 *
 * @category  OWASP
 * @package   ESAPI_Reference
 * @author    Jeff Williams <jeff.williams@aspectsecurity.com>
 * @author    Linden Darling <Linden.Darling@jds.net.au>
 * @author    jah <jah@jahboite.co.uk>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   SVN: $Id$
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * DefaultEncoder requires the interface it implements and any Codecs it uses.
 */
require_once dirname(__FILE__) . '/../Encoder.php';
require_once dirname(__FILE__) . '/../codecs/Base64Codec.php';
require_once dirname(__FILE__) . '/../codecs/CSSCodec.php';
require_once dirname(__FILE__) . '/../codecs/HTMLEntityCodec.php';
require_once dirname(__FILE__) . '/../codecs/JavaScriptCodec.php';
require_once dirname(__FILE__) . '/../codecs/PercentCodec.php';
require_once dirname(__FILE__) . '/../codecs/VBScriptCodec.php';
require_once dirname(__FILE__) . '/../codecs/XMLEntityCodec.php';

/**
 * Reference implementation of the Encoder interface.
 *
 * @category  OWASP
 * @package   ESAPI_Reference
 * @author    Linden Darling <Linden.Darling@jds.net.au>
 * @author    jah <jah@jahboite.co.uk>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   Release: @package_version@
 * @link      http://www.owasp.org/index.php/ESAPI
 */
class DefaultEncoder implements Encoder
{

    private $base64Codec = null;
    private $cssCodec = null;
    private $htmlCodec = null;
    private $javascriptCodec = null;
    private $percentCodec = null;
    private $vbscriptCodec = null;
    private $xmlCodec = null;

    /*
     * Character sets that define characters (in addition to alphanumerics) that are
     * immune from encoding in various formats
     */
    private $immuneCss = array(' ');
    private $immuneHtml = array(',', '.', '-', '_', ' ');
    private $immuneHtmlAttr = array(',', '.', '-', '_');
    private $immuneJavascript = array(',', '.', '_');
    private $immuneOs = array('-');
    private $immuneSql = array(' ');
    private $immuneVbScript = array(' ');
    private $immuneXml = array(',', '.', '-', '_', ' ');
    private $immuneXmlAttr = array(',', '.', '-', '_');
    private $immuneXpath = array(',', '.', '-', '_', ' ');
    private $immuneUrl = array('.', '-', '*', '_');

    private $codecs = array();
    private $auditor = null;

    /**
     * Encoder constructor.
     *
     * @param array $codecs An array of Codec instances which will be used for
     *                      canonicalization.
     *
     * @return does not return a value.
     *
     * @throws InvalidArgumentException
     */
    public function __construct($codecs = null)
    {
        $this->logger = ESAPI::getAuditor("Encoder");

        // initialise codecs
        $this->base64Codec = new Base64Codec();
        $this->cssCodec = new CSSCodec();
        $this->htmlCodec = new HTMLEntityCodec();
        $this->javascriptCodec = new JavaScriptCodec();
        $this->percentCodec = new PercentCodec();
        $this->vbscriptCodec = new VBScriptCodec();
        $this->xmlCodec = new XMLEntityCodec();

        // initialise array of codecs for use by canonicalize
        if ($codecs === null) {
            array_push($this->codecs, $this->htmlCodec);
            array_push($this->codecs, $this->javascriptCodec);
            array_push($this->codecs, $this->percentCodec);
            // leaving css and vbs codecs out - they eat / and " chars respectively
            // array_push($this->codecs,$this->cssCodec);
            // array_push($this->codecs,$this->vbscriptCodec);
        } else {
            if (!is_array($codecs)) {
                throw new InvalidArgumentException(
                    'Expected the $codecs array parameter to be an array of instances of Codec.'
                );
            } else {
                // check array contains only codec instances
                foreach ($codecs as $codec) {
                    if ($codec instanceof Codec == false) {
                        throw new InvalidArgumentException(
                            'Expected every member of the $codecs array parameter to be an instance of Codec.'
                        );
                    }
                }
                $this->codecs = array_merge($this->codecs, $codecs);
            }
        }

    }

    /**
     * @inheritdoc
     */
    public function canonicalize($input, $strict = true)
    {
        if ($input === null) {
            return null;
        }
        $working = $input;
        $codecFound = null;
        $mixedCount = 1;
        $foundCount = 0;
        $clean = false;
        while (!$clean) {
            $clean = true;

            foreach ($this->codecs as $codec) {
                $old = $working;
                $working = $codec->decode($working);
                if ($old != $working) {
                    if ($codecFound != null && $codecFound != $codec) {
                        $mixedCount++;
                    }
                    $codecFound = $codec;
                    if ($clean) {
                        $foundCount++;
                    }
                    $clean = false;
                }
            }
        }
        if ($foundCount >= 2 && $mixedCount > 1) {
            if ($strict == true) {
                throw new IntrusionException(
                    'Input validation failure',
                    'Multiple (' . $foundCount . 'x) and mixed ('
                    . $mixedCount . 'x) encoding detected in ' . $input
                );
            } else {
                $this->logger->warning(
                    Auditor::SECURITY,
                    false,
                    'Multiple (' . $foundCount . 'x) and mixed ('
                    . $mixedCount . 'x) encoding detected in ' . $input
                );
            }
        } else {
            if ($foundCount >= 2) {
                if ($strict == true) {
                    throw new IntrusionException(
                        'Input validation failure',
                        "Multiple encoding ({$foundCount}x) detected in {$input}"
                    );
                } else {
                    $this->logger->warning(
                        Auditor::SECURITY,
                        false,
                        "Multiple encoding ({$foundCount}x) detected in {$input}"
                    );
                }
            } else {
                if ($mixedCount > 1) {
                    if ($strict == true) {
                        throw new IntrusionException(
                            'Input validation failure',
                            "Mixed encoding ({$mixedCount}x) detected in {$input}"
                        );
                    } else {
                        $this->logger->warning(
                            Auditor::SECURITY,
                            false,
                            "Mixed encoding ({$mixedCount}x) detected in {$input}"
                        );
                    }
                }
            }
        }
        return $working;
    }

    /**
     * @inheritdoc
     */
    public function encodeForCSS($input)
    {
        if ($input === null) {
            return null;
        }
        return $this->cssCodec->encode($this->immuneCss, $input);
    }


    /**
     * @inheritdoc
     */
    public function encodeForHTML($input)
    {
        if ($input === null) {
            return null;
        }
        return $this->htmlCodec->encode($this->immuneHtml, $input);
    }

    /**
     * @inheritdoc
     */
    public function encodeForHTMLAttribute($input)
    {
        if ($input === null) {
            return null;
        }
        return $this->htmlCodec->encode($this->immuneHtmlAttr, $input);
    }

    /**
     * @inheritdoc
     */
    public function encodeForJavaScript($input)
    {
        if ($input === null) {
            return null;
        }
        return $this->javascriptCodec->encode($this->immuneJavascript, $input);
    }

    /**
     * @inheritdoc
     */
    public function encodeForVBScript($input)
    {
        if ($input === null) {
            return null;
        }
        return $this->vbscriptCodec->encode($this->immuneVbScript, $input);
    }

    /**
     * @inheritdoc
     */
    public function encodeForSQL($codec, $input)
    {
        if ($input === null) {
            return null;
        }
        return $codec->encode($this->immuneSql, $input);
    }

    /**
     * @inheritdoc
     */
    public function encodeForOS($codec, $input)
    {
        if ($input === null) {
            return null;
        }

        if ($codec instanceof Codec == false) {
            ESAPI::getLogger('Encoder')->error(
                ESAPILogger::SECURITY,
                false,
                'Invalid Argument, expected an instance of an OS Codec.'
            );
            return null;
        }

        return $codec->encode($this->immuneOs, $input);
    }

    /**
     * @inheritdoc
     */
    public function encodeForXPath($input)
    {
        if ($input === null) {
            return null;
        }
        return $this->htmlCodec->encode($this->immuneXpath, $input);
    }

    /**
     * @inheritdoc
     */
    public function encodeForXML($input)
    {
        if ($input === null) {
            return null;
        }
        return $this->xmlCodec->encode($this->immuneXml, $input);
    }

    /**
     * @inheritdoc
     */
    public function encodeForXMLAttribute($input)
    {
        if ($input === null) {
            return null;
        }
        return $this->xmlCodec->encode($this->immuneXmlAttr, $input);
    }

    /**
     * @inheritdoc
     */
    public function encodeForURL($input)
    {
        if ($input === null) {
            return null;
        }
        $encoded = $this->percentCodec->encode($this->immuneUrl, $input);

        $initialEncoding = $this->percentCodec->detectEncoding($encoded);
        $decodedString = mb_convert_encoding('', $initialEncoding);

        $pcnt = $this->percentCodec->normalizeEncoding('%');
        $two = $this->percentCodec->normalizeEncoding('2');
        $zero = $this->percentCodec->normalizeEncoding('0');
        $char_plus = mb_convert_encoding('+', $initialEncoding);

        $index = 0;
        $limit = mb_strlen($encoded, $initialEncoding);
        for ($i = 0; $i < $limit; $i++) {
            if ($index > $i) {
                continue; // already dealt with this character
            }
            $c = mb_substr($encoded, $i, 1, $initialEncoding);
            $d = mb_substr($encoded, $i + 1, 1, $initialEncoding);
            $e = mb_substr($encoded, $i + 2, 1, $initialEncoding);
            if ($this->percentCodec->normalizeEncoding($c) == $pcnt
                && $this->percentCodec->normalizeEncoding($d) == $two
                && $this->percentCodec->normalizeEncoding($e) == $zero
            ) {
                $decodedString .= $char_plus;
                $index += 3;
            } else {
                $decodedString .= $c;
                $index++;
            }
        }

        return $decodedString;
    }

    /**
     * @inheritdoc
     */
    public function decodeFromURL($input)
    {
        if ($input === null) {
            return null;
        }
        $canonical = $this->canonicalize($input, true);

        // Replace '+' with ' '
        $initialEncoding = $this->percentCodec->detectEncoding($canonical);
        $decodedString = mb_convert_encoding('', $initialEncoding);

        $find = $this->percentCodec->normalizeEncoding('+');
        $char_space = mb_convert_encoding(' ', $initialEncoding);

        $limit = mb_strlen($canonical, $initialEncoding);
        for ($i = 0; $i < $limit; $i++) {
            $c = mb_substr($canonical, $i, 1, $initialEncoding);
            if ($this->percentCodec->normalizeEncoding($c) == $find) {
                $decodedString .= $char_space;
            } else {
                $decodedString .= $c;
            }
        }

        return $this->percentCodec->decode($decodedString);
    }


    /**
     * @inheritdoc
     */
    public function encodeForBase64($input, $wrap = true)
    {
        if ($input === null) {
            return null;
        }
        return $this->base64Codec->encode($input, $wrap);
    }


    /**
     * @inheritdoc
     */
    public function decodeFromBase64($input)
    {
        if ($input === null) {
            return null;
        }
        return $this->base64Codec->decode($input);
    }
}
