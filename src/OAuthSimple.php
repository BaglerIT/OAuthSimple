<?php namespace BaglerIT\OAuthSimple;

/**
 * OAuthSimple - A simpler version of OAuth
 *
 * https://github.com/jrconlin/oauthsimple
 *
 * @author     jr conlin <src@jrconlin.com>
 * @copyright  unitedHeroes.net 2011
 * @version    1.3
 * @license    LICENSE
 * Composer Package and PSR-2 compliance refactoring by Dave Bagler <dave@baglerit.com>
 */
class OAuthSimple
{
    protected $secrets;

    protected $default_signature_method;

    protected $action;

    protected $nonce_chars;

    protected $parameters;

    protected $path;

    protected $sbs;

    /**
     * Constructor
     *
     * @access public
     * @param string $APIKey The API Key (sometimes referred to as the consumer key)
     * This value is usually supplied by the site you wish to use.
     * @param string $sharedSecret The shared secret. This value is also usually provided by the site you wish to use.
     * @return OAuthSimple (Object)
     */
    public function __construct($APIKey = "", $sharedSecret = "")
    {

        if (!empty($APIKey)) {
            $this->secrets['consumer_key'] = $APIKey;
        }

        if (!empty($sharedSecret)) {
            $this->secrets['shared_secret'] = $sharedSecret;
        }

        $this->default_signature_method = "HMAC-SHA1";
        $this->action = "GET";
        $this->nonce_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        return $this;
    }

    /**
     * Reset the parameters and URL
     *
     * @access public
     * @return OAuthSimple (Object)
     */
    public function reset()
    {
        $this->parameters = [];
        $this->path = null;
        $this->sbs = null;

        return $this;
    }

    /**
     * Set the parameters either from a hash or a string
     *
     * @access public
     * @param mixed $parameters List of parameters for the call, this can either be a URI string
     * (e.g. "foo=bar&gorp=banana" or an object/hash)
     * @return OAuthSimple (Object)
     */
    public function setParameters($parameters = [])
    {

        if (is_string($parameters)) {
            $parameters = $this->parseParameterString($parameters);
        }
        if (empty($this->parameters)) {
            $this->parameters = $parameters;
        } elseif (!empty($parameters)) {
            $this->parameters = array_merge($this->parameters, $parameters);
        }
        if (empty($this->parameters['oauth_nonce'])) {
            $this->getNonce();
        }
        if (empty($this->parameters['oauth_timestamp'])) {
            $this->getTimeStamp();
        }
        if (empty($this->parameters['oauth_consumer_key'])) {
            $this->getApiKey();
        }
        if (empty($this->parameters['oauth_token'])) {
            $this->getAccessToken();
        }
        if (empty($this->parameters['oauth_signature_method'])) {
            $this->setSignatureMethod();
        }
        if (empty($this->parameters['oauth_version'])) {
            $this->parameters['oauth_version']="1.0";
        }

        return $this;
    }

    /**
     * Convenience method for setParameters
     *
     * @param mixed $parameters
     * @access public
     * @see setParameters
     * @return OAuthSimple
     */
    public function setQueryString($parameters)
    {
        return $this->setParameters($parameters);
    }

    /**
     * Set the target URL (does not include the parameters)
     *
     * @param string $path the fully qualified URI (excluding query arguments) (e.g "http://example.org/foo")
     * @return $this
     * @throws OAuthSimpleException
     */
    public function setURL($path)
    {
        if (empty($path)) {
            throw new OAuthSimpleException('No path specified for OAuthSimple.setURL');
        }
        $this->path=$path;

        return $this;
    }

    /**
     * Convenience method for setURL
     *
     * @param path (String)
     * @see setURL
     */
    public function setPath($path)
    {
        return $this->path=$path;
    }

    /**
     * Set the "action" for the url, (e.g. GET,POST, DELETE, etc.)
     *
     * @param string $action HTTP Action word.
     * @return $this
     * @throws OAuthSimpleException
     */
    public function setAction($action)
    {
        if (empty($action)) {
            $action = 'GET';
        }

        $action = strtoupper($action);

        if (preg_match('/[^A-Z]/', $action)) {
            throw new OAuthSimpleException('Invalid action specified for OAuthSimple.setAction');
        }

        $this->action = $action;

        return $this;
    }

    /**
     * Set the signatures (as well as validate the ones you have)
     *
     * @param object $signatures object/hash of the token/signature pairs
     * {api_key:, shared_secret:, oauth_token: oauth_secret:}
     * @return $this
     * @throws OAuthSimpleException
     */
    public function signatures($signatures)
    {
        if (!empty($signatures) && !is_array($signatures)) {
            throw new OAuthSimpleException('Must pass dictionary array to OAuthSimple.signatures');
        }
        if (!empty($signatures)) {
            if (empty($this->secrets)) {
                $this->secrets = [];
            }
            $this->secrets=array_merge($this->secrets, $signatures);
        }
        if (isset($this->secrets['api_key'])) {
            $this->secrets['consumer_key'] = $this->secrets['api_key'];
        }
        if (isset($this->secrets['access_token'])) {
            $this->secrets['oauth_token'] = $this->secrets['access_token'];
        }
        if (isset($this->secrets['access_secret'])) {
            $this->secrets['shared_secret'] = $this->secrets['access_secret'];
        }
        if (isset($this->secrets['oauth_token_secret'])) {
            $this->secrets['oauth_secret'] = $this->secrets['oauth_token_secret'];
        }
        if (empty($this->secrets['consumer_key'])) {
            throw new OAuthSimpleException('Missing required consumer_key in OAuthSimple.signatures');
        }
        if (empty($this->secrets['shared_secret'])) {
            throw new OAuthSimpleException('Missing requires shared_secret in OAuthSimple.signatures');
        }
        if (!empty($this->secrets['oauth_token']) && empty($this->secrets['oauth_secret'])) {
            throw new OAuthSimpleException('Missing oauth_secret for supplied oauth_token in OAuthSimple.signatures');
        }

        return $this;
    }

    /**
     * @param $signatures
     * @return OAuthSimple
     * @throws OAuthSimpleException
     */
    public function setTokensAndSecrets($signatures)
    {
        return $this->signatures($signatures);
    }

    /**
     * Set the signature method (currently only Plaintext or SHA-MAC1)
     *
     * @param string $method Method of signing the transaction (only PLAINTEXT and SHA-MAC1 allowed for now)
     * @return $this
     * @throws OAuthSimpleException
     */
    public function setSignatureMethod($method = "")
    {
        if (empty($method)) {
            $method = $this->default_signature_method;
        }
        $method = strtoupper($method);
        switch ($method) {
            case 'PLAINTEXT':
            case 'HMAC-SHA1':
                $this->parameters['oauth_signature_method']=$method;
                break;
            default:
                throw new OAuthSimpleException(
                    "Unknown signing method $method specified for OAuthSimple.setSignatureMethod"
                );
                break;
        }

        return $this;
    }

    /**
     * Sign the request
     *
     * note: all arguments are optional, provided you've set them using the
     * other helper functions.
     *
     * @param array $args hash of arguments for the call {action, path, parameters (array),
     * method, signatures (array)} all arguments are optional.
     * @return array
     * @throws OAuthSimpleException
     */
    public function sign($args = [])
    {
        if (!empty($args['action'])) {
            $this->setAction($args['action']);
        }
        if (!empty($args['path'])) {
            $this->setPath($args['path']);
        }
        if (!empty($args['method'])) {
            $this->setSignatureMethod($args['method']);
        }
        if (!empty($args['signatures'])) {
            $this->signatures($args['signatures']);
        }
        if (empty($args['parameters'])) {
            $args['parameters'] = [];
        }
        $this->setParameters($args['parameters']);
        $normParams = $this->normalizedParameters();

        return [
            'parameters' => $this->parameters,
            'signature' => self::oauthEscape($this->parameters['oauth_signature']),
            'signed_url' => $this->path . '?' . $normParams,
            'header' => $this->getHeaderString(),
            'sbs'=> $this->sbs
        ];
    }

    /**
     * Return a formatted "header" string
     *
     * NOTE: This doesn't set the "Authorization: " prefix, which is required.
     * It's not set because various set header functions prefer different
     * ways to do that.
     *
     * @param array $args
     * @return mixed
     * @throws OAuthSimpleException
     */
    public function getHeaderString($args = [])
    {
        if (empty($this->parameters['oauth_signature'])) {
            $this->sign($args);
        }
        $result = 'OAuth ';

        foreach ($this->parameters as $pName => $pValue) {
            if (strpos($pName, 'oauth_') !== 0) {
                continue;
            }
            if (is_array($pValue)) {
                foreach ($pValue as $val) {
                    $result .= $pName .'="' . self::oauthEscape($val) . '", ';
                }
            } else {
                $result .= $pName . '="' . self::oauthEscape($pValue) . '", ';
            }
        }

        return preg_replace('/, $/', '', $result);
    }

    /**
     * @param $paramString
     * @return array
     */
    protected function parseParameterString($paramString)
    {
        $elements = explode('&', $paramString);
        $result = array();
        foreach ($elements as $element) {
            list ($key, $token) = explode('=', $element);
            if ($token) {
                $token = urldecode($token);
            }
            if (!empty($result[$key])) {
                if (!is_array($result[$key])) {
                    $result[$key] = array($result[$key],$token);
                } else {
                    array_push($result[$key], $token);
                }
            } else {
                $result[$key]=$token;
            }
        }
        return $result;
    }

    /**
     * @param $string
     * @return int|mixed|string
     * @throws OAuthSimpleException
     */
    protected static function oauthEscape($string)
    {
        if ($string === 0) {
            return 0;
        }
        if ($string == '0') {
            return '0';
        }
        if (strlen($string) == 0) {
            return '';
        }
        if (is_array($string)) {
            throw new OAuthSimpleException('Array passed to oauthEscape');
        }
        $string = urlencode($string);

        //FIX: urlencode of ~ and '+'
        $string = str_replace(['%7E', '+'], ['~', '%20'], $string);

        return $string;
    }

    /**
     * @param int $length
     * @return string
     */
    protected function getNonce($length = 5)
    {
        $result = '';
        $cLength = strlen($this->nonce_chars);
        for ($i = 0; $i < $length; $i++) {
            $rnum = rand(0, $cLength - 1);
            $result .= substr($this->nonce_chars, $rnum, 1);
        }
        $this->parameters['oauth_nonce'] = $result;

        return $result;
    }

    /**
     * @return mixed
     * @throws OAuthSimpleException
     */
    protected function getApiKey()
    {
        if (empty($this->secrets['consumer_key'])) {
            throw new OAuthSimpleException('No consumer_key set for OAuthSimple');
        }
        $this->parameters['oauth_consumer_key'] = $this->secrets['consumer_key'];

        return $this->parameters['oauth_consumer_key'];
    }

    /**
     * @return string
     * @throws OAuthSimpleException
     */
    protected function getAccessToken()
    {
        if (!isset($this->secrets['oauth_secret'])) {
            return '';
        }

        if (!isset($this->secrets['oauth_token'])) {
            throw new OAuthSimpleException('No access token (oauth_token) set for OAuthSimple.');
        }

        $this->parameters['oauth_token'] = $this->secrets['oauth_token'];

        return $this->parameters['oauth_token'];
    }

    /**
     * @return int
     */
    protected function getTimeStamp()
    {
        return $this->parameters['oauth_timestamp'] = time();
    }

    /**
     * @return string
     * @throws OAuthSimpleException
     */
    protected function normalizedParameters()
    {
        $normalized_keys = array();
        $return_array = array();

        foreach ($this->parameters as $paramName => $paramValue) {
            if (preg_match('/w+_secret/', $paramName)
                || $paramName == "oauth_signature") {
                continue;
            }
            // Read parameters from a file. Hope you're practicing safe PHP.
            if (strpos($paramValue, '@') === 0) {
                try {
                    $file_exists = file_exists(substr($paramValue, 1));
                } catch (\ErrorException $e) {
                    $file_exists = false;
                }

                if ($file_exists) {
                    continue;
                }
            }

            if (is_array($paramValue)) {
                $normalized_keys[self::oauthEscape($paramName)] = array();
                foreach ($paramValue as $item) {
                    array_push($normalized_keys[self::oauthEscape($paramName)], self::oauthEscape($item));
                }
            } else {
                $normalized_keys[self::oauthEscape($paramName)] = self::oauthEscape($paramValue);
            }
        }

        ksort($normalized_keys);

        foreach ($normalized_keys as $key => $val) {
            if (is_array($val)) {
                sort($val);
                foreach ($val as $element) {
                    array_push($return_array, $key . "=" . $element);
                }
            } else {
                array_push($return_array, $key . '=' . $val);
            }
        }
        $presig = join("&", $return_array);
        $sig = $this->generateSignature($presig);
        $this->parameters['oauth_signature'] = $sig;
        array_push($return_array, "oauth_signature=$sig");
        return join("&", $return_array);
    }

    /**
     * @param string $parameters
     * @return string
     * @throws OAuthSimpleException
     */
    protected function generateSignature($parameters = "")
    {
        $secretKey = '';
        if (isset($this->secrets['shared_secret'])) {
            $secretKey = self::oauthEscape($this->secrets['shared_secret']);
        }

        $secretKey .= '&';
        if (isset($this->secrets['oauth_secret'])) {
            $secretKey .= self::oauthEscape($this->secrets['oauth_secret']);
        }
        if (!empty($parameters)) {
            $parameters = urlencode($parameters);
        }
        switch ($this->parameters['oauth_signature_method']) {
            case 'PLAINTEXT':
                return urlencode($secretKey);
            case 'HMAC-SHA1':
                $this->sbs = self::oauthEscape($this->action).'&'.self::oauthEscape($this->path).'&'.$parameters;

                return base64_encode(hash_hmac('sha1', $this->sbs, $secretKey, true));
            default:
                throw new OAuthSimpleException('Unknown signature method for OAuthSimple');
                break;
        }
    }
}
