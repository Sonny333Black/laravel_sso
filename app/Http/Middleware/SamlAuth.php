<?php

namespace App\Http\Middleware;

use Illuminate\Http\Request;
use Closure;
use App\Http\Controllers\SamlIdpController;
use Illuminate\Support\Facades\Storage;
use LightSaml\Model\Protocol\Response as Response;
use Illuminate\Support\Facades\Log;

class SamlAuth
{
    /**
     * Create a new controller instance, directly handle an http request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public function __construct($request)
    {
        $SAML = $request->SAMLRequest;
        $decoded = base64_decode($SAML);
        $xml = gzinflate($decoded);
        $deserializationContext = new \LightSaml\Model\Context\DeserializationContext();
        $deserializationContext->getDocument()->loadXML($xml);
        $authnRequest = new \LightSaml\Model\Protocol\AuthnRequest();
        $authnRequest->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);
        $this->buildSAMLResponse($authnRequest, $request);
    }

    /**
     * Get the failed login response instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    protected function buildSAMLResponse($authnRequest, $request)
    {
        // Get the saml auth request url (also base64 encoded)
        Log::debug('Assertion URL: ' . $authnRequest->getAssertionConsumerServiceURL());
        Log::debug('Assertion URL: ' . base64_encode($authnRequest->getAssertionConsumerServiceURL()));

        $destination = config('saml.sp.'.base64_encode($authnRequest->getAssertionConsumerServiceURL()).'.destination');
        $issuer = config('saml.sp.'.base64_encode($authnRequest->getAssertionConsumerServiceURL()).'.issuer');

        // Note: Storing the certificate key in an openly accessible path is very insecure !
        $certificate = \LightSaml\Credential\X509Certificate::fromFile(storage_path('saml/').config('saml.idp.cert'));
        $privateKey = \LightSaml\Credential\KeyHelper::createPrivateKey(storage_path('saml/').config('saml.idp.key'), '', true);

        $response = new \LightSaml\Model\Protocol\Response();
        $response
            ->addAssertion($assertion = new \LightSaml\Model\Assertion\Assertion())
            ->setID(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination($destination)
            ->setIssuer(new \LightSaml\Model\Assertion\Issuer($issuer))
            ->setStatus(new \LightSaml\Model\Protocol\Status(new \LightSaml\Model\Protocol\StatusCode(\LightSaml\SamlConstants::STATUS_SUCCESS)))
//            ->setStatus(new \LightSaml\Model\Protocol\Status(new \LightSaml\Model\Protocol\StatusCode('urn:oasis:names:tc:SAML:2.0:status:Success')))
            ->setSignature(new \LightSaml\Model\XmlDSig\SignatureWriter($certificate, $privateKey))
        ;

        if(\Auth::check()){
            $email= \Auth::user()->email;
            $name = \Auth::user()->name;
        }else {
            $email = $request['email'];
            $name = 'Place Holder';
        }

        $assertion
            ->setId(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setIssuer(new \LightSaml\Model\Assertion\Issuer($issuer))

            ->setSubject(
                (new \LightSaml\Model\Assertion\Subject())
                    ->setNameID(new \LightSaml\Model\Assertion\NameID(
                        $email,
                        \LightSaml\SamlConstants::NAME_ID_FORMAT_EMAIL
                    ))
                    ->addSubjectConfirmation(
                        (new \LightSaml\Model\Assertion\SubjectConfirmation())
                            ->setMethod(\LightSaml\SamlConstants::CONFIRMATION_METHOD_BEARER)
                            ->setSubjectConfirmationData(
                                (new \LightSaml\Model\Assertion\SubjectConfirmationData())
                                    ->setInResponseTo($authnRequest->getId())
                                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                                    ->setRecipient($authnRequest->getAssertionConsumerServiceURL())
                            )
                    )
            )
            ->setConditions(
                (new \LightSaml\Model\Assertion\Conditions())
                    ->setNotBefore(new \DateTime())
                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                    ->addItem(
                        new \LightSaml\Model\Assertion\AudienceRestriction([$authnRequest->getAssertionConsumerServiceURL()])
                    )
            )
            ->addItem(
                (new \LightSaml\Model\Assertion\AttributeStatement())
                    ->addAttribute(new \LightSaml\Model\Assertion\Attribute(
                        \LightSaml\ClaimTypes::EMAIL_ADDRESS,
                        $email
                    ))
                    ->addAttribute(new \LightSaml\Model\Assertion\Attribute(
                        \LightSaml\ClaimTypes::COMMON_NAME,
                        $name
                    ))
            )
            ->addItem(
                (new \LightSaml\Model\Assertion\AuthnStatement())
                    ->setAuthnInstant(new \DateTime('-10 MINUTE'))
                    ->setSessionIndex('_some_session_index')
                    ->setAuthnContext(
                        (new \LightSaml\Model\Assertion\AuthnContext())
                            ->setAuthnContextClassRef(\LightSaml\SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
                    )
            )
        ;

        $this->sendSAMLResponse($response);
    }

    /**
     * Send saml response object (print out)
     *
     * @param  \LightSaml\Model\Protocol\Response  $response
     * @return \Illuminate\Http\RedirectResponse
     */
    protected function sendSAMLResponse(Response $response)
    {
        Log::debug('Send SAML Response');
        $bindingFactory = new \LightSaml\Binding\BindingFactory();
        $postBinding = $bindingFactory->create(\LightSaml\SamlConstants::BINDING_SAML2_HTTP_POST);
        $messageContext = new \LightSaml\Context\Profile\MessageContext();
        $messageContext->setMessage($response)->asResponse();
        /** @var \Symfony\Component\HttpFoundation\Response $httpResponse */
        $httpResponse = $postBinding->send($messageContext);

        // Make a debug log for retrieving the saml response data
        Log::debug('Message send, http response content: \n'. $httpResponse->getContent().'\n\n');

        print $httpResponse->getContent()."\n\n";
    }
}