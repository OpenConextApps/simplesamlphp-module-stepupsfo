<?php

declare(strict_types=1);

namespace SimpleSAML\Module\stepupsfo\Controller;

use Exception;
use SAML2\Binding;
use SAML2\HTTPPost;
use SAML2\Response;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\saml\Message;
use SimpleSAML\XHTML\Template;

use function sprintf;
use function var_export;

/**
 * Controller class for the stepupsfo module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\stepupsfo
 */
class SFO
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;


    /**
     * Controller constructor.
     *
     * It initializes the global configuration and auth source configuration for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        Configuration $config
    ) {
        $this->config = $config;
    }


    /**
     * Perform second factor only
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function acs(): Template
    {
        Logger::debug('SFO - receiving response');

        $b = Binding::getCurrentBinding();

        if (!($b instanceof HTTPPost)) {
            throw new Error\BadRequest('Only HTTP-POST binding supported for SFO.');
        }

        $response = $b->receive();
        if (!($response instanceof Response)) {
            throw new Error\BadRequest('Invalid message received to SFO AssertionConsumerService endpoint.');
        }

        $issuer = $response->getIssuer()->getValue();
        $relaystate = $response->getRelayState();
        $inResponseTo = $response->getInResponseTo();

        Logger::info(sprintf(
            'SFO - received response; Issuer = %s, InResponseTo = %s',
            var_export($issuer, true),
            var_export($inResponseTo, true)
        ));
        Logger::debug('SFO - received response; RelayState = ' . $relaystate);

        $prestate = Auth\State::loadState($relaystate, 'stepupsfo:pre');
        $spMetadata = $prestate['sfo:sp:metadata'];
        $idpEntityId = $prestate['sfo:idp:entityid'];

        // check that the issuer is the one we are expecting
        if ($idpEntityId !== $issuer) {
            throw new Error\Exception(
                'The issuer of the response does not match to the SFO identity provider we sent the request to.'
            );
        }

        // Look up metadata for the IdP
        $metadataHandler = MetaDataStorageHandler::getMetadataHandler();
        try {
            $idpMetadata = $metadataHandler->getMetaDataConfig($idpEntityId, 'saml20-idp-remote');
        } catch (Exception $e) {
            /* Not found. */
            throw new Error\Exception(sprintf(
                'Could not find the metadata of SFO IdP with entity ID %s',
                var_export($idpEntityId, true)
            ));
        }

        // Validate the received response
        try {
            $assertions = Message::processResponse($spMetadata, $idpMetadata, $response);
        } catch (Module\saml\Error $e) {
            // the status of the response wasn't "success"
            Logger::debug('SFO - status response received, showing error page.');

            $t = new Template($this->config, 'stepupsfo:handlestatus.twig');
            $t->data['status'] = $e->getStatus();
            $t->data['subStatus'] = $e->getSubStatus();
            $t->data['statusMessage'] = $e->getStatusMessage();
            $t->data['selfserviceUrl'] = $idpMetadata->getOptionalString('sfo:selfserviceUrl', '');

            return $t;
        }

        Logger::debug('SFO - successful response received, resume processing');
        Auth\ProcessingChain::resumeProcessing($prestate);
    }
}
