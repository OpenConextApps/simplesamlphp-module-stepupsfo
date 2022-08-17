<?php

declare(strict_types=1);

namespace SimpleSAML\Module\stepupsfo\Auth\Process;

use Exception;
use SAML2\AuthnRequest;
use SAML2\Binding;
use SAML2\Constants as C;
use SAML2\XML\saml\NameID;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\saml\Message;

use function in_array;
use function sprintf;
use function substr;
use function var_export;

/**
 * @package SimpleSAMLphp
 */
class SFO extends Auth\ProcessingFilter
{
    /** @var \SimpleSAML\Configuration */
    private Configuration $metadata;

    /** @var \SimpleSAML\Configuration */
    private Configuration $idpMetadata;

    /** @var string */
    private string $subjectidattribute;

    /** @var array */
    private array $skipentities = [];


    /**
     * Initialize this filter.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use.
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        $this->subjectidattribute = $config['subjectattribute'];
        if (isset($config['skipentities'])) {
            $this->skipentities = $config['skipentities'];
        }

        $this->idpMetadata = $this->getIdPMetadata($config['idpEntityid']);

        $config['AuthnContextClassRef'] = $config['loa'];
        $this->metadata = Configuration::loadFromArray($config);
    }


    /**
     * Process an authentication response.
     *
     * @param array $state  The state of the response.
     */
    public function process(array &$state): void
    {
        foreach ($this->skipentities as $skip) {
            if ($skip === $state['SPMetadata']['entityid'] || in_array($skip, $state['saml:RequesterID'], true)) {
                Logger::info('SFO - skipping SFO for entity ' . var_export($skip, true));
                return;
            }
        }

        $state['sfo:sp:metadata'] = $this->metadata;
        $state['sfo:idp:entityid'] = $this->idpMetadata->getString('entityid');
        $samlstateid = Auth\State::saveState($state, 'stepupsfo:pre');

        if (empty($state['Attributes'][$this->subjectidattribute])) {
            throw new Exception("Subjectid " . $this->subjectidattribute . " not found in attributes.");
        }

        $subjectid = $state['Attributes'][$this->subjectidattribute][0];
        if (substr($subjectid, 0, 18) !== 'urn:collab:person:') {
            throw new Exception(sprintf(
                "Subjectid %s does not start with urn:collab:person:",
                var_export($subjectid, true)
            ));
        }

        $nameid = new NameID();
        $nameid->setValue($subjectid);

        // Start the authentication request
        $this->startSFO($this->idpMetadata, $nameid, $samlstateid);
    }


    /**
     * Retrieve the metadata of an IdP.
     *
     * @param string $entityId  The entity id of the IdP.
     * @return \SimpleSAML\Configuration  The metadata of the IdP.
     */
    public function getIdPMetadata(string $entityId): Configuration
    {
        $metadataHandler = MetaDataStorageHandler::getMetadataHandler();

        try {
            return $metadataHandler->getMetaDataConfig($entityId, 'saml20-idp-remote');
        } catch (Exception $e) {
            /* Metadata wasn't found. */
            Logger::debug('getIdpMetadata: ' . $e->getMessage());
        }

        /* Not found. */
        throw new Error\Exception(sprintf(
            'Could not find the metadata of an IdP with entity ID %s',
            var_export($entityId, true)
        ));
    }


    /**
     * Send a SAML2 SSO request to the SFO IdP.
     *
     * @param \SimpleSAML\Configuration $idpMetadata  The metadata of the IdP.
     * @param \SAML2\XML\saml\NameID $nameid The unspecified NameID of the principal to perform SFO for.
     * @param string $relay  RelayState to pass
     */
    private function startSFO(Configuration $idpMetadata, NameID $nameid, $relay): void
    {
        $ar = Message::buildAuthnRequest($this->metadata, $idpMetadata);

        $ar->setAssertionConsumerServiceURL(Module::getModuleURL('stepupsfo/acs.php'));

        $ar->setNameId($nameid);
        $ar->setRelayState($relay);

        Logger::debug(sprintf(
            'Sending SAML 2 SFO AuthnRequest for %s to %s with id %s',
            $nameid->getValue(),
            var_export($idpMetadata->getString('entityid'), true),
            $ar->getId()
        ));

        $dst = $idpMetadata->getEndpointPrioritizedByBinding(
            'SingleSignOnService',
            [C::BINDING_HTTP_REDIRECT]
        );

        $ar->setDestination($dst['Location']);

        $b = Binding::getBinding($dst['Binding']);

        $this->sendSAML2AuthnRequest($b, $ar);

        assert(false);
    }


    /**
     * Function to actually send the authentication request.
     *
     * This function does not return.
     *
     * @param \SAML2\Binding $binding  The binding.
     * @param \SAML2\AuthnRequest  $ar  The authentication request.
     */
    private function sendSAML2AuthnRequest(Binding $binding, AuthnRequest $ar): void
    {
        $binding->send($ar);
        assert(false);
    }
}
