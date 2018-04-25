<?php

use \SimpleSAML_Configuration as Configuration;

/**
 * @package SimpleSAMLphp
 */
class sspmod_stepupsfo_Auth_Process_SFO extends SimpleSAML_Auth_ProcessingFilter
{

    private $metadata;
    private $idpMetadata;

    private $subjectidattribute;

    /**
     * Initialize this filter.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        assert(is_array($config));

        $this->subjectidattribute = $config['subjectattribute'];

        $this->idpMetadata = $this->getIdPMetadata($config['idpEntityid']);

        $config['AuthnContextClassRef'] = $config['loa'];
        $this->metadata = Configuration::loadFromArray($config);
    }

    /**
     * Process an authentication response.
     *
     * @param array $state  The state of the response.
     */
    public function process(&$state)
    {
        $state['sfo:sp:metadata'] = $this->metadata;
        $state['sfo:idp:entityid'] = $this->idpMetadata->getString('entityid');
        $samlstateid = SimpleSAML_Auth_State::saveState($state, 'stepupsfo:pre');

        if ( empty($state['Attributes'][$this->subjectidattribute]) ) {
            throw new Exception("Subjectid " . $this->subjectid . " not found in attributes.");
        }

        $subjectid = $state['Attributes'][$this->subjectidattribute][0];
        if ( substr($subjectid,0,18) !== 'urn:collab:person:' ) {
            throw new Exception("Subjectid " . var_export($subjectid,true) . " does not start with urn:collab:person:");
        }

        $nameid = \SAML2\XML\saml\NameID::fromArray(['Value' => $subjectid]);

        // Start the authentication request
        $this->startSFO($this->idpMetadata, $nameid, $samlstateid);
    }

    /**
     * Retrieve the metadata of an IdP.
     *
     * @param string $entityId  The entity id of the IdP.
     * @return SimpleSAML_Configuration  The metadata of the IdP.
     */
    public function getIdPMetadata($entityId)
    {
        assert(is_string($entityId));

        $metadataHandler = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();

        try {
            return $metadataHandler->getMetaDataConfig($entityId, 'saml20-idp-remote');
        } catch (Exception $e) {
            /* Metadata wasn't found. */
            SimpleSAML\Logger::debug('getIdpMetadata: ' . $e->getMessage());
        }

        /* Not found. */
        throw new SimpleSAML_Error_Exception('Could not find the metadata of an IdP with entity ID ' .
            var_export($entityId, true));
    }

    /**
     * Send a SAML2 SSO request to the SFO IdP.
     *
     * @param SimpleSAML_Configuration $idpMetadata  The metadata of the IdP.
     * @param NameID $nameid The unspecified NameID of the principal to perform SFO for.
     * @param string $relay  RelayState to pass
     */
    private function startSFO(SimpleSAML_Configuration $idpMetadata, $nameid, $relay)
    {
        $ar = sspmod_saml_Message::buildAuthnRequest($this->metadata, $idpMetadata);

        $ar->setAssertionConsumerServiceURL(SimpleSAML\Module::getModuleURL('stepupsfo/acs.php'));

        $ar->setNameId($nameid);
        $ar->setRelayState($relay);

        SimpleSAML\Logger::debug('Sending SAML 2 SFO AuthnRequest for ' . $nameid->value .  ' to ' .
            var_export($idpMetadata->getString('entityid'), true). ' with id ' . $ar->getId());

        $dst = $idpMetadata->getDefaultEndpoint('SingleSignOnService',
                array( \SAML2\Constants::BINDING_HTTP_REDIRECT )
            );

        $ar->setDestination($dst['Location']);

        $b = \SAML2\Binding::getBinding($dst['Binding']);

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
    private function sendSAML2AuthnRequest( \SAML2\Binding $binding, \SAML2\AuthnRequest $ar)
    {
        $binding->send($ar);
        assert(false);
    }
}
