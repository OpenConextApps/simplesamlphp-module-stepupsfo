<?php
use \SimpleSAML_Configuration as Configuration;

/**
 * Receive an assertion from SFO
 *
 * @package SimpleSAMLphp
 */

function handleStatusResponse($exception, $selfserviceurl)
{
    // the status of the response wasn't "success"
    SimpleSAML\Logger::debug('SFO - status response received, showing error page.');
    $config = SimpleSAML_Configuration::getInstance();

    $t = new SimpleSAML_XHTML_Template($config, 'stepupsfo:handlestatus.php');
    $t->data['status'] = $exception->getStatus();
    $t->data['subStatus'] = $exception->getSubStatus();
    $t->data['statusMessage'] = $exception->getStatusMessage();
    $t->data['selfserviceUrl'] = $selfserviceurl;
    $t->show();
    exit();
}

SimpleSAML\Logger::debug('SFO - receiving response');

$b = \SAML2\Binding::getCurrentBinding();

if (! $b instanceof \SAML2\HTTPPost) {
    throw new SimpleSAML_Error_BadRequest('Only HTTP-POST binding supported for SFO.');
}

$response = $b->receive();
if (!($response instanceof \SAML2\Response)) {
    throw new SimpleSAML_Error_BadRequest('Invalid message received to SFO AssertionConsumerService endpoint.');
}

$issuer = $response->getIssuer();
$relaystate = $response->getRelayState();
$inResponseTo = $response->getInResponseTo();

SimpleSAML\Logger::info('SFO - received response; Issuer = ' . var_export($issuer,true) .
    ', InResponseTo = ' . var_export($inResponseTo,true));
SimpleSAML\Logger::debug('SFO - received response; RelayState = ' . $relaystate);

$prestate = SimpleSAML_Auth_State::loadState($relaystate, 'stepupsfo:pre');
$spMetadata = $prestate['sfo:sp:metadata'];
$idpEntityId = $prestate['sfo:idp:entityid'];

// check that the issuer is the one we are expecting
if ($idpEntityId !== $issuer) {
    throw new SimpleSAML_Error_Exception(
        'The issuer of the response does not match to the SFO identity provider ' .
        'we sent the request to.'
    );
}

// Look up metadata for the IdP
$metadataHandler = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();
try {
    $idpMetadata = $metadataHandler->getMetaDataConfig($idpEntityId, 'saml20-idp-remote');
} catch (Exception $e) {
    /* Not found. */
    throw new SimpleSAML_Error_Exception('Could not find the metadata of SFO IdP with entity ID ' .
        var_export($entityId, true));
}

// Validate the received response
try {
    $assertions = sspmod_saml_Message::processResponse($spMetadata, $idpMetadata, $response);
} catch (sspmod_saml_Error $e) {
    // the status of the response wasn't "success" (SSP < 1.17)
    handleStatusResponse($e, $idpMetadata->getString('sfo:selfserviceUrl', ''));
} catch (SimpleSAML\Module\saml\Error $e) {
    // the status of the response wasn't "success" (SSP >= 1.17)
    handleStatusResponse($e, $idpMetadata->getString('sfo:selfserviceUrl', ''));
}

SimpleSAML\Logger::debug('SFO - successful response received, resume processing');
SimpleSAML_Auth_ProcessingChain::resumeProcessing($prestate);
