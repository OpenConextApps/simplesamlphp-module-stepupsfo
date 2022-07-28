<?php

use \SimpleSAML\Configuration;

/**
 * Receive an assertion from SFO
 *
 * @package SimpleSAMLphp
 */

function handleStatusResponse($exception, $selfserviceurl)
{
    // the status of the response wasn't "success"
    SimpleSAML\Logger::debug('SFO - status response received, showing error page.');
    $config = SimpleSAML\Configuration::getInstance();

    $t = new SimpleSAML\XHTML\Template($config, 'stepupsfo:handlestatus.php');
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
    throw new SimpleSAML\Error\BadRequest('Only HTTP-POST binding supported for SFO.');
}

$response = $b->receive();
if (!($response instanceof \SAML2\Response)) {
    throw new SimpleSAML\Error\BadRequest('Invalid message received to SFO AssertionConsumerService endpoint.');
}

$issuer = $response->getIssuer();
$relaystate = $response->getRelayState();
$inResponseTo = $response->getInResponseTo();

SimpleSAML\Logger::info('SFO - received response; Issuer = ' . var_export($issuer,true) .
    ', InResponseTo = ' . var_export($inResponseTo,true));
SimpleSAML\Logger::debug('SFO - received response; RelayState = ' . $relaystate);

$prestate = SimpleSAML\Auth\State::loadState($relaystate, 'stepupsfo:pre');
$spMetadata = $prestate['sfo:sp:metadata'];
$idpEntityId = $prestate['sfo:idp:entityid'];

// check that the issuer is the one we are expecting
if ($idpEntityId !== $issuer) {
    throw new SimpleSAML\Error\Exception(
        'The issuer of the response does not match to the SFO identity provider ' .
        'we sent the request to.'
    );
}

// Look up metadata for the IdP
$metadataHandler = SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
try {
    $idpMetadata = $metadataHandler->getMetaDataConfig($idpEntityId, 'saml20-idp-remote');
} catch (Exception $e) {
    /* Not found. */
    throw new SimpleSAML\Error\Exception('Could not find the metadata of SFO IdP with entity ID ' .
        var_export($entityId, true));
}

// Validate the received response
try {
    $assertions = \SimpleSAML\Module\sam\Message::processResponse($spMetadata, $idpMetadata, $response);
} catch (SimpleSAML\Module\saml\Error $e) {
    handleStatusResponse($e, $idpMetadata->getString('sfo:selfserviceUrl', ''));
}

SimpleSAML\Logger::debug('SFO - successful response received, resume processing');
SimpleSAML\Auth\ProcessingChain::resumeProcessing($prestate);
