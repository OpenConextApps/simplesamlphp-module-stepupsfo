StepupSFO authproc module
=========================

This module provides an authentication processing filter for OpenConext
Stepup Second Factor Only. After the first factor authentication on
the hosted idp this filter can be invoked to verify the second factor.

The module requires the following:
1. Metadata for the SFO endpoint in saml20-idp-remote.
1. Configuration of the authproc's own metadata.
1. An attribute containing the full collabPersonId of the authenticated
   user o send to SFO.

You can get the metadata of the SFO endpoint from the party running that
endpoint. In `saml20-idp-remote.php` it could look like this. Note that
SHA-256 and signed authentication requests are mandatory. Optionally
you can add the `sfo:selfserviceurl` config parameter used in the
feedback message when a user does not have a token registered.

    $metadata['https://gateway.pilot.stepup.surfconext.nl/second-factor-only/metadata'] = array (
        'certificate' => 'sa_pilot_saml_signing_certificate_pem.crt',
        'metadata-set' => 'saml20-idp-remote',
        'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'SingleSignOnService' => array(
              0 => array(
                'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                'Location' => 'https://gateway.pilot.stepup.surfconext.nl/second-factor-only/single-sign-on',
              )),
        'redirect.sign' => true,
        // ssp has broken/fixed the fact that you could set this to null see #771
        //'NameIDPolicy' => null,
        
        'sfo:selfserviceUrl' => 'https://selfservice.pilot.stepup.surfconext.nl/',
    );

Configuration of the authproc filter could be done in `saml20-idp-hosted.php` so
it is ran after the first factor has been authenticated. In the authproc's confg,
you will specify the name of the attribute that contains the exact collabPersonId
to send to the SFO endpoint, which looks like `urn:collab:person:example.org:jdoe`.
You can construct this from existing attributes e.g. with the `core:AttributeAlter`
filter. In the example the existing uid attribute is prefixed with the right urn
and stored in the collabPersonId attribute. SFO is configured to read that attribute.


    'authproc' => array(
        // prepare attribute for sfo
        24 => array(
                'class' => 'core:AttributeAlter',
                'subject' => 'uid',
                'pattern' => '/^/',
                'replacement' => 'urn:collab:person:example.org:',
                'target' => 'collabPersonId'
        ),
        // fire off sfo
        25 => array(
            'class' => 'stepupsfo:SFO',

            // attribute to use as identifier to the sfo idp
            'subjectattribute' => 'collabPersonId',

            // hosted sfo-sp metadata
            'entityid' => 'https://example.org/',
            'certificate' => 'example.crt',
            'privatekey' => 'example.key',
            'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',

            // entityid to be found in saml20-idp-remote
            'idpEntityid' => 'https://gateway.pilot.stepup.surfconext.nl/second-factor-only/metadata',

            // desired minimum loa
            'loa' => 'http://pilot.surfconext.nl/assurance/sfo-level2'
        ),
    )
