StepupSFO authproc module
=========================

This module provides an authentication processing filter for OpenConext
Stepup Second Factor Only. After the first factor authentication on
the hosted idp this filter can be invoked to verify the second factor.

The module requires the following:
1. Metadata for the SFO endpoint in saml20-idp-remote.
1. Configuration of the authproc's own metadata.
1. An attribute containing the full collabPersonId of the authenticated
   user to send to SFO.

You can get the metadata of the SFO endpoint from the party running that
endpoint. In `saml20-idp-remote.php` it could look like this. Note that
SHA-256 and signed authentication requests are mandatory. Optionally
you can add the `sfo:selfserviceurl` config parameter used in the
feedback message when a user does not have a token registered.

    $metadata['https://gateway.pilot.stepup.surfconext.nl/second-factor-only/metadata'] = [
        'certificate' => 'sa_pilot_saml_signing_certificate_pem.crt',
        'metadata-set' => 'saml20-idp-remote',
        'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'SingleSignOnService' => [
              0 => [
                'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                'Location' => 'https://gateway.pilot.stepup.surfconext.nl/second-factor-only/single-sign-on',
              ]],
        'redirect.sign' => true,
        // ssp has broken/fixed the fact that you could set this to null see #771
        //'NameIDPolicy' => null,
        
        'sfo:selfserviceUrl' => 'https://selfservice.pilot.stepup.surfconext.nl/',
    ];

Configuration of the authproc filter could be done in any place that supports
authproc filters, so it runs after the first factor has been authenticated.
You can add it e.g. to `saml20-idp-hosted` authproc to protect an entire IdP,
or if you use it to protect an SP to your `saml20-sp-hosted` configuration.

In the authproc's confg, you will specify the name of the attribute that
contains the exact collabPersonId to send to the SFO endpoint, which looks like
`urn:collab:person:example.org:jdoe`.  You can construct this from existing
attributes e.g. with the `core:AttributeAlter` filter. In the example the
existing uid attribute is prefixed with the right urn and stored in the
collabPersonId attribute. SFO is configured to read that attribute.

    'authproc' => [
        // prepare attribute for sfo
        24 => [
                'class' => 'core:AttributeAlter',
                'subject' => 'uid',
                'pattern' => '/^/',
                'replacement' => 'urn:collab:person:example.org:',
                'target' => 'collabPersonId'
        ],
        // fire off sfo
        25 => [
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
            'loa' => 'http://pilot.surfconext.nl/assurance/sfo-level2',

            // optional: list of remote entityids/requesterids for which SFO
            // should NOT be performed, instead they will just pass through.
            // 'skipentities' => [],
        ],
    ]

If you use the module to protect an IdP, you will want to exclude at least the
token registration portal via the `skipentities` setting, if that portal uses
said IdP for authentication.

After setting the configuration up, you supply the following to the persons
running the SFO service:
- The entityid and certificate configured in the authsource above.
- The namespace of the subjectattribute you're using (likely something like `urn:collab:person:example.org:`).
- The AssertionConsumerService location: `<your ssp base url>/module.php/stepupsfo/acs.php`.
