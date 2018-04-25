<?php
/**
 * Display a message to the user when a SAML Status response has been received
 */
$this->includeAtTemplateBase('includes/header.php');
?>
<h1>Error while performing second factor authentication</h1>

<?php
if (
    $this->data['status'] === "urn:oasis:names:tc:SAML:2.0:status:Responder" &&
    $this->data['subStatus'] === "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" ):
?>

<p>Authentication not successful:<br/><br/>
<strong>
    <?= htmlspecialchars($this->data['statusMessage']) ?>
</strong></p>

<?php
elseif (
    $this->data['status'] === "urn:oasis:names:tc:SAML:2.0:status:Responder" &&
    $this->data['subStatus'] === "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext" ):
?>

<p>You could not be authenticated at the requested level.<br/>
<?=htmlspecialchars($this->data['statusMessage'])?></p>

<p>Do you have a token registered with the required level?<br/><br/>
Please go to the <a href="<?=$this->data['selfserviceUrl']?>">Selfservice Registration Portal</a>
to review or enroll your token.</p>

<?php
else:
?>

<p>Unexpected error occurred while performing second factor authentication.<br/><br/>
<?=htmlspecialchars($this->data['status'])?><br/>
<?=htmlspecialchars($this->data['subStatus'])?><br/>
<?=htmlspecialchars($this->data['statusMessage'])?></p>

<p>Please try again or contact your support desk.</p>

<?php
endif;

$this->includeAtTemplateBase('includes/footer.php');
