<@extends src="./base.ftl">

<@block name="title">
 Change your password
</@block>

<@block name="content">
<form action="${This.path}/changepassword" method="post" enctype="application/x-www-form-urlencoded" name="submitNewPassword">
	<input type="hidden" id="RequestId" value="${data['RequestId']}" name="RequestId"/>
	<#if err??>
	  <div class="errorMessage">
	    ${err}
	  </div>
	</#if>
	<#if info??>
	  <div class="infoMessage">
	    ${info}
	  </div>
	</#if>
	<div class="info">Enter your new password</div>
	<div>
	  <input placeholder="Password" type="password" id="Password" value="${data['Password']}" name="Password" class="login_input" isRequired="true" autofocus required/>
	  <i class="icon-key"></i>
	</div>
	<div>
    <input placeholder="Confirm password" type="password" id="PasswordConfirmation" value="${data['PasswordConfirmation']}" name="PasswordConfirmation" class="login_input" isRequired="true" required/>
    <i class="icon-key"></i>
	</div>
	<div>
	  <input type="submit" name="submit" value="Save" />
	</div>
</form>

</@block>
</@extends>