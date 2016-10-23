<@extends src="./base.ftl">

<@block name="title">
 Change your password
</@block>

<@block name="content">
<form action="${This.path}/sendpassword" method="post" enctype="application/x-www-form-urlencoded" name="sendPassword">
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
	<div class="info">Enter your email</div>
	<div>
	  <input type="text" id="Email" value="${data['Email']}" name="Email" class="email_input" isRequired="true" autofocus required/>
	  <i class="icon-key"></i>
	</div>
	<div>
	  <input type="submit" name="submit" value="Send" />
	</div>
</form>

</@block>
</@extends>