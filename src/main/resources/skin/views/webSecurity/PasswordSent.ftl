<@extends src="./base.ftl">

<@block name="title">
 ${Context.getMessage('label.rememberPassword.title')}
</@block>

<@block name="content">
<script>
	setTimeout(function(){window.location.replace("${logout}")},6000);
</script>
  
<div class="info">
Ready! Check your email browser and click the link to change your password.
</div>

</@block>
</@extends>