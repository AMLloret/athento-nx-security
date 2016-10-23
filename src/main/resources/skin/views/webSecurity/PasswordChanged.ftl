<@extends src="./base.ftl">

<@block name="title">
 ${Context.getMessage('label.rememberPassword.title')}
</@block>

<@block name="content">
<script>
	setTimeout(function(){window.location.replace("${logout}")},6000);
</script>
  
<div class="info">
Fine! You password has been changed.
You are going to be redirected to access the platform to use it.
</div>

</@block>
</@extends>