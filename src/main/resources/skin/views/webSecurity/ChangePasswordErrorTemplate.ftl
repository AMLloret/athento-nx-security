<@extends src="./base.ftl">

<@block name="title">
 ${Context.getMessage('label.rememberPassword.title')}
</@block>

<@block name="content">
<div class="info">
<p>
<#if exceptionMsg??>
  Your change password request cannot be changed : "${exceptionMsg}".
</#if>
<#if error??>
  An error occured during your remember password processs.
</#if>
</p>
<br />
<a href="${logout}" class="button">Close</a>
</div>

</@block>
</@extends>
