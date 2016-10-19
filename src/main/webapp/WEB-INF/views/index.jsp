<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ page session="false" %>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ESIA</title>
</head>
<body>
<c:url var="actionUrl" value="/esia-get"/>
<form:form class="form-horizontal clearfix" role="form" commandName="oauthParams" action="${actionUrl}" method="get">
    <input type="submit" class="btn btn-primary pull-right" value="Get Authorization" />
</form:form>
</body>