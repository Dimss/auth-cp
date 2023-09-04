<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Token page</title>
</head>
<body>

<script>
    function login() {
        let cookieName = "{{ .AuthCookie }}"
        let cookieValue = document.getElementById("input-token-id").value
        let expireDate = new Date();
        expireDate.setMonth(expireDate.getMonth() + 3)
        document.cookie = cookieName + "=" + cookieValue + ";expires=" + expireDate + ";path=/"
        location.reload();
    }
</script>

<div>
    <h1>Insert token</h1>
    <label> Authentication token: <input id="input-token-id"/></label>
    <button onclick="login()">GO</button>
</div>

</body>
</html>