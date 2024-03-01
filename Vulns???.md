


# <font color="red">XSS</font>
#### 1- check for any value you can control (parameter , path, header, cookie) is being reflected in the **HTML** or used by **JS** code  
#### if reflected: 
####  <font color="red">   in raw HTML : </font>
#####           1- create HTML tag?
#####           2-use events or attribiutes supporting javascript: protocol ?
#####           3- HTML content being interpreted by any client side JS engine (Angular , Vue , Mavo ...)? -> you can abuse  a [CSTI](https://book.hacktricks.xyz/pentesting-web/client-side-template-injection-csti) and [THIS](https://portswigger.net/research/abusing-javascript-frameworks-to-bypass-xss-mitigations)

#####           4-bypass protection
#####           5-if can not create tags that excecute JS code , could you abuse [dangling markup](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection) 


####     <font color="red">in  HTML tag :</font> 
#####     1-exit the html tag?
#####     2-create new events/attributes to execute JS code?
#####     3-the attr you trapped support JS execution? 
#####     4-bypass protection?
#####     NOTE: If your input is reflected inside "**unexpoitable tags**" you could try the `**accesskey**` trick to abuse the vuln (you will need some kind of social engineer to exploit this): `**" accesskey="x" onclick="alert(1)" x="**`

####    <font color="red"> in JavaScript code :</font > 
#####     1-escape `<script>` tag?
#####     2-escape string execute your own js code?
#####     3-are your input in template literals \`\`?
#####     4-bypass protection?
#####     <font color="green">NOTE</font>: If reflected between `**<script> [...] </script>**` tags, even if your input if inside any kind of quotes, you can try to inject `</script>` and escape from this context. This works because the **browser will first parse the HTML tags** and then the content, therefore, it won't notice that your injected `</script>` tag is inside the HTML code.

#####    <font color="green"> NOTE</font>: If reflected **inside a JS string** and the last trick isn't working you would need to **exit** the string, **execute** your code and **reconstruct** the JS code (if there is any error, it won't be executed:

#####     <font color="green"> NOTE</font>: If reflected inside template literals you can **embed JS expressions** using `${ ... }` syntax: `` var greetings = `Hello, ${alert(1)}` ``
#####    <font color="green"> NOTE</font>: unicode encode works for writing valid javascript codes
	\u{61}lert(1) \u0061lert(1) \u{0061}lert(1)

####     <font color="red">in JavaScript file being executed :</font>
#####         1-indicate the name of function to execute e.g `?callback=alert(1)`

#####    <font color="green"> NOTE</font>: everal web pages have endpoints that accept as parameter **the name of the function to execute**. firstElementChild
`lastElementChild, nextElementSibiling, lastElementSibiling, parentElement` 
#####     <font color="red"> SOME(Same Origin Method Execution)</font>
######         the attack flow is the following:
######            . Find a **callback that you can abuse** (potentially limited to \[\\w\\._\]).

######             If it's not limited and you can execute any JS, you could just abuse this as a regular XSS
######             . Make the **victim open a page** controlled by the **attacker**
######            . The **page will open itself** in a **different window** (the new window will have the object `**opener**` referencing the initial one)

######             . The **initial page** will load the **page** where the **interesting DOM** is located.
######             . The **second page** will load the **vulnerable page abusing the callback** and using the `**opener**` object to **access and execute some action in the initial page** (which now contains the interesting DOM).

#### if used : 

## <font color="GREEN"> TO READ </font>
### <font color="orange">LINKS:</font>
- [ ]  https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting 
- [ ]  https://portswigger.net/research/dom-based-angularjs-sandbox-escapes#indirectcall 
- [x] https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/debugging-client-side-js
- [x] https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/js-hoisting
- [x] https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/some-same-origin-method-execution
- [ ] https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-xss


# <font color="red">RCE</font>


# <font color="red" >XXE</font>


# <font color="red">RACE</font>


# <font color="red">CORS</font>



# <font color="red">SQLi</font> 



# <font color="red"> HOST HEADER INJ..</font>


# <font color="red">HTTP SMUGGLING </font>



# <font color="red">FILE INCLUSION / PATH TRAVERSAL</font>


# <font color="red">0Auth</font>


# <font color="red" >SSTI</font>


# <font color="red">CSTI</font>

# <font color="red">SSRF</font>


# <font color="red"> COMMAND INJ..</font>

# <font color="red">OPEN REDIRECT</font>
#### NOTE: THERE IS A WAY TO CHAIN OPEN REDIRECTS TO SSRF AND I DONT KNOW IT YET


# <font color ="red">ESI INJ..</font>


# <font color="red">NOSQL</font>


# <font color="red">LDAP INJ..</font>

# <font color="red">XPATH</font>

# <font color="red">CLICKJACKING</font>

# <font color="red">CSP BYPASS</font>

# <font color="red">COOKIE HACKING</font>

# <font color="red">2FA/OTP BYPASS</font>

# <font color="red">CAPTCHA BYPASS</font>

# <font color="red">RATE LIMIT BYPASS</font>

# <font color="red">LOGIN BYPASS</font>

# <font color="red">DESERIALIZATION </font>
#### <font color="red">NOTE</font> JWT supports a none option for the algorithm type. If the alg field is set to none, even tokens with empty signature sections would be considered valid.

# <font color="red">JWT VULNS </font>

# <font color="red">IDOR</font>

# <font color="red">DOMAIN/SUBDOMAIN TAKEOVER </font>

# <font color="red">PARAM POLLUTION </font>
