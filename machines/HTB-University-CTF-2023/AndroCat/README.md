# HTB University CTF 2023 Write-Up: AndroCat

## Challenge

- We are given an android APK for some kind of student app (CampusConnect)
- And the IP of a server running ssh and a web service (API) at port 80

## Foothold + User

- Emulate an Android device using Genymotion
- Install APK and setup proxy to intercept requests using Burp
- Register and login into the app
- We have 2 functionalities
  - Submit posts: vulnerable to XSS
  - Submit study materials
- There's also a note saying that teachers will review all student posts
- By reversing the APK we see that:
  - The user token (for students and teachers) is stored in shared preferences and in the webview's local storage
  - The admin token (for teachers) is stored in shared preferences only
  - There's 3 endpoints that can only be hit using the admin token:
    - /api/users
    - /api/attendance
    - /api/exportAttendance
- Using the XSS we can leak the teacher's token from local storage but it's not enough as we also need admin token
- Shared preferences are stored as an XML file in the APK in `./shared_prefs/user.xml`
- By trying to fetch that file using the XSS, we get access denied
- There's a piece of code related to caching in the APK that seems vulnerable to path traversal, the piece of code is exactly the one in this blog: <https://0xn3va.gitbook.io/cheat-sheets/android-application/webview-vulnerabilities/web-resource-response-vulnerabilities>
- We use the PoC in the blog to retrieve the admin token from `./shared_prefs/user.xml`
- With the admin token we explore the 3 endpoints we saw before:
  - `/api/users`: returns users
  - `/api/attendance`: returns students' attendance
  - `/api/exportAttendance`: exports students' attendance as a PDF
- When we export attendance we see that our created user's name is reflected in the PDF, so we could maybe try to use some payloads from <https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf#read-local-file-ssrf> to read local files
- We create a user with the name `<iframe src=file:///etc/passwd></iframe>` and export attendance, and indeed we get back the contents of `/etc/passwd` in the PDF
- In `/etc/passwd` we see a user named `rick`, so we try the same payload to leak his ssh private key `/home/rick/.ssh/id_rsa`
- And it works, we can now ssh into the box as user `rick` and can retrieve the first flag `user.txt`

## Root

- We do some standard enumeration using tools like `linpeas`, and we see an odd root process running a `nodejs` server on port 8080 with an option called `--experimental-permission` with 2 permission rules set:
  - `--allow-fs-read=/root/serviceManager/`
  - `--allow-fs-write=/root/serviceManager/`
- We forward the port to local machines using SSH tunneling so we can look into the web server, and after some digging we find an SSTI vulnerability in the email template feature (templating engine used is `nunjucks`)
- We try some RCE payloads but no luck, even trying to read root flag `/root/root.txt` doesn't work
- After reading documentation from <https://nodejs.org/api/permissions.html>, we conclude that this means the `nodejs` server can only access files for read/write in directory `/root/serviceManager` and it's not possible to execute child processes because for that to work a separate permission option has to be set
- After a lot of digging, while keeping in mind that the node version used on the server is `20.5.0`, we find this in the official release page of `nodejs`: <https://github.com/nodejs/node/releases/tag/v20.5.1>
- So there's a lot of CVEs related to bypassing the experimental permissions model
- We tried this one first: [CVE-2023-32558](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32558): process.binding() can bypass the permission model through path traversal (High)
- The HackerOne report for it contains a PoC, but when we tried it the server crashed and we had to restart the whole box
- Next up we tried this one: [CVE-2023-32004](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32004): Permission model can be bypassed by specifying a path traversal sequence in a Buffer (High)
- The HackerOne report doesn't contain any details about the PoC so we decided to write one ourselves by looking at the commit that fixes this issue <https://github.com/nodejs/node/commit/1f0cde466b>
- We came up with this payload:

```jinja2
{{range.constructor("return global.process.mainModule.require('fs').readFileSync(Buffer.from('/root/serviceManager/../root.txt')).toString()")()}}
```

- And it works, we get the root flag with it
