# ZAP authenticated scan

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 1 |
| Medium | 1 |
| Low | 0 |
| Informational | 2 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 13    |
| Info | Informational |  | Percentage of network failures | 1 % |
| Info | Informational | http://bank-safe:3000 | Percentage of responses with status code 2xx | 57 % |
| Info | Informational | http://bank-safe:3000 | Percentage of responses with status code 3xx | 20 % |
| Info | Informational | http://bank-safe:3000 | Percentage of responses with status code 4xx | 22 % |
| Info | Informational | http://bank-safe:3000 | Percentage of endpoints with content type text/css | 8 % |
| Info | Informational | http://bank-safe:3000 | Percentage of endpoints with content type text/html | 75 % |
| Info | Informational | http://bank-safe:3000 | Percentage of endpoints with content type text/plain | 16 % |
| Info | Informational | http://bank-safe:3000 | Percentage of endpoints with method GET | 83 % |
| Info | Informational | http://bank-safe:3000 | Percentage of endpoints with method POST | 16 % |
| Info | Informational | http://bank-safe:3000 | Count of total endpoints | 12    |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| SQL Injection | High | 1 |
| CSP: Failure to Define Directive with No Fallback | Medium | 4 |
| User Agent Fuzzer | Informational | Systemic |
| User Controllable HTML Element Attribute (Potential XSS) | Informational | 2 |




## Alert Detail



### [ SQL Injection ](https://www.zaproxy.org/docs/alerts/40018/)



##### High (Medium)

### Description

SQL injection may be possible.

* URL: http://bank-safe:3000/account%3Fnotice=Sent+%25E2%2582%25AC3+to+mallory+AND+1%253D1+--+
  * Node Name: `http://bank-safe:3000/account (notice)`
  * Method: `GET`
  * Parameter: `notice`
  * Attack: `Sent €3 to mallory OR 1=1 -- `
  * Evidence: ``
  * Other Info: `The page results were successfully manipulated using the boolean conditions [Sent €3 to mallory AND 1=1 -- ] and [Sent €3 to mallory OR 1=1 -- ]
The parameter value being modified was stripped from the HTML output for the purposes of the comparison.
Data was NOT returned for the original parameter.
The vulnerability was detected by successfully retrieving more data than originally returned, by manipulating the parameter.`


Instances: 1

### Solution

Do not trust client side input, even if there is client side validation in place.
In general, type check all data on the server side.
If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'
If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.
If database Stored Procedures can be used, use them.
Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or equivalent functionality!
Do not create dynamic SQL queries using simple string concatenation.
Escape all data received from the client.
Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in user input.
Apply the principle of least privilege by using the least privileged database user possible.
In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but minimizes its impact.
Grant the minimum database access that is necessary for the application.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)


#### CWE Id: [ 89 ](https://cwe.mitre.org/data/definitions/89.html)


#### WASC Id: 19

#### Source ID: 1

### [ CSP: Failure to Define Directive with No Fallback ](https://www.zaproxy.org/docs/alerts/10055/)



##### Medium (High)

### Description

The Content Security Policy fails to define one of the directives that has no fallback. Missing/excluding them is the same as allowing anything.

* URL: http://bank-safe:3000/robots.txt
  * Node Name: `http://bank-safe:3000/robots.txt`
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'none'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://bank-safe:3000/sitemap.xml
  * Node Name: `http://bank-safe:3000/sitemap.xml`
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'none'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://bank-safe:3000/static
  * Node Name: `http://bank-safe:3000/static`
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'none'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://bank-safe:3000/static/
  * Node Name: `http://bank-safe:3000/static/`
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'none'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`


Instances: 4

### Solution

Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

### Reference


* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://caniuse.com/#search=content+security+policy ](https://caniuse.com/#search=content+security+policy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)
* [ https://github.com/HtmlUnit/htmlunit-csp ](https://github.com/HtmlUnit/htmlunit-csp)
* [ https://web.dev/articles/csp#resource-options ](https://web.dev/articles/csp#resource-options)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: http://bank-safe:3000/account
  * Node Name: `http://bank-safe:3000/account`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://bank-safe:3000/account%3Fnotice=Sent%2520%25E2%2582%25AC3%2520to%2520mallory
  * Node Name: `http://bank-safe:3000/account (notice)`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://bank-safe:3000/transfer
  * Node Name: `http://bank-safe:3000/transfer ()(amount,csrf,to)`
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``

Instances: Systemic


### Solution



### Reference


* [ https://owasp.org/www-project-web-security-testing-guide/ ](https://owasp.org/www-project-web-security-testing-guide/)



#### Source ID: 1

### [ User Controllable HTML Element Attribute (Potential XSS) ](https://www.zaproxy.org/docs/alerts/10031/)



##### Informational (Low)

### Description

This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.

* URL: http://bank-safe:3000/transfer%3Fto=mallory&amount=10
  * Node Name: `http://bank-safe:3000/transfer (amount,to)`
  * Method: `GET`
  * Parameter: `amount`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://bank-safe:3000/transfer?to=mallory&amount=10

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
amount=10

The user-controlled value was:
10`
* URL: http://bank-safe:3000/transfer%3Fto=mallory&amount=10
  * Node Name: `http://bank-safe:3000/transfer (amount,to)`
  * Method: `GET`
  * Parameter: `to`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://bank-safe:3000/transfer?to=mallory&amount=10

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
to=mallory

The user-controlled value was:
mallory`


Instances: 2

### Solution

Validate all input and sanitize output it before writing to any HTML attributes.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)


#### CWE Id: [ 20 ](https://cwe.mitre.org/data/definitions/20.html)


#### WASC Id: 20

#### Source ID: 3


