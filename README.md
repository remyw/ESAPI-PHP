### What is ESAPI?
ESAPI (The OWASP Enterprise Security API - catchy, eh?) is a free, open source, web application security control library that makes it easier for programmers to write lower-risk applications. The ESAPI libraries are designed to make it easier for programmers to retrofit security into existing applications. The ESAPI libraries also serve as a solid foundation for new development.

Allowing for language-specific differences, all OWASP ESAPI versions have the same basic design:

* There is a set of security control interfaces. They define for example types of parameters that are passed to types of security controls.
* There is a reference implementation for each security control. The logic is not organization-specific and the logic is not application-specific. An example: string-based input validation.
* There are optionally your own implementations for each security control. There may be application logic contained in these classes which may be developed by or for your organization. An example: enterprise authentication.

The following organizations are a few of the many organizations that are starting to adopt ESAPI to secure their web applications: American Express, Apache Foundation, Booz Allen Hamilton, Aspect Security, Coraid, The Hartford, Infinite Campus, Lockheed Martin, MITRE, U.S. Navy - SPAWAR, The World Bank, SANS Institute.

###Is this the official repository?
Not currently. For the official repository go [here](http://code.google.com/p/owasp-esapi-php/). The move to github is an experiment to see if it will raise community awareness and involvement in the ESAPI project and other OWASP initiatives.

###Where can I find more information?
The official [OWASP ESAPI](https://www.owasp.org/index.php/Category:OWASP_Enterprise_Security_API) website provides a wealth of information about all of the ESAPI language variants.

The [OWASP website](https://www.owasp.org/index.php/Main_Page) is an invaluable resource on security mitigation techniques and other great security related projects.

### License Information
The source code is licensed under the BSD license, which is very permissive and about as close to public domain as is possible. The project documentation is licensed under the Creative Commons license. You can use or modify ESAPI however you want, even include it in commercial products.