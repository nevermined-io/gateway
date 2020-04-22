History
=======

0.6.0 (October 9th, 2019)
------------------------
* Add execute endpoint

0.5.2 (September 17th, 2019)
----------------------------
* Fix access token issue

0.5.1 (September 11th, 2019)
----------------------------
* Fix signature issue

0.5.0 (September 6th, 2019)
--------------------------
* Update ocean-utils to work with the new ddos structure.

0.4.4 (Sep 16, 2019)
------------------------
* Support `ipfs` files by using the osmosis-ipfs-driver

0.4.1 (September 2nd, 2019)
---------------------------
* Upgrade the keeper contracts to v0.11.1

0.4.0 (Sep 10, 2019)
------------------------
* Keep only the proxy in Brizo and move events handling to a 
separate stand-alone tool
* Remove squid-py dependency, instead use the lower level ocean 
libraries that were split out of squid-py (ocean-utils and ocean-keeper)
* Remove support for the `initialize` endpoint

0.3.14 (July 16th ,2019)
-------------------------
* Fix error when running on Pacific network.

0.3.13 (July 3rd ,2019)
-------------------------
* Update squid-py version with improved events handling.

0.3.12 (Jun 21nd, 2019)
------------------------
* Not dispenser when pacific network.
* Squid-py 0.6.13

0.3.11 (Jun 20th, 2019)
------------------------ 
* Update with keeper-contracts v0.10.2

0.3.10 (Jun 11th, 2019)
------------------------ 
* Better error handling
* Improved processing of agreement events

0.3.9 (May 29th, 2019)
------------------------ 
* Fix some small issues using squid-py v0.6.7
* Add info about the contracts and version used.

0.3.8 (May 20th, 2019)
------------------------  
* Support the use of auth token in place of signature for off-chain requests.

0.3.7 (May 7th, 2019)
------------------------   
* Use squid-py 0.6.4 with proper keeper-contracts version

0.3.6 (April 30th, 2019)
------------------------   
* Implement watcher to allow consumer initialize the agreement
* Reduce logging
* Use squid-py 0.6.2

0.3.3 (April 5th, 2019)
------------------------ 
* Update entrypoint to add worker timeout as an environment variable

0.3.2 (April 5th, 2019)
------------------------ 
* Download request using streaming.

0.3.1 (April 1st, 2019)
------------------------ 
* Fix signature issue for javascript implementation

0.3.0 (March 29th, 2019)
------------------------ 
* New API to expose the decryption of the Secret Store and make it compatible with squid-js.
* Upgrade squid-py to 0.5.9

0.2.10 (March 26th, 2019)
-------------------------
* Upgrade to squid-py 0.5.7

0.2.9 (March 21th, 2019)
-------------------------
* Update to squid-py 0.5.5
* Fix error with the validation of the signature

0.2.8 (March 20th, 2019)
-------------------------
* Add more logging.
* Use squid-py 0.5.4

0.2.7 (March 19th, 2019)
-------------------------
* Set up the validation of the creator by default to false.


0.2.6 (March 18th, 2019)
-------------------------
* Update to Squid v0.5.3 and keeper v0.8.6


0.2.5 (March 15th, 2019)
-------------------------
* Fix bug in the initialize method.
* Upgrade to squid-py v0.5.2

0.2.4 (March 14th, 2019)
-------------------------
* Using squid-py v0.5.1
* Small bugs fixed

0.2.3 (March 6th, 2019)
-------------------------
* Working with keeper-contracts 0.8.1
* Upgrade squid-py to v0.5.0

0.2.2 (February 21st, 2019)
-------------------------
* Change log level in squid-py
* Upgrade to squid-py 0.4.4

0.2.1 (February 20th, 2019)
-------------------------
* Update to squid-py 0.4.3.

0.2.0 (February 7th, 2019)
-------------------------
* Working with squid-py 0.4.2

0.1.9 (February 1st, 2019)
-------------------------
* Update to squid-py v0.3.3 with the checksum requirement

0.1.8 (January 30th, 2019)
-------------------------
* Compatible with v0.6.11 of keeper-contracts
* Last changes in the OEP-8

0.1.5 (January 17th, 2019)
-------------------------
* Compatibility
    - squid-py 0.2.22
    - keeper-contracts 0.5.3
    - aquarius 0.1.5

0.1.3 (December 14th, 2019)
-------------------------
* Remove aquarius url reference #43

0.1.2 (November 29th, 2019)
-------------------------
* Added redirect to consume
