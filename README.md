Robots Rider
============

Summary
-------

* __Author__: Felipe Molina ([@felmoltor](https://twitter.com/felmoltor))
* __Version__: 0.3
* __Summary__: Detects and deduce CMS from robots.txt, generator Tags, Powered By text. Then, optionaly launch CMS scanners to the targets.
* __Warning__: Check the "__Required third party binaries__" section to download them before executing this tool. 

Introduction
------------

The __first step (1)__ this tool does is to search information about the CMS installed in the target web. This is done with three methods:
* Search Tag "generator" in the web: It provides us with the CMS name and sometimes the exact version.
* Search "Powered By" text in the page: It provides us with the CMS name and sometimes the exact version.
* Deduce the CMS from "robots.txt" file: If it is available, this file will be explored and the "Disallowed" entries on this file will provide us enough information to infere what CMS is installed here. 

The __second step (2)__ is to explore the disallowed entries of robots.txt and visit them to confirm if this entries exists and if they exists, this tool will explore it to see if it seems to be interesting. This "insteresting" entries are highlighted with three methods:

- The disallowed URL contains an insteresting word like *"admin", "private" or "upload"*. This list can be customized in file 'config/juicytext/juicypaths.list'.
- The disallowed URL page Title has an interesting word like *cPanel*,*Control Panel*,*"Members Area*, etc. This list can be customized in file 'config/juicytext/juicytitles.list'.
- The disallowed URL body content has interesting words like *Index of / & Parent Directory*, *Incorrect syntax near*, *You are using MySQL as an anonymous user* or another useful error messages. This list can be customized in file 'config/juicytext/juicybody.list'

_TODO_: In near future Google Dorks database will be used for this previous purposes.

The __third step (3)__ is to execute the appropiate CMS vulnerability scanner when the targeted URL has been properly identified. For now, we only have four (4) CMS scanners for now:

- __WPScan__: Configured in file 'config/scanners/wpscan.cfg'
- __Joomscan__: Configured in file 'config/scanners/joomscan.cfg' _*_
- __DPScan__: Configured in file 'config/scanners/joomscan.cfg'
- __Plown__: Configured in file 'config/scanners/joomscan.cfg'

*Warning*: Current version of Joomscan (0.0.4 - Not maintained anymore) is not correctly working if you invoke the perl script from anywhere in your file system. It only works when you invoke 'joomscan.pl' in the same folder this script it is. To __fix__ this you'll have to overwrite the original 'joomscan.pl' with this patched one (http://pastebin.com/tJxLBcy9).

All those scanners ought to be avaliable in your system before complete this vulnerability phase successfuly. The paths to this scanners must be customized in their own configuration files.

Usage
-----

The script can be executed with this options:

```
Usage: ./robotsrider.rb [OPTIONS]
    -d, --domain DOMAIN              Domain to explore for robots.txt (This option needs program 'theharvester' in your PATH)
    -u, --urls FILE                  File containing the list of URLs to check for robots.txt
    -v, --[no-]visit                 Visit the disallowed entries and record the server response [default: True]
    -F, --[no-]follow                Follow redirect for disallowed entries with 30X responses [default: False]
    -w, --[no-]wfuzz                 Use wfuzz program to fuzz wildcards in the disallowed entries [Default: False]
    -o, --output                     TODO: Save the summary of the execution to this beautiful HTML file
    -L, --loglevel [LOGLEVEL]        Set loggin level (DEBUG, INFO, WARN, ERROR, FATAL)  [default: DEBUG]
    -h, --help                       Help screen
```

Options Details
---------------

* __-d, --domain__: If you provide this option you'l need to have installed and in your PATH the program 'theharvester'. It recollects information about the domain you wan to test and its output will be parsed to obtain all the subdomains related with it. Then, with all those subdomains and virtual hosts, file 'robots.txt' will be requested and explored.
* __-u, --urls__: You provide a file with a big list of URL you want to test with Robots Rider. Either you provide this option or you provide '-d' option. One of this two options is mandatory.
* __-v, --[no-]visit__: This flag tells Robots Rider if he is allowed to visit, explore and save the disallowed entries found in robots.txt. If you don't provide this option Robots Rider will only list the disallowed entries found in robots.txt
* __-F, --[no-]follow__: Follow redirections or not (Usually 301 and 302 codes).
* __-w, --[no-]wfuzz__: You'll need to have installed and in your PATH the program 'wfuzz'. When a wildcard ('\*') is found in a disallowed entry, Robots Rider can use a dictionary to fuzz this wildcard. For example, if there is a disallowed entry like this '/informes/\*.zip', the fuzzer will use a dictionary provided by you to substitute the wildcard. The dictionary used can be configured in file 'config/wfuzz.cfg'.
* __-o, --output__: NOT IMPLEMENTED. Output file name to save the results.
* __-L, --loglevel__: This is the level of verbosity that will be recorded in the logs.

Required gems
-------------

* colorize (0.6.0)
* nokogiri (1.6.0, 1.5.5)

Required third party binaries
-----------------------------

For domain identification, information gathering and CMS scanning we will need to have the following external tools:

* __The Harvester__ (https://code.google.com/p/theharvester/downloads/list): If you want to use the option '-d' you'll need this program.
* __Wfuzz__ (https://code.google.com/p/wfuzz/downloads/list): If you want to user '-w' options, you'll need this program.
* __WPScan__ (https://github.com/wpscanteam/wpscan): This is the CMS scanner you'll need to download if you want to scan for vulnerabilies in __Wordpress__ sites.
* __Joomscan__ (http://sourceforge.net/projects/joomscan/): This is the CMS scanner you'll need to download if you want to scan for vulnerabilies in __Joomla__ sites (_There is a bug with this tool that prevents you to execute it from anywhere in your filesystem, please download [this modified script](http://pastebin.com/tJxLBcy9) to bypass this issue_).
* __DPScan__ (https://github.com/cervoise/DPScan): This is the CMS scanner you'll need to download if you want to scan for installed plugins in __Drupal__ sites.
* __Plown__ (https://github.com/unweb/plown): This is the CMS scanner you'll need to download if you want to scan for vulnerabilities in __Plone CMS__ sites.

