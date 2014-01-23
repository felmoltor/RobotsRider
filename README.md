Robots Rider
============

The script receives a list of URLs (or a domain name) and visit them looking for robots.txt files.
When there is a "Disallowed" entry in the file, the bot optionally visit it and download a copy of the page to your hard drive to let you explore the page afterwards.

Robots Rider shows you highlighted in red the interesting URL found in the file robots.txt when one or more of the following conditions are met:
- The disallowed URL contains an insteresting word like *"admin", "private" or "upload"*. This list can be customized in file 'config/juicypaths.list'.
- The disallowed URL page Title has an interesting word like *cPanel*,*Control Panel*,*"Members Area*, etc. This list can be customized in file 'config/juicytitles.list'.
- The disallowed URL body content has interesting words like *Index of / & Parent Directory*, *Incorrect syntax near*, *You are using MySQL as an anonymous user* or another useful error messages. This list can be customized in file 'config/juicybody.list'

_TODO_: In near future Google Dorks database will be used for this previous purposes.

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

* -d, --domain: 
    If you provide this option you'l need to have installed and in your PATH the program 'theharvester'. It recollects information about the domain you wan to test and its output will be parsed to obtain all the subdomains related with it. Then, with all those subdomains and virtual hosts, file 'robots.txt' will be requested and explored.
* -u, --urls:
    You provide a file with a big list of URL you want to test with Robots Rider. Either you provide this option or you provide '-d' option. One of this two options is mandatory.
* -v, --[no-]visit: 
    This flag tells Robots Rider if he is allowed to visit, explore and save the disallowed entries found in robots.txt. If you don't provide this option Robots Rider will only list the disallowed entries found in robots.txt
* -F, --[no-]follow: 
    Follow redirections or not (Usually 301 and 302 codes).
* -w, --[no-]wfuzz:
    You'll need to have installed and in your PATH the program 'wfuzz'. When a wildcard ('*') is found in a disallowed entry, Robots Rider can use a dictionary to fuzz this wildcard. For example, if there is a disallowed entry like this '/informes/*.zip', the fuzzer will use a dictionary provided by you to substitute the wildcard. The dictionary used can be configured in file 'config/wfuzz.cfg'.
* -o, --output:
    NOT IMPLEMENTED. Output file name to save the results.
* -L, --loglevel:
    This is the level of verbosity that will be recorded in the logs.

Required gems
-------------

* colorize (0.6.0)
* nokogiri (1.6.0, 1.5.5)

Optional binaries
-----------------

* __The Harvester__ (https://code.google.com/p/theharvester/downloads/list): If you want to use the option '-d' you'll need this program.
* __Wfuzz__ (https://code.google.com/p/wfuzz/downloads/list): If you want to user '-w' options, you'll need this program.
