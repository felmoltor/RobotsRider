Robots Rider
============

The script receives a list of URLs and visit them looking for robots.txt files.
When there is a "Disallowed" entry in the file, the bot optionally visit it and download a copy of the page to your hard drive to let you explore the page afterwards.

It also prints you in red color if there is a special word discovered in the robots.txt file, like **"admin", "private" or "upload"**.
This special word list can be found in the file __'juicypaths.list'__ and can be customized.

The script can be executed with this options:

```
Usage: ./robotsrider.rb [OPTIONS]
    -d, --domain DOMAIN              Domain to explore for robots.txt (This option needs program 'theharvester' in your PATH)
    -u, --urls FILE                  File containing the list of URLs to check for robots.txt
    -v, --[no-]visit                 Visit the disallowed entries and record the server response [default: True]
    -F, --[no-]follow                Follow redirect for disallowed entries with 30X responses [default: False]
    -w, --[no-]wfuzz                 Use wfuzz program to fuzz wildcards in the disallowed entries [Default: False]
    -o, --output                     TODO: Save the summary of the execution to this beautiful HTML file
    -L, --loglevel [LOGLEVEL]        Set loggin level (DEBUG, WARN, ERROR, CRITICAL)  [default: DEBUG]
    -h, --help                       Help screen
```

The script doew not visit URLs containing wildcards like '*' or the root domain, for example, when it is disallowed the path "/".

**Required gems**

* colorize (0.6.0)
* nokogiri (1.6.0, 1.5.5)

** Optional binaries**

* theHarvester (https://code.google.com/p/theharvester/downloads/list): If you prefer to use the option '-d' you'll need this program.
