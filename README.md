Robots Rider
============

The script receives a list of URLs and visit them looking for robots.txt files.
When there is a "Disallowed" entry in the file, the bot optionally visit it and download a copy of the page to your hard drive to let you explore the page afterwards.

It also prints you in red color if there is a special word discovered in the robots.txt file, like **"admin", "private" or "upload"**.
This special word list can be found in the file __'juicypaths.list'__ and can be customized.

The script can be executed with this options:

```
Usage: ./robotsrider.rb [OPTIONS]
    -u, --urls FILE                  (MANDATORY) File containing the list of URLs to check for robots.txt
    -s, --snapshot                   Take a snapshot of the disallowed entries found in robots.txt
    -v, --[no-]visit                 Visit the disallowed entries and record the server response (code and html)
    -l, --logfile [LOGFILE]          Set the name of the output log file
    -L, --loglevel [LOGLEVEL]        Set loggin level (DEBUG, WARN, ERROR, CRITICAL)
    -h, --help                       Help screen
```

The script doew not visit URLs containing wildcards like '*' or the root domain, for example, when it is disallowed the path "/".

**Required gems**

* colorize (0.6.0)
* nokogiri (1.6.0, 1.5.5)
