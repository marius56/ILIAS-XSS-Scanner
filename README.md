# Installation
To use this script, you have to install it's dependencies first. This can be done with the additional requirements file.
To do so, run the command `pip3 install -r requirements.txt` in the folder where the requirements.txt file is placed.

# Usage
This program searches through the ILIAS database to find potential XSS attacks.
The default mode searches the table 'page_object' and the history mode the
table 'page_history'
```
usage: Ilias_XSS_Database_search.py [-h] [--password] [--database DATABASE]
                                    [--database-ip DATABASE_IP]
                                    [--search-all-pages] [--search-history]
                                    [--url URL] [--show-complete-entry]
                                    [--show-only-critical]
                                    [--disable-highlighting] [--quiet]
                                    [--output OUTPUT]
                                    database_user

optional arguments:
  -h, --help            show this help message and exit

Database options:
  Specify options to connect to the database

  user                  Set the user to connect to the database
  --password, -p        Enter the password for the user to connect to the
                        database
  --database DATABASE   Set the database for the ILIAS installation. Default:
                        'ilias'
  --database-ip DATABASE_IP
                        Set the database IP adress for the ILIAS database.
                        Default: 'localhost'

Search options:
  Specify option for the database search

  --search-all-pages    Show every possible XSS attempts, even on pages where
                        the XSS is not possible (e.g. wiki page)
  --search-history      If set, the program will search though the history
                        instead of the current active content.

Output:
  Set options for the output

  --url URL, -u URL     Set a different url for the link output. Default:
                        'https://elearning.hs-albsig.de'
  --show-complete-entry
                        Prints the whole entry instead of just the HTML tags.
  --show-only-critical  Show only entries with critical keywords, e.g. script,
                        onerror, onload
  --disable-highlighting
                        Disables the console highlighting for critical
                        keywords
  --quiet, -q           Disables the console output
  --output OUTPUT, -o OUTPUT
                        Save the result to a file. Only .csv and .txt are
                        valid extensions!
```