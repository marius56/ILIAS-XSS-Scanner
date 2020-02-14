#!/usr/bin/python3
# Copyright 2020, Marius Binal, All rights reserved.
# Contact:
# Github: https://github.com/marius5602
# Email: marius.binal(at)protonmail.com
# Special Thanks goes to Bastian Buck for the cooperation to identify the affected database tables and php files of the XSS vulnerability.

import re
import csv
import argparse
from getpass import getpass
import pymysql as db
from colorama import Style, Fore, init
from bs4 import BeautifulSoup
from prettytable import PrettyTable

init() # Fix for windows cmd to highlighted the important keywords

######################### Database settings ##########################
dbUsername = "" # database user
dbPassword = "" # database password
databaseName = "" # the database name for an ILIAS installation (default: ilias)
databaseIP = "" # the database name for an ILIAS installation (default: ilias)
searchHistory = False # if true, search the history instead of the active content
#---------------------- Database settings end ------------------------

############################# ILIAS URL ###############################
url = "" # the url of the ILIAS website
#-------------------------- ILIAS URL END -----------------------------


filename = None # Filename to save the output
outputFile = None # File to save the output
outputAsCSV = True # Set whether the file is saved as a csv or a txt file
hightlightKeywords = True # set to False if the criticalKeyword should not be hightlighted in the console output
consoleOutput = True # set to False if the console ouput should be disabled
displayAll = False # if true, every possible XSS attempt gets displayed, even on pages where it wont work (e.g. wiki)
displayOnlyCritical = False


######################### Vulnerable types ############################
# The types will always be searched for XSS attacks
vulnerable_types = ["gdf", "lm", "cont"]
#--------------------- Vulnerable types end ---------------------------

############################## Keywords ###############################
# the keywords get hightlighted red in the console output to set the focus on possible critical statements
criticalKeywords = ["javascript", "vbscript", "alert", "script", "iframe", "XSS", "onAbort", "onActivate", "onAfterPrint", "onAfterUpdate", 
                    "onBeforeActivate", "onBeforeCopy", "onBeforeCut", "onBeforeDeactivate", "onBeforeEditFocus", "onBeforePaste", "onBeforePrint", 
                    "onBeforeUnload", "onBeforeUpdate", "onBegin", "onBlur", "onBounce", "onCellChange", "onChange", "onClick", "onContextMenu", 
                    "onControlSelect", "onCopy", "onCut", "onDataAvailable", "onDataSetChanged", "onDataSetComplete", "onDblClick", "onDeactivate", 
                    "onDrag", "onDragEnd", "onDragLeave", "onDragEnter", "onDragOver", "onDragDrop", "onDragStart", "onDrop", "onEnd", "onError", 
                    "onErrorUpdate", "onFilterChange", "onFinish", "onFocus", "onFocusIn", "onFocusOut", "onHashChange", "onHelp", "onInput", "onKeyDown", 
                    "onKeyPress", "onKeyUp", "onLayoutComplete", "onLoad", "onLoseCapture", "onMediaComplete", "onMediaError", "onMessage", "onMouseDown", 
                    "onMouseEnter", "onMouseLeave", "onMouseMove", "onMouseOut", "onMouseOver", "onMouseUp", "onMouseWheel", "onMove", "onMoveEnd", 
                    "onMoveStart", "onOffline", "onOnline", "onOutOfSync", "onPaste", "onPause", "onPopState", "onProgress", "onPropertyChange", 
                    "onReadyStateChange", "onRedo", "onRepeat", "onReset", "onResize", "onResizeEnd", "onResizeStart", "onResume", "onReverse", "onRowsEnter", 
                    "onRowExit", "onRowDelete", "onRowInserted", "onScroll", "onSeek", "onSelect", "onSelectionChange", "onSelectStart", "onStart", "onStop", 
                    "onStorage", "onSyncRestored", "onSubmit", "onTimeError", "onTrackChange", "onUndo", "onUnload", "onURLFlip", "seekSegmentTime" ]
#--------------------------- Keywords end -----------------------------


############################## CMD Arguments ############################### 
description = "This program searches through the ILIAS database to find potential XSS attacks\nThe default mode searches the table 'page_object' and the history mode the table 'page_history'"
parser = argparse.ArgumentParser(description=description, epilog="Created by: Marius Binal <marius.binal(at)protonmail.com>")
groupDatabase = parser.add_argument_group("Database options", "Specify options to connect to the database")
groupDatabase.add_argument("user", help="Set the user to connect to the database")
groupDatabase.add_argument("--password", "-p", action="store_true", help="Enter the password for the user to connect to the database")
groupDatabase.add_argument("--database", default="ilias", help="Set the database for the ILIAS installation. Default: 'ilias'")
groupDatabase.add_argument("--database-ip", default="localhost", help="Set the database IP adress for the ILIAS database. Default: 'localhost'")

groupSelection = parser.add_argument_group('Search options', 'Specify option for the database search')
groupSelection.add_argument("--search-all-pages", action="store_true", help="Show every possible XSS attempts, even on pages where the XSS is not possible (e.g. wiki page)")
groupSelection.add_argument("--search-history", action="store_true", help="If set, the program will search though the history instead of the current active content.")

groupOutput = parser.add_argument_group("Output", "Set options for the output")
groupOutput.add_argument("--url", "-u", default="https://elearning.hs-albsig.de", help="Set a different url for the link output. Default: 'https://elearning.hs-albsig.de'")
groupOutput.add_argument("--show-complete-entry", action="store_true", default=False, help="Prints the whole entry instead of just the HTML tags.")
groupOutput.add_argument("--show-only-critical", action="store_true", help="Show only entries with critical keywords, e.g. script, onerror, onload")
groupOutput.add_argument("--disable-highlighting", action="store_true", help="Disables the console highlighting for critical keywords")
groupOutput.add_argument("--quiet", "-q", action="store_true", help="Disables the console output")
groupOutput.add_argument("--output", "-o", help="Save the result to a file. Only .csv and .txt are valid extensions!")

args = parser.parse_args()

dbUsername = args.user
databaseName = args.database
databaseIP = args.database_ip
url = args.url

if (args.search_history != None):
    searchHistory = args.search_history

if (args.search_all_pages == True):
    displayAll = True

if (args.show_only_critical == True):
    displayOnlyCritical = True
    
printCompletePage = args.show_complete_entry

if (args.disable_highlighting == True):
    hightlightKeywords = False

if (args.quiet):
    consoleOutput = False

if (args.output != None and args.output != ""):
    filename = args.output
    if (filename.endswith(".csv")):
        outputAsCSV = True
    elif(filename.endswith(".txt")):
        outputAsCSV = False
    else:
        print("Error: The output file extension must be .csv or .txt")
        exit()

if (args.password != None and args.password == True):
    dbPassword = getpass()
#--------------------------- CMD Arguments end -----------------------------


############################ Regex statements ##############################
# These regex statements are used to search throught the ILIAS styled content for normal HTML code
# Note: User HTML input is always saved as HTML Entities: "<" is saved as "&lt;", ">" is saved as "&gt;"
# Example:
# <PageContent PCID="[...]"><Paragraph Language="de" Characteristic="Standard">
#   &lt;h1&gt;H1 Headline&lt;/h1&gt;<br/>&lt;img src=x onerror="alert(\'Bild konnte nicht geladen werden\')" /&gt;
# </Paragraph></PageContent>'

# The PHP file "/Services/COPage/classes/class.ilPageObjectGUI.php" convert them back to valid HTML tags, 
# if HTMLrendering of the page is activated.
patternParagraphStart = re.compile("<Paragraph[^>]*>")
patternParagraphEnd = re.compile("</Paragraph[^>]*>")
patternHTMLTagStart = re.compile("<([^> ]*)[^>]*>") # finds every <Tag id="asdf">...</Tag>
patternHTMLTagEnd = None
#-------------------------- Regex statments end ----------------------------


################ Function to change back the HTML Entities #################
def removeHTMLEntities(content):
    content = content.replace("&lt;", "<") # change back &lt; to < for better readability
    content = content.replace("&gt;", ">") # change back &gt; to > for better readability
    return content
#------------- Function to change back the HTML Entities end ---------------


##################### Function to search for HTML tags #####################
def searchForHTML(content):
    soup = BeautifulSoup(content, "html.parser")
    htmlTags = soup.find_all() # searching for any HTML tags in the content
    
    usages = []

    if (htmlTags != None): # if any tag was found, create a list of them and return it
        if (displayOnlyCritical): # if the user toggled that only critical keywords should be shown:
            for element in htmlTags: # search through the current elements
                element = str(element)
                for keyword in criticalKeywords: 
                    if keyword.lower() in element.lower(): # look if any critical keyword is in the current element
                        usages.append(element) # if so, add it the the output and stop the search for the current element
                        break

        else: # if not only critical keywords should be added, just add every HTML element
            usages = [str(element) for element in htmlTags]
        
    return usages
#----------------- Function to search for HTML tags  end -------------------

##################### Function to create the url path ######################
def createPath(parent_type, ref_id):
    if (parent_type == "lm"): # if parent page is a learn modul:
        return "/ilias.php?baseClass=ilLMPresentationGUI&ref_id=%s" % (str(ref_id))
    elif (parent_type == "wpg"): # if parent page is a wiki, a differend url needs to be used
        return "/goto.php?target=wiki_%s" % (str(ref_id)) # create the url path to the page
    elif (parent_type == "blp"): # if parent page is a blog
        return "/ilias.php?ref_id=%s&cmd=preview&cmdClass=ilrepositorygui&cmdNode=tz&baseClass=ilrepositorygui" % (str(ref_id)) 
    elif (parent_type == "gdf"): # if parent page is a glossar
        return "/ilias.php?baseClass=ilGlossaryPresentationGUI&ref_id=%s" % (str(ref_id))
    elif (parent_type == "copa"):
        return "/ilias.php?ref_id=%s&type=copa&item_ref_id=%s&cmd=view&cmdClass=ilobjcontentpagegui&cmdNode=tz:jj&baseClass=ilRepositoryGUI" % (str(ref_id), str(ref_id))
    else: # otherwise:
        return "/goto.php?target=crs_%s" % (str(ref_id)) # create the url path to the page
#------------------ Function to create the url path end --------------------

def searchForUsages(content):
    usages = []
    paragraphStart = patternParagraphStart.search(content) # Search for the first "<Paragraph [...]>" tag
    paragraphEnd = None

    while (paragraphStart != None): # Repeat the search for opening "<Paragraph [...]>" tag as long as one can be found
        paragraphEnd = patternParagraphEnd.search(content, paragraphStart.end()) # search for the closing "</Paragraph>" tag
        
        if (paragraphEnd != None): # if a closign </Paragraph> was found
            currentContent = content[paragraphStart.end():paragraphEnd.start()]

            if (printCompletePage): # if the user wants to get the complete page:
                usages.append(currentContent)
            else: # otherwise search the page for HTML tags:
                usages += searchForHTML(currentContent)

            paragraphStart = patternParagraphStart.search(content, paragraphEnd.end()) # New point to start is the end of the closing </Paragraph>
        
        else: # if no closing </Paragraph> was found, search through the rest of the text and exit the while loop
            usages += searchForHTML(content[paragraphStart.end():])
            paragraphStart = None
    return usages




############################### File output ################################ 
def prepareFile(searchHistory):
    writer = None
    if (searchHistory == False):
        if (outputAsCSV):
            outputFile = open(filename, "w") # open the file ...
            writer = csv.writer(outputFile) # ... and create a csv writer to write the output to the file
            writer.writerow(["Name", "Username", "E-Mail", "Created", "Last change", "Last changed by", "Link to page", "Content"]) # start with the headlines of the columns
        else:
            writer = PrettyTable()
            writer.field_names = ["Name", "Username", "E-Mail", "Created", "Last change", "Last changed by", "Link to page", "Content"]
    else:
        if (outputAsCSV):
            outputFile = open(filename, "w") # open the file ...
            writer = csv.writer(outputFile) # ... and create a csv writer to write the output to the file
            writer.writerow(["Name", "Username", "E-Mail", "Timestamp", "PageID", "Nr. of edit", "Link to page", "Content"]) # start with the headlines of the columns
        else:
            writer = PrettyTable()
            writer.field_names = ["Name", "Username", "E-Mail", "Timestamp", "PageID", "Nr. of edit", "Link to page", "Content"]
    return writer
#---------------------------- File output end ------------------------------


############################## Database part ############################### 
def fetchData(searchHistory):
    database = db.connect(databaseIP, dbUsername, dbPassword, databaseName)
    cursor = database.cursor()

    if (searchHistory == False):
        # Removed column "page.create_user" and "page.parent_id" from the query because they were not necessary 
        cursor.execute("""SELECT page.page_id, page.parent_type, ref.ref_id, ref.deleted, page.content, user.login, user.firstname, user.lastname, user.email, page.active, page.created, page.last_change, changedBy.login  FROM page_object page
        INNER JOIN usr_data user ON page.create_user = user.usr_id 
        INNER JOIN usr_data changedBy ON page.last_change_user = changedBy.usr_id 
        INNER JOIN object_reference ref ON ref.obj_id = page.parent_id 
        WHERE page.content LIKE '%&lt;%';""")
    else:
       cursor.execute("""SELECT page.page_id, page.parent_type, ref.ref_id, ref.deleted, page.content, user.login, user.firstname, user.lastname, user.email, page.hdate, page.nr FROM page_history page
        INNER JOIN usr_data user ON page.user_id = user.usr_id 
        INNER JOIN object_reference ref ON ref.obj_id = page.parent_id 
        WHERE page.content LIKE '%&lt;%';""")

    return cursor
#-------------------------- Database part end ------------------------------ 

def parseData(data, searchHistory, writer=None):
    counterFound = 0 # Variable to count the amount of pages with potential XSS attacks

    if (searchHistory == False):
        #################### Parsing the database response ######################### 
        # Variables:
        # page_id = id of page; ref_id = id for the url -> crs_[ref_id], 
        # parent_type = page type (e.g. content, wiki) of the parent page
        # deleted = whether the "ref_id" page containing the content was deleted
        # content = ILIAS styled content; active = whether the page is active 
        for page_id, parent_type, ref_id, deleted, content, username, firstname, lastname, email, active, created, last_change, last_change_by in data:
            # its only possible to inject javascript an html code on a page overview
            # therefore we can skip for example items of the type "wpg" because thats a page
            # in a wiki, where HTML rendering isnt allowed at all

            if (parent_type not in vulnerable_types and displayAll == False):
                continue

            content = removeHTMLEntities(content)
            usages = searchForUsages(content)
        

            if (len(usages) == 0): # if no html tag were found, skip this entry
                continue

            counterFound += 1

            path = createPath(parent_type, ref_id)

            link = "%s%s" % (url, path)
            name = "%s %s" % (firstname, lastname)

            if (filename != None and filename != ""):
                linkText = link
                if (deleted != None): # if the page which contained the element was deleted, add a note into the link column
                    linkText += "\n==> The page (ref_id=%d) which included this element (page_id=%d), was deleted on the %s!" % (ref_id, page_id, deleted)
                if (active != 1): # if the element is not active, add a note into the link column
                    linkText += "\n==> This element (page_id=%d) is not active at the moement (Row active=0 in the database)" % (page_id)


                if (writer != None):
                    if (outputAsCSV):
                        writer.writerow([name, username, email, created, last_change, last_change_by, linkText, "\n\r".join(usages)])
                    else:
                        writer.add_row([name, username, email, created, last_change, last_change_by, linkText, usages[0]])
                        if (len(usages) > 1):
                            for usage in usages[1:]:
                                writer.add_row(["", "", "", "", "", "", "", usage ])

                        writer.add_row(["", "", "", "", "", "", "", ""])



            if (consoleOutput == True):
                print("#################################### Found - Start ####################################")
                print("Name: %s | Username: %s | E-Mail: %s" % (name, username, email))
                print("Created: %s | Last change: %s (by: %s)" % (created, last_change, last_change_by))
                print("Link to the page: %s" % (link))

                colorRed = ""
                colorReset = ""

                if (hightlightKeywords == True):
                    colorRed = Fore.LIGHTRED_EX
                    colorReset = Style.RESET_ALL

                if (deleted != None): # if the page which contained the element was deleted, add a note to the console output
                    print("%sThe page (ref_id=%d) which included this element (page_id=%d), was deleted on the %s!%s" % (colorRed, ref_id, page_id, deleted, colorReset))
                if (active != 1): # if the element is not active, add a note to the console output
                    print("%sThis element (page_id=%d) is not active at the moement (Row active=0 in the database)%s" % (colorRed, page_id, colorReset))
                #if (parent_type == "wpg"): # if the element is inside a wiki page
                #    print("%sThe XSS is only executed on the property page of the table.%s" % (colorRed, colorReset))

                if (hightlightKeywords == True):  
                    for i in range(len(usages)):
                        for keyword in criticalKeywords: # hightlight any critical keyword, to give a better overview when looking over the console output
                            occurences = re.findall(keyword, usages[i], re.IGNORECASE) # using regex to be able to search case insensetive
                            for occurence in occurences:
                                usages[i] = usages[i].replace(occurence, "%s%s%s" % (Fore.RED, occurence, Style.RESET_ALL)) # using colorama to paint critical keywords red

                print("Content: \n%s" % ("\n".join(usages)))
                print("------------------------------------  Found - End  ------------------------------------\n\n")
        #----------------- Parsing the database response end -----------------------
    else:
        #################### Parsing the database response ######################### 
        # Variables:
        # page_id = id of page; ref_id = id for the url -> crs_[ref_id], 
        # parent_type = page type (e.g. content, wiki) of the parent page
        # deleted = whether the "ref_id" page containing the content was deleted
        # content = ILIAS styled content; active = whether the page is active 
        # date = Timestamp when the entry was changed
        # nr = Number of change of the page

        #page.page_id, page.parent_type, ref.ref_id, ref.deleted, page.content, user.login, user.firstname, user.lastname, user.email, page.hdate, page.nr 
        for page_id, parent_type, ref_id, deleted, content, username, firstname, lastname, email, date, nr in data:
            # its only possible to inject javascript an html code on a page overview
            # therefore we can skip for example items of the type "wpg" because thats a page
            # in a wiki, where HTML rendering isnt allowed at all
            if (parent_type not in vulnerable_types and displayAll == False):
                continue

            content = removeHTMLEntities(content)
            usages = searchForUsages(content)
        

            if (len(usages) == 0): # if no html tag were found, skip this entry
                continue

            counterFound += 1

            path = createPath(parent_type, ref_id)

            link = "%s%s" % (url, path)
            name = "%s %s" % (firstname, lastname)

            if (filename != None and filename != ""):
                linkText = link
                if (deleted != None): # if the page which contained the element was deleted, add a note into the link column
                    linkText += "\n==> The page (ref_id=%d) which included this element (page_id=%d), was deleted on the %s!" % (ref_id, page_id, deleted)
                
                if (writer != None):
                    if (outputAsCSV):
                        writer.writerow([name, username, email, date, page_id, nr, linkText, "\n\r".join(usages)])
                    else:
                        writer.add_row([name, username, email, date, page_id, nr, linkText, usages[0]])
                        if (len(usages) > 1):
                            for usage in usages[1:]:
                                writer.add_row(["", "", "", "", "", "", "", usage ])

                        writer.add_row(["", "", "", "", "", "", "", ""])


            if (consoleOutput == True):
                print("#################################### Found - Start ####################################")
                print("Name: %s | Username: %s | E-Mail: %s" % (name, username, email))
                print("Timestamp: %s | PageID: %d | Nr. of edit: %d" % (date, page_id, nr))
                print("Link to the page: %s" % (link))

                colorRed = ""
                colorReset = ""

                if (hightlightKeywords == True):
                    colorRed = Fore.LIGHTRED_EX
                    colorReset = Style.RESET_ALL

                if (deleted != None): # if the page which contained the element was deleted, add a note to the console output
                    print("%sThe page (ref_id=%d) which included this element (page_id=%d), was deleted on the %s!%s" % (colorRed, ref_id, page_id, deleted, colorReset))
               
                if (hightlightKeywords == True):  
                    for i in range(len(usages)):
                        for keyword in criticalKeywords: # hightlight any critical keyword, to give a better overview when looking over the console output
                            occurences = re.findall(keyword, usages[i], re.IGNORECASE) # using regex to be able to search case insensetive
                            for occurence in occurences:
                                usages[i] = usages[i].replace(occurence, "%s%s%s" % (Fore.RED, occurence, Style.RESET_ALL)) # using colorama to paint critical keywords red

                print("Content: \n%s" % ("\n".join(usages)))
                print("------------------------------------  Found - End  ------------------------------------\n\n")
        #----------------- Parsing the database response end -----------------------


    if (consoleOutput == True):
        print("#######################################################################################")
        print("####################################### Finished ######################################")
        print("#######################################################################################")
        print("=> Number of entries with potential XSS attacks: %d" % (counterFound))

    if (writer != None and outputAsCSV == False):
        outputFile = open(filename, "w") # open the file ...
        outputFile.write(writer.get_string())


if __name__ == "__main__":
    if (filename != None and filename != ""): # if an output file was specified
        writer = prepareFile(searchHistory)    
        parseData(fetchData(searchHistory), searchHistory, writer)
    else:
        parseData(fetchData(searchHistory), searchHistory)
        
