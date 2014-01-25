#!/usr/bin/env ruby

# This script updates the sqlite3 database of Google Dorks
# The dorks are retrieved with mechanize from http://www.exploit-db.com/google-dorks/
# If this web changes, probably this script will stop working.

require './classes/GoogleDorkUpdater'
require 'colorize'

puts "STUB: Updating Google Dork database!"
gdupdater = GoogleDorkUpdater.new
result = gdupdater.update("googledorks.db")

if result
  puts "The database was successfully updated".green
else
  puts "There was some error updating Google Dorks database".red
end
