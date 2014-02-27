#!/usr/bin/env ruby
# encoding: utf-8

require './classes/RobotsRider'
require 'optparse'
require 'colorize'
require 'fileutils'
require 'pp'

# TODO: Save in summary the results in HTML or XML
# TODO: Add queries to archive.org API to retrieve cached entries of webpages

$SCRIPT_VERSION = "0.3"

##########################

def parseOptions()
  options = {
    :urlfile => nil,
    :domain => nil,
    :visit => true, 
    :follow => false, 
    :fuzz => false,
    :outputfile => nil, 
    :loglevel => "DEBUG"
  }
  optparse = OptionParser.new do |opts|   
    
    opts.banner = "Usage: #{__FILE__} [OPTIONS]"
     
    opts.on( '-d', '--domain DOMAIN', String, "Domain to explore for robots.txt (This option needs program 'theharvester' in your PATH)" ) do |domain|
      options[:domain] = domain
    end
    opts.on( '-u', '--urls FILE', String, "File containing the list of URLs to check for robots.txt" ) do |file|
      options[:urlfile] = file
    end
    opts.on( '-v', '--[no-]visit', 'Visit the disallowed entries and record the server response [default: True]' ) do |visit|
      options[:visit] = visit
    end
    opts.on( '-F', '--[no-]follow', 'Follow redirect for disallowed entries with 30X responses [default: False]' ) do |follow|
      options[:follow] = follow
    end
    opts.on( '-w', '--[no-]wfuzz', "Use wfuzz program to fuzz wildcards in the disallowed entries [Default: False]" ) do |fuzz|
      options[:fuzz] = fuzz
    end
    opts.on( '-o', '--output [OFILE]', 'TODO: Save the summary of the execution to this beautiful HTML file' ) do |ofile|
      options[:outputfile] = ofile
    end
    opts.on( '-L', '--loglevel [LOGLEVEL]', ["DEBUG","INFO","WARN","ERROR","FATAL"], 'Set loggin level (DEBUG, INFO, WARN, ERROR, FATAL)  [default: DEBUG]' ) do |loglevel|
      if ["DEBUG","INFO","WARN","ERROR","FATAL"].include?(loglevel)
        options[:loglevel] = loglevel
      end
    end     
    opts.on( '-h', '--help', 'Help screen' ) do
      puts optparse
      exit
    end
  end
  
  optparse.parse!
  
  if options[:urlfile].nil? and options[:domain].nil?
    puts optparse
    raise OptionParser::MissingArgument
  end
  
  return options
end

##########################

def initializeFolders()
  if !Dir.exists?("visited")
    Dir.mkdir("visited")
  end
  if !Dir.exists?("logs")
    Dir.mkdir("logs")
  end
  if !Dir.exists?("outputs/scanners/dpscan")
    FileUtils.mkdir_p("outputs/scanners/dpscan")
  end
  if !Dir.exists?("outputs/scanners/joomscan")
    FileUtils.mkdir_p("outputs/scanners/joomscan")
  end
  if !Dir.exists?("outputs/scanners/plown")
    FileUtils.mkdir_p("outputs/scanners/plown")
  end
  if !Dir.exists?("outputs/scanners/wpscan")
    FileUtils.mkdir_p("outputs/scanners/wpscan")
  end
  if !Dir.exists?("outputs/visited/")
    FileUtils.mkdir_p("outputs/visited/")
  end
  if !Dir.exists?("dictionaries")
    FileUtils.mkdir_p("dictionaries")
  end
end

##########################

def printBanner()
  bender = %q{
          _
         ( )
          H
          H
         _H_           _____________________________________
      .-'-.-'-.       /                                     \
     /         \      |         ROBOTS RIDER v0.3           |        
    |           |     |      Author: Felipe Molina          |
    |   .-------'._   |       Twitter: @felmoltor           |
    |  / /  '.' '. \  |                                     |   
    |  \ \ @   @ / /  | robots.txt and CMS explorer program |
    |   '---------'   / ___________________________________/  
    |    _______|    / /
    |  .'-+-+-+|    /_/
    |  '.-+-+-+|         
    |    """""" |
    '-.__   __.-'
         """  
}
  puts bender.cyan
end

##########################

########
# MAIN #
########

printBanner()
initializeFolders()
op = parseOptions()
robotsrider = RobotsRider.new(op)
scanners = {}

# Check for third party scanners
puts "Checking if the third party scanners are presents in your system..."
scanners,tools = robotsrider.getThirdPartyStatus()
scannersOk = true
toolsOk = true

scanners.each {|scanner,values|
  puts "Scanner file #{scanner}:"
  print " - Present: "
  puts "Yes (#{values['path']})".green if values["present"]
  puts "No (#{values['path']})".red if !values["present"]
  print " - Readable: "
  puts "Yes".green if values["readable"]
  puts "No".red if !values["readable"]
  print " - Executable: "
  puts "Yes".green if values["executable"]
  puts "No".red if !values["executable"]
  scannersOk = false if values["error"]  
}
if !scannersOk
  $stderr.puts "There was an error with your scanners configuarion. Please fix it and try again."
  exit(1)
end

tools.each {|tool,values|
  puts "Scanner file #{tool}:"
  print " - Present: "
  puts "Yes (#{values['path']})".green if values["present"]
  puts "No (#{values['path']})".red if !values["present"]
  print " - Readable: "
  puts "Yes".green if values["readable"]
  puts "No".red if !values["readable"]
  print " - Executable: "
  puts "Yes".green if values["executable"]
  puts "No".red if !values["executable"]
  scannersOk = false if values["error"]  
}
if !scannersOk
  $stderr.puts "There was an error with your scanners configuarion. Please fix it and try again."
  exit(1)
end

exit(2)

# If the user specified a domain, the URLs to explore will be found in the output of the harvester
summary = robotsrider.rideRobots
robotsrider.saveReport  
