#!/usr/bin/env ruby
# encoding: utf-8

require './classes/RobotsRider'
require 'optparse'
require 'colorize'
require 'fileutils'
require 'pp'

# TODO: Save in summary the results in HTML or XML

$SCRIPT_VERSION = "0.3"

##########################

def parseOptions()
  options = {
    :urlfile => nil,
    :domain => nil,
    :visit => true, 
    :follow => false, 
    :fuzz => false,
    :vulnscan => false,
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
    opts.on( '-s', '--[no-]scan-vulns', "Use vulnerability scanners to scan detected CMS sites [Default: False]" ) do |vulnscan|
      options[:vulnscan] = vulnscan
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

def saveReport(ofile)
  # STUB: Save output in a beautiful HTML or XML
  if !@outputfile.nil?
    puts "STUB: Saving summary to #{@outputfile}"
  end
  return false
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

def printToolStatus(tools)  
  toolsOk = true
  tools.each {|tool,values|
    if values["path"] == "<AUTODISCOVER>"
      puts "Scanner file '#{tool}':"
      print " Is present? "
      print "#{values["path"]},".yellow
      print " Is readable? "
      print "n/a,".yellow
      print " Is executable? "
      puts "n/a".yellow
    else
      puts "Scanner file '#{tool}':"
      print " Is present? "
      print "Yes (#{values['path']}),".green if values["present"]
      print "No (#{values['path']}),".red if !values["present"]
      print " Is readable? "
      print "Yes,".green if values["readable"]
      print "No,".red if !values["readable"]
      print " Is executable? "
      puts "Yes".green if values["executable"]
      puts "No".red if !values["executable"]
      toolsOk = false if values["error"]  
    end
  }
  return toolsOk
end

##########################

def printDogs()
  dogs = %q{
    .         |\      ___________________
     \`-. _.._| \    /                   \
      |_,'  __`. \   | Scanning for CMS  |
      (.\ _/.| _  |  |  Vulnerabilities  |
     ,'      __ \ |  / __________________/
   ,'     __/||\  | /_/
  (_)   ,/|||||/  |
     `-'_----    /
        /`-._.-'/
        `-.__.-' 
}
  puts dogs.cyan
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
     /         \      |         ROBOTS RIDER v0.4           |        
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
puts
puts "********************"
puts "* Scanners Status: *"
puts "********************"
scannersOk = printToolStatus(scanners)
puts
puts "*****************"
puts "* Tools Status: *"
puts "*****************"
toolsOk = printToolStatus(tools)
if !scannersOk or !toolsOk
  $stderr.puts "There was an error with your tools configuration. Please fix it and try again."
  exit(1)
end
# If the user specified a domain, the URLs to explore will be found in the output of the harvester
# Set the targets as the output of The Harvester
if !op[:domain].nil?
  puts
  puts "Setting the URL targets from the output of The Harvester. Please be patient..."
  robotsrider.setSubdomainsAsTargets()
else
  puts "Setting the URL targets from the file #{op[:urlfile]}."
end

robotsrider.rideRobots # Just obtain information about the installed CMS and interesting routes
puts "Identification phase finished."

if !op[:vulnscan]
  puts "You don't want to scan for vulnerabilities so we won't release the dogs."  
else
  puts
  puts "Releasing the dogs!"
  printDogs
  vulnSummary = robotsrider.releaseTheDogs
end

if (!op[:outputfile].nil? and !saveReport(op[:outputfile]))
  $stderr.puts "Ups! There was an error saving the results in '#{op[:outputfile]}'. Please, check your permissions or something..."
end  
