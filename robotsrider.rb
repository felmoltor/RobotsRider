#!/usr/bin/env ruby
# encoding: utf-8

require './classes/RobotsRider'
require 'optparse'
require 'colorize'
require 'fileutils'

# TODO: Save in summary the results in HTML or XML
# TODO: Add queries to archive.org API to retrieve cached entries of webpages

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
  if !Dir.exists?("tmpoutputs")
    Dir.mkdir("tmpoutputs")
  end
end

##########################

def printBanner()
  unicorn = %q{
                ,%%%,
               ,%%%` %==--
              ,%%`( '|         ,    ,
             ,%%@ /\_/        (\___/)
   ,%.-"""--%%% "@@__         (_oo_)
  %%/             |__`\         (O)
 .%'\     |   \   /  //       __||__    \)
 ,%' >   .'----\ |  [/     []/______\[] /
    < <<`       ||         / \______/ \/
     `\\\        ||        /    /__\
       )\\       )\\       (\   /____\
^^^^^^^"""^^^^^^""^^^^^^^^^^^^^^^^^^^^^^^^^^^
}
  puts " ***************************************".cyan
  puts " *          ROBOTS RIDER v0.2          *".cyan
  puts " *        Author: Felipe Molina        *".cyan
  puts " *         Twitter: @felmoltor         *".cyan
  puts " *                                     *".cyan
  puts " *    'robots.txt' explorer program    *".cyan
  puts " ***************************************".cyan
  puts unicorn.cyan
end

##########################

########
# MAIN #
########

printBanner()
initializeFolders()
op = parseOptions()
robotsrider = RobotsRider.new(op)
# If the user specified a domain, the URLs to explore will be found in the output of the harvester
summary = robotsrider.rideRobots
robotsrider.saveReport
robotsrider.cleanTheHouse
