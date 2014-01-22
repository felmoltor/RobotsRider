#!/usr/bin/env ruby
# encoding: utf-8

require 'net/http'
require 'optparse'
require 'logger'
require 'uri'
require 'colorize'

class RobotsRider
  def initialize(options)
    @urlfile = options[:urlfile]
    @takesnapshot = options[:takesnapshot]
    @visit = options[:visit]
    if (!options[:urlfile].nil? and File.exists?(options[:urlfile]))
      @randomsearch = false 
    else
      @randomsearch = true
    end
    if !options[:logfile].nil?
      @log = Logger.new(options[:logfile])
    else
      @log = Logger.new("logs/#{Time.now.strftime('%Y%m%d_%H%M%S')}_robotsrider.log")
    end
    if !options[:loglevel].nil?
      if options[:loglevel] = "DEBUG"
        @log.level = Logger::DEBUG
      elsif options[:loglevel] = "WARN"
        @log.level = Logger::WARN
      elsif options[:loglevel] = "ERROR"
        @log.level = Logger::ERROR
      elsif options[:loglevel] = "CRITICAL"
        @log.level = Logger::CRITICAL
      else
        @log.level = Logger::DEBUG
      end      
    else
      @log.level = Logger::DEBUG
    end
    
    @juicypaths = []
    if (File.exists?("juicypaths.list"))
      jf = File.open("juicypaths.list","r")
      jf.each {|jline|
        @juicypaths << jline.upcase.strip
      }
    end
    @juicywords = []
    if (File.exists?("juicybody.list"))
      jw = File.open("juicybody.list","r")
      jw.each {|jline|
        @juicywords << jline.upcase.gsub(/\s+/," ").strip
      }
    end
    # @stats = {}
  end
  
  #############
  
  def hasJuicyFiles(path)
    @juicypaths.each {|jpath|
      if !path.upcase.match(jpath).nil?
        return true 
      end
    }
    return false
  end
  
  #############
  
  def hasJuicyWords(htmlcode)
    # Normalize html code
    normalizedhtml = htmlcode.upcase.gsub(/\s+/," ")
    jphrases = {}
    # pp @juicywords
    #puts 
    #puts normalizedhtml
    
    @juicywords.each {|jline|
      jphrases = {}
      # Multiple words or phrases can be found in the file separated by "&"
      jwords = jline.split("&")
      jwords.each{|jword|
        jphrases[jword.strip] = false # Initialize status to "phrase not found in the body" 
      }
      # Search each phrase in the body
      jphrases.keys.each{ |phrase|
        if !normalizedhtml.match(phrase).nil?
          jphrases[phrase] = true
        end
      }
      if jphrases.values.uniq.length == 1 and jphrases.values.uniq[0] == true
        return true
      end
    }
    
    return false
  end
  
  #############
  
  def rideRobots()
    
    # Create folder for visited in this execution
    visiteddir = "visited/#{Time.now.strftime('%Y%m%d_%H%M%S')}/"
    if @visit
      Dir.mkdir(visiteddir)
    end    
    # Read the file with URLs
    urlf = File.open(@urlfile,"r")
    urlf.each {|url|
      url.strip!
      puts 
      puts "#"*(url.length + 4)
      puts "# #{url} #"
      puts "#"*(url.length + 4)
      begin
        uri = URI.parse(url)
        robotsurl = "#{uri.scheme}://#{uri.host}/robots.txt"
        robots_response = Net::HTTP.get_response(URI(robotsurl))
        if robots_response.code.to_i == 200
          robots_body = robots_response.body
          if !robots_body.nil?
            # print robots_body
            if robots_body.length > 0
              robots_body.split("\n").each {|rline|
                disallowm =  /^\s*Disallow\s*:\s*(.*)\s*$/.match(rline)  
                if disallowm
                  prohibido = disallowm.captures[0].strip
                  if prohibido.length > 0 and prohibido.strip != "/"
                    if prohibido[0]=="/"
                      prohibido =  prohibido[1,prohibido.length-1]
                    end
                    
                    disurl = "#{uri.scheme}://#{uri.host}/#{prohibido}"
                    @log.debug "Found '#{disurl}' as a disallowed entry."
                    puts "Found '#{disurl}' as a disallowed entry."
                    
                      
                    # TODO: Save in summary the results
                    if @visit
                      # If disallowed entry has wildcards, skip it from visiting
                      if (prohibido.match(/\*/).nil?)
                        savefile = "#{visiteddir}#{disurl.gsub("/","_").gsub(":","_")}"
                        @log.debug("Visiting #{disurl} and saving in file #{savefile}")
                        dis_response = Net::HTTP.get_response(URI(disurl))
                        if dis_response.code.to_i == 200
                          # Search for juicy words in the url
                          if hasJuicyFiles(prohibido)
                            @log.debug "URL '#{disurl}' exists. (And it seems interesting)"
                            puts "URL '#{disurl}' exists. (And it seems interesting)".red
                            # Search for juicy words in the body
                          elsif hasJuicyWords(dis_response.body)
                            @log.debug "URL '#{disurl}' exists. (And it seems interesting in his body)"
                            puts "URL '#{disurl}' exists. (And it seems interesting in his body)".red
                          else
                            @log.debug "URL '#{disurl}' exists."
                            puts "URL '#{disurl}' exists.".yellow                          
                          end
                          sf = File.open(savefile,"w")
                          sf.write(dis_response.body)
                          sf.close
                        else
                          @log.debug "URL '#{disurl}' does not exists. (#{dis_response.code})"
                          puts "URL '#{disurl}' does not exists. (#{dis_response.code})".blue
                        end
                      else
                        @log.debug("Disallowed entry has wildcard '*'. Not visiting.")
                        puts "Disallowed entry has wildcard '*'. Not visiting."
                      end
                    end
                  end
                end
              }
            else
              @log.warn("Request to #{robotsurl} returned empty body. Skipping.")
            end
          else
            @log.warn("Request to #{robotsurl} was not successfull. Skipping.")
          end
        else # if robots_response.code == 200
          @log.warn("Response code for #{robotsurl} was not 200 (#{robots_response.code}).")
          puts "Response code for #{robotsurl} was not 200 (#{robots_response.code}).".yellow
        end        
      rescue URI::BadURIError => e
        @log.error("The specified URL #{url} is not valid. Ignoring...")
        @log.error("Error: #{e.message}")
      rescue URI::InvalidURIError => e
        @log.error("The specified URL #{url} is not valid. Ignoring...")
        @log.error("Error: #{e.message}") 
      rescue Errno::ETIMEDOUT => e
        @log.error("Connexion with #{url} timed out. Probably the port is not open...")
        @log.error("Error: #{e.message}")     
        puts "Connexion with #{url} timed out. Probably the port is not open".red    
      end  
    }
    urlf.close
  end
  
end

##########################

def parseOptions()
  
  options = {
    :urlfile => nil,
    :takesnapshot => false, 
    :visit => true, 
    :crawl => false, 
    :logfile => nil, 
    :loglevel => nil
  }
  optparse = OptionParser.new do |opts|   
    
    opts.banner = "Usage: #{__FILE__} [OPTIONS]"
     
    opts.on( '-u', '--urls FILE', String, "(MANDATORY) File containing the list of URLs to check for robots.txt" ) do |file|
      options[:urlfile] = file
    end
    opts.on( '-s', '--snapshot','Take a snapshot of the disallowed entries found in robots.txt' ) do
      options[:takesnapshot] = true
    end
    opts.on( '-v', '--[no-]visit', 'Visit the disallowed entries and record the server response (code and html)' ) do |visit|
      options[:visit] = visit
    end
    opts.on( '-l', '--logfile [LOGFILE]', 'Set the name of the output log file' ) do |logfile|
      options[:logfile] = logfile
    end   
    opts.on( '-L', '--loglevel [LOGLEVEL]', ["DEBUG","WARN","ERROR","CRITICAL"], 'Set loggin level (DEBUG, WARN, ERROR, CRITICAL)' ) do |loglevel|
      if ["DEBUG","WARN","ERROR","CRITICAL"].include?(loglevel)
        options[:loglevel] = loglevel
      end
    end     
    opts.on( '-h', '--help', 'Help screen' ) do
      puts optparse
      exit
    end
  end
  
  optparse.parse!
  
  if options[:urlfile].nil?
    puts optparse
    raise OptionParser::MissingArgument
  end
  
  return options
end

##########################

def printBanner()
  puts "*******************************".blue
  puts "*      ROBOTS RIDER v0.1      *".blue
  puts "*    Author: Felipe Molina    *".blue
  puts "*     Twitter: @felmoltor     *".blue
  puts "*                             *".blue
  puts "* robots.txt explorer program *".blue
  puts "*******************************".blue
  puts
end

##########################

########
# MAIN #
########

if !Dir.exists?("visited")
  Dir.mkdir("visited")
end
if !Dir.exists?("logs")
  Dir.mkdir("logs")
end

printBanner()
op = parseOptions()
robotsrider = RobotsRider.new(op)
puts "Riding wild! Wait a little robots are not horses..."
puts
summary = robotsrider.rideRobots
# TODO: Print summary in screen
