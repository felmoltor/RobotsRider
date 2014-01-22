#!/usr/bin/env ruby
# encoding: utf-8

require 'net/http'
require 'optparse'
require 'logger'
require 'uri'
require 'colorize'
require 'nokogiri'

class RobotsRider
  def initialize(options)
    @urlfile = options[:urlfile]
    @domain = options[:domain].gsub("http://","").gsub("https://","").gsub("www.","")
    @visit = options[:visit]
    @follow = options[:follow]
    @outputfile = options[:outputfile]
    @log = Logger.new("logs/#{Time.now.strftime('%Y%m%d_%H%M%S')}_robotsrider.log")
    
    if (!options[:urlfile].nil? and File.exists?(options[:urlfile]))
      @randomsearch = false 
    else
      @randomsearch = true
    end
    
    if !options[:loglevel].nil?
      if options[:loglevel] = "DEBUG"
        @log.level = Logger::DEBUG
      elsif options[:loglevel] = "WARN"
        @log.level = Logger::WARN
      elsif options[:loglevel] = "ERROR"
        @log.level = Logger::ERROR
      elsif options[:loglevel] = "FATAL"
        @log.level = Logger::FATAL
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
    
    @juicytitles = []
    if (File.exists?("juicytitles.list"))
      jt = File.open("juicytitles.list","r")
      jt.each {|jtitle|
        @juicytitles << jtitle.upcase.gsub(/\s+/," ").strip
      }
    end
    
    # Initialize the URL file if there was a domain specified and the user has 
    # theHarvester in hist PATH.
    if !@domain.nil?
      
      newurlfile = queryTheHarvester
      if !newurlfile.nil?
        @urlfile = newurlfile
      end
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
  
  def hasJuicyTitle(htmlcode)
    html_doc = Nokogiri::HTML(htmlcode)
    pagetitle = html_doc.css('title').text.upcase.gsub(/\s+/," ")
    
    @juicytitles.each {|jtitle|
      if pagetitle == jtitle
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
    
  ##########################
  
  def getTheHarvesterPath()
    # Check if theharvester is in the path
    whereisoutput = `whereis theharvester`
    thpaths = whereisoutput.split(":")[1]
    thpaths.split(" ").each {|path|
      if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-python"
        return path
      end      
    }
    return nil
  end
  
  ##########################
  
  def queryTheHarvester()
    # This function calls the programwhereis theharvester theHarvester automaticaly to harvest URLs from a domain
    # Instead of providing the program with a list of urls we can directly ask for a domain
    resultfile = "harvester_output_#{@domain}.list"
    thtmpfile = "#{@domain}.html"
    thbin = getTheHarvesterPath
    
    if !thbin.nil?
      # Create an URL file with the outuput of the harvester for hosts
      # Retrieve the host found in the domain provided by the user
      cmdline = "#{thbin} -f #{thtmpfile} -d #{@domain} -b all "
      puts "Searching with 'theharvester' information about the domain '#{@domain}'. Please, be patient."
      @log.debug "Searching with 'theharvester' information about the domain #{@domain}"
      @log.debug " #{cmdline}"
      salida = `#{cmdline}`
      if File.exists?(thtmpfile)
        fdomain = File.open(thtmpfile)
        html_doc = Nokogiri::HTML(fdomain)
        fdomain.close
        # Busca los <li> <ul class="softlist"> y <ul class="pathslist">   
        hostfound = []
        html_doc.xpath("//li[@class='softitem']").each { |sitem|
          # puts "softitem: #{sitem.content}"
          hostfound << sitem.content.split(":")[1]
        }
        html_doc.xpath("//li[@class='pathitem']").each { |pitem|
          # puts "pathitem #{pitem.content}"    
          hostfound << pitem.content.split(":")[1]       
        }
        hostfound = hostfound.sort.uniq
        urlsfile = File.open(resultfile,"w")
        hostfound.each {|h|
          if h.include?(@domain)
            urlsfile.puts("http://#{h}")
          end
        }  
        urlsfile.close        
      else
        @log.error "The tool 'theHarvester' didn't create the file '#{@domain}.html'"
        puts "The tool 'theHarvester' didn't create the file'#{@domain}.html'"
        resultfile = nil
      end
      File.delete(thtmpfile)
    else
      @log.fatal "You don't have the tool 'theharvester' installed. Donwload and install it before using option '-d' again"
      puts "You don't have the tool 'theharvester' installed. Donwload and install it before using option '-d' again (https://code.google.com/p/theharvester/downloads/list)"
      resultfile = nil
    end
    return resultfile    
  end
  
  #############
  
  def fetch(uri_str, limit = 5)
    # You should choose better exception.
    raise ArgumentError, 'HTTP redirect too deep' if limit == 0
  
    url = URI.parse(uri_str)
    req = Net::HTTP::Get.new(url.path, {'User-Agent' => 'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322)' })
    response = Net::HTTP.start(url.host, url.port) { |http| http.request(req) }
    
    if response == Net::HTTPRedirection and @follow
      @log.debug "Following redirection to #{response['location']}..."
      puts "Following redirection to #{response['location']}..."
      return fetch(response['location'], limit - 1)
    else
      if response == Net::HTTPRedirection
        @log.debug "No following redirection to #{response['location']}..."
        puts "No following redirection to #{response['location']}..."
      end
      return response
    end
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
        # TODO: Change timeout for the HTTP connexion (https://stackoverflow.com/questions/13074779/ruby-nethttp-idle-timeout)
        robots_response = fetch(robotsurl)
        # robots_response = Net::HTTP.get_response(URI(robotsurl))
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
                        dis_response = fetch(disurl)
                        # dis_response = Net::HTTP.get_response(URI(disurl))
                        if dis_response.code.to_i == 200
                          # Search for juicy words in the url
                          @log.debug "URL '#{disurl}' exists."
                          puts "URL '#{disurl}' exists."  
                          
                          if hasJuicyFiles(prohibido)
                            @log.debug "URL '#{disurl}' exists. (And it seems interesting)"
                            puts " It seems interesting in the Path!".red
                          end
                          if hasJuicyWords(dis_response.body)
                            @log.debug "URL '#{disurl}' exists. (And it seems interesting in his body)"
                            puts " It seems interesting in his body content!".red
                          end
                          if hasJuicyTitle(dis_response.body)
                            @log.debug "URL '#{disurl}' exists. (And it seems interesting in his Title)"
                            puts " It seems interesting in his page Title!".red
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
          @log.warn("It seems #{robotsurl} does not exists (#{robots_response.code}).")
          puts "It seems #{robotsurl} does not exists (#{robots_response.code}).".yellow
        end        
      rescue URI::BadURIError => e
        @log.error("The specified URL #{url} is not valid. Ignoring...")
        @log.error("Error: #{e.message}")
      rescue URI::InvalidURIError => e
        @log.error("The specified URL #{url} is not valid. Ignoring...")
        @log.error("Error: #{e.message}") 
      rescue Errno::ETIMEDOUT, Timeout::Error => e
        @log.error("Connexion with #{robotsurl} timed out. Probably the port is not open...")
        @log.error("Error: #{e.message}")        
      rescue EOFError => e
        @log.error("There was some problem with the data receive. Skiping #{robotsurl}")
        @log.error("Error: #{e.message}")      
      rescue Errno::ECONNREFUSED => e
        @log.error("The connection to this URL was rejected. Skiping #{robotsurl}")
        @log.error("Error: #{e.message}")  
      end  
    }
    urlf.close
  end
  
  ##########################

  def saveReport()
    # STUB: Save output in a beautiful HTML or XML
    if !@outputfile.nil?
      puts "STUB: Saving summary to #{@outputfile}"
    end
  end
  
end # class RobotsRider

##########################
##########################
##########################

def parseOptions()
  # TODO: Output results to a HTML or XML file to later exploration 
  options = {
    :urlfile => nil,
    :domain => nil,
    :visit => true, 
    :follow => false, 
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
    opts.on( '-w', '--write', 'TODO: Save the summary of the execution to this beautiful HTML file' ) do |ofile|
      options[:outputfile] = ofile
    end
    opts.on( '-L', '--loglevel [LOGLEVEL]', ["DEBUG","WARN","ERROR","FATAL"], 'Set loggin level (DEBUG, WARN, ERROR, CRITICAL)  [default: DEBUG]' ) do |loglevel|
      if ["DEBUG","WARN","ERROR","FATAL"].include?(loglevel)
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

if !Dir.exists?("visited")
  Dir.mkdir("visited")
end
if !Dir.exists?("logs")
  Dir.mkdir("logs")
end

printBanner()
op = parseOptions()
robotsrider = RobotsRider.new(op)
# If the user specified a domain, the URLs to explore will be found in the output of the harvester
summary = robotsrider.rideRobots
robotsrider.saveReport
