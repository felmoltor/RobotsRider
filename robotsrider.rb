#!/usr/bin/env ruby
# encoding: utf-8

require 'net/http'
require 'net/https'
require 'optparse'
require 'logger'
require 'uri'
require 'colorize'
require 'nokogiri'
require 'fileutils'

# TODO: Save in summary the results in HTML or XML
# TODO: Add queries to archive.org API to retrieve cached entries of webpages

class RobotsRider
  def initialize(options)
    @urlfile = options[:urlfile]
    @domain = options[:domain]
    if !@domain.nil?
      @domain = @domain.gsub("http://","").gsub("https://","").gsub("www.","")
    end
    @fuzz = options[:fuzz]
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
      elsif options[:loglevel] = "INFO"
        @log.level = Logger::INFO
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
    if (File.exists?("config/juicypaths.list"))
      jf = File.open("config/juicypaths.list","r")
      jf.each {|jline|
        @juicypaths << jline.upcase.strip
      }
    end
    @juicywords = []
    if (File.exists?("config/juicybody.list"))
      jw = File.open("config/juicybody.list","r")
      jw.each {|jline|
        @juicywords << jline.upcase.gsub(/\s+/," ").strip
      }
    end
    
    @juicytitles = []
    if (File.exists?("config/juicytitles.list"))
      jt = File.open("config/juicytitles.list","r")
      jt.each {|jtitle|
        @juicytitles << jtitle.upcase.gsub(/\s+/," ").strip if jtitle.strip[0] != "#"
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
        @log.debug "Following words found in the body content: #{jphrases}"
        return jphrases
      end
    }
    
    return nil
  end
    
  ##########################
  
  def getWfuzzPath()
    # Check if theharvester is in the path
    whereisoutput = `whereis wfuzz`
    thpaths = whereisoutput.split(":")[1]
    thpaths.split(" ").each {|path|
      if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-python"
        return path
      end      
    }
    return nil
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
    resultfile = "tmpoutputs/harvester_output_#{@domain}.list"
    thtmpfile = "tmpoutputs/#{@domain}.html"
    thbin = getTheHarvesterPath
    
    if !thbin.nil?
      # Create an URL file with the outuput of the harvester for hosts
      # Retrieve the host found in the domain provided by the user
      cmdline = "#{thbin} -f #{thtmpfile} -d #{@domain} -b all "
      puts "Searching with 'theharvester' information about the domain '#{@domain}'. Please, be patient."
      @log.info "Searching with 'theharvester' information about the domain #{@domain}"
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
          domainfilter = @domain.gsub(/\..{2,4}$/,"")
          if h.include?(domainfilter)
            urlsfile.puts("http://#{h}")
          end
        }  
        urlsfile.close
        File.delete(thtmpfile)     
      else
        @log.error "The tool 'theHarvester' didn't create the file '#{@domain}.html'"
        puts "The tool 'theHarvester' didn't create the file'#{@domain}.html (Don't blame me!)'".red
        resultfile = nil
      end
    else
      @log.fatal "You don't have the tool 'theharvester' installed. Donwload and install it before using option '-d' again"
      puts "You don't have the tool 'theharvester' installed. Donwload and install it before using option '-d' again (https://code.google.com/p/theharvester/downloads/list)"
      resultfile = nil
    end
    return resultfile    
  end
  
  #############
  
  def fuzzDisalowedEntry(disentry)
    
    wfbin = getWfuzzPath 
    defaultdic = "/usr/share/wfuzz/wordlist/general/common.txt"
    defaultdelay = 0.3
    defaultthreads =  10
    defaultignorec = "404,400"
    disentry_output = "tmpoutputs/#{disentry.gsub("/","_").gsub(":","").gsub("*","FUZZ")}.html"
    wfuzzcmd = "#{wfbin} -o html -t $threads$ -s $delay$ --hc $ignorec$ -z file,$dict$ #{disentry.gsub("*","FUZZ")} 2> #{disentry_output}"
    fuzzdict = {}
    
    if File.exists?("config/wfuzz.cfg")
      wf = File.open("config/wfuzz.cfg","r")
      wf.each {|wline|
        # Ignoring comentaries
        if wline.strip[0] != "#"
          key,val = wline.split(":")
          key.strip!
          val.strip!
          
          case key.upcase
            when "DICTIONARY" then wfuzzcmd.gsub!("$dict$",val)
            when "THREADS" then wfuzzcmd.gsub!("$threads$",val)
            when "DELAY" then wfuzzcmd.gsub!("$delay$",val)
            when "IGNORE" then wfuzzcmd.gsub!("$ignorec$",val)
          end
        end
      }
      # Set the default values if there is some option no specified by the user
      wfuzzcmd.gsub!("$dict$",defaultdic) if wfuzzcmd.include?("$dict$")
      wfuzzcmd.gsub!("$threads$",defaultdic) if wfuzzcmd.include?("$threads$")
      wfuzzcmd.gsub!("$delay$",defaultdic) if wfuzzcmd.include?("$delay$")
      wfuzzcmd.gsub!("$ignorec$",defaultdic) if wfuzzcmd.include?("$ignorec$")
      
      @log.debug "Executing the following command #{wfuzzcmd}"
      # puts "Executing the following command #{wfuzzcmd}. Be patient"
      wfuzzres = `#{wfuzzcmd}`
      
      # Parse html output with nokogiri to retrieve the output
      html_doc = Nokogiri::HTML(File.open(disentry_output,"r"))
      nrow = 0
      rcode = nil
      href = nil
      html_doc.xpath("//table/tr").each { |trow|
        if nrow > 0
          ncolumn = 0
          trow.css('td').each{|td| 
            if ncolumn == 1
              rcode = td.css('font')[0].text.to_i
            end
            if ncolumn == 4
              href = td.css('a')[0].attributes["href"]
            end
            ncolumn += 1
          }
        end
        fuzzdict[href] = rcode if !href.nil? and !rcode.nil?
        nrow += 1
      }
      return fuzzdict
    else
      return nil
    end    
  end
  
  #############
  
  def fetch(uri_str, limit = 10)
    redirection_url = nil
    raise ArgumentError, 'HTTP redirect too deep' if limit == 0
  
    url = URI.parse(uri_str)
    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = (url.scheme == 'https')
    req = Net::HTTP::Get.new(uri_str, {'User-Agent' => 'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322)' })
    response = http.start{ |h| 
      h.request(req) 
    }
            
    if response.code.to_i == 301 or response.code.to_i == 302 
      if !response['location'].nil?
        location = response['location']
        location = location[1,location.length-1] if location[0] == "/"
        location_uri = nil
        # Try to conver to an URI
        begin
          location_uri = URI.parse(location)
        rescue URI::BadURIError, URI::InvalidURIError => e
          @log.error("Redirection location is invalid! (#{location})")
        end
        # If the redirection is a complete and correct URI
        if !location_uri.host.nil?
          redirection_url = "#{location_uri.to_s}"
        else
          redirection_url = "#{url.scheme}://#{url.host}:#{url.port}/#{location_uri.path}?#{location_uri.query}"
        end
      end
      if @follow
        @log.info "Following redirection to #{redirection_url}"
        return fetch(redirection_url, limit - 1)
      else
        @log.info "No following redirection to #{redirection_url}"
        return response
      end
    else
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
        @log.debug "Searching for robots.txt file..."
        puts "Searching for robots.txt file..."
        puts 
        robotsurl = "#{uri.scheme}://#{uri.host}/robots.txt"
        # TODO: Change timeout for the HTTP connexion (https://stackoverflow.com/questions/13074779/ruby-nethttp-idle-timeout)
        robots_response = fetch(robotsurl)
        if robots_response.code.to_i == 200
          robots_body = robots_response.body
          if !robots_body.nil?
            # print robots_body
            if robots_body.length > 0
              @log.debug  "Searching for 'Disallowed' URLs..."
              puts "Searching for 'Disallowed' URLs..."
              puts
              robots_body.split("\n").each {|rline|
                disallowm =  /^\s*Disallow\s*:\s*(.*)\s*$/.match(rline)  
                if disallowm
                  prohibido = disallowm.captures[0].strip
                  if prohibido.length > 0 and prohibido.strip != "/"
                    if prohibido[0]=="/"
                      prohibido =  prohibido[1,prohibido.length-1]
                    end
                    
                    disurl = "#{uri.scheme}://#{uri.host}/#{prohibido}"
                    @log.info "Found '#{disurl}' as a disallowed entry."
                    # print "Found '#{disurl}' as a disallowed entry "                    
                      
                    if @visit
                      # If disallowed entry has wildcards, skip it from visiting
                      if (prohibido.match(/\*/).nil?)
                        savefile = "#{visiteddir}#{disurl.gsub("/","_").gsub(":","_")}"
                        @log.info("Visiting #{disurl} and saving in file #{savefile}")
                        dis_response = fetch(disurl)
                        if dis_response.code.to_i == 200
                          # Search for juicy words in the url
                          @log.info "URL '#{disurl}' exists."
                          print "[EXISTS] (#{dis_response.code}): ".green
                          puts "#{disurl}"
                          if hasJuicyFiles(prohibido)
                            @log.info "URL '#{disurl}' exists. (And it seems interesting)"
                            # puts " It seems interesting in the Path!".red
                            puts " * [INTERESTING PATH]".red
                          end
                          if !(jw = hasJuicyWords(dis_response.body)).nil?
                            @log.info "URL '#{disurl}' exists. (And it seems interesting in his body)"
                            # puts " It seems interesting in his body content! (Words found: #{jw})".red
                            puts " * [INTERESTING BODY]: #{jw}".red
                          end
                          if hasJuicyTitle(dis_response.body)
                            @log.info "URL '#{disurl}' exists. (And it seems interesting in his Title)"
                            # puts " It seems interesting in his page Title!".red
                            puts " * [INTERESTING TITLE]".red
                          end
                          sf = File.open(savefile,"w")
                          sf.write(dis_response.body)
                          sf.close
                        else
                          @log.debug "URL '#{disurl}' is not accessible. (#{dis_response.code})"
                          print "[NOT ACCESSIBLE] (#{dis_response.code}): ".light_red
                          puts "#{disurl}"
                        end
                      else
                        # TODO: Support more than one wildcard in the URL
                        if @fuzz and !getWfuzzPath.nil? and disurl.count("*") == 1
                          @log.info("Widlcard found. Fuzzing with 'wfuzz'")
                          puts "Widlcard found in #{disurl}. Fuzzing it!"
                          # Fuzz this URL with wfuzz
                          fuzzdictionary = fuzzDisalowedEntry(disurl)
                          if fuzzdictionary.size == 0
                            @log.info "Fuzzer didn't find anything"
                            puts "Fuzzer didn't find anything"
                          else
                            fuzzdictionary.each {|f_href,f_code|
                              if f_code.to_i == 200
                                print "[FUZZ FOUND] (#{f_code}): ".green
                              else
                                print "[FUZZ FOUND] (#{f_code}): "                            
                              end
                              puts "#{f_href}"
                            }
                          end 
                        else
                          @log.info("Disallowed entry has wildcard '*'. Not visiting.")
                          puts "Disallowed entry has wildcard '*'. Not visiting."
                        end
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
          @log.warn("It seems #{robotsurl} is not accesible (#{robots_response.code}).")
          print "[NOT ACCESSIBLE] (#{robots_response.code}): ".light_red
          puts "#{robotsurl}"
        end        
      rescue URI::BadURIError, URI::InvalidURIError => e
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
  
  ##########################

  def cleanTheHouse()
    @log.debug("Deleting temporal files")
    FileUtils.rm_r Dir.glob("tmpoutputs/*")
    Dir.delete("tmpoutputs/")
  end
  
end # class RobotsRider

##########################
##########################
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
    opts.on( '-o', '--output', 'TODO: Save the summary of the execution to this beautiful HTML file' ) do |ofile|
      options[:outputfile] = ofile
    end
    opts.on( '-L', '--loglevel [LOGLEVEL]', ["DEBUG","INFO","WARN","ERROR","FATAL"], 'Set loggin level (DEBUG, WARN, ERROR, CRITICAL)  [default: DEBUG]' ) do |loglevel|
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
if !Dir.exists?("tmpoutputs")
  Dir.mkdir("tmpoutputs")
end

printBanner()
op = parseOptions()
robotsrider = RobotsRider.new(op)
# If the user specified a domain, the URLs to explore will be found in the output of the harvester
summary = robotsrider.rideRobots
robotsrider.saveReport
robotsrider.cleanTheHouse
