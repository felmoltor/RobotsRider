require 'net/http'
require 'net/https'
require 'logger'
require 'uri'
require 'colorize'
require 'nokogiri'
require 'fileutils'

# TODO: Save in summary the results in HTML or XML
# TODO: Add queries to archive.org API to retrieve cached entries of webpages

class RobotsRider
  
  def initialize(options)
    @@CMSCONFIDENCE = 0.75
    @WPSCANPATH = getWPScanPath()
    @JOOMSCANPATH = getJoomscanPath()
    @wpscanconfig = readWPScanConfig()
    @joomscanconfig = readJoomscanConfig()
    
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
  
  def readWPScanConfig()
    wpscanconfig = eval(File.open("config/wpscan.cfg","r").read)
  end
  
  #############
  
  def readJoomscanConfig()
    joomscanconfig = eval(File.open("config/joomscan.cfg","r").read)
  end
  
  #############
  
  def launchWPScan(path)
    # Launch wpscan
    @log.debug "Launching wpscan: #{@WPSCANPATH}  -u #{path}"
    # -ot output/scanners/#{path.gsub(/(:|\/)/,"_")} -oh output/scanners/#{path.gsub(/(:|\/)/,"_")}
    system("#{@WPSCANPATH}  -u #{path}")
  end
  
  #############
  
  def launchJoomscan(path)
    # If this script downloaded the scanner previously execute the last downloaded
    # Launch joomscan
    @log.debug "Launching Joomscan: #{@JOOMSCANPATH} -u #{path}"
    # -ot output/scanners/#{path.gsub(/(:|\/)/,"_")} -oh output/scanners/#{path.gsub(/(:|\/)/,"_")}
    system("#{@JOOMSCANPATH} -u #{path}")
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
  
  def getWPScanPath()
    # Check if wfuzz is in the path
    whereisoutput = `whereis wpscan`
    thpaths = whereisoutput.split(":")[1]
    thpaths.split(" ").each {|path|
      if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-ruby"
        return path
      end      
    }
    return nil
  end
  
  ##########################
  
  def getJoomscanPath()
    # Check if wfuzz is in the path
    whereisoutput = `whereis joomscan`
    thpaths = whereisoutput.split(":")[1]
    thpaths.split(" ").each {|path|
      if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-shellscript"
        return path
      end      
    }
    return nil
  end
   
  ##########################
  
  def getWfuzzPath()
    # Check if wfuzz is in the path
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
    clean_disentry = disentry.gsub("$","")
    disentry_output = "tmpoutputs/#{clean_disentry.gsub("/","_").gsub(":","").gsub("*","FUZZ")}.html"
    wfuzzcmd = "#{wfbin} -o html -t $threads$ -s $delay$ --hc $ignorec$ -z file,$dict$ #{clean_disentry.gsub("*","FUZZ")} 2> #{disentry_output}"
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
      if url.index("http://").nil? and url.index("https://").nil?
        url = "http://#{url}"
      end 
      puts 
      puts "#"*(url.length + 4)
      puts "# #{url} #"
      puts "#"*(url.length + 4)
      begin
        uri = URI.parse(url)
        @log.debug "Searching for robots.txt file..."
        puts
        puts "Searching for robots.txt file..."
        robotsurl = "#{uri.scheme}://#{uri.host}/robots.txt"
        # TODO: Change timeout for the HTTP connexion (https://stackoverflow.com/questions/13074779/ruby-nethttp-idle-timeout)
        robots_response = fetch(robotsurl)
        if robots_response.code.to_i == 200
          @log.warn("It seems #{robotsurl} is accesible (#{robots_response.code}).")
          print "[FOUND] (#{robots_response.code}): ".green
          puts "#{robotsurl}"
          robots_body = robots_response.body
          if !robots_body.nil?
            if robots_body.length > 0
              # Deduce the CMS from the robots.txt entries
              @log.debug "Deducing CMS from '#{robotsurl}' file."
              puts
              puts "Deducing CMS from '#{robotsurl}' file"
              deducedCMSs = deducePossiblesCMS(robots_body)
              @log.info("Possibles CMS engines detected #{deducedCMSs}")
              deducedCMSs.each{|possiblecms|
                if (possiblecms[1] > @@CMSCONFIDENCE)
                  print " [POSSIBLE CMS]: ".green
                  puts "#{possiblecms[0]} (#{(possiblecms[1]*100)}% coincidences)"
                  # If the CMS is WP or Joomla or Drupal, execute the scanners
                  if possiblecms[0].downcase.include?("joomla")
                    if @joomscanconfig["enabled"].to_i != 0
                      puts "Executing Joomla Scanner"
                      launchJoomscan("#{uri.scheme}://#{uri.host}/")
                    else
                      @log.debug("Not scanning with joomscan '#{uri.scheme}://#{uri.host}/'")
                    end
                  elsif possiblecms[0].downcase.include?("wordpress")
                    if @wpscanconfig["enabled"].to_i != 0
                      puts "Executing Wordpress scanner if enabled"
                      launchWPScan("#{uri.scheme}://#{uri.host}/")
                    else
                      @log.debug("Not scanning with wpscan '#{uri.scheme}://#{uri.host}/'")
                    end
                  elsif possiblecms[0].downcase.include?("drupal")
                    puts "STUB: Executing Drupal scanner"
                  else
                    puts "No scanner configured for this CMS."
                  end
                end                
              }
              @log.debug  "Searching for 'Disallowed' URLs"
              puts
              puts "Searching for 'Disallowed' URLs..."
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
                          print "[FOUND] (#{dis_response.code}): ".green
                          puts "#{disurl}"
                          if hasJuicyFiles(prohibido)
                            @log.info "URL '#{disurl}' exists. (And it seems interesting)"
                            # puts " It seems interesting in the Path!".red
                            puts " * [INTERESTING PATH]".red
                          end
                          if !(jw = hasJuicyWords(dis_response.body)).nil?
                            @log.info "URL '#{disurl}' exists. (And it seems interesting in his body)"
                            # puts " It seems interesting in his body content! (Words found: #{jw})".red
                            jw.each{ |k,v|
                              puts " * [INTERESTING TEXT]: '#{v}'"                              
                            }
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
                          print "[NOT FOUND] (#{dis_response.code}): ".light_red
                          puts "#{disurl}"
                        end
                      else
                        # TODO: Support more than one wildcard in the URL
                        if @fuzz and !getWfuzzPath.nil?
                          if disurl.count("*") == 1
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
                            @log.info("Disallowed entry has more than one wildcard '*'. Not fuzzing.")
                            puts "Disallowed entry has more than one wildcard '*'. Not fuzzing."
                          end 
                        else
                          @log.info("Disallowed entry has wildcards '*'. Not visiting.")
                          puts "Disallowed entry has wildcards '*'. Not visiting."
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
          print "[NOT FOUND] (#{robots_response.code}): ".light_red
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
      rescue Exception => e
        @log.error("Error on connexion: #{e.message}")  
      end  
    }
    urlf.close
  end
  
  ##########################

  def deducePossiblesCMS(robots_content)
    # Returns a percentage of coincidence with tipical robots.txt files
    cmssimilarity = {}
    if File.exists?("config/cmsrobots.cfg")
      cmsh = eval(File.open("config/cmsrobots.cfg","r").read)
      cmsh.each {|cms,cmsentries|
        # Calculating similarity of this robots.txt content with the cmsentries
        norm_cmsentries = []
        cmsentries.each{|entry| norm_cmsentries << entry.upcase }
        # puts "Norm entries: #{norm_cmsentries}"
        cmssimilarity[cms] = 0.0
        
        robots_content.split("\n").each{ |rline|
          disallowm =  /^\s*Disallow\s*:\s*(.*)\s*$/.match(rline)  
          if disallowm
            prohibido = disallowm.captures[0].strip
            if !norm_cmsentries.index(prohibido.upcase).nil?
              cmssimilarity[cms] += 1
            end
          end              
        }
        cmssimilarity[cms] = (cmssimilarity[cms]/norm_cmsentries.size.to_f).round(1) if norm_cmsentries.size > 0
      }
    end
    cmssimilarity = cmssimilarity.sort_by{|key,value| value}.reverse
    return cmssimilarity
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
    @log.debug("Deleting temporal files from 'tmpoutputs/'")
    FileUtils.rm_r Dir.glob("tmpoutputs/*")
    Dir.delete("tmpoutputs/")
  end
  
end # class RobotsRider