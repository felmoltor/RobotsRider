require 'net/http'
require 'net/https'
require 'logger'
require 'uri'
require 'colorize'
require 'nokogiri'
require 'open-uri'
require 'fileutils'

# TODO: Save in summary the results in HTML or XML
# TODO: Add queries to archive.org API to retrieve cached entries of webpages
# TODO: Optionaly bruteforce with wfuzz authentication to pages found with '403 Forbidden' code
# TODO: Add Plown vuln scanner for Plone CMS https://github.com/unweb/plown
# TODO: Add CMS Xoomp and Nuke cms scan support with http://sourceforge.net/projects/odz/
# TODO: Add threads to launch CMS Scans.

class RobotsRider
  
  def initialize(options)
    @@CMSCONFIDENCE = 0.75
    @wpscanconfig = readWPScanConfig()
    @joomscanconfig = readJoomscanConfig()
    @plownconfig = readPlownConfig()
    @dpscanconfig = readDPScanConfig()
    
    # Get executable path if not defined in the config files
    if !@wpscanconfig["path"].nil? and @wpscanconfig["path"].size > 0 and File.exists?(@wpscanconfig["path"])
      @wpscanpath = @wpscanconfig["path"]
    else
      @wpscanpath = getWPScanPath()
    end
    if !@joomscanconfig["path"].nil? and @joomscanconfig["path"].size > 0 and File.exists?(@joomscanconfig["path"])
      @joomscanpath = @joomscanconfig["path"]
    else
      @joomscanpath = getJoomscanPath()
    end
    if !@plownconfig["path"].nil? and @plownconfig["path"].size > 0 and File.exists?(@plownconfig["path"])
      @plownpath = @plownconfig["path"]
    else
      @plownpath = getPlownPath()
    end
    if !@dpscanconfig["path"].nil? and @dpscanconfig["path"].size > 0 and File.exists?(@dpscanconfig["path"])
      @dpscanpath = @dpscanconfig["path"]
    else
      @dpscanpath = getDPScanPath()
    end
    
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
    wpscanconfig = eval(File.open("config/scanners/wpscan.cfg","r").read)
  end
  
  #############
  
  def readJoomscanConfig()
    joomscanconfig = eval(File.open("config/scanners/joomscan.cfg","r").read)
  end
  
  #############
  
  def readPlownConfig()
    joomscanconfig = eval(File.open("config/scanners/plown.cfg","r").read)
  end
  #############
  
  def readDPScanConfig()
    joomscanconfig = eval(File.open("config/scanners/dpscan.cfg","r").read)
  end
  
  #############
  
  def launchDPScan(path)
    outfile = "#{File.expand_path(File.dirname(__FILE__))}/../outputs/scanners/dpscan/#{path.gsub(/(:|\/)/,"_")}.txt"
    # Launch wpscan
    dpscancmd = "#{@dpscanpath} #{path}"
    if !@dpscanconfig["user"].nil? and @dpscanconfig["user"].size.to_i > 0
      dpscancmd += " #{@dpscanconfig['user']}"
    end
    if !@dpscanconfig["password"].nil? and @dpscanconfig["password"].size.to_i > 0
      dpscancmd += " #{@dpscanconfig['password']}"
    end
    @log.debug "Launching DPScan #{dpscancmd}"
    puts "Launching DPScan. This could take a while, you can check the process of the scan executing 'tail -f #{outfile}'"
    dpoutput = %x(#{dpscancmd} > #{outfile})
    puts "Exit status of the scan #{$?.exitstatus}"
  end
  
  #############
  
  def launchPlown(path)
    outfile = "#{File.expand_path(File.dirname(__FILE__))}/../outputs/scanners/plown/#{path.gsub(/(:|\/)/,"_")}.txt"
    # Launch plown
    plowncmd = "#{@plowpath}"
    if !@plownconfig["threads"].nil? and @plownconfig["threads"].to_i > 0
      plowncmd += " -T #{@plownconfig['threads']}"
    end
    if !@plownconfig["bruteforce"].nil? and @plownconfig["bruteforce"].to_i > 0
      plowncmd += " -b"
    end
    if !@plownconfig["userlist"].nil? and @plownconfig["userlist"].size.to_i > 0 and File.exists?(@plownconfig["userlist"])
      plowncmd += " -U #{@plownconfig["userlist"]}"
    end
    if !@plownconfig["passwordlist"].nil? and @plownconfig["passwordlist"].size.to_i > 0 and File.exists?(@plownconfig["passwordlist"])
      plowncmd += " -P #{@plownconfig["passwordlist"]}"
    end
    plowncmd += " #{path} "
    @log.debug "Launching plown: #{plowncmd}"
    puts "Launching Plown. This could take a while, you can check the process of the scan executing 'tail -f #{outfile}'"
    plownout = %x(#{plowncmd} > #{outfile})
    puts "Exit status of the scan #{$?.exitstatus}"
  end
  
  #############
  
  def launchWPScan(path)
    outfile = "#{File.expand_path(File.dirname(__FILE__))}/../outputs/scanners/joomscan/#{path.gsub(/(:|\/)/,"_")}.txt"
    # Launch wpscan
    wpscancmd = "#{@wpscanpath}"
    if !@wpscanconfig["wordlist"].nil? and File.exists?(@wpscanconfig["wordlist"])
      wpscancmd += " --wordlist #{@wpscanconfig['wordlist']}"
    end
    if !@wpscanconfig["threads"].nil? and @wpscanconfig["threads"].to_i > 0
      wpscancmd += " --threads #{@wpscanconfig['threads']}"
    end
    if !@wpscanconfig["username"].nil? and @wpscanconfig["username"].size > 0
      wpscancmd += " --username #{@wpscanconfig['username']}"
    end
    if !@wpscanconfig["enumerate plugins"].nil? and @wpscanconfig["enumerate plugins"].to_i > 0
      wpscancmd += " --enumerate p"
    end
    if !@wpscanconfig["enumerate themes"].nil? and @wpscanconfig["enumerate themes"].to_i > 0
      wpscancmd += " --enumerate t"
    end
    if !@wpscanconfig["enumerate users"].nil? and @wpscanconfig["enumerate users"].to_i > 0
      wpscancmd += " --enumerate u"
    end
    if !@wpscanconfig["enumerate timthumbs"].nil? and @wpscanconfig["enumerate timthumbs"].to_i > 0
      wpscancmd += " --enumerate tt"
    end
    if !@wpscanconfig["proxy"].nil? and @wpscanconfig["proxy"].size.to_i > 0
      wpscancmd += " --proxy #{@wpscanconfig["proxy"]}"
    end
    wpscancmd += " --url #{path} "
    @log.debug "Launching wpscan: #{wpscancmd}"
    puts "Launching Joomscan. This could take a while, you can check the process of the scan executing 'tail -f #{outfile}'"
    wpoutput = %x(#{wpscancmd} > #{outfile})
    puts "Exit status of the scan #{$?.exitstatus}"
  end
  
  #############
  
  def launchJoomscan(path)
    outfile = "#{File.expand_path(File.dirname(__FILE__))}/../outputs/scanners/joomscan/#{path.gsub(/(:|\/)/,"_")}.txt"
    # Launch joomscan
    jscancmd = "#{@joomscanpath}"
    puts jscancmd
    if !@joomscanconfig["htmlout"].nil? and @joomscanconfig["htmlout"].to_i > 0
      jscancmd += " -oh" # #{File.expand_path(File.dirname(__FILE__))}/../outputs/scanners/joomscan/#{path.gsub(/(:|\/)/,'_')}.html"
    end
    if !@joomscanconfig["textout"].nil? and @joomscanconfig["textout"].to_i > 0
      jscancmd += " -ot" # #{File.expand_path(File.dirname(__FILE__))}/../outputs/scanners/joomscan/#{path.gsub(/(:|\/)/,'_')}.txt"
    end
    if !@joomscanconfig["useragent"].nil? and @joomscanconfig["useragent"].size.to_i > 0
      jscancmd += " -g '#{@joomscanconfig["useragent"]}'"
    end
    if !@joomscanconfig["novfingerprint"].nil? and @joomscanconfig["novfingerprint"].to_i > 0
      jscancmd += " -nv"
    end
    if !@joomscanconfig["nofwdetection"].nil? and @joomscanconfig["nofwdetection"].to_i > 0
      jscancmd += " -nf"
    end
    if !@joomscanconfig["pokeversion"].nil? and @joomscanconfig["pokeversion"].to_i > 0
      jscancmd += " -pe"
    end
    if !@joomscanconfig["cookie"].nil? and @joomscanconfig["cookie"].size.to_i > 0
      jscancmd += " -c #{@wpscanconfig["cookie"]}"
    end
    if @joomscanconfig["proxy"].nil? and @joomscanconfig["proxy"].size.to_i > 0
      jscancmd += " -x #{@joomscanconfig["proxy"]}"
    end
    jscancmd += " -u #{path} "
    @log.debug "Launching Joomscan: #{jscancmd}"
    puts "Launching Joomscan. This could take a while, you can check the process of the scan executing 'tail -f #{outfile}'"
    joutput = %x(#{jscancmd} > #{outfile})
    puts "Exit status of the scan #{$?.exitstatus}" 
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
  
  def getDPScanPath()
    # Check if wfuzz is in the path
    whereisoutput = `whereis DPScan`
    thpaths = whereisoutput.split(":")[1]
    thpaths.split(" ").each {|path|
      if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-python"
        return path
      end      
    }
    return nil
  end
  
  ##########################
  
  def getPlownPath()
    # Check if wfuzz is in the path
    whereisoutput = `whereis plown`
    thpaths = whereisoutput.split(":")[1]
    thpaths.split(" ").each {|path|
      if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-python"
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
  
  def findCMSByGeneratorTag(bodycontent)
    # Busca algo como:
    # <meta name="Generator" content="Joomla! - Copyright (C) 2005 - 2007 Open Source Matters. All rights reserved." />
    # <meta name="generator" content="WordPress 3.7.1" />   
    generator = nil
    html_doc = Nokogiri::HTML(bodycontent)
    if !html_doc.xpath("//meta[@name='Generator']").nil?
      if html_doc.xpath("//meta[@name='Generator']").size > 0 and !html_doc.xpath("//meta[@name='Generator']")[0].nil?
        generator = html_doc.xpath("//meta[@name='Generator']")[0]['content']
      end
    end
    
    if !html_doc.xpath("//meta[@name='generator']").nil?
      if html_doc.xpath("//meta[@name='generator']").size > 0 and !html_doc.xpath("//meta[@name='generator']")[0].nil?
        generator = html_doc.xpath("//meta[@name='generator']")[0]['content']
      end
    end
    return generator
  end
  
  ##########################
  
  def findCMSByPoweredByText(bodycontent)
    # Busca algo como <p align="center">Copyright &copy; 2014 <a href="http://www.awsnabooks.org/store/index.php">Books&More</a><br />Powered by <a href="http://www.oscommerce.com" target="_blank">osCommerce</a></p> -->
    # Busqueda en texto claro de "Powered By <a href="http://www.joomla.org">Joomla!</a>"
    poweredby = nil
    pbregex = /Powered By <a\s+href=.*>(.*)<\/a>/i
    if !bodycontent.match(pbregex).nil?
      poweredby = bodycontent.match(pbregex)[1]
    end
    return poweredby
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
  
  def launchCMSScans(cmsname,uri)
    # If the CMS is WP or Joomla or Drupal, execute the scanners
    if cmsname.downcase.include?("joomla")
      if @joomscanconfig["enabled"].to_i != 0
        launchJoomscan("#{uri.scheme}://#{uri.host}/")
      else
        @log.debug("Not scanning with joomscan '#{uri.scheme}://#{uri.host}/'")
      end
    elsif cmsname.downcase.include?("wordpress")
      if @wpscanconfig["enabled"].to_i != 0
        launchWPScan("#{uri.scheme}://#{uri.host}/")
      else
        @log.debug("Not scanning with wpscan '#{uri.scheme}://#{uri.host}/'")
      end
    elsif cmsname.downcase.include?("drupal")
      if @dpscanconfig["enabled"].to_i != 0
        launchDPScan("#{uri.scheme}://#{uri.host}/")
      else
        @log.debug("Not scanning with wpscan '#{uri.scheme}://#{uri.host}/'")
      end
    elsif cmsname.downcase.include?("plone")
      if @plownconfig["enabled"].to_i != 0
        launchPlowns("#{uri.scheme}://#{uri.host}/")
      else
        @log.debug("Not scanning with plown '#{uri.scheme}://#{uri.host}/'")
      end
      # If the user has no plown installed tell him to download it from https://github.com/unweb/plown
    else
      puts "No scanner configured for this CMS."
    end
  end
  
  #############
  
  def rideRobots()
    # Create folder for visited in this execution
    visiteddir = "outputs/visited/#{Time.now.strftime('%Y%m%d_%H%M%S')}/"
    if @visit
      Dir.mkdir(visiteddir)
    end    
    # Read the file with URLs
    urlf = File.open(@urlfile,"r")
    urlf.each {|url|
      cmsname = ""
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
        # Deducing CMS by Generator Tag and Powered By Text 
        @log.debug "Searching for Generator tag and Powered By text in #{url}..."
        rootbody = uri.read 
        generator = findCMSByGeneratorTag(rootbody)
        poweredby = findCMSByPoweredByText(rootbody)
        if !generator.nil?
          if generator.size > 0
            @log.debug "Found generator #{generator}..."
            print "Found generator "
            puts "#{generator}".green
            cmsname = generator
          end           
        end        
        if !poweredby.nil?
          if poweredby.size > 0
            @log.debug "Found generator #{poweredby}..."
            print "Found generator "
            puts "#{poweredby}".green
            cmsname = poweredby if cmsname.size == 0
          end           
        end
        # Looking for robots.txt file
        @log.debug "Searching for robots.txt file..."
        puts
        puts "Searching for robots.txt file..."
        robotsurl = "#{uri.scheme}://#{uri.host}/robots.txt"
        # TODO: Change timeout for the HTTP connexion (https://stackoverflow.com/questions/13074779/ruby-nethttp-idle-timeout)
        robots_response = fetch(robotsurl)
        if robots_response.code.to_i == 200
          @log.info("It seems #{robotsurl} is accesible (#{robots_response.code}).")
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
              firstcms = 0
              deducedCMSs.each{|possiblecms|
                firstcms += 1
                if (possiblecms[1] > @@CMSCONFIDENCE)
                  print " [POSSIBLE CMS]: ".green
                  puts "#{possiblecms[0]} (#{(possiblecms[1]*100)}% coincidences)"
                  cmsname = possiblecms[0] if cmsname.size == 0 and firstcms == 1
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
                            puts " |-> [INTERESTING PATH]".red
                          end
                          if !(jw = hasJuicyWords(dis_response.body)).nil?
                            @log.info "URL '#{disurl}' exists. (And it seems interesting in his body)"
                            # puts " It seems interesting in his body content! (Words found: #{jw})".red
                            jw.each{ |k,v|
                              puts " |-> [INTERESTING TEXT]: '#{v}'"                              
                            }
                          end
                          if hasJuicyTitle(dis_response.body)
                            @log.info "URL '#{disurl}' exists. (And it seems interesting in his Title)"
                            # puts " It seems interesting in his page Title!".red
                            puts " |-> [INTERESTING TITLE]".red
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
                            @log.info("Disallowed entry '#{disurl}' has more than one wildcard '*'. Not fuzzing.")
                            puts "Disallowed entry '#{disurl}' has more than one wildcard '*'. Not fuzzing."
                          end 
                        else
                          @log.info("Disallowed entry has wildcards '*'. Not visiting.")
                          puts "Disallowed entry '#{disurl}' has wildcards '*'. Not visiting."
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
        # Launch vulnerability scan for detected CMS
        launchCMSScans(cmsname,uri)
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
    #FileUtils.rm_r Dir.glob("tmpoutputs/*")
    #Dir.delete("tmpoutputs/")
  end
  
end # class RobotsRider