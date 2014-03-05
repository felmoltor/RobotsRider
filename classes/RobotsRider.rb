require 'net/http'
require 'net/https'
require 'logger'
require 'uri'
require 'colorize'
require 'nokogiri'
require 'open-uri'
require 'fileutils'
require 'timeout'
require_relative 'RobotsWeb'
require 'pp'

# TODO: Save in summary the results in HTML or XML
# TODO: Optionaly bruteforce with wfuzz authentication to pages found with '403 Forbidden' code
# TODO: Add CMS Xoomp and Nuke cms scan support with http://sourceforge.net/projects/odz/
# TODO: Add threads to launch CMS Scans.

class RobotsRider
  
  # attr_accessor :robotswebs
  
  def initialize(options)
    @@CMSCONFIDENCE = 0.6
    @@CONNECTTIMEOUT= 15 
    
    @robotswebs = []
    # Read Scanner configurations:
    @wpscanconfig = readWPScanConfig()
    @joomscanconfig = readJoomscanConfig()
    @plownconfig = readPlownConfig()
    @dpscanconfig = readDPScanConfig()
    # Read Tools Configurations:
    @wfuzzconfig = readWfuzzConfig()
    @harvesterconfig = readTheHarvesterConfig()
    
    # Autodiscover scanners path if not defined in the config files
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
    # Autodiscover tools path if not defined in the config files
    if !@wfuzzconfig["path"].nil? and @wfuzzconfig["path"].size > 0 and File.exists?(@wfuzzconfig["path"])
      @wfuzzpath = @wfuzzconfig["path"]
    else
      @wfuzzpath = getWfuzzPath()
    end
    if !@harvesterconfig["path"].nil? and @harvesterconfig["path"].size > 0 and File.exists?(@harvesterconfig["path"])
      @harvesterpath = @harvesterconfig["path"]
    else
      @harvesterpath = getTheHarvesterPath()
    end
    
    @urlfile = options[:urlfile]
    @domain = options[:domain]
    if !@domain.nil?
      @domain = @domain.gsub("http://","").gsub("https://","").gsub("www.","")
    end
    @fuzz_urls = options[:fuzz]
    @visit = options[:visit]
    @follow = options[:follow]
    @outputfile = options[:outputfile]
    @log = Logger.new("logs/#{Time.now.strftime('%Y%m%d_%H%M%S')}_robotsrider.log")
    
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
    if (File.exists?("config/juicytext/juicypaths.list"))
      jf = File.open("config/juicytext/juicypaths.list","r")
      jf.each {|jline|
        @juicypaths << jline.upcase.strip
      }
    end
    @juicywords = []
    if (File.exists?("config/juicytext/juicybody.list"))
      jw = File.open("config/juicytext/juicybody.list","r")
      jw.each {|jline|
        @juicywords << jline.upcase.gsub(/\s+/," ").strip
      }
    end
    
    @juicytitles = []
    if (File.exists?("config/juicytext/juicytitles.list"))
      jt = File.open("config/juicytext/juicytitles.list","r")
      jt.each {|jtitle|
        @juicytitles << jtitle.upcase.gsub(/\s+/," ").strip if jtitle.strip[0] != "#"
      }
    end
  end
  
  #############
  
  def setSubdomainsAsTargets()
    # Initialize the URL file if there was a domain specified and the user has 
    # theHarvester in hist PATH.
    if !@domain.nil?
      newurlfile = queryTheHarvester
      if !newurlfile.nil?
        @urlfile = newurlfile
      end
    end
  end
  
  #############
  
  def readWPScanConfig()
    eval(File.open("config/scanners/wpscan.cfg","r").read)
  end
  
  #############
  
  def readJoomscanConfig()
    eval(File.open("config/scanners/joomscan.cfg","r").read)
  end
  
  #############
  
  def readPlownConfig()
    eval(File.open("config/scanners/plown.cfg","r").read)
  end
  
  #############
  
  def readDPScanConfig()
    eval(File.open("config/scanners/dpscan.cfg","r").read)
  end
  
  #############
  
  def readWfuzzConfig()
    eval(File.open("config/tools/wfuzz.cfg","r").read)
  end
  
  #############
  
  def readTheHarvesterConfig()
    eval(File.open("config/tools/theharvester.cfg","r").read)
  end
  
  #############
  
  def printVulnScanOutput(outfile)
    puts " >> Scan resuls extracted from #{outfile}"
    of = File.open(outfile,"r")
    of.each{|line|
      print " >> #{line}"
    }    
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
    puts "Launching DPScan. This could take a while, please be patient..."
    puts "dpscancmd: #{dpscancmd}"
    dpoutput = %x(python #{dpscancmd} > #{outfile})
    @log.info("Exit status of the scan #{$?.exitstatus}")
    if $?.exitstatus != 0
      puts "There was an error doing this scan!".red
    else
      if File.zero?(outfile)
        @log.info("It seems the output of DPScan was empty...")
      end
      # Output of the scan
      printVulnScanOutput(outfile)
    end
  end
  
  #############
  
  def launchPlown(path)
    outfile = "#{File.expand_path(File.dirname(__FILE__))}/../outputs/scanners/plown/#{path.gsub(/(:|\/)/,"_")}.txt"
    # Launch plown
    plowncmd = "#{@plownpath}"
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
    @log.info("Exit status of the scan #{$?.exitstatus}")
    if $?.exitstatus != 0 or File.zero?(outfile)
      puts "There was an error doing this scan!".red
    else
      # Output of the scan
      printVulnScanOutput(outfile)
    end
  end
  
  #############
  
  def launchWPScan(path)
    outfile = "#{File.expand_path(File.dirname(__FILE__))}/../outputs/scanners/wpscan/#{path.gsub(/(:|\/)/,"_")}.txt"
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
    puts "Launching WPScan. This could take a while, you can check the process of the scan executing 'tail -f #{outfile}'"
    wpoutput = %x(#{wpscancmd} > #{outfile})
    @log.info("Exit status of the scan #{$?.exitstatus}")
    if $?.exitstatus != 0 or File.zero?(outfile)
      puts "There was an error doing this scan!".red
    else
      # Output of the scan
      printVulnScanOutput(outfile)
    end
  end
  
  #############
  
  def launchJoomscan(path)
    outfile = "#{File.expand_path(File.dirname(__FILE__))}/../outputs/scanners/joomscan/#{path.gsub(/(:|\/)/,"_")}.txt"
    # Launch joomscan
    jscancmd = "perl #{@joomscanpath}"
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
      jscancmd += " -c #{@joomscanconfig["cookie"]}"
    end
    if @joomscanconfig["proxy"].nil? and @joomscanconfig["proxy"].size.to_i > 0
      jscancmd += " -x #{@joomscanconfig["proxy"]}"
    end
    jscancmd += " -u #{path} "
    @log.debug "Launching Joomscan: #{jscancmd}"
    puts "Launching Joomscan. This could take a while, you can check the process of the scan executing 'tail -f #{outfile}'"
    joutput = %x(#{jscancmd} > #{outfile})
    
    @log.info("Exit status of the scan #{$?.exitstatus}")
    if $?.exitstatus != 0 or File.zero?(outfile)
      puts "There was an error doing this scan!".red
    else
      # Output of the scan
      printVulnScanOutput(outfile)
    end
  end
  
  #############
  
  def hasJuicyUrl?(path)
    @juicypaths.each {|jpath|
      jp = Regexp.escape(jpath)
      if !path.upcase.match(jp).nil?
        return true 
      end
    }
    return false
  end
  
  #############
  
  def hasJuicyTitle?(htmlcode)
    html_doc = Nokogiri::HTML(htmlcode)
    pagetitle = html_doc.css('title').text.upcase.gsub(/\s+/," ")
    @juicytitles.each {|jtitle|
      jt = Regexp.escape(jtitle)
      if !pagetitle.match(jt).nil? 
        return jt
      end
    }
    return nil
  end
  
  #############
  
  def hasJuicyWords?(htmlcode)
    # Normalize html code
    normalizedhtml = htmlcode.upcase.gsub(/\s+/," ")
    jphrases = {}
    
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
    # Check if wpscan is in the path
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
    # Check if Joomscan is in the path
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
    # Check if dpscan is in the path
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
    # Check if plown is in the path
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
  
  def processHtmlOutput(thtmpfile,resultfile)
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
  end
  
  ##########################
  
  def processRawTextOutput(cmdoutput,resultfile)
    
    fdomain = File.open(cmdoutput)
    hostfound = []
    
    ipname_1 = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(.*)$/
    ipname_2 = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(.*)$/
    
    fdomain.each{|dline|
      m1 = dline.match(ipname_1)
      if !m1.nil? and !m1[2].nil?
        hostfound << m1[2]        
      end
      m2 = dline.match(ipname_2)
      if !m2.nil? and !m2[2].nil?
        hostfound << m2[2]        
      end
    }
    urlsfile = File.open(resultfile,"w")
    hostfound = hostfound.sort.uniq
    hostfound.each {|h|
      domainfilter = @domain.gsub(/\..{2,4}$/,"")
      if h.include?(domainfilter)
        urlsfile.puts("http://#{h}")
      end
    }
    urlsfile.close
  end  
  
  ##########################
  
  def queryTheHarvester()
    # This function calls the programwhereis theharvester theHarvester automaticaly to harvest URLs from a domain
    # Instead of providing the program with a list of urls we can directly ask for a domain
    resultfile = "/tmp/harvester_output_#{@domain.gsub(/[\/|:]/,"_")}.list"
    cmdoutput = "/tmp/harvester_output_#{@domain.gsub(/[\/|:]/,"_")}.out"
    thtmpfile = "/tmp/#{@domain.gsub(/[\/|:]/,"_")}.html"
    # thbin = getTheHarvesterPath()
    
    if !@harvesterpath.nil?
      # Create an URL file with the outuput of the harvester for hosts
      # Retrieve the host found in the domain provided by the user
      cmdline = "#{@harvesterpath} -f #{thtmpfile} -d #{@domain} -b all "
      @log.info "Searching with 'theharvester' information about the domain #{@domain}"
      @log.debug " #{cmdline}"
      salida = %x(#{cmdline} > #{cmdoutput})
      # Sometimes theHarvester does not work properly (a.k.a. Bug) and does not save the output in the file
      # In this case we'll explore the text output of the command
      if File.exists?(thtmpfile)
        @log.debug("theHarvester properly and saved the results in #{thtmpfile}. Exploring results from html output...")
        processHtmlOutput(thtmpfile,resultfile)  
        File.delete(thtmpfile)   
      elsif (File.exists?(cmdoutput))
        @log.warn("theHarvester didn't work properly and did not save the results in #{thtmpfile}. Exploring incomplete results from text output...")
        processRawTextOutput(cmdoutput,resultfile)       
        File.delete(cmdoutput)    
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
   
  # TODO: Support more than basic authentication
  def fuzzForbiddenEntry(forbiddenentry)
    
    defaultuserdic = "/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/unix-os/unix_users.txt"
    defaultpassdic = "/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/unix-os/unix_passwords.txt"
    defaultdelay = "0.3"
    defaultthreads =  "10"
    defaultignorec = "404,400"
    forbidden_output = "/tmp/#{forbiddenentry.gsub("/","_").gsub(":","")}_basic_auth_fuzz.txt"
    wfuzzcmd = "#{@wfuzzpath} -t $threads$ -s $delay$ --hc $ignorec$ -z file,$userdict$ -z file,$passdict$ --basic FUZZ:FUZ2Z #{forbiddenentry} > #{forbidden_output}"
    validcredentials = []
    
    if File.exists?("config/tools/wfuzz.cfg")
      # Fill in the blanks
      wfuzzh = eval(File.open("config/tools/wfuzz.cfg","r").read)
      
      if !wfuzzh["auth_name_dict"].nil?
        wfuzzcmd.gsub!("$userdict$",wfuzzh["auth_name_dict"])      
      else
        wfuzzcmd.gsub!("$userdict$",defaultuserdic)        
      end      
      if !wfuzzh["auth_pass_dict"].nil?
        wfuzzcmd.gsub!("$passdict$",wfuzzh["auth_pass_dict"])      
      else
        wfuzzcmd.gsub!("$passdict$",defaultuserdic)        
      end      
      if !wfuzzh["threads"].nil?
        wfuzzcmd.gsub!("$threads$",wfuzzh["threads"].to_s)      
      else
        wfuzzcmd.gsub!("$threads$",defaultthreads)        
      end      
      if !wfuzzh["delay"].nil?
        wfuzzcmd.gsub!("$delay$",wfuzzh["delay"].to_s)      
      else
        wfuzzcmd.gsub!("$delay$",defaultdelay)        
      end      
      if !wfuzzh["ignore"].nil?
        wfuzzcmd.gsub!("$ignorec$",wfuzzh["ignore"])      
      else
        wfuzzcmd.gsub!("$ignorec$",defaultdic)        
      end
      
      @log.debug "Executing the following command #{wfuzzcmd}"
      wfuzzres = `#{wfuzzcmd}`
      
      File.open(forbidden_output,"r").each {|line|
        m_validcreds = /.*C=200.*\" - (.*) - (.*)\"/.match(line)
        if !m_validcreds.nil? and !m_validcreds[1].nil? and !m_validcreds[2].nil? 
          validuser = m_validcreds[1]
          validpass = m_validcreds[2]
          validcredentials << "#{validuser}:#{validpass}"      
        end
      }
      return validcredentials
    else
      return nil
    end    
  end
  
  #############
  
  # This funciont fuzz possible URLs
  def fuzzDisallowedEntry(disentry)
    
    defaultdic = "/usr/share/wfuzz/wordlist/general/common.txt"
    defaultdelay = "0.3"
    defaultthreads =  "10"
    defaultignorec = "404,400"
    clean_disentry = disentry.gsub("$","")
    disentry_output = "/tmp/#{clean_disentry.gsub("/","_").gsub(":","").gsub("*","FUZZ")}.html"
    wfuzzcmd = "#{@wfuzzpath} -o html -t $threads$ -s $delay$ --hc $ignorec$ -z file,$dict$ #{clean_disentry.gsub("*","FUZZ")} 2> #{disentry_output}"
    fuzzdict = {}
    

    if File.exists?("config/tools/wfuzz.cfg")
      # Fill in the blanks
      wfuzzh = eval(File.open("config/tools/wfuzz.cfg","r").read)
      if !wfuzzh["dictionary"].nil?
        wfuzzcmd.gsub!("$dict$",wfuzzh["dictionary"])      
      else
        wfuzzcmd.gsub!("$dict$",defaultdic)        
      end
      if !wfuzzh["threads"].nil?
        wfuzzcmd.gsub!("$threads$",wfuzzh["threads"].to_s)      
      else
        wfuzzcmd.gsub!("$threads$",defaultthreads)        
      end      
      if !wfuzzh["delay"].nil?
        wfuzzcmd.gsub!("$delay$",wfuzzh["delay"].to_s)      
      else
        wfuzzcmd.gsub!("$delay$",defaultdelay)        
      end      
      if !wfuzzh["ignore"].nil?
        wfuzzcmd.gsub!("$ignorec$",wfuzzh["ignore"])      
      else
        wfuzzcmd.gsub!("$ignorec$",defaultdic)        
      end
      
      
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
  
  def launchCMSScans(cmsname,url)
    # If the CMS is WP or Joomla or Drupal, execute the scanners
    if cmsname.downcase.include?("joomla")
      if @joomscanconfig["enabled"].to_i != 0
        launchJoomscan("#{url}")
      else
        @log.debug("Not scanning with joomscan '#{url}'")
      end
    elsif cmsname.downcase.include?("wordpress")
      if @wpscanconfig["enabled"].to_i != 0
        launchWPScan("#{url}")
      else
        @log.debug("Not scanning with wpscan '#{url}'")
      end
    elsif cmsname.downcase.include?("drupal")
      if @dpscanconfig["enabled"].to_i != 0
        launchDPScan("#{url}")
      else
        @log.debug("Not scanning with dpscan '#{url}'")
      end
    elsif cmsname.downcase.include?("plone")
      if @plownconfig["enabled"].to_i != 0
        launchPlown("#{url}")
      else
        @log.debug("Not scanning with plown '#{url}'")
      end
      # If the user has no plown installed tell him to download it from https://github.com/unweb/plown
    else
      puts "No scanner configured for this CMS."
    end
  end
  
  #############
  
  # Not a very acurate way of detect name and version of a CMS...
  def getNameAndVersionFromString(cmsstr)
    name = version = nil
    # Words followed by a string with numbers and points 
    m = /([^\s]+)\s+(\d+(\.\d+)*)?\s*.*/.match(cmsstr)
    if !m.nil?
      name = m[1]
      version = m[2]
    else 
      name = cmsstr
      version = "<UNKNOWN>"
      name = "<UNKNOWN>" if name.nil? or name.size == 0
    end
    return name,version
  end
  
  #############
  
  def releaseTheDogs()
    # This method launch the CMS scanners to all the identified CMS sites
    # webs Is an array of Webs objects to iterate 
    @robotswebs.each {|rweb|
      puts 
      puts "#"*(rweb.url.length + 4)
      puts "# #{rweb.url} #"
      puts "#"*(rweb.url.length + 4)
      if rweb.cms[:name] == "<UNKNOWN>"
        print "[NOT SCANNING]: ".red
        puts "We couldn't detect a CMS"
      else
        print "[SCANNING]: ".green
        puts "Releasing the dogs for '#{rweb.cms[:name]} #{rweb.cms[:version]}'"
        launchCMSScans(rweb.cms[:name],rweb.url)        
      end
    }
    
  end
  
  #############
  
  def releaseTheKraken()
    # Start bruteforce to all 403 pages
    foundCredentials = {}
    @robotswebs.each {|rweb|
      rweb.disallowed.each {|disentry,vals|
        if vals[:response].to_i == 401
          # Bruteforce the authenticatio
          @log.info("Bruteforcing #{disentry}")
          print " [BRUTEFORCING]".red
          puts " #{disentry}"
          creds = fuzzForbiddenEntry(disentry)
          if !creds.nil? and creds.size > 0
            foundCredentials["#{disentry}"] = creds
          end
        else
          @log.info("Not bruteforcing #{disentry} because is not a Forbidden entry")
          # print " [NOT BRUTEFORCING]".green
          # puts " #{disentry}"
        end
      }
    }
    return foundCredentials
  end
  
  #############
  
  def rideRobots()
    # Create folder for visited in this execution"
    visiteddir = "outputs/visited/#{Time.now.strftime('%Y%m%d_%H%M%S')}/"
    if @visit
      Dir.mkdir(visiteddir)
    end    
    # Read the file with URLs
    urlf = File.open(@urlfile,"r")
    urlf.each {|url|
      rweb = RobotsWeb.new(url)
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
        # If the connection is not produced after X seconds we can conclude this is not a web server 
        # and skip further tests
        rootbody = ""
        begin
          Timeout::timeout(@@CONNECTTIMEOUT) do
            rootbody = uri.read 
          end
          # If previous block does not timeout, continue with the web tests
          generator = findCMSByGeneratorTag(rootbody)
          poweredby = findCMSByPoweredByText(rootbody)
          rweb.generators << generator
          rweb.poweredby << poweredby
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
          separator = "/"
          if (uri.path.to_s[-1] == "/") 
            separator = ""
          end
          robotsurl = "#{uri.scheme}://#{uri.host}#{uri.path}#{separator}robots.txt"
          rweb.robots[:url] = robotsurl
          # TODO: Change timeout for the HTTP connexion (https://stackoverflow.com/questions/13074779/ruby-nethttp-idle-timeout)
          robots_response = fetch(robotsurl)
          rweb.robots[:response] = robots_response.code.to_i
          puts "Guardando en rweb.robots[:response] el valor #{rweb.robots[:response]} para rweb.robots[:url] "
          if robots_response.code.to_i == 200
            @log.info("It seems #{robotsurl} is accesible (#{robots_response.code}).")
            print " [FOUND] (#{robots_response.code}): ".green
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
                puts " No CMS could be deduced from file 'robots.txt'" if cmsname.size == 0
                @log.debug  "Searching for 'Disallowed' URLs"
                puts
                puts "Searching for 'Disallowed' URLs..."
                robots_body.split("\n").each {|rline|
                  disallowm =  /^\s*Disallow\s*:\s*(.*)\s*$/.match(rline)  
                  if disallowm
                    prohibido = disallowm.captures[0].strip
                    if prohibido.length > 0 and prohibido.strip != "/"
                      separator = "/"
                      if (uri.path.to_s[-1] == "/") 
                        separator = ""
                      end
                      if prohibido[0]=="/"
                        prohibido =  prohibido[1,prohibido.length-1]
                      end
                      
                      disurl = "#{uri.scheme}://#{uri.host}#{uri.path}#{separator}#{prohibido}" # "#{uri.scheme}://#{uri.host}/#{prohibido}"
                      @log.info "Found '#{disurl}' as a disallowed entry."    
                      rweb_dentry = rweb.addDisallowedEntry(disurl)                
                        
                      if @visit
                        # If disallowed entry has wildcards, skip it from visiting
                        if (prohibido.match(/\*/).nil?)
                          savefile = "#{visiteddir}#{disurl.gsub("/","_").gsub(":","_")}"
                          @log.info("Visiting #{disurl} and saving in file #{savefile}")
                          dis_response = fetch(disurl)
                          rweb_dentry[:response] = dis_response.code.to_i
                          # Check if is a Juicy URL
                          interestingparts={:body=>false,:url=>false,:title=>false}
                          if dis_response.code.to_i == 200
                            # Search for juicy words in the url
                            @log.info "URL '#{disurl}' exists."
                            print " [FOUND] (#{dis_response.code}): ".green
                            puts "#{disurl}"
                            # Is this URL interesting?
                            if hasJuicyUrl?(prohibido)
                              @log.info "URL '#{disurl}' exists. (And it seems interesting)"
                              puts "  |-> [INTERESTING PATH]".red
                              interestingparts[:url] = true    
                            end
                            # Is the body interesting?
                            if !(jw = hasJuicyWords?(dis_response.body)).nil?
                              @log.info "URL '#{disurl}' exists. (And it seems interesting in his body)"
                              jw.each{ |k,v|
                                puts "  |-> [INTERESTING TEXT]: '#{k}'".red                        
                              }
                              interestingparts[:body] = true    
                            end
                            # Is the title interesting?
                            jt = hasJuicyTitle?(dis_response.body)
                            if !jt.nil?
                              @log.info "URL '#{disurl}' exists. (And it seems interesting in his Title)"
                              # puts " It seems interesting in his page Title!".red
                              puts "  |-> [INTERESTING TITLE]: '#{jt}'".red
                              interestingparts[:title] = true  
                            end
                            rweb_dentry[:interestingparts] = interestingparts
                            sf = File.open(savefile,"w")
                            sf.write(dis_response.body)
                            sf.close
                          else
                            @log.debug "URL '#{disurl}' is not accessible. (#{dis_response.code})"
                            print " [NOT ACCESSIBLE] (#{dis_response.code}): ".light_red
                            puts "#{disurl}"
                            # Is this URL interesting?
                            if hasJuicyUrl?(prohibido)
                              @log.info "URL '#{disurl}' is not accessible. (But it seems interesting)"
                              puts "  |-> [INTERESTING PATH]".red
                              interestingparts[:url] = true
                            end
                          end
                        else
                          # TODO: Support more than one wildcard in the URL
                          if @fuzz_urls and !@wfuzzpath.nil?
                            if disurl.count("*") == 1
                              @log.info("Widlcard found. Fuzzing with 'wfuzz'")
                              puts "Widlcard found in #{disurl}. Fuzzing it!"
                              # Fuzz this URL with wfuzz
                              fuzzdictionary = fuzzDisallowedEntry(disurl)
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
                            end 
                          else
                            @log.info("Disallowed entry has wildcards '*'. Not visiting.")
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
            print " [NOT FOUND] (#{robots_response.code}): ".light_red
            puts "#{robotsurl}"
          end
        rescue Timeout::Error => te
          $stderr.puts "Connection timed out. It seems this host is not a web server. Skipping further tests."
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
      
      rweb.cms[:name],rweb.cms[:version] = getNameAndVersionFromString(cmsname)
      # Save possible CMS 
      @log.info("Obtained CMS Name and version: #{rweb.cms[:name]}, #{rweb.cms[:version]}")
      # Append this robot web information
      @robotswebs << rweb
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

  def getThirdPartyStatus()
    # This method checks for presence of the scanners in your system
    # Open all files hanging from 'config/scanners'
    # For each file search for "path" and check if the path is pressent in this system
    scanners = {}
    tools = {}
    if Dir.exists?("config/scanners")
      Dir.entries("config/scanners").each {|entry|
        if /.*\.cfg$/.match(entry)
          scanners[entry] = {}
          # Explore this config file
          cfg = eval(File.open("config/scanners/#{entry}").read)
          # Check if the executable exists
          if !cfg["path"].nil?
            scanners[entry]["path"] = cfg["path"]
            scanners[entry]["autodiscover"] = false
            scanners[entry]["error"] = false
            
            if File.exists?(cfg["path"])
              scanners[entry]["present"] = true           
            else
              scanners[entry]["present"] = false
              scanners[entry]["error"] = true
            end
            # Check for its permissions
            if !File.readable?(cfg["path"])
                scanners[entry]["readable"] = false
                scanners[entry]["error"] = true             
            else
                scanners[entry]["readable"] = true            
            end
            if !File.executable?(cfg["path"])
                scanners[entry]["executable"] = false
                scanners[entry]["error"] = true  
            else
                scanners[entry]["executable"] = true            
            end
          else
            # This tool should be autodiscovered
            scanners[entry]["path"] = "<AUTODISCOVER>"
            scanners[entry]["autodiscover"] = true
            scanners[entry]["executable"] = nil
            scanners[entry]["readable"] = nil
          end
        end
      }
    end
    
    if Dir.exists?("config/tools")
      Dir.entries("config/tools").each {|entry|
        if /.*\.cfg$/.match(entry)
          tools[entry] = {}
          # Explore this config file
          cfg = eval(File.open("config/tools/#{entry}").read)
          # Check if the executable exists
          if !cfg["path"].nil?
            tools[entry]["path"] = cfg["path"]
            tools[entry]["autodiscover"] = false
            tools[entry]["error"] = false
            
            if File.exists?(cfg["path"])
              tools[entry]["present"] = true           
            else
              tools[entry]["present"] = false
              tools[entry]["error"] = true
            end
            # Check for its permissions
            if !File.readable?(cfg["path"])
                tools[entry]["readable"] = false
                tools[entry]["error"] = true             
            else
                tools[entry]["readable"] = true            
            end
            if !File.executable?(cfg["path"])
                tools[entry]["executable"] = false
                tools[entry]["error"] = true  
            else
                tools[entry]["executable"] = true            
            end
          else
            # This tool should be autodiscovered
            tools[entry]["path"] = "<AUTODISCOVER>"
            tools[entry]["autodiscover"] = true
            tools[entry]["executable"] = nil
            tools[entry]["readable"] = nil
          end
        end
      }
    end
    
    return scanners, tools
  end
  
  ##########################
  
  def saveHTMLReport(ofile)
    # STUB: Save output in a beautiful HTML 
    # Template to use is located in "samples/scan.output.sample.html"
    if !@outputfile.nil?
      puts "STUB: Saving summary to #{@outputfile}"
    end
    return false
  end
  
  ##########################
  
  def saveCSVReport(ofile)
    # Save output in CSV
    if !ofile.nil? and @robotswebs.size > 0
      of = File.open(ofile,"w")
      of.puts('URL;Robots.txt;CMS Name;CMS Version;Disallowed URL;Dis. Response;Interesting Title;Interesting URL;Interesting Body')
      
      @robotswebs.each {|rweb|
        
        robotsfield = "<UNKNOWN>"
        cmsname = "<UNKNOWN>"
        cmsversion = "<UNKNOWN>"
            
        if !rweb.robots[:url].nil? and !rweb.robots[:response].nil?
          if rweb.robots[:response].to_i == 200
            robotsfield = "ACCESSIBLE (200)"
          else
            robotsfield = "NOT ACCESSIBLE (#{rweb.robots[:response]})"
          end
        end
        cmsname = "#{rweb.cms[:name]}" if !rweb.cms[:name].nil? and rweb.cms[:name].size > 0
        cmsversion = "#{rweb.cms[:version]}" if !rweb.cms[:version].nil? and rweb.cms[:name].size > 0
        
        if rweb.disallowed.size > 0
          rweb.disallowed.each{|disurl,vals|
            # Default text
            durl = "<UNKNOWN>"
            disresponse = "<UNKNOWN>"
            ititle = "<UNKNOWN>"
            ibody = "<UNKNOWN>"
            iurl = "<UNKNOWN>"
            
            durl = "#{disurl}" if !disurl.nil? and disurl.size > 0
            disresponse = "#{vals[:response]}" if !vals[:response].nil? and vals[:response].size > 0
            # Interesting title?
            if !vals[:interestingparts][:title].nil?
              if vals[:interestingparts][:title]
                ititle = "YES"
              else
                ititle = "NO"
              end
            end
            # Interesting body?
            if !vals[:interestingparts][:body].nil?
              if vals[:interestingparts][:body]
                ibody = "YES"
              else
                ibody = "NO"
              end
            end
            # Interesting URL?
            if !vals[:interestingparts][:url].nil?
              if vals[:interestingparts][:url]
                iurl = "YES"
              else
                iurl = "NO"
              end
            end
  
            of.puts("\"#{rweb.url}\";\"#{robotsfield}\";\"#{cmsname}\";\"#{cmsversion}\";\"#{durl}\";\"#{disresponse}\";\"#{ititle}\";\"#{iurl}\";\"#{ibody}\"")
          }
        else # No disallowed entries were found or no robots file was found
          durl = "<UNKNOWN>"
          disresponse = "<UNKNOWN>"
          ititle = "<UNKNOWN>"
          ibody = "<UNKNOWN>"
          iurl = "<UNKNOWN>"
          
          of.puts("\"#{rweb.url}\";\"#{robotsfield}\";\"#{cmsname}\";\"#{cmsversion}\";\"#{durl}\";\"#{disresponse}\";\"#{ititle}\";\"#{iurl}\";\"#{ibody}\"")
        end        
      }
      of.close
      return true
    end
    return false
  end

  ##########################
  
  def saveReports(ofile)
    saveCSVReport(ofile)
    # saveHTMLReport(ofile)
  end

  ##########################
  
end # class RobotsRider