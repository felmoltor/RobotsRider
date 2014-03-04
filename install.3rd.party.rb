#!/usr/bin/env ruby
# This script download and install in your home directory the third party programs needed by Robots Rider.

require 'fileutils'

$destfolder="#{ENV['PWD']}/ThirdParty"

####################

def checkThirdPartyTools()
  tools = {
    :wpscan => nil,
    :dpscan => nil,
    :joomscan => nil,
    :plown => nil,
    :wfuzz => nil,
    :theharvester => nil,
  }
  
  # Searching wpscan
  whereisoutput = `whereis wpscan`
  thpaths = whereisoutput.split(":")[1]
  thpaths.split(" ").each {|path|
    if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-ruby"
      tools[:wpscan] = path
    end   
  }   
  
  whereisoutput = `whereis joomscandd`
  thpaths = whereisoutput.split(":")[1]
  thpaths.split(" ").each {|path|
    if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-shellscript"
      tools[:joomscan] = path
    end      
  }
  
  whereisoutput = `whereis DPScan`
  thpaths = whereisoutput.split(":")[1]
  thpaths.split(" ").each {|path|
    if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-python"
      tools[:dpscan] = path
    end      
  }
  
  whereisoutput = `whereis plown`
  thpaths = whereisoutput.split(":")[1]
  thpaths.split(" ").each {|path|
    if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-python"
      tools[:plown] = path
    end      
  }
  
  whereisoutput = `whereis wfuzz`
  thpaths = whereisoutput.split(":")[1]
  thpaths.split(" ").each {|path|
    if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-python"
      tools[:wfuzz] = path
    end      
  }
  
  whereisoutput = `whereis theharvester`
  thpaths = whereisoutput.split(":")[1]
  thpaths.split(" ").each {|path|
    if `file -i #{path}`.split(":")[1].strip.split(";")[0].strip == "text/x-python"
      tools[:theharvester] = path
    end      
  }
  
  return tools
end

####################

def downloadTheHarvester()
  %x(svn checkout http://theharvester.googlecode.com/svn/trunk/ #{$destfolder}/theharvester && chmod u+x  #{$destfolder}/theharvester/theHarvester.py) 
end

####################

def downloadWfuzz()
  %x(svn checkout http://wfuzz.googlecode.com/svn/trunk/ #{$destfolder}/wfuzz && chmod u+x  #{$destfolder}/wfuzz/wfuzz.py) 
end

####################

def downloadWPScan()
  %x(git clone https://github.com/wpscanteam/wpscan #{$destfolder}/wpscan && chmod u+x #{$destfolder}/wpscan/wpscan.rb)
end

####################

def downloadDPScan()
  %x(git clone https://github.com/cervoise/DPScan #{$destfolder}/DPScan && chmod u+x #{$destfolder}/DPScan/DPScan.py) 
end

####################

def downloadPlown()
  %x(git clone https://github.com/unweb/plown #{$destfolder}/plown && chmod u+x #{$destfolder}/plown/plown.py)
end

####################

def downloadJoomscan()
  %x(curl -L http://sourceforge.net/projects/joomscan/files/joomscan/2012-03-10/joomscan-latest.zip/download -o #{$destfolder}/joomscan.zip)
  %x(cd #{$destfolder} && unzip joomscan.zip -d joomscan) 
  %x(cd #{$destfolder} && rm joomscan.zip) 
  %x(cd #{$destfolder} && curl http://pastebin.com/raw.php?i=tJxLBcy9 -o joomscan/joomscan.pl)
  %x(cd #{$destfolder} && chmod u+x joomscan/joomscan.pl )
end

####################

def downloadMissingTool(tool)
  case tool.to_s.upcase
  when "WPSCAN"
    downloadWPScan()
  when "DPSCAN"
    downloadDPScan()
  when "JOOMSCAN"
    downloadJoomscan()
  when "PLOWN"
    downloadPlown()
  when "THEHARVESTER"
    downloadTheHarvester()
  when "WFUZZ"
    downloadWfuzz()
  end
end

####################

def installMissingTools(tools)
  tools.each{|k,v|
    if v.nil?
      print "- #{k} is not installed. Do you want to download and install it? [Y/n]: "
      c = gets.chomp
      if c.upcase == "Y"
        puts " > Downloading and installing #{k}. Please wait..."
        downloadMissingTool(k)
      end
    else
      puts "- #{k} is installed in your system. Not need to download."
    end
    puts
  }
end

########
# MAIN #
########

# Create destination folder
if !Dir.exists?($destfolder)
  puts "Creating third party folder in #{$destfolder}"
	FileUtils.mkdir_p($destfolder)
end

puts "Checking if you have installed the third party tools."
tools = checkThirdPartyTools()
installed = installMissingTools(tools)
puts "Now, change the 'path' of the config files located in 'config/scanners/' and 'config/tools/'"
