
class RobotsWeb
  attr_accessor :url,:robots,:generators,:poweredby,:cms,:disallowed
  
  def initialize(url=nil)
    @url = url
    @robots = {:url => nil, :response => nil}
    @generators = []
    @poweredby = []
    @disallowed = {}
    @cms = {:name => nil, :version => nil}
  end
  
  def addDisallowedEntry(url,response=nil,finalresponse=nil,interestingparts={:body=>nil,:url=>nil,:title=>nil})
    @disallowed["#{url}"] = {
      :response => response,
      :interestingparts => interestingparts
      }
  end
  
  def getEntryResponse(url)
    @disalowed["#{url}"][:response]
  end
  
  def getEntryFinalResponse(url)
    @disalowed["#{url}"][:finalresponse]
  end
  
  def isInterestingEntry?(url)
    interesting = false
    if interestingparts[:url] or interestingparts[:title] or interestingparts[:body] 
      interesting = true
    end
    return interesting
  end
  
  def getCMSName()
    @cms[:name]
  end
  
  def getCMSVersion()
    @cms[:version]
  end
  
  def getRobotsURL()
    @robotsurl
  end
  
end