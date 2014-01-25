#!/usr/bin/env ruby

require 'mechanize'
require 'sqlite3'

class GoogleDorkUpdater
  def initialize
    @@dorkweb = "http://www.exploit-db.com/google-dorks/1/"
    @@dorkdbfile = "GoogleDorks.db"
    initializeDatabase
  end
  
  #####################
  
  def initializeDatabase
    if !File.exists?(@@dorkdbfile)
      gddb = SQLite3::Database.new(@@dorkdbfile)
      gddb.query(
      """
      CREATE TABLE IF NOT EXISTS
      GoogleDorks (
        id INT PRIMARY KEY AUTO INCREMENT,
        url VARCHAR(150),
        date INT,
        rawsearch TEXT,
        intext VARCHAR(200),
        allintext VARCHAR(200),
        inurl VARCHAR(150),
        allinurl VARCHAR(150),
        intitle VARCHAR(150),
        allintitle VARCHAR(150)        
      )      
      """      
      )
    else
      puts "Nothing to do here"
    end
  end
  
  #####################
  
  def updateDatabase
    a = Mechanize.new { |agent|
      agent.user_agent_alias = 'Mac Safari'
    }
    
    a.get(@@dorkweb) do |page|
      dorkstable = page.tables[0]
      dorkstable.tr.each {|dorkrow|
        dorkrow.td[]
        
      }
    
      search_result.links.each do |link|
        puts link.text
      end
    end
  end
  
  
end
