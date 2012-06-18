#!/usr/bin/python

# Domain Checker: Google Safe Browsing, Dshield Suspicious Domains
# Version 1

##############################
#                            #
# Ismael Valenzuela (c) 2012 #
#                            #
##############################

import sys
import urllib2

from safebrowsinglookup import SafebrowsinglookupClient

# Constants

Google_API = 'ABQIAAAALYeV_q-p6Q3auGxphpFf6RRy3UYRkydJeionXsFbTIQgKROkXg'

Dshield_Low = 'http://www.dshield.org/feeds/suspiciousdomains_Low.txt'
Dshield_Medium = 'http://www.dshield.org/feeds/suspiciousdomains_Medium.txt'
Dshield_High = 'http://www.dshield.org/feeds/suspiciousdomains_High.txt'

class domainlist:

  def __init__(self):

    """ Class constructor """

    self.items = []

  def build_from_file(self, filename):

    """ 
    Builds a dictionary based on a file

    Arguments:
      file: file with list of domains

    """

    data=[]
    
    for line in file(filename):
      if not self.__iscomment(line):
          data.append(line.strip())
    
    return data
  
  def googlesafebrowsing (self):

    """ Uses Google SafeBrowsing Lookup API on each of the domains passed as argument """
  
    # API, use your own !!!

    client=SafebrowsinglookupClient(Google_API)
    results=client.lookup(*self.items)

    return results

  def dshield (self):

    """ Uses Dshield's list of Suspcious Domains - Sensitivity: Low/Medium/High """

    self.__download_file(Dshield_Low,'suspiciousdomains_Low.txt')
    self.__download_file(Dshield_Medium,'suspiciousdomains_Medium.txt')
    self.__download_file(Dshield_High,'suspiciousdomains_High.txt')

    # The domain lists are loaded from the downloaded files using its own class constructor and methods

    lista_dshield_low=domainlist()
    lista_dshield_low.items=lista_dshield_low.build_from_file('suspiciousdomains_Low.txt')

    lista_dshield_medium=domainlist()
    lista_dshield_medium.items=lista_dshield_medium.build_from_file('suspiciousdomains_Medium.txt')

    lista_dshield_high=domainlist()
    lista_dshield_high.items=lista_dshield_high.build_from_file('suspiciousdomains_High.txt')

    for domain in self.items:
      if domain in lista_dshield_low.items:
        print "%s is in Dshield Suspicious Domains Low" % (domain)
      elif domain in lista_dshield_medium.items:
        print "%s is in Dshield Suspicious Domains Medium" % (domain)
      elif domain in lista_dshield_high.items:
        print "%s is in Dshield Suspicious Domains High" % (domain)


  # PRIVATE METHODS

  def __download_file(self,url,filename):

    """ Downloads files via HTTP using urllib2. Existing files are overwritten """
  
    f=urllib2.urlopen(url)
    output=open(filename,'w')
    output.write(f.read())
    output.close()

    print "File %s successfully downloaded \n" % (filename)

  def __iscomment(self,s):
    
    """ Filters out comments, blank lines and other non wanted lines """

    return s.startswith('#') or not s.strip() or s == "Site\n"


def main ():

  if len(sys.argv) != 2:
    print 'Usage: \n', sys.argv[0], '<filename>'
    sys.exit(1)

  """ We start building the LIST of domains to be investigated, loaded from the file """

  lista=domainlist()
  lista.items=lista.build_from_file(sys.argv[1])

  """ Google Safe Browsing """

  raw_input("Parsing domains against Google Safe Browsing. Press any key to continue...\n")

  google_results=lista.googlesafebrowsing()
  
  for x in google_results:
    print "%s: %s \n\n" % (x,google_results[x])

  """ Dshield Suspicious Domains """

  raw_input("Parsing domains against Dshield MDL. Press any key to continue...\n")

  dshield_results=lista.dshield()

if __name__ == '__main__':

  main()

