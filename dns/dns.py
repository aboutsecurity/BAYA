#!/usr/bin/python2.7

# DNS Parser - Uses Dug Song's dpkt
# Version 1

##############################
#                            #
# Ismael Valenzuela (c) 2012 #
#                            #
##############################

import dpkt, socket, sys

def dns_responses(pkt):
  """
  This function checks for DNS responses in a given libpcap file passed as an
  argument.
  """
  f = open(pkt)
  pcap=dpkt.pcap.Reader(f)

  for ts, buf in pcap:
    """
    Parsing the pcap file, iterating through the pcap object and access each
    packet contained in the dump
    ts = timestamp / buf = raw buffer
    """
    
    try:
      eth=dpkt.ethernet.Ethernet(buf)

      """
      Raw buffer is parsed and decoded into python objects
      eth = Ethernet object / eth.data = IP object / eth.data.data = TCP object
      """

    except: 
      continue # Continues with the next iteration of the loop
    
    if eth.type != 2048: 
      continue # If Ethernet Frame Type is not IP, continue with next iteration

    try:
      ip=eth.data
    except:
        continue

    if ip.p != 17:
      continue # If protocol is not UDP contine with next iteration

    
    try:
      udp=ip.data
    except:
      continue
    
    if udp.sport != 53 and udp.dport != 53:
      continue # If it doesn't use DNSp ports continue with next iteration

    try:
      dns=dpkt.dns.DNS(udp.data)

      """
      Parse the DNS object out of the UDP data and check for it being a RR
      answer and opcode QUERY
      """
    except:
      continue

    if dns.qr != dpkt.dns.DNS_R: continue
    if dns.opcode != dpkt.dns.DNS_QUERY: continue
    if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue

    if len(dns.an) < 1: continue

    """
    Printing the responses based on record type
    Ref: http://en.wikipedia.org/wiki/List_of_DNS_record_types
    """

    for answer in dns.an:
      if answer.type == 5:
        print '\n\nCNAME REQUEST:', answer.name, '--> RESPONSE:', answer.cname
      elif answer.type == 1:
        print '\n\nA REQUEST:', answer.name, '--> RESPONSE:',socket.inet_ntoa(answer.rdata)
      elif answer.type == 12:
        print '\n\nPTR REQUEST:', answer.name, '--> RESPONSE:', answer.ptrname

  f.close()

def main ():

  if len(sys.argv) != 2:
    print 'Usage: \n', sys.argv[0], '<filename.pcap>'
    sys.exit(1)

  dns_responses(sys.argv[1])

if __name__=='__main__':
  main()

