#!/usr/bin/python

import sys
import itertools #set functions
import hashlib #library for hashing


def main():
 
 candidateList = []         #stores plaintext password
 candidateHashList = []     #stores plaintext hash password 
 hashList = []              #stores hashed list read from file
 userList = []              #stores usernames
 crack_pw_count = 0         #keeps track of cracked passwords
 pw_count = 0               #password count
 orig_hash_dic ={}          #dictionary for original hash
 tmp_str = ""
 
 #Opens username and password file
 fo = open(sys.argv[1], "r")

 #loops through username & password file
 for line in fo:
  
  credentials = line.strip()
  credentials  = credentials.split(":") #splits line where : is encountered
  userList.append(credentials[0])
  hashList.append(credentials[1])
  
   #if entry already exist in dictionary update
  if credentials[1]in orig_hash_dic:   
   tmp_str = orig_hash_dic [credentials[1]]
   orig_hash_dic [credentials[1]] = (tmp_str,credentials[0],credentials[1])
   
  #new entry 
  orig_hash_dic [credentials[1]] = (credentials[0],credentials[1])
   
  pw_count+=1 #increment password count


 #closes file
 fo.close()
 
 #--------------------------


 #Opens candidate password file
 fo = open(sys.argv[2], "r")
 #loops through pw_candidates.txt
 for line in fo:
  
  #appends candidate password to list  
  candidateList.append(line.strip()) 
 
 fo.close()
 #closes file
 #--------------------------

 
 if sys.argv[3] == "md5":
        
        for plaintext_pw in candidateList:
                md5 = hashlib.md5(plaintext_pw)
                hex_md5 = md5.hexdigest()
                candidateHashList.append(hex_md5)
                if hex_md5 in orig_hash_dic:
                    tmp_str = orig_hash_dic[hex_md5]
                    orig_hash_dic[hex_md5] = (tmp_str,plaintext_pw)
        found_pw_hashes = list(set(candidateHashList).intersection(set(hashList)))
        for hash_pws in found_pw_hashes:
                 crack_pw_count+=1
                 if hash_pws in orig_hash_dic:
                         print str(orig_hash_dic[hash_pws])
                         del orig_hash_dic[hash_pws]
                         
        print "\nCracked "+str(crack_pw_count)+" passwords of the total "+str(pw_count)
 elif sys.argv[3] == "sha1":
        for plaintext_pw in candidateList:
                sha1 = hashlib.sha1(plaintext_pw)
                hex_sha1 = sha1.hexdigest()
                candidateHashList.append(hex_sha1)
                if hex_sha1 in orig_hash_dic:
                    tmp_str = orig_hash_dic[hex_sha1]
                    orig_hash_dic[hex_sha1] = (tmp_str,plaintext_pw)
        found_pw_hashes = list(set(candidateHashList).intersection(set(hashList)))
        for hash_pws in found_pw_hashes:
                crack_pw_count+=1
                if hash_pws in orig_hash_dic:
                     print str(orig_hash_dic[hash_pws])
                     del orig_hash_dic[hash_pws]
             
        print "\nCracked "+str(crack_pw_count)+" passwords of the total "+str(pw_count)            

 elif sys.argv[3] == "sha256":
        for plaintext_pw in candidateList:
                sha256 = hashlib.sha256(plaintext_pw)
                hex_sha256 = sha256.hexdigest()
                candidateHashList.append(hex_sha256)
                if hex_sha256 in orig_hash_dic:
                    tmp_str = orig_hash_dic[hex_sha256]
                    orig_hash_dic[hex_sha1] = (tmp_str,plaintext_pw)
        found_pw_hashes = list(set(candidateHashList).intersection(set(hashList)))
        for hash_pws in found_pw_hashes:
                crack_pw_count+=1
                if hash_pws in orig_hash_dic:
                     print str(orig_hash_dic[hash_pws])
                     del orig_hash_dic[hash_pws]
             
        print "\nCracked "+str(crack_pw_count)+" passwords of the total "+str(pw_count)            
     


main()
