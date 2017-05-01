from scapy.all import *
ans = sr1(IP(src="http://localhost/website/http.php",ttl=5),verbose=0)
address = ans.getlayer(HTTPrequest).Authorization
print address