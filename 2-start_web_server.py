import os
import sys
import subprocess
#import SimpleHTTPServer

print("\n\t Navigate to http://localhost:8888/index.html\n")
subprocess.call(["python","-m","http.server","8888"])
