from flask import Flask
import redis
from waitress import serve
from flask_cors import CORS


r = redis.StrictRedis('127.0.0.1',6379,db=0,charset='utf-8',decode_responses=True,errors='ignore')
dict1={}
i=0
for key in r.scan_iter():
    v=r.get(key)
    dict1[i] = dict([(key,v)])
    i=i+1
print(dict1)
app = Flask(__name__)
CORS(app)
@app.route("/")       
def test():
    return dict1


if __name__ == "__main__":
    app.run(host="127.0.0.1", port = 8080)
   

