# Backend service for project
from flask import Flask, request
from requests import post
import json
from predict import predict
app = Flask(__name__)

@app.route("/", methods=['POST'])
def getResult():
  try:
    print(f'data: {request.data}')
    data = request.get_json(force=True)
    url = data['url']
    isSafe = predict(url)
    response = app.response_class(
      response = json.dumps({"isSafe": isSafe}),
      status=200,
      mimetype= 'application/json'
    )
  except Exception as e:
    print(e.args)
    response = app.response_class(
      response = json.dumps({"errors": e.args}),
      status=400,
      mimetype= 'application/json'
    )
  return response