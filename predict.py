import pickle
import pandas as pd
import sys

from sklearn.ensemble import VotingClassifier
from sklearn.preprocessing import LabelEncoder

from featureExtraction import extractAllFeatures


def predict(url):
  with open("model.pkl", "rb") as file:
      clf:VotingClassifier = pickle.load(file)

  with open("ipEncoder.pkl", "rb") as file:
      ipEncoder: LabelEncoder = pickle.load(file)

  with open("geoEncoder.pkl", "rb") as file:
      geoEncoder: LabelEncoder = pickle.load(file)

  with open("tldEncoder.pkl", "rb") as file:
      tldEncoder: LabelEncoder = pickle.load(file)

  data = extractAllFeatures(url)
  data = pd.DataFrame(data, index=[0])
  data['ip_add'] = ipEncoder.fit_transform(data['ip_add'])
  data['geo_loc'] = geoEncoder.fit_transform(data['geo_loc'])
  data['tld'] = tldEncoder.fit_transform(data['tld'])
  data['who_is'] = data['who_is'].apply(
      lambda x: (True if x == 'complete' else False))
  data['https'] = data['https'].apply(lambda x: (True if x == 'yes' else False))
  data = data[['url_len', 'ip_add', 'geo_loc', 'tld', 'who_is',
              'https', 'js_len', 'js_obf_len', 'hopCount', 'content']]

  return not bool(clf.predict(pd.DataFrame(data, index=[0]))[0])


if __name__ == "__main__":
  url = input("Please enter url\n").strip()
  print(predict(url))