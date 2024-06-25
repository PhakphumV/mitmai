# VirusTotal API



## Scan URL

curl --request POST \
  --url https://www.virustotal.com/api/v3/urls \
  --form url=<Your URL here>
  --header 'x-apikey: <your API key>'


This API will return Analysis ID

## URL Analysis report

curl --request GET \
  --url https://www.virustotal.com/api/v3/analyses/{id} \
  --header 'x-apikey: <your API key>'

This API will return [Analysis object](https://docs.virustotal.com/reference/analyses-object)

## Reference

- https://docs.virustotal.com/
- https://docs.virustotal.com/reference/analyses-object