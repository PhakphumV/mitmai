
## Scan URL


curl --request POST \
  --url https://www.virustotal.com/api/v3/urls \
  --form url=<Your URL here>
  --header 'x-apikey: <your API key>'