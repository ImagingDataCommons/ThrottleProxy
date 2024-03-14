mkdir ./json
mkdir ./txt

# AppEngine-module specific app.yaml
gsutil cp "gs://${DEPLOYMENT_BUCKET}/${PROXY_APP_YAML}" ./app.yaml

# Print module and version of app.yaml
grep '^service:' ./app.yaml

# Configuration file (env vars not used in proxy)
gsutil cp "gs://${DEPLOYMENT_BUCKET}/${IDC_PROXY_CONFIG}" ./config.txt

# Pack staged files for caching
echo "Packing JSON and text files for caching into deployment..."
cp --verbose *.json ./json
cp --verbose *.txt ./txt
