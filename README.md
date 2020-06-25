# ThrottleProxy


A basic throttling proxy, implemented in Flask. Enforces a configurable daily byte limit per IP address. Also
enforces a global daily byte limit for the whole server. Prior to hitting the daily limit, the server
begins to degrade performance by inserting sleep requests between each chunk of relayed bytes. This
degredation occurs in two steps. Once the daily limit is reached, the proxy returns HTTP status 429.

You need to deploy a *REDIS* server with Serverless VPC Access.

Using a redis server:

1) Set up the server. Enable the Memorystore API. Create the instance.
2) For App Enging Standard, have to set up Serverless VPC Access.
3) Enable the Serverless VPC Access API
3) Create a connector, e.g.: redis-connector default us-central1 10.8.180.0/28 200 300
