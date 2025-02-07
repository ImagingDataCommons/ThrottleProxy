# ThrottleProxy

A basic throttling proxy, implemented in Flask. Enforces a configurable daily byte limit per IP address. Also
enforces a global daily byte limit for the whole server. Prior to hitting the daily limit, the server
is capable of degraded performance by inserting sleep requests between each chunk of relayed bytes. This
degradation occurs in two steps. This functionality is not actively used in IDC production, as sleeping the
server has implications on server performance. Thus, currently deployed configurations allows full performance 
up until the limit is reached. Once the daily limit is reached, the proxy returns HTTP status 429.

You need to deploy a *REDIS* server with Serverless VPC Access for this to work. There is a script 
`shell/prepareBackend.sh` that does this for you. You can customize this script by creating a sibling file
named `shell/prepareBackend-SetEnv.sh` to set the needed env variables. (Note that `.gitignore` is configured
to not upload files named *-SetEnv.sh.) You need a VPC connector is deploying to AppEngine standard; an
env variable can configure this.

Once completed you can see the set up in the Google console under `Memorystore->Redis` and 
`VPC Network->Serverless VPC access`.

The values provided choose a 1 GB capacity in the REDIS Basic tier (no need for high availability; 
if we lost the data due to a failure, we would just end up doubling the quota for the day).
For the VPC connector, note that once the connector has spooled up to the max instances, *it never 
scales back down*.

The server can be deployed from your desktop using the script `shell/deployToCloud.sh`. You need to set
the environment variables in that script, or in a file `shell/deployToCloud-SetEnv.sh`.

The two files that need customization are:

1) `config.txt`
2) `app.yaml`

You can either edit those files in place, or set the "LOAD_FROM_CLOUD=TRUE" variable in `deployToCloud.sh` to keep the
configuration files up in a cloud bucket in the deployed project. They will be then used instead of the demo files
living in the repo. The example `app.yaml` in this repo is good to go, needing only customizations to the 
vpc_access_connector name string, though you may want to tweak the scaling set-up. The example `config.txt` will 
need extensive customization for your site. 

If you need to do debugging by running locally, there is a `shell/run-proxy.sh` script, though it will not
be able to talk to the cache.

Note that when you want to tear down the proxy, you will want to delete the Redis cache and the
connector, since they cost money to run. You will also want to disable AppEngine in the project (it
cannot be deleted, only disabled).

As it is currently set up, the proxy will serve up content with this path, per the config file. Note how
the trailing "/" separator needs to be the last character of the USAGE_DECORATION value, and "current"
is hardwired into the path:

https://${ALLOWED_HOST}/current/${USAGE_DECORATION}${PATH_TAIL}/studies/....


**Force Redeploy**
