Authenticate to Microsoft Graph using the OAuth2 client-credentials flow
(tenant ID + client ID + client secret) and report which application
permissions ("roles") the resulting access token actually carries.
 
This is a pure-Python / cross-platform reimplementation of the "what Graph permissions does this app registration grant" check that!!

 
Usage:
    python3 graph_perm_check.py -t <tenant_id_or_domain> -c <client_id> -s <client_secret>    
