Authenticate to Microsoft Graph using the OAuth2 client-credentials flow
(tenant ID + client ID + client secret) and report which application
permissions ("roles") the resulting access token actually carries.
 
This is a pure-Python / cross-platform reimplementation of the "what Graph permissions does this app registration grant" check that!!

 
Usage:
    python3 graph_perm_check.py -t <tenant_id_or_domain> -c <client_id> -s <client_secret>
    /n OR//
    python3 graph_perm_check.py -t <tenant> -c <client_id> -s <client_secret> --whoami
    /n OR//
    python3 graph_perm_check.py -t <tenant> -c <client_id> --cert mycert.pem --key mykey.pem
    python3 graph_perm_check.py -t contoso.onmicrosoft.com -c <app-id> -s <secret> --probe --whoami
    python3 graph_perm_check.py -t 78w3xsuernXXXXYYZZZZZ -c 78787-234234-xyz-xyz -s 89_asdfi~XYZXYZ 
