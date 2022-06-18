# authz-server

**authz-server** is an authorization server written in Golang. Authentication process is done by implementing an OAuth2 client with `authorization_code` grant type. For user's authorization it queries to an LDAP server if the current user exist or not in database (a basic ACL approach). It was intended to work with Envoy proxy and OpenLDAP server.

### The authorization flow is as follows:

1. The user requests access to a resource.
2. **authz-server** checks if request contains a valid token, if not, redirects to Google login to enter your credentials.
3. Once **auth-server** receives a valid token, it requests the authenticated user info to Google resource server.
4. It checks if user ID is stored in LDAP database. If user exists in LDAP it permits the access to the target resource, if not, returns a 403 HTTP status.

### How to run authz-server in local machine:

This repo contains a `demo/` folder where you will find all necessary files to deploy **authz-server** using Docker. I assume you have [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) installed in your computer

Steps to deploy demo:

1. `cd demo/`
2. `docker-compose up`
3. `https://localhost:10000`

Authorized users in LDAP for this demo are:

| email                 |         password         |
|-----------------------|:------------------------:|
| foo20379905@gmail.com | @ZL[(;Z-!;B:PUJD8dE{&W(! |
| bar20379905@gmail.com | @ZL[(;Z-!;B:PUJD8dE{&W(! |
