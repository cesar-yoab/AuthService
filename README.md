# User Authentication Service
Implementation of a user authentication service using JSON Web Tokens (JWT). More information
on JWT can be found [here](https://jwt.io/). This service is based on [GraphQL](https://graphql.org/),
all information on the service itself can be found under "graph/model/schema.graphqls" or 
equivalently [here]("https://github.com/cesar-yoab/auth/graph/schema.graphqls). The application
contains the bare minimum to allow for extension. You can see the code in this repository as 
template code for a more sophisticated user authentication service.

## Prereqs
1. A MongoDB server in Atlas or running on a Docker container or on a separate server
2. A .env file containing the following:
   1. "DB" containing the URI to the Mongo database
   2. "KEY" to sign the tokens
   3. "DBNAME" with the name of the database to connect
   4. "COLLECTION" with the name of the collection