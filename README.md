
# gcp-functional-auth
A set of Google Cloud Functions to implement User auth on Google Cloud Platform.
Compatible with react-bp
Deployable with wac-bp

# Requires
* Ability to deploy Google Cloud Functions
* Google Oauth 2.0 credentials
* Google Cloud Firestore
** Create an index on the users collection over googleId: ASC and createTs: ASC
