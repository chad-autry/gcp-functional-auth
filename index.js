
'use strict';

let config = require('./config');
var jwt = require('jwt-simple');

function createJWT(user) {
  var payload = {
    sub: user._id,
    iat: moment().unix(),
    exp: moment().add(14, 'days').unix(),
    displayName: user.displayName
  };
  return jwt.encode(payload, config.JWT_TOKEN_SECRET);
}

/**
 * HTTP Cloud Function.
 *
 * @param {Object} req Cloud Function request context.
 *                     More info: https://expressjs.com/en/api.html#req
 * @param {Object} res Cloud Function response context.
 *                     More info: https://expressjs.com/en/api.html#res
 */
exports.auth = (req, res) => {
  var accessTokenUrl = 'https://accounts.google.com/o/oauth2/token';
  var peopleApiUrl = 'https://www.googleapis.com/plus/v1/people/me/openIdConnect';
  var params = {
    code: req.query.code,
    client_id: config.GOOGLE_CLIENT_ID,
    client_secret: config.GOOGLE_AUTH_SECRET,
    redirect_uri: config.GOOGLE_REDIRECT_URI,
    grant_type: 'authorization_code'
  };

  // Step 1. Exchange authorization code for access token.
  request.post(accessTokenUrl, { json: true, form: params }, function(err, response, token) {
    var accessToken = token.access_token;
    var headers = { Authorization: 'Bearer ' + accessToken };

    // Step 2. Retrieve profile information about the current user.
    request.get({ url: peopleApiUrl, headers: headers, json: true }, function(err, response, profile) {
      if (profile.error) {
        return res.status(500).send({message: profile.error.message});
      }
      // Step 3. Check if the user already exists
      var user = {};
      user.google = profile.sub;
      user.picture = profile.picture.replace('sz=50', 'sz=200');
      user.displayName = profile.name;
      user.name = profile.name;
      var token = createJWT(user);
      var responseString = "<html><body><div id=\"token\">" + token + "</div></body></html>";
      res.send(responseString);
    });
  });
};


