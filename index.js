
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

function validateJWT (req, res) {
  try {
    console.log('JWT_TOKEN_SECRET:'+config.JWT_TOKEN_SECRET);
    req.jwtPayload = jwt.decode(req.get('Authorization'), config.JWT_TOKEN_SECRET);
  } catch(err) {
    console.log(err.message);
    res.status(401).send(err.message).end();
    return false;
  }
    return true;
}

/**
 * Authorizes GCP OAuth
 * Creates a JWT if the user exists or not
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
    // The access token is a JWT with a payload of the info we want
    let decoded = jwt.decode(token.access_token, null, true);
    var user = {};
    user.google = decoded.sub;
    //TODO Get Check if the user exists in the service's DB
    user.displayName = decoded.name;
    user.name = decoded.name;
    var token = createJWT(user);
    var responseString = "<html><body><div id=\"token\">" + token + "</div></body></html>";
    res.send(responseString);
  });
};

/**
 * Creates a user
 *
 * @param {Object} req Cloud Function request context.
 *                     More info: https://expressjs.com/en/api.html#req
 * @param {Object} res Cloud Function response context.
 *                     More info: https://expressjs.com/en/api.html#res
 */
exports.createUser = (req, res) => {
  if (!validateJWT(req, res)) {
    return;
  }
};

/**
 * Gets a user's details
 *
 * @param {Object} req Cloud Function request context.
 *                     More info: https://expressjs.com/en/api.html#req
 * @param {Object} res Cloud Function response context.
 *                     More info: https://expressjs.com/en/api.html#res
 */
exports.getUser = (req, res) => {
  if (!validateJWT(req, res)) {
    return;
  }
};

/**
 * Updates a user object
 *
 * @param {Object} req Cloud Function request context.
 *                     More info: https://expressjs.com/en/api.html#req
 * @param {Object} res Cloud Function response context.
 *                     More info: https://expressjs.com/en/api.html#res
 */
exports.updateUser = (req, res) => {
  if (!validateJWT(req, res)) {
    return;
  }
};

/**
 * Deletes a user
 *
 * @param {Object} req Cloud Function request context.
 *                     More info: https://expressjs.com/en/api.html#req
 * @param {Object} res Cloud Function response context.
 *                     More info: https://expressjs.com/en/api.html#res
 */
exports.deleteUser = (req, res) => {
  if (!validateJWT(req, res)) {
    return;
  }
};
