"use strict";

let config = require("./config");
let request = require("request");
let jwt = require("jwt-simple");
let moment = require("moment");

const Firestore = require("@google-cloud/firestore");

const firestore = new Firestore({
  projectId: config.PROJECTID
});

function createJWT(user) {
  var payload = {
    sub: user.google,
    iat: moment().unix(),
    exp: moment()
      .add(14, "days")
      .unix(),
    name: user.displayName
  };
  if (user.pendingUserCreation) {
    payload.pendingUserCreation = true;
  }
  if (user.user_id) {
    payload.user_id = user.user_id;
  }
  return jwt.encode(payload, config.JWT_TOKEN_SECRET);
}

/*
function uuidv4() {
  return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
    (
      c ^
      (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))
    ).toString(16)
  );
}
*/
function validateJWT(req, res) {
  try {
    console.log("JWT_TOKEN_SECRET:" + config.JWT_TOKEN_SECRET);
    let jwtPayload = jwt.decode(
      req.get("Authorization"),
      config.JWT_TOKEN_SECRET
    );
    if (typeof jwtPayload.exp === "number") {
      // JWT with an optonal expiration claims
      let now = Math.round(new Date().getTime() / 1000);
      if (jwtPayload.exp < now) {
        req.jwtPayload = jwtPayload;
      } else {
        throw { message: "JWT Expired" };
      }
    }
  } catch (err) {
    console.log(err.message);
    res
      .status(401)
      .send(err.message)
      .end();
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
  var accessTokenUrl = "https://oauth2.googleapis.com/token"; //'https://accounts.google.com/o/oauth2/token';
  var params = {
    code: req.query.code,
    client_id: config.GOOGLE_CLIENT_ID,
    client_secret: config.GOOGLE_AUTH_SECRET,
    redirect_uri: config.GOOGLE_REDIRECT_URI,
    grant_type: "authorization_code"
  };

  // Step 1. Exchange authorization code for access token.
  request.post(accessTokenUrl, { json: true, form: params }, function(
    err,
    response,
    token
  ) {
    // The access token is a JWT with a payload of the info we want
    let decoded = jwt.decode(token.id_token, null, true);
    let user = {};
    user.google = decoded.sub;
    user.displayName = decoded.name;
    user.name = decoded.name;
    return firestore
      .collection("users")
      .where("google_id", "==", decoded.sub)
      .get()
      .then(results => {
        if (!(results && results.length > 0)) {
          user.pendingUserCreation = true;
        } else {
          user.user_id = results[0].user_id;
        }
        let applicationJWT = createJWT(user);
        let responseString =
          '<html><body><div id="token">' +
          applicationJWT +
          "</div></body></html>";
        res.send(responseString);
      })
      .catch(err => {
        console.error(err);
        return res.status(500).send({ error: "Database error" });
      });
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
