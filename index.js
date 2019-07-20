"use strict";

let config = require("./config");
let request = require("request");
let jwt = require("jwt-simple");
let moment = require("moment");
const uuidv4 = require("uuid/v4");

const Firestore = require("@google-cloud/firestore");

const firestore = new Firestore({
  projectId: config.PROJECTID
});

function createJWT(user) {
  var payload = {
    googleId: user.googleId,
    iat: moment().unix(),
    exp: moment()
      .add(14, "days")
      .unix(),
    name: user.displayName
  };
  if (user.pendingUserCreation) {
    payload.pendingUserCreation = true;
  }
  if (user.userId) {
    payload.userId = user.userId;
  }
  return jwt.encode(payload, config.JWT_TOKEN_SECRET);
}

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
      if (jwtPayload.exp > now) {
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

    return firestore
      .collection("users")
      .where("googleId", "==", decoded.sub)
      .get()
      .then(results => {
        // eslint-disable-next-line no-console
        if (results.empty) {
            
          user.pendingUserCreation = true;
          user.googleId = decoded.sub;
          user.displayName = decoded.name;
              
        } else {
            results.forEach(doc => {
          user.userId = doc.data().userId;
          user.displayName = doc.data().name;
          });
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
        return res
          .status(500)
          .set("Content-Type", "application/json")
          .send({ error: "Database error" });
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
  let userId = uuidv4();
  firestore
    .collection("users")
    .doc(userId)
    .set({
      googleId: req.jwtPayload.google_id,
      name: req.jwtPayload.name,
      userId: userId
    })
    .then(function() {
      let applicationJWT = createJWT({
        google_id: req.jwtPayload.google_id,
        displayName: req.jwtPayload.name,
        userId: userId
      });
      // eslint-disable-next-line no-console
      console.log("Document successfully written!");
      return res
        .set("Content-Type", "application/json")
        .send(JSON.stringify({ token: applicationJWT }));
    })
    .catch(function(error) {
      console.error("Error writing document: ", error);
      return res
        .status(500)
        .set("Content-Type", "application/json")
        .send({ error: "Database error" });
    });
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
  firestore
    .collection("users")
    .doc(req.jwtPayload.userId)
    .get()
    .then(function(doc) {
      if (doc.empty) {
        // doc.data() will be undefined in this case
        console.error("No such document!");
        return res
          .status(500)
          .set("Content-Type", "application/json")
          .send({ error: "No User" });

      } else {
        // eslint-disable-next-line no-console
        console.log("Document data:", doc.data());
        return res
          .set("Content-Type", "application/json")
          .send(JSON.stringify(doc.data()));
      }
    })
    .catch(function(error) {
      console.error("Error retrieving user: ", error);
      return res
        .status(500)
        .set("Content-Type", "application/json")
        .send({ error: "Database error" });
    });
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
  firestore
    .collection("users")
    .doc(req.jwtPayload.userId)
    .delete()
    .then(function() {
      // eslint-disable-next-line no-console
      console.log("Delete success");
      return res
        .set("Content-Type", "application/json")
        .send({ success: true });
    })
    .catch(function(error) {
      console.error("Error retrieving user: ", error);
      return res
        .status(500)
        .set("Content-Type", "application/json")
        .send({ error: "Database error" });
    });
};
