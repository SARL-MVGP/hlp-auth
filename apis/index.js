import * as jwt from 'jsonwebtoken';
import moment from 'moment';
import fetch from 'node-fetch'


// Liste des APIS consommées
const GET_USER_INFOS = "/login/oauth/userinfos";
const GET_ACCREDITATIONS_EMP = "/apis/employes/accreditationsEmploye/";
const GET_AUTH_ACCESS_TOKEN = "/login/oauth/access_token";
const GET_AUTH_LIEU_INFOS = "/login/oauth/lieuinfos";
const GET_EXTERNAL_INFOS = "/login/oauth/externalinfos";


/******
 * Récupération des accreditations de l'utilisateur
 */
export const getAccreditations = async (config, id) => {
  try {
    const res = await fetch(
      `${config.apis_url}${GET_ACCREDITATIONS_EMP}${id}`,
      {
        headers: {
          client_id: `${config.apis_client_id}`,
          client_secret: `${config.apis_client_secret}`,
        },
      }
    );
    if (res.status !== 200) {
      throw 'cient_id/client_secret non valides';
    }
    return await res.json();
  } catch (_) {
    console.error(_);
    return null;
  }
}

/******
 * Récupération des infos de l'utilisateur connecté
 */
export const getUserInfos = async (config, token) => {
  try {
    const REMOTE_USER_INFOS_URI = `${config.auth_url}${GET_USER_INFOS}`;

    const res = await fetch(REMOTE_USER_INFOS_URI, {
      headers: {
        Authorization: `bearer ${token}`
      }
    });
    if (res.status !== 200) {
      throw 'Token non valide';
    }

    return await res.json();
  } catch (_) {
    console.error(_);
    return null;
  }
};

/******
 * Récupération d'un access token
 */
export const getAccessToken = async (config, code, lieu) => {
  try {
    const REMOTE_ACCESS_TOKEN_URI = `${config.auth_url}${GET_AUTH_ACCESS_TOKEN}`;

    const res = await fetch(REMOTE_ACCESS_TOKEN_URI,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          client_id: config.auth_client_id,
          client_secret: config.auth_client_secret,
          code: code,
          lieu: lieu ? false : true
        })
      });
    return await res.json();
  } catch (_) {
    console.error(_);
    return null;
  }
};

/******
 * Récupération des infos de l'utilisateur connecté
 */
export const getLieuInfos = async (token) => {
  try {
    const REMOTE_USER_INFOS_URI = `${auth_url}${GET_AUTH_LIEU_INFOS}`;

    const res = await fetch(REMOTE_USER_INFOS_URI,
      {
        headers: {
          Authorization: `bearer ${token}`
        }
      });
    if (res.status !== 200) {
      throw 'Token non valide';
    }

    return await res.json();
  } catch (_) {
    console.error(_);
    return null;
  }
};

export const verify = (config, req, res, returnResponse = true) => {
  const token =
    req.headers.authorization && req.headers.authorization.length > 0
      ? req.headers.authorization.split(' ')[1]
      : false;

  if (!token) {
    if (returnResponse) throw new Error('Access denied');
  }

  try {
    const decoded = jwt.verify(token, config.jwt_secret);
    return decoded;
  } catch (ex) {
    if (returnResponse) throw new Error('Invalid token');
  }
};

/******
 * Récupération des infos d'un utilisateur connecté en externe (mobile app)
 */
export const getExternalInfos = async (config, token) => {
  const REMOTE_EXTERNAL_INFOS_URI = `${config.auth_url}${GET_EXTERNAL_INFOS}`;
  try {
    const res = await fetch(REMOTE_EXTERNAL_INFOS_URI, {
      headers: {
        Authorization: `bearer ${token}`
      }
    });
    if (res.status !== 200) {
      throw 'Invalid token';
    }
    return await res.json();
  } catch (_) {
    throw _;
  }
};


export const getAccessTokenExternal = async (config, res, req) => {
  try {
    const token =
    req.headers.authorization && req.headers.authorization.length > 0
        ? req.headers.authorization.split(' ')[1]
        : false;

    // const isExternal =
    //   req.header('external') && req.header('external').length > 0 ? req.header('external') === 'mobile' : false;

    const result = await getExternalInfos(config, token);

    // Calcul de l'expiration à 30 jours
    const now = moment().toDate();
    let expiredTime = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    expiredTime.setDate(expiredTime.getDate() + 30);
    var seconds = moment(expiredTime).seconds(0).diff(now, 'seconds');

    const access_token = jwt.sign(result, config.jwt_secret, {
      expiresIn: seconds
    });
    return res.send({ access_token });
  } catch (Err) {
    return res.code(401).send('getAccessTokenExternal: ' + Err);
  }
};