import moment from 'moment';
import * as jwt from 'jsonwebtoken';

import { getAccessToken, getAccreditations, getLieuInfos, getUserInfos, verify } from "../apis";
import {
  DISCONNECTED_URI,
  DISCONNECTED_LIEU_URI,
  AUTH_CALLBACK_URI,
  AUTH_CALLBACK_LIEU_URI
} from '../constants';


// ----- LOGIN
export const _Login = (config, redirect, isLieu, res) => {
  const remoteUri = !isLieu
    ? '/login/oauth/authorize?client_id=<CLIENT_ID>&redirect_uri=<REDIRECT_URI>'
    : '/login/oauth/authorize/lieu?client_id=<CLIENT_ID>&redirect_uri=<REDIRECT_URI>';

  let redirectUri = `${config.auth_url}${remoteUri}`;

  redirectUri = redirectUri.replace('<CLIENT_ID>', config.auth_client_id);
  redirectUri = redirectUri.replace(
    '<REDIRECT_URI>',
    `${config.auth_back_url}${!isLieu ? AUTH_CALLBACK_URI : AUTH_CALLBACK_LIEU_URI}${redirect ? encodeURI('?redirect_uri=' + redirect) : ''
    }`
  );
  return res.redirect(redirectUri);
};

// ----- DISCONNECT
export const _Disconnect = (config, redirect, isLieu, res) => {
  let remoteUri = '/login/oauth/disconnect?client_id=<CLIENT_ID>&redirect_uri=<REDIRECT_URI>';
  if (isLieu) remoteUri += '&lieu=true';

  let redirectUri = `${config.auth_url}${remoteUri}`;

  redirectUri = redirectUri.replace('<CLIENT_ID>', config.auth_client_id);
  redirectUri = redirectUri.replace(
    '<REDIRECT_URI>',
    `${config.auth_back_url}${isLieu ? DISCONNECTED_LIEU_URI : DISCONNECTED_URI}${redirect ? encodeURI('?redirect_uri=' + redirect) : ''
    }`
  );

  return res.redirect(redirectUri);
};

// ----- DISCONNECTED
export const _Disconnected = (config, redirect, isLieu, res) => {
  const remoteUri = !isLieu ? '/login/oauth/authorize' : '/login/oauth/authorize/lieu';

  let redirectUri = `${config.auth_url}${remoteUri}?client_id=<CLIENT_ID>&redirect_uri=<REDIRECT_URI>`;

  redirectUri = redirectUri.replace('<CLIENT_ID>', config.auth_client_id);
  redirectUri = redirectUri.replace(
    '<REDIRECT_URI>',
    `${config.auth_back_url}${isLieu ? AUTH_CALLBACK_LIEU_URI : AUTH_CALLBACK_URI}${redirect ? '?redirect_uri=' + redirect : ''
    }`
  );
  return res.redirect(redirectUri);
};

// ----- AUTHCALLBACK
export const _AuthCallback = async (
  config,
  redirect,
  code,
  isLieu,
  res
) => {
  let payload = {};
  console.log("redirect", redirect);

  try {
    if (isLieu) {
      const data_token = await getAccessToken(config, code, true);
      const token = data_token.access_token;
      const lieuInfos = await getLieuInfos(config, token);

      payload = {
        ...lieuInfos,
        data_token
      };
    } else {
      const data_token = await getAccessToken(config, code);
      const token = data_token.access_token;

      const userInfos = await getUserInfos(config, token);

      if (!userInfos) {
        throw new Error('Auth error');
      }

      delete userInfos['accreditations']; // Hack car volumineux parfois (ex. Mathieu)

      payload = {
        ...userInfos,
        data_token: data_token
        // exp: Math.floor(new Date(data_token.expired).getDate() / 1000),
      };
    }
    // Calcul de l'expiration à 23:59:59
    const now = moment();
    const expiredTime = moment().hour(23).minute(59).second(59);
    var seconds = expiredTime.seconds(0).diff(now, 'seconds');

    const jwToken = jwt.sign(payload, config.jwt_secret, {
      expiresIn: seconds
    });
    return res.redirect(`${config.front_end_url}${redirect || ''}?token=${jwToken}`);
  } catch (Err) {
    // authLogger.error(Err);
    throw new Error('Auth error: ' + Err);
  }
};

// ----- GETINFOS
export const _GetInfos = (config, isLieu, res, req) => {
  const decoded = verify(config, req, res, false);
  if (!isLieu && !decoded.email) {
    throw new Error('Invalid token');
  }
  if (isLieu && decoded.email) {
    throw new Error('Invalid token');
  }
  if (decoded) {
    return res.send({ ok: true, data: decoded });
  }
  throw new Error('Invalid token');
};

// ----- GETACCREDITATIONS
export const _GetAccreditations = async (config, res, req) => {
  try {
    const decoded = verify(config, req, res, false);
    const { typeUserId } = decoded;

    if (!typeUserId) {
      throw "Unable to get 'typeUserId'";
    }

    const accreditations = await getAccreditations(config, typeUserId);
    if (!accreditations) {
      throw "Unable to get 'accreditations'";
    }

    return res.send({ ok: true, data: accreditations.data });
  } catch (_) {
    throw new Error(_);
  }
};
