import { _AuthCallback, _Disconnect, _Disconnected, _GetAccreditations, _GetInfos, _Login } from "./actions";
import { getAccessTokenExternal, verify } from "./apis";

import {
  LOGIN_URI,
  LOGIN_LIEU_URI,
  DISCONNECT_URI,
  DISCONNECT_LIEU_URI,
  DISCONNECTED_URI,
  DISCONNECTED_LIEU_URI,
  AUTH_CALLBACK_URI,
  AUTH_CALLBACK_LIEU_URI,
  USERINFOS_URI,
  LIEUINFOS_URI,
  EXTERNALINFOS_URI,
  USER_ACCREDITATIONS,
  EXTERNAL_TOKEN
} from './constants';

export const applyFastifyHlpAuthMiddleware = (fastify, {
  jwt_secret,
  auth_url,
  auth_client_id,
  auth_client_secret,
  auth_back_url,
  apis_url,
  apis_client_id,
  apis_client_secret,
  front_end_url
} = {}) => {
  const config = {
    jwt_secret,
    auth_url,
    auth_client_id,
    auth_client_secret,
    auth_back_url,
    apis_url,
    apis_client_id,
    apis_client_secret,
    front_end_url
  };
  const authHook = async (req, res) => {
    const redirect = req.query["redirect"];
    const redirect_uri = req.query["redirect_uri"];
    const code = req.query["code"];

    const url = req.params["*"];

    const isLieu =
      url === LOGIN_LIEU_URI ||
      url === AUTH_CALLBACK_LIEU_URI ||
      url === DISCONNECT_LIEU_URI ||
      url === DISCONNECTED_LIEU_URI ||
      url === LIEUINFOS_URI;

    switch ("/" + url) {
      case LOGIN_URI:
      case LOGIN_LIEU_URI:
        // authLogger.debug(`LOGIN|LOGIN_LIEU_URI ${LOGIN_URI} ${auth_url}`);
        return _Login(config, redirect, isLieu, res);

      case DISCONNECT_URI:
      case DISCONNECT_LIEU_URI:
        return _Disconnect(config, redirect, isLieu, res);

      case DISCONNECTED_LIEU_URI:
      case DISCONNECTED_URI:
        return _Disconnected(config, redirect_uri, isLieu, res);

      case AUTH_CALLBACK_LIEU_URI:
      case AUTH_CALLBACK_URI:
        return await _AuthCallback(config, redirect_uri, code, isLieu, res);

      case LIEUINFOS_URI:
      case USERINFOS_URI:
      case EXTERNALINFOS_URI:
        return _GetInfos(config, isLieu, res, req);

      case USER_ACCREDITATIONS: {
        return _GetAccreditations(config, res, req);
      }
      case EXTERNAL_TOKEN: {
        return getAccessTokenExternal(config, res, req);
      }
      default:
        // done();
        break;
    }
  };

  fastify.decorate("hlpAuthenticate", async function(request, reply) {
    try {
      const decoded = verify(config, request, reply, false);
      request._USER = decoded;
    } catch (err) {
      throw new Error("Invalid user (auth bearer)");
    }
  });

  fastify.addHook('onRequest', authHook);
};




