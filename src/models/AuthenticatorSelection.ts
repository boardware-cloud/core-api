/* tslint:disable */
/* eslint-disable */
/**
 * BoardWare Cloud APIs
 * BoardWare cloud console api
 *
 * The version of the OpenAPI document: 0.0.12
 * Contact: dan.chen@boardware.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { exists, mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface AuthenticatorSelection
 */
export interface AuthenticatorSelection {
    /**
     * 
     * @type {boolean}
     * @memberof AuthenticatorSelection
     */
    requireResidentKey: boolean;
    /**
     * 
     * @type {string}
     * @memberof AuthenticatorSelection
     */
    userVerification: string;
}

/**
 * Check if a given object implements the AuthenticatorSelection interface.
 */
export function instanceOfAuthenticatorSelection(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "requireResidentKey" in value;
    isInstance = isInstance && "userVerification" in value;

    return isInstance;
}

export function AuthenticatorSelectionFromJSON(json: any): AuthenticatorSelection {
    return AuthenticatorSelectionFromJSONTyped(json, false);
}

export function AuthenticatorSelectionFromJSONTyped(json: any, ignoreDiscriminator: boolean): AuthenticatorSelection {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'requireResidentKey': json['requireResidentKey'],
        'userVerification': json['userVerification'],
    };
}

export function AuthenticatorSelectionToJSON(value?: AuthenticatorSelection | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'requireResidentKey': value.requireResidentKey,
        'userVerification': value.userVerification,
    };
}

