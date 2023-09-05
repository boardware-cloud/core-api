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
 * @interface Authentication
 */
export interface Authentication {
    /**
     * 
     * @type {Array<string>}
     * @memberof Authentication
     */
    factors: Array<string>;
}

/**
 * Check if a given object implements the Authentication interface.
 */
export function instanceOfAuthentication(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "factors" in value;

    return isInstance;
}

export function AuthenticationFromJSON(json: any): Authentication {
    return AuthenticationFromJSONTyped(json, false);
}

export function AuthenticationFromJSONTyped(json: any, ignoreDiscriminator: boolean): Authentication {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'factors': json['factors'],
    };
}

export function AuthenticationToJSON(value?: Authentication | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'factors': value.factors,
    };
}

