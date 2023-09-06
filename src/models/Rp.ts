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
 * @interface Rp
 */
export interface Rp {
    /**
     * 
     * @type {string}
     * @memberof Rp
     */
    id: string;
    /**
     * 
     * @type {string}
     * @memberof Rp
     */
    name: string;
}

/**
 * Check if a given object implements the Rp interface.
 */
export function instanceOfRp(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "name" in value;

    return isInstance;
}

export function RpFromJSON(json: any): Rp {
    return RpFromJSONTyped(json, false);
}

export function RpFromJSONTyped(json: any, ignoreDiscriminator: boolean): Rp {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'id': json['id'],
        'name': json['name'],
    };
}

export function RpToJSON(value?: Rp | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'id': value.id,
        'name': value.name,
    };
}
