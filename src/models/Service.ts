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
import type { ServiceType } from './ServiceType';
import {
    ServiceTypeFromJSON,
    ServiceTypeFromJSONTyped,
    ServiceTypeToJSON,
} from './ServiceType';

/**
 * 
 * @export
 * @interface Service
 */
export interface Service {
    /**
     * 
     * @type {string}
     * @memberof Service
     */
    id: string;
    /**
     * 
     * @type {string}
     * @memberof Service
     */
    name: string;
    /**
     * 
     * @type {string}
     * @memberof Service
     */
    title: string;
    /**
     * 
     * @type {string}
     * @memberof Service
     */
    description: string;
    /**
     * 
     * @type {string}
     * @memberof Service
     */
    url: string;
    /**
     * 
     * @type {ServiceType}
     * @memberof Service
     */
    type: ServiceType;
}

/**
 * Check if a given object implements the Service interface.
 */
export function instanceOfService(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "title" in value;
    isInstance = isInstance && "description" in value;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function ServiceFromJSON(json: any): Service {
    return ServiceFromJSONTyped(json, false);
}

export function ServiceFromJSONTyped(json: any, ignoreDiscriminator: boolean): Service {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'id': json['id'],
        'name': json['name'],
        'title': json['title'],
        'description': json['description'],
        'url': json['url'],
        'type': ServiceTypeFromJSON(json['type']),
    };
}

export function ServiceToJSON(value?: Service | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'id': value.id,
        'name': value.name,
        'title': value.title,
        'description': value.description,
        'url': value.url,
        'type': ServiceTypeToJSON(value.type),
    };
}
