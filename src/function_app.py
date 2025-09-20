import json
import logging
import os
import requests
import msal
import traceback
import jwt
import uuid
from datetime import datetime
from jwt.exceptions import PyJWTError

import azure.functions as func
from azure.mgmt.resource import ResourceManagementClient

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# This variable is set in Bicep and is automatically provisioned.
application_uami = os.environ.get('APPLICATION_UAMI', 'Not set')
application_cid = os.environ.get('APPLICATION_CID', 'Not set')
application_tenant = os.environ.get('APPLICATION_TENANT', 'Not set')

application_secret = os.environ.get('APPLICATION_SECRET', 'Not set')

managed_identity = msal.UserAssignedManagedIdentity(client_id=application_uami)

mi_auth_client = msal.ManagedIdentityClient(managed_identity, http_client=requests.Session())

# Define the token function before using it
def get_managed_identity_token(audience):
    token = mi_auth_client.acquire_token_for_client(resource=audience)

    if "access_token" in token:
        return token["access_token"]
    else:
        raise Exception(f"Failed to acquire token: {token.get('error_description', 'Unknown error')}")

def get_jwks_key(token):
    """
    Fetches the JSON Web Key from Azure AD for token signature validation.
    
    Args:
        token: The JWT token to validate
        
    Returns:
        tuple: (signing_key, error_message)
            - signing_key: The public key to verify the token, or None if retrieval failed
            - error_message: Detailed error message if retrieval failed, None otherwise
    """
    try:
        # Get the kid and issuer from the token
        try:
            header = jwt.get_unverified_header(token)
            if not header:
                return None, "Failed to parse JWT header"
        except Exception as e:
            return None, f"Invalid JWT header format: {str(e)}"
            
        kid = header.get('kid')
        if not kid:
            return None, "JWT header missing 'kid' (Key ID) claim"
        
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            if not payload:
                return None, "Failed to decode JWT payload"
        except Exception as e:
            return None, f"Invalid JWT payload format: {str(e)}"        
        
        issuer = payload.get('iss')
        if not issuer:
            return None, "JWT payload missing 'iss' (Issuer) claim"
        
        # Check that the issuer exactly matches the expected format
        expected_issuer = f"https://sts.windows.net/{application_tenant}/"
        if issuer != expected_issuer:
            return None, f"JWT issuer '{issuer}' does not match expected issuer '{expected_issuer}'"
            
        # Get the JWKS URI
        jwks_uri = f"https://login.microsoftonline.com/{application_tenant}/discovery/v2.0/keys"
        try:
            resp = requests.get(jwks_uri, timeout=10)
            if resp.status_code != 200:
                return None, f"Failed to fetch JWKS: HTTP {resp.status_code} - {resp.text[:100]}"
                
            jwks = resp.json()
            if not jwks or 'keys' not in jwks or not jwks['keys']:
                return None, "JWKS response is empty or missing 'keys' array"
        except requests.RequestException as e:
            return None, f"Network error fetching JWKS: {str(e)}"
        except json.JSONDecodeError as e:
            return None, f"Invalid JWKS response format: {str(e)}"
        
        # Find the signing key in the JWKS
        signing_key = None
        for key in jwks['keys']:
            if key.get('kid') == kid:
                try:
                    signing_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                    break
                except Exception as e:
                    return None, f"Failed to parse JWK for kid='{kid}': {str(e)}"
                
        if not signing_key:
            return None, f"No matching key found in JWKS for kid='{kid}'"
            
        return signing_key, None
    except Exception as e:
        return None, f"Unexpected error getting JWKS key: {str(e)}"

def validate_bearer_token(bearer_token, expected_audience):
    """
    Validates a JWT bearer token against the expected audience and verifies its signature.
    
    Args:
        bearer_token: The JWT token to validate
        expected_audience: The expected audience value
        
    Returns:
        tuple: (is_valid, error_message, decoded_token)
            - is_valid: boolean indicating if the token is valid
            - error_message: error message if validation failed, None otherwise
            - decoded_token: the decoded token if validation succeeded, None otherwise
    """
    if not bearer_token:
        return False, "No bearer token provided", None
    
    try:
        logging.info(f"Validating JWT token against audience: {expected_audience}")
        
        signing_key, key_error = get_jwks_key(bearer_token)
        if not signing_key:
            return False, f"JWT key retrieval failed: {key_error}", None
        
        # Validate the token with full verification
        try:
            decoded_token = jwt.decode(
                bearer_token,
                signing_key,
                algorithms=['RS256'],
                audience=expected_audience,
                options={"verify_aud": True}
            )
            
            logging.info(f"JWT token successfully validated. Token contains claims for subject: {decoded_token.get('sub', 'unknown')}")
            return True, None, decoded_token
        except jwt.exceptions.InvalidAudienceError:
            return False, f"JWT has an invalid audience. Expected: {expected_audience}", None
        except jwt.exceptions.ExpiredSignatureError:
            return False, "JWT token has expired", None
        except jwt.exceptions.InvalidSignatureError as sig_error:
            try:
                header = jwt.get_unverified_header(bearer_token)
                payload = jwt.decode(bearer_token, options={"verify_signature": False})
                
                # Log detailed signature validation failure information
                logging.error(f"JWT signature validation failed - "
                            f"Algorithm: {header.get('alg', 'unknown')}, "
                            f"Key ID: {header.get('kid', 'unknown')}, "
                            f"Token type: {header.get('typ', 'unknown')}, "
                            f"Issuer: {payload.get('iss', 'unknown')}, "
                            f"Subject: {payload.get('sub', 'unknown')}, "
                            f"Audience: {payload.get('aud', 'unknown')}, "
                            f"Expected audience: {expected_audience}, "
                            f"App ID: {payload.get('appid', 'unknown')}, "
                            f"Tenant ID: {payload.get('tid', 'unknown')}")
                
                # Log signing key information (without exposing the key itself)
                if hasattr(signing_key, 'key_size'):
                    logging.error(f"Signing key details - Key size: {signing_key.key_size} bits")
                    
                return False, f"JWT signature validation failed. Key ID: {header.get('kid', 'unknown')}, Algorithm: {header.get('alg', 'unknown')}, Token audience: {payload.get('aud', 'unknown')}, Expected audience: {expected_audience}", None
            except Exception as context_error:
                logging.error(f"JWT signature validation failed (could not extract context: {str(context_error)})")
                return False, f"JWT signature validation failed (unable to extract token details: {str(context_error)})", None
        except PyJWTError as jwt_error:
            error_message = f"JWT validation failed: {str(jwt_error)}"
            logging.error(f"JWT validation error: {error_message}")
            return False, error_message, None
    except Exception as e:
        error_message = f"Unexpected error during JWT validation: {str(e)}"
        logging.error(error_message)
        return False, error_message, None

cca_auth_client = msal.ConfidentialClientApplication(
    application_cid, 
    authority=f'https://login.microsoftonline.com/{application_tenant}',
    client_credential={"client_assertion": get_managed_identity_token('api://AzureADTokenExchange')}
)

# Replace your existing cca_auth_client initialization
cca_auth_client_using_static_secret = msal.ConfidentialClientApplication(
    application_cid, 
    authority=f'https://login.microsoftonline.com/{application_tenant}',
    client_credential=application_secret  # Use the secret directly
)

@app.generic_trigger(
    arg_name="context",
    type="mcpToolTrigger",
    toolName="list_resource_groups",
    description="List all resource groups in the specified subscription.",
    toolProperties="[]",
    # toolProperties="[{\"name\": \"subscription_id\", \"description\": \"Azure subscription ID (GUID format)\", \"type\": \"string\", \"required\": true}]",
)
def list_resource_groups(context) -> str:
    """
    List all resource groups in the specified subscription.
    
    Args:
        context: The trigger context as a JSON string containing the request information.
                Expected to contain 'subscription_id' in the arguments.
        
    Returns:
        JSON string with list of resource groups or error information.
    """
    
    token_error = None
    resource_group_data = None
    
    try:
        logging.info(f"Context type: {type(context).__name__}")
        try:
            context_obj = json.loads(context)
            arguments = context_obj.get('arguments', {})
            bearer_token = None
            subscription_id = None
            logging.info(f"Arguments structure: {json.dumps(arguments)[:500]}")
            
            if isinstance(arguments, dict):
                bearer_token = arguments.get('bearerToken')
                # subscription_id = arguments.get('subscription_id')
                subscription_id = '32758ed5-6e7b-4f7a-90ac-e60d869ce968'
            
            if not bearer_token:
                logging.warning("No bearer token found in context arguments")
                token_acquired = False
                token_error = "No bearer token found in context arguments"
            elif not subscription_id:
                logging.warning("No subscription_id found in context arguments")
                return json.dumps({
                    "error": "Missing required parameter: subscription_id",
                    "status": "Failed"
                }, indent=2)
            else:
                expected_audience = f"{application_cid}"
                is_valid, validation_error, decoded_token = validate_bearer_token(bearer_token, expected_audience)
                
                if is_valid:
                    # Use static secret based client for token acquisition.
                    # Not using the OBO flow here because admin consent is not provided for the app.
                    # "error": "AADSTS65001: The user or administrator has not consented to use the application with ID 'ddad3aee-d646-4ccc-a3ae-acc9f2ff237f' named 'arpijainmcp05'. Send an interactive authorization request for this user and resource. Trace ID: cdc64abe-5053-4788-a2f9-2d93c1e7de00 Correlation ID: f999d0be-b438-4cbf-a902-e577e8cad657 Timestamp: 2025-09-19 08:25:30Z"
                    result = cca_auth_client_using_static_secret.acquire_token_for_client(
                        scopes=['https://management.azure.com/.default']
                    )
                else:
                    token_acquired = False
                    token_error = validation_error
                    result = {"error": "invalid_token", "error_description": validation_error}
                
                if "access_token" in result:
                    logging.info("Successfully acquired access token using OBO flow")
                    token_acquired = True
                    access_token = result["access_token"]
                    token_error = None
                    
                    # Use the token to call Resource Management API
                    try:
                        # Create an authentication object for Resouce Management
                        headers = {
                            'Authorization': f'Bearer {access_token}',
                            'Content-Type': 'application/json'
                        }
                        
                        # Get the resource groups
                        resource_groups_url = f'https://management.azure.com/subscriptions/{subscription_id}/resourcegroups?api-version=2021-04-01'
                        response = requests.get(resource_groups_url, headers=headers)
                        
                        if response.status_code == 200:
                            resource_group_data = response.json()
                            logging.info("Successfully retrieved resource group data")
                        else:
                            logging.error(f"Failed to get resource group data: {response.status_code}, {response.text}")
                            token_error = f"Resource Management API error: {response.status_code}"
                    except Exception as ex:
                        logging.error(f"Error calling Resource Management API: {str(ex)}")
                        token_error = f"Resoure Management error: {str(ex)}"
                else:
                    token_acquired = False
                    token_error = result.get('error_description', 'Unknown error acquiring token')
                    logging.warning(f"Failed to acquire token using OBO flow: {token_error}")
        except Exception as e:
            token_acquired = False
            token_error = str(e)
            logging.error(f"Exception when acquiring token: {token_error}")

        # Prepare the response
        try:
            response = {}
            
            if resource_group_data:
                # Return resource group data as the primary content
                response = resource_group_data
                # Add status information
                response['success'] = True
            else:
                # If we failed to get resource group data, return error information
                response['success'] = False
                response['error'] = token_error or "Failed to retrieve resource group data"
            
            logging.info(f"Returning response: {json.dumps(response)[:500]}...")
            return json.dumps(response, indent=2)
        except Exception as format_error:
            logging.error(f"Error formatting response: {str(format_error)}")
            return json.dumps({
                "success": False,
                "error": f"Error formatting response: {str(format_error)}"
            }, indent=2)
    except Exception as e:
        stack_trace = traceback.format_exc()
        return json.dumps({
            "error": f"An error occurred: {str(e)}\n{stack_trace}",
            "stack_trace": stack_trace,
            "raw_context": str(context)
        }, indent=2)
    
@app.generic_trigger(
    arg_name="context",
    type="mcpToolTrigger",
    toolName="create_storage_mover",
    description="Create a StorageMover resource with the specified parameters using Azure SDK.",
    toolProperties="[]",
)
def create_storage_mover(context) -> str:
    """
    Create a StorageMover resource with the specified parameters using Azure SDK.
    
    Args:
        context: The trigger context as a JSON string containing the request information.
                Expected to contain 'subscription_id' in the arguments.
        
    Returns:
        JSON string with resource creation details, error information, or parameter guidance.
    """
    
    token_error = None
    resource_group_data = None
    
    try:
        logging.info(f"Context type: {type(context).__name__}")
        try:
            context_obj = json.loads(context)
            arguments = context_obj.get('arguments', {})
            bearer_token = None
            subscription_id = None
            name = None
            location = None
            resource_group = None
            logging.info(f"Arguments structure: {json.dumps(arguments)[:500]}")
            
            if isinstance(arguments, dict):
                bearer_token = arguments.get('bearerToken')
                # subscription_id = arguments.get('subscription_id')
                subscription_id = '32758ed5-6e7b-4f7a-90ac-e60d869ce968'
                name = 'arpijain-hackathon-mover-01'
                location = 'eastus'
                resource_group = 'sunidhi'
            
            if not bearer_token:
                logging.warning("No bearer token found in context arguments")
                token_acquired = False
                token_error = "No bearer token found in context arguments"
            elif not subscription_id:
                logging.warning("No subscription_id found in context arguments")
                return json.dumps({
                    "error": "Missing required parameter: subscription_id",
                    "status": "Failed"
                }, indent=2)
            else:
                expected_audience = f"{application_cid}"
                is_valid, validation_error, decoded_token = validate_bearer_token(bearer_token, expected_audience)
                
                if is_valid:
                    # Use static secret based client for token acquisition.
                    # Not using the OBO flow here because admin consent is not provided for the app.
                    # "error": "AADSTS65001: The user or administrator has not consented to use the application with ID 'ddad3aee-d646-4ccc-a3ae-acc9f2ff237f' named 'arpijainmcp05'. Send an interactive authorization request for this user and resource. Trace ID: cdc64abe-5053-4788-a2f9-2d93c1e7de00 Correlation ID: f999d0be-b438-4cbf-a902-e577e8cad657 Timestamp: 2025-09-19 08:25:30Z"
                    result = cca_auth_client_using_static_secret.acquire_token_for_client(
                        scopes=['https://management.azure.com/.default']
                    )
                else:
                    token_acquired = False
                    token_error = validation_error
                    result = {"error": "invalid_token", "error_description": validation_error}
                
                if "access_token" in result:
                    logging.info("Successfully acquired access token using OBO flow")
                    token_acquired = True
                    access_token = result["access_token"]
                    token_error = None
                    
                    # Use the token to call Resource Management API
                    try:
                        # Create an authentication object for Resouce Management
                        headers = {
                            'Authorization': f'Bearer {access_token}',
                            'Content-Type': 'application/json'
                        }
                        
                        # Define the Storage Mover resource body
                        storage_mover_body = {
                            "location": location,
                            "tags": {
                                "created_by": "mcp_tool",
                                "purpose": "hackathon"
                            },
                            "properties": {
                                "description": f"Storage Mover created via MCP tool for hackathon"
                            }
                        }
                        
                        # Create the Storage Mover using REST API
                        # API reference: https://docs.microsoft.com/en-us/rest/api/storagemover/storage-movers/create-or-update
                        storage_mover_url = f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.StorageMover/storageMovers/{name}?api-version=2023-10-01'
                        
                        logging.info(f"Creating Storage Mover at URL: {storage_mover_url}")
                        response = requests.put(storage_mover_url, headers=headers, json=storage_mover_body)
                        
                        if response.status_code == 200:
                            resource_group_data = response.json()
                            logging.info("Successfully retrieved resource group data")
                        else:
                            logging.error(f"Failed to get resource group data: {response.status_code}, {response.text}")
                            token_error = f"Resource Management API error: {response.status_code}"
                    except Exception as ex:
                        logging.error(f"Error calling Resource Management API: {str(ex)}")
                        token_error = f"Resoure Management error: {str(ex)}"
                else:
                    token_acquired = False
                    token_error = result.get('error_description', 'Unknown error acquiring token')
                    logging.warning(f"Failed to acquire token using OBO flow: {token_error}")
        except Exception as e:
            token_acquired = False
            token_error = str(e)
            logging.error(f"Exception when acquiring token: {token_error}")

        # Prepare the response
        try:
            response = {}
            
            if resource_group_data:
                # Return resource group data as the primary content
                response = resource_group_data
                # Add status information
                response['success'] = True
            else:
                # If we failed to get resource group data, return error information
                response['success'] = False
                response['error'] = token_error or "Failed to retrieve resource group data"
            
            logging.info(f"Returning response: {json.dumps(response)[:500]}...")
            return json.dumps(response, indent=2)
        except Exception as format_error:
            logging.error(f"Error formatting response: {str(format_error)}")
            return json.dumps({
                "success": False,
                "error": f"Error formatting response: {str(format_error)}"
            }, indent=2)
    except Exception as e:
        stack_trace = traceback.format_exc()
        return json.dumps({
            "error": f"An error occurred: {str(e)}\n{stack_trace}",
            "stack_trace": stack_trace,
            "raw_context": str(context)
        }, indent=2)

@app.generic_trigger(
    arg_name="context",
    type="mcpToolTrigger",
    toolName="create_aws_storage_migration",
    description="Create a StorageMover resource to move data from AWS S3 to Azure Blob Storage.",
    toolProperties="[]",
)
def create_aws_storage_migration(context) -> str:
    """
    Create a StorageMover resource with the specified parameters using Azure SDK.
    Also creates a project for the Storage Mover with a unique GUID-based name.
    Creates a storage account with a container for use with the Storage Mover.
    Optionally creates an Azure Arc multicloud connector for AWS integration.
    Optionally creates an AWS S3 source endpoint for the Storage Mover.
    
    Args:
        context: The trigger context as a JSON string containing the request information.
                Expected to contain 'subscription_id' in the arguments.
        
    Returns:
        JSON string with resource creation details, error information, or parameter guidance.
    """
    
    storage_mover_data = None
    project_data = None
    
    try:
        logging.info(f"Context type: {type(context).__name__}")
        try:
            context_obj = json.loads(context)
            arguments = context_obj.get('arguments', {})
            bearer_token = None
            subscription_id = None
            name = None
            location = None
            resource_group = None
            logging.info(f"Arguments structure: {json.dumps(arguments)[:500]}")
            
            if isinstance(arguments, dict):
                bearer_token = arguments.get('bearerToken')
                randomSuffix = datetime.now().strftime("%Y-%m-%d-%H%M%S")
                subscription_id = '32758ed5-6e7b-4f7a-90ac-e60d869ce968'
                name = f"arpijain-hackathon-mover-{randomSuffix}"
                location = 'eastus'
                resource_group = 'arpijain-aws-storage-mover-test-01'
            
            if not bearer_token:
                logging.warning("No bearer token found in context arguments")
                return json.dumps({
                    "error": "No bearer token found in context arguments",
                    "status": "Failed"
                }, indent=2)
            else:
                expected_audience = f"{application_cid}"
                is_valid, validation_error, decoded_token = validate_bearer_token(bearer_token, expected_audience)
                
                if is_valid:
                    # Use static secret based client for token acquisition.
                    # Not using the OBO flow here because admin consent is not provided for the app.
                    # "error": "AADSTS65001: The user or administrator has not consented to use the application with ID 'ddad3aee-d646-4ccc-a3ae-acc9f2ff237f' named 'arpijainmcp05'. Send an interactive authorization request for this user and resource. Trace ID: cdc64abe-5053-4788-a2f9-2d93c1e7de00 Correlation ID: f999d0be-b438-4cbf-a902-e577e8cad657 Timestamp: 2025-09-19 08:25:30Z"
                    result = cca_auth_client_using_static_secret.acquire_token_for_client(
                        scopes=['https://management.azure.com/.default']
                    )
                else:
                    return json.dumps({
                        "error": "invalid_token",
                        "error_description": validation_error,
                        "status": "Failed"
                    }, indent=2)
                
                if "access_token" in result:
                    logging.info("Successfully acquired access token using OBO flow")
                    access_token = result["access_token"]
                    
                    # Use the token to call Resource Management API
                    try:
                        # Create an authentication object for Resouce Management
                        headers = {
                            'Authorization': f'Bearer {access_token}',
                            'Content-Type': 'application/json'
                        }
                        
                        # Define the Storage Mover resource body
                        storage_mover_body = {
                            "location": location,
                            "tags": {
                                "created_by": "mcp_tool",
                                "purpose": "hackathon"
                            },
                            "properties": {
                                "description": f"Storage Mover created via MCP tool for hackathon"
                            }
                        }
                        
                        ################################################################################
                        ##################### STEP 1: Create a Storage Mover ###########################
                        ################################################################################

                        # Create the Storage Mover using REST API
                        # API reference: https://docs.microsoft.com/en-us/rest/api/storagemover/storage-movers/create-or-update
                        storage_mover_url = f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.StorageMover/storageMovers/{name}?api-version=2023-10-01'
                        
                        logging.info(f"Creating Storage Mover at URL: {storage_mover_url}")
                        storage_mover_response = requests.put(storage_mover_url, headers=headers, json=storage_mover_body)
                        
                        if storage_mover_response.status_code == 200:
                            storage_mover_data = storage_mover_response.json()
                            logging.info("Successfully retrieved resource group data")
                        else:
                            logging.error(f"Failed to get resource group data: {storage_mover_response.status_code}, {storage_mover_response.text}")
                            return json.dumps({
                                "error": f"Resource Management API error: {storage_mover_response.status_code}",
                                "status": "Failed"
                            }, indent=2)
                        ######################### STEP 1 END ###############################

                        ################################################################################
                        ############### STEP 2: Create a Project for the Storage Mover #################
                        ################################################################################

                        project_guid = str(uuid.uuid4())[:8]
                        project_name = f"{name}-project-{project_guid}"

                        # Define the Project resource body
                        project_body = {
                            "properties": {
                                "description": f"Project for StorageMover {name}"
                            }
                        }

                        # Create the Project using REST API
                        # API reference: https://docs.microsoft.com/en-us/rest/api/storagemover/projects/create-or-update
                        project_url = f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.StorageMover/storageMovers/{name}/projects/{project_name}?api-version=2023-10-01'

                        logging.info(f"Creating Storage Mover Project at URL: {project_url}")
                        project_response = requests.put(project_url, headers=headers, json=project_body)

                        if project_response.status_code in [200, 201]:
                            project_data = project_response.json()
                            logging.info("Successfully created Storage Mover Project")
                        else:
                            logging.error(f"Failed to create Storage Mover Project: {project_response.status_code}, {project_response.text}")
                            return json.dumps({
                                "error": f"Storage Mover Project API error: {project_response.status_code} - {project_response.text}",
                                "status": "Failed"
                            }, indent=2)
                        ######################### STEP 2 END ###############################

                    except Exception as ex:
                        logging.error(f"Error calling Resource Management API: {str(ex)}")
                        return json.dumps({
                                "error": f"Resoure Management error: {str(ex)}",
                                "status": "Failed"
                            }, indent=2)
                else:
                    logging.warning(f"Failed to acquire token using OBO flow: {token_error}")
                    return json.dumps({
                        "error": "Unknown error acquiring token",
                        "status": "Failed"
                    }, indent=2)
        except Exception as e:
            error_msg = str(e)
            logging.error(f"Exception when acquiring token: {error_msg}")
            return json.dumps({
                "error": f"Exception when acquiring token: {error_msg}",
                "status": "Failed"
            }, indent=2)

        # Prepare the response
        try:
            response = {}
            
            response['storage_mover_data'] = storage_mover_data
            response['project_data'] = project_data
            response['success'] = True
            
            logging.info(f"Returning response: {json.dumps(response)[:500]}...")
            return json.dumps(response, indent=2)
        except Exception as format_error:
            logging.error(f"Error formatting response: {str(format_error)}")
            return json.dumps({
                "success": False,
                "error": f"Error formatting response: {str(format_error)}"
            }, indent=2)
    except Exception as e:
        stack_trace = traceback.format_exc()
        return json.dumps({
            "error": f"An error occurred: {str(e)}\n{stack_trace}",
            "stack_trace": stack_trace,
            "raw_context": str(context)
        }, indent=2)

@app.generic_trigger(
    arg_name="context",
    type="mcpToolTrigger",
    toolName="get_graph_user_details",
    description="Get user details from Microsoft Graph.",
    toolProperties="[]",
)
def get_graph_user_details(context) -> str:
    """
    Gets user details from Microsoft Graph using the bearer token.
    
    Args:
        context: The trigger context as a JSON string containing the request information.
        
    Returns:
        str: JSON containing the user details from Microsoft Graph.
    """
    
    token_error = None
    user_data = None
    
    try:
        logging.info(f"Context type: {type(context).__name__}")
        try:
            context_obj = json.loads(context)
            arguments = context_obj.get('arguments', {})
            bearer_token = None
            logging.info(f"Arguments structure: {json.dumps(arguments)[:500]}")
            
            if isinstance(arguments, dict):
                bearer_token = arguments.get('bearerToken')
            
            if not bearer_token:
                logging.warning("No bearer token found in context arguments")
                token_acquired = False
                token_error = "No bearer token found in context arguments"
            else:
                expected_audience = f"{application_cid}"
                is_valid, validation_error, decoded_token = validate_bearer_token(bearer_token, expected_audience)
                
                if is_valid:
                    # Use On-Behalf-Of flow with the validated user's token
                    result = cca_auth_client.acquire_token_on_behalf_of(
                        user_assertion=bearer_token,
                        scopes=['https://graph.microsoft.com/.default']
                    )
                else:
                    token_acquired = False
                    token_error = validation_error
                    result = {"error": "invalid_token", "error_description": validation_error}
                
                if "access_token" in result:
                    logging.info("Successfully acquired access token using OBO flow")
                    token_acquired = True
                    access_token = result["access_token"]
                    token_error = None
                    
                    # Use the token to call Microsoft Graph API
                    try:
                        # Create an authentication object for Microsoft Graph
                        headers = {
                            'Authorization': f'Bearer {access_token}',
                            'Content-Type': 'application/json'
                        }
                        
                        # Get the user profile information
                        graph_url = 'https://graph.microsoft.com/v1.0/me'
                        response = requests.get(graph_url, headers=headers)
                        
                        if response.status_code == 200:
                            user_data = response.json()
                            logging.info("Successfully retrieved user data from Microsoft Graph")
                        else:
                            logging.error(f"Failed to get user data: {response.status_code}, {response.text}")
                            token_error = f"Graph API error: {response.status_code}"
                    except Exception as graph_error:
                        logging.error(f"Error calling Graph API: {str(graph_error)}")
                        token_error = f"Graph API error: {str(graph_error)}"
                else:
                    token_acquired = False
                    token_error = result.get('error_description', 'Unknown error acquiring token')
                    logging.warning(f"Failed to acquire token using OBO flow: {token_error}")
        except Exception as e:
            token_acquired = False
            token_error = str(e)
            logging.error(f"Exception when acquiring token: {token_error}")

        # Prepare the response
        try:
            response = {}
            
            if user_data:
                # Return user data as the primary content
                response = user_data
                # Add status information
                response['success'] = True
            else:
                # If we failed to get user data, return error information
                response['success'] = False
                response['error'] = token_error or "Failed to retrieve user data"
            
            logging.info(f"Returning response: {json.dumps(response)[:500]}...")
            return json.dumps(response, indent=2)
        except Exception as format_error:
            logging.error(f"Error formatting response: {str(format_error)}")
            return json.dumps({
                "success": False,
                "error": f"Error formatting response: {str(format_error)}"
            }, indent=2)
    except Exception as e:
        stack_trace = traceback.format_exc()
        return json.dumps({
            "error": f"An error occurred: {str(e)}\n{stack_trace}",
            "stack_trace": stack_trace,
            "raw_context": str(context)
        }, indent=2)

def get_managed_identity_token(audience):
    token = mi_auth_client.acquire_token_for_client(resource=audience)

    if "access_token" in token:
        return token["access_token"]
    else:
        raise Exception(f"Failed to acquire token: {token.get('error_description', 'Unknown error')}")

