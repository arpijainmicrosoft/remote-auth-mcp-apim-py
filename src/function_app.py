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
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storagemover import StorageMoverMgmtClient
from azure.storage.blob import BlobServiceClient
from azure.identity import ClientSecretCredential
from azure.core.credentials import AccessToken

# Import helper functions
from helpers import (
    extract_multicloud_connector_id,
    construct_aws_resource_group_name,
    create_storage_mover_endpoint_payload
)

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# This variable is set in Bicep and is automatically provisioned.
application_uami = os.environ.get('APPLICATION_UAMI', 'Not set')
application_cid = os.environ.get('APPLICATION_CID', 'Not set')
application_tenant = os.environ.get('APPLICATION_TENANT', 'Not set')

application_secret = os.environ.get('APPLICATION_SECRET', 'Not set')

managed_identity = msal.UserAssignedManagedIdentity(client_id=application_uami)

mi_auth_client = msal.ManagedIdentityClient(managed_identity, http_client=requests.Session())

# Custom credential class to use the bearer token from context
class BearerTokenCredential:
    def __init__(self, access_token, expires_on=None):
        self.access_token = access_token
        # Set expiry to 1 hour from now if not provided
        self.expires_on = expires_on or (datetime.now().timestamp() + 3600)
    
    def get_token(self, *scopes, **kwargs):
        return AccessToken(self.access_token, int(self.expires_on))

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
    storage_account_data = None
    container_data = None
    source_endpoint_data = None
    target_endpoint_data = None
    job_definition_data = None

    try:
        logging.info(f"Context type: {type(context).__name__}")
        try:
            context_obj = json.loads(context)
            arguments = context_obj.get('arguments', {})
            bearer_token = None
            datetimeSuffix = None
            subscription_id = None
            name = None
            location = None
            resource_group = None
            connector_id = None
            aws_account_id = None
            bucket_name = None
            logging.info(f"Arguments structure: {json.dumps(arguments)[:500]}")
            
            if isinstance(arguments, dict):
                bearer_token = arguments.get('bearerToken')
                datetimeSuffix = datetime.now().strftime("%Y-%m-%d-%H%M%S")
                subscription_id = '32758ed5-6e7b-4f7a-90ac-e60d869ce968'
                name = f"arpijain-hackathon-mover-{datetimeSuffix}"
                location = 'eastus'
                resource_group = 'arpijain-aws-storage-mover-test-01'
                connector_id = "/subscriptions/32758ed5-6e7b-4f7a-90ac-e60d869ce968/resourceGroups/sunidhi/providers/Microsoft.HybridConnectivity/publicCloudConnectors/connector1/providers/Microsoft.HybridConnectivity/solutionConfigurations/storageMover"
                aws_account_id = '332061897005'
                bucket_name = 'sunidhibucket1'

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

                    # Create an authentication object
                    headers = {
                        'Authorization': f'Bearer {access_token}',
                        'Content-Type': 'application/json'
                    }

                    # Create credential object for SDK clients
                    credential = BearerTokenCredential(access_token)
                    
                    # Use the token to call Resource Management API
                    try:

                        ################################################################################
                        ##################### STEP 1: Create a Storage Mover ###########################
                        ################################################################################

                        storage_mover_name = name

                        # Initialize StorageMover client
                        storage_mover_client = StorageMoverMgmtClient(
                            credential=credential,
                            subscription_id=subscription_id
                        )
                        
                        # Define the Storage Mover properties                        
                        from azure.mgmt.storagemover.models import StorageMover  # Import locally to avoid module-level issues
                        storage_mover_properties = StorageMover(
                            location=location,
                            tags={},
                            description=f"StorageMover resource created via MCP server"
                        )
                        
                        try:
                            logging.info(f"[Storage-Mover-Create] Creating Storage Mover: {storage_mover_name}")
                            storage_mover_data = storage_mover_client.storage_movers.create_or_update(
                                resource_group_name=resource_group,
                                storage_mover_name=storage_mover_name,
                                storage_mover=storage_mover_properties
                            )

                            logging.info("[Storage-Mover-Create] Successfully created Storage Mover")
                        except Exception as ex:
                            logging.error(f"[Storage-Mover-Create] Exception creating Storage Mover: {str(ex)}")
                            return json.dumps({
                                "error": f"Storage Mover creation exception: {str(ex)}",
                                "status": "Failed"
                            }, indent=2)
                        
                        ######################### STEP 1 END ###############################



                        ################################################################################
                        ############### STEP 2: Create a Project for the Storage Mover #################
                        ################################################################################

                        project_name = f"project-{datetimeSuffix}"

                        from azure.mgmt.storagemover.models import Project
        
                        project_params = Project(
                            description=f"Project for StorageMover {storage_mover_name}"
                        )
                        
                        # Create the project
                        try:
                            project_data = storage_mover_client.projects.create_or_update(
                                resource_group_name=resource_group,
                                storage_mover_name=storage_mover_name,
                                project_name=project_name,
                                project=project_params
                            )
                            logging.info("[Storage-Mover-Project-Create] Successfully created Storage Mover Project")
                        except Exception as ex:
                            logging.error(f"[Storage-Mover-Project-Create] Exception creating Storage Mover Project: {str(ex)}")
                            return json.dumps({
                                "error": f"Storage Mover Project creation exception: {str(ex)}",
                                "status": "Failed"
                            }, indent=2)
                        
                        ######################### STEP 2 END ###############################



                        ################################################################################
                        ####################### STEP 3: Create a Storage Account #######################
                        ################################################################################

                        # Generate storage account name with timestamp suffix
                        storage_account_name = f"sa{datetimeSuffix.replace('-', '')}"
                        logging.info(f"[Storage-Account-Create] Generated storage account name: {storage_account_name}")

                        storage_client = StorageManagementClient(credential, subscription_id)

                        from azure.mgmt.storage.models import StorageAccountCreateParameters, Sku, Kind, AccessTier
                        # Create storage account parameters
                        storage_params = StorageAccountCreateParameters(
                            sku=Sku(name="Standard_LRS"),
                            kind=Kind.STORAGE_V2,
                            location=location,
                            tags={"purpose": "StorageMover"},
                            enable_https_traffic_only=True
                        )
                        
                        storage_account_create_operation = None
                        # Create storage account
                        try:
                            storage_account_create_operation = storage_client.storage_accounts.begin_create(
                                resource_group_name=resource_group,
                                account_name=storage_account_name,
                                parameters=storage_params
                            )
                            logging.info(f"[Storage-Account-Create] Storage account creation initiated: {storage_account_name}")
                        except Exception as ex:
                            logging.error(f"[Storage-Account-Create] Exception initiating storage account creation: {str(ex)}")
                            return json.dumps({
                                "error": f"Storage account creation initiation exception: {str(ex)}",
                                "status": "Failed"
                            }, indent=2)
                        
                        # Wait for completion (with timeout)
                        import time
                        start_time = time.time()
                        timeout_seconds = 120
                        
                        while not storage_account_create_operation.done() and (time.time() - start_time < timeout_seconds):
                            time.sleep(5)
                        
                        if not storage_account_create_operation.done():
                            return json.dumps({
                                "error": f"Storage account creation timed out after {timeout_seconds} seconds",
                                "status": "Failed"
                            }, indent=2)

                        logging.info(f"[Storage-Account-Create] Storage account creation completed: {storage_account_name}")
                        storage_account_data = storage_account_create_operation.result()

                        ############################ STEP 3 END #######################################



                        ################################################################################
                        ################## STEP 4: Create Container in Storage Account #################
                        ################################################################################

                        # Create blob container
                        container_name = "container1"

                        # Get storage account keys
                        keys = storage_client.storage_accounts.list_keys(
                            resource_group_name=resource_group,
                            account_name=storage_account_name
                        )

                        if keys.keys:
                            account_key = keys.keys[0].value
                            
                            # Create blob service client using connection string
                            from azure.storage.blob import BlobServiceClient
                            
                            connection_string = f"DefaultEndpointsProtocol=https;AccountName={storage_account_name};AccountKey={account_key};EndpointSuffix=core.windows.net"
                            blob_service_client = BlobServiceClient.from_connection_string(connection_string)
                            
                            # Create container
                            container_response = blob_service_client.create_container(container_name)
                            container_data = {
                                'container_name': container_name,
                                'storage_account_name': storage_account_name,
                                'url': container_response.url if hasattr(container_response, 'url') else None,
                                'account_name': container_response.account_name if hasattr(container_response, 'account_name') else None
                            }
                            logging.info(f"[Blob-Container-Creation] Successfully created blob container: {container_name}")
                        else:
                            logging.warning("[Blob-Container-Creation] No storage account keys found")
                            return json.dumps({
                                "error": f"No storage account keys available for storage account {storage_account_name}",
                                "status": "Failed"
                            }, indent=2)

                        ############################ STEP 4 END #######################################


                        ################################################################################
                        ######################## STEP 5: Create the source endpoint ####################
                        ################################################################################

                        logging.info(f"[Source-Endpoint-Creation] Creating AWS S3 source endpoint for StorageMover: {name}")
                        
                        # Auto-generate endpoint name with GUID
                        import uuid
                        endpoint_guid = str(uuid.uuid4())[:8]  # Use first 8 chars of GUID
                        source_endpoint_name = f"source-{endpoint_guid}"

                        # Extract base connector ID
                        multicloud_connector_id = extract_multicloud_connector_id(connector_id)
                        
                        # Construct AWS resource group name
                        aws_resource_group = construct_aws_resource_group_name(str(aws_account_id))

                        # Create endpoint payload
                        source_data_endpoint_payload = create_storage_mover_endpoint_payload(
                            endpoint_type="AzureMultiCloudConnector",
                            multicloud_connector_id=multicloud_connector_id,
                            subscription_id=subscription_id,
                            aws_resource_group=aws_resource_group,
                            bucket_name=bucket_name,
                            description=f"AWS S3 source endpoint for bucket {bucket_name}"
                        )

                        # Create the source endpoint using REST api call
                        try:
                            storage_mover_api_version = "2025-01-01-preview"
                            source_endpoint_creation_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.StorageMover/storageMovers/{storage_mover_name}/endpoints/{source_endpoint_name}?api-version={storage_mover_api_version}"

                            source_endpoint_creation_response = requests.put(source_endpoint_creation_url, headers=headers, json=source_data_endpoint_payload)

                            if source_endpoint_creation_response.status_code in [200, 201]:
                                 source_endpoint_data = source_endpoint_creation_response.json()
                                 logging.info(f"[Source-Endpoint-Creation] Successfully created source endpoint: {source_endpoint_name}")
                            else:
                                logging.error(f"[Source-Endpoint-Creation] Failed to create source endpoint: {source_endpoint_creation_response.status_code}, {source_endpoint_creation_response.text}")
                                return json.dumps({
                                    "error": f"Source endpoint creation failed: {source_endpoint_creation_response.status_code}, {source_endpoint_creation_response.text}",
                                    "status": "Failed"
                                }, indent=2)
                            
                        except Exception as ex:
                            logging.error(f"[Source-Endpoint-Creation] Exception creating source endpoint: {str(ex)}")
                            return json.dumps({
                                "error": f"Source endpoint creation exception: {str(ex)}",
                                "status": "Failed"
                            }, indent=2)

                        ############################ STEP 5 END #######################################


                        ################################################################################
                        ######################## STEP 6: Create the target endpoint ####################
                        ################################################################################

                        target_endpoint_name = f"target-{str(uuid.uuid4())[:8]}"
                                
                        # Get storage account ID from the storage account result
                        storage_account_id = storage_account_data.id

                        # Prepare endpoint payload for Azure Storage Blob Container
                        target_data_endpoint_payload = {
                            "identity": {
                                "type": "SystemAssigned"
                            },
                            "properties": {
                                "blobContainerName": container_name,
                                "endpointType": "AzureStorageBlobContainer",
                                "storageAccountResourceId": storage_account_id
                            }
                        }
                        
                        # Prepare REST API request
                        target_endpoint_api_version = "2025-01-01-preview"
                        target_endpoint_creation_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.StorageMover/storageMovers/{storage_mover_name}/endpoints/{target_endpoint_name}?api-version={target_endpoint_api_version}"

                        try:
                            target_endpoint_creation_response = requests.put(target_endpoint_creation_url, headers=headers, json=target_data_endpoint_payload)

                            if target_endpoint_creation_response.status_code in [200, 201]:
                                 target_endpoint_data = target_endpoint_creation_response.json()
                                 logging.info(f"[Target-Endpoint-Creation] Successfully created target endpoint: {target_endpoint_name}")
                            else:
                                logging.error(f"[Target-Endpoint-Creation] Failed to create target endpoint: {target_endpoint_creation_response.status_code}, {target_endpoint_creation_response.text}")
                                return json.dumps({
                                    "error": f"Target endpoint creation failed: {target_endpoint_creation_response.status_code}, {target_endpoint_creation_response.text}",
                                    "status": "Failed"
                                }, indent=2)
                            
                        except Exception as ex:
                            logging.error(f"[Target-Endpoint-Creation] Exception creating target endpoint: {str(ex)}")
                            return json.dumps({
                                "error": f"Target endpoint creation exception: {str(ex)}",
                                "status": "Failed"
                            }, indent=2)

                        ############################ STEP 6 END #######################################


                        ################################################################################
                        ########################### STEP 7: Create Job Definition ######################
                        ################################################################################

                        job_definition_name = f"{name}-{str(uuid.uuid4())[:8]}"
                        project_name = project_data.name
                        
                        job_def_creation_payload = {
                            "properties": {
                                "copyMode": "Additive",
                                "jobType": "CloudToCloud",
                                "sourceName": source_endpoint_name,
                                "sourceSubpath": "/",
                                "targetName": target_endpoint_name,
                                "targetSubpath": "/"
                            }
                        }

                        job_def_creation_api_version = "2025-01-01-preview"
                        job_def_creation_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.StorageMover/storageMovers/{storage_mover_name}/projects/{project_name}/jobDefinitions/{job_definition_name}?api-version={job_def_creation_api_version}"

                        try:
                            job_def_creation_response = requests.put(job_def_creation_url, headers=headers, json=job_def_creation_payload)

                            if job_def_creation_response.status_code in [200, 201]:
                                 job_definition_data = job_def_creation_response.json()
                                 logging.info(f"[Job-Definition-Creation] Successfully created job definition: {job_definition_name}")
                            else:
                                logging.error(f"[Job-Definition-Creation] Failed to create job definition: {job_def_creation_response.status_code}, {job_def_creation_response.text}")
                                return json.dumps({
                                    "error": f"Job definition creation failed: {job_def_creation_response.status_code}, {job_def_creation_response.text}",
                                    "status": "Failed"
                                }, indent=2)
                            
                        except Exception as ex:
                            logging.error(f"[Job-Definition-Creation] Exception creating job definition: {str(ex)}")
                            return json.dumps({
                                "error": f"Job definition creation exception: {str(ex)}",
                                "status": "Failed"
                            }, indent=2)

                        ############################ STEP 7 END #######################################


                    except Exception as ex:
                        logging.error(f"Error while performing aws migration tool steps: {str(ex)}")
                        return json.dumps({
                                "error": f"Generic error in aws migration tool steps: {str(ex)}",
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
            
            response['storage_mover_data'] = storage_mover_data.as_dict()
            response['project_data'] = project_data.as_dict()
            response['storage_account_data'] = storage_account_data.as_dict()
            response['container_data'] = container_data # as_dict() not applicable, already a dict
            response['source_endpoint_data'] = source_endpoint_data # as_dict() not applicable, already a dict since we are using REST API and not SDK
            response['target_endpoint_data'] = target_endpoint_data # as_dict() not applicable, already a dict since we are using REST API and not SDK
            response['job_definition_data'] = job_definition_data # as_dict() not applicable, already a dict since we are using REST API and not SDK
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

