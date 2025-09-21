#!/usr/bin/env python3
"""
Helper functions for StorageMover MCP Server

This module contains utility functions for StorageMover resource management.
"""

def extract_multicloud_connector_id(full_connector_id: str) -> str:
    """
    Extract base connector ID by removing the solution configuration part.
    
    Args:
        full_connector_id: Full connector ID with solution configuration
        
    Returns:
        Base connector ID without solution configuration
    """
    if "/providers/Microsoft.HybridConnectivity/solutionConfigurations/" in full_connector_id:
        return full_connector_id.split("/providers/Microsoft.HybridConnectivity/solutionConfigurations/")[0]
    return full_connector_id

def construct_aws_resource_group_name(aws_account_id: str) -> str:
    """
    Construct AWS resource group name in the format: aws_{aws_account_id}
    
    Args:
        aws_account_id: AWS account ID
        
    Returns:
        AWS resource group name
    """
    return f"aws_{aws_account_id}"

def create_storage_mover_endpoint_payload(endpoint_type: str, multicloud_connector_id: str, 
                          subscription_id: str, aws_resource_group: str, 
                          bucket_name: str, description: str) -> dict:
    """
    Create the endpoint payload for REST API call.
    
    Args:
        endpoint_type: Type of endpoint (e.g., "AzureMultiCloudConnector")
        multicloud_connector_id: Base connector ID
        subscription_id: Azure subscription ID
        aws_resource_group: AWS resource group name
        bucket_name: S3 bucket name
        description: Endpoint description
        
    Returns:
        Dictionary containing the endpoint payload
    """
    return {
        "properties": {
            "endpointType": endpoint_type,
            "multiCloudConnectorId": multicloud_connector_id,
            "awsS3BucketId": f"/subscriptions/{subscription_id}/resourceGroups/{aws_resource_group}/providers/Microsoft.AWSConnector/s3Buckets/{bucket_name}",
            "description": description
        }
    }
