from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import decorators as rest_decorators
from rest_framework import permissions as rest_permissions
from rest_framework import response, status


@extend_schema(
    request=None,
    responses={
        status.HTTP_200_OK: OpenApiResponse(
            description="Payment processed successfully"
        ),
        status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description="Unauthorized"),
    },
    description="Endpoint to process payment for a subscription",
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def paySubscription(request):
    return response.Response({"msg": "Success"}, status=status.HTTP_200_OK)


@extend_schema(
    request=None,
    responses={
        status.HTTP_200_OK: OpenApiResponse(
            description="List of subscriptions retrieved successfully"
        ),
        status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description="Unauthorized"),
    },
    description="Endpoint to list all subscriptions for an authenticated user",
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def listSubscriptions(request):
    return response.Response({"msg": "Success"}, status=status.HTTP_200_OK)
