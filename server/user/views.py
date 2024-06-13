import stripe
from django.conf import settings
from django.contrib.auth import authenticate
from django.middleware import csrf
from drf_spectacular.utils import extend_schema
from rest_framework import decorators as rest_decorators
from rest_framework import exceptions as rest_exceptions
from rest_framework import permissions as rest_permissions
from rest_framework import response
from rest_framework import serializers as s
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt import exceptions as jwt_exceptions
from rest_framework_simplejwt import serializers as jwt_serializers
from rest_framework_simplejwt import tokens
from rest_framework_simplejwt import views as jwt_views

from user import models, serializers

from .serializers import (
    ErrorResponseLogInFailedSerializer,
    ErrorResponseSerializerAlreadyExists,
    ErrorResponseSerializerInvalidToken,
    ErrorResponseSerializerNotFound,
    LoginSerializer,
    LoginSerializerDTO,
    LogoutSerializer,
    RegistrationSerializer,
    RegistrationSuccessSerializer,
    SubscriptionsSerializer,
    UserSerializer,
)

stripe.api_key = settings.STRIPE_SECRET_KEY
prices = {
    settings.WORLD_INDIVIDUAL: "world_individual",
    settings.WORLD_GROUP: "world_group",
    settings.WORLD_BUSINESS: "world_business",
    settings.UNIVERSE_INDIVIDUAL: "universe_individual",
    settings.UNIVERSE_GROUP: "universe_group",
    settings.UNIVERSE_BUSINESS: "universe_business",
}


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {"refresh_token": str(refresh), "access_token": str(refresh.access_token)}


@extend_schema(
    request=LoginSerializer,
    responses={
        status.HTTP_200_OK: LoginSerializerDTO,
        status.HTTP_403_FORBIDDEN: ErrorResponseLogInFailedSerializer,
    },
    description="Log in a user and set JWT tokens in cookies",
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([AllowAny])
@rest_decorators.authentication_classes([])
def loginView(request):
    serializer = serializers.LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]

    user = authenticate(email=email, password=password)

    if user is not None:
        tokens = get_user_tokens(user)
        res = response.Response()
        res.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE"],
            value=tokens["access_token"],
            expires=settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"],
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )

        res.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
            value=tokens["refresh_token"],
            expires=settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"],
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )

        res.data = tokens
        res["X-CSRFToken"] = csrf.get_token(request)
        return res
    raise rest_exceptions.AuthenticationFailed("Email or Password is incorrect!")


@extend_schema(
    request=None,
    responses={
        status.HTTP_200_OK: LogoutSerializer,
        status.HTTP_400_BAD_REQUEST: ErrorResponseSerializerInvalidToken,
    },
    description="Log out from your account",
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def logoutView(request):
    try:
        refreshToken = request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"])
        token = tokens.RefreshToken(refreshToken)
        token.blacklist()

        res = response.Response()
        res.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE"])
        res.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"])
        res.delete_cookie("X-CSRFToken")
        res.delete_cookie("csrftoken")
        res["X-CSRFToken"] = None
        return response.Response(
            {"message": "Logged out successfully!"}, status=status.HTTP_200_OK
        )
    except Exception:
        raise rest_exceptions.ParseError("Invalid token")


@extend_schema(
    request=RegistrationSerializer,
    responses={
        status.HTTP_200_OK: RegistrationSuccessSerializer,
        status.HTTP_400_BAD_REQUEST: ErrorResponseSerializerAlreadyExists,
    },
    description="Register a new user",
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([AllowAny])
@rest_decorators.authentication_classes([])
def registerView(request):
    serializer = serializers.RegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    if user is not None:
        return response.Response({"detail": "Registered Successfully!"})
    raise rest_exceptions.ParseError("User already exists")


class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs["refresh"] = self.context["request"].COOKIES.get("refresh")
        if attrs["refresh"]:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken(
                "No valid token found in cookie 'refresh'"
            )


class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    class TokenRefreshSerializer(s.Serializer):
        refresh_token = s.CharField()

    @extend_schema(
        request=None,
        description="Refresh JWT token using the refresh token stored in cookies",
        responses={status.HTTP_200_OK: TokenRefreshSerializer},
        auth=None,
    )
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        access_token = response.data.get("access")
        del response.data["access"]
        response.data["access_token"] = access_token

        return response

    def finalize_response(self, request, response, *args, **kwargs):
        if response.data.get("refresh"):
            response.set_cookie(
                key=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
                value=response.data["refresh"],
                expires=settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"],
                secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
                httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )

            del response.data["refresh"]
        response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response, *args, **kwargs)


@extend_schema(
    responses={
        status.HTTP_200_OK: UserSerializer,
        status.HTTP_404_NOT_FOUND: ErrorResponseSerializerNotFound,
    },
    description="Get current user profile",
)
@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def user(request):
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status=status.HTTP_404_NOT_FOUND)

    serializer = serializers.UserSerializer(user)
    return response.Response(serializer.data)


@extend_schema(
    responses={
        status.HTTP_200_OK: SubscriptionsSerializer,
        status.HTTP_404_NOT_FOUND: ErrorResponseSerializerNotFound,
    },
    description="Get current user subscriptions",
)
@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def getSubscriptions(request):
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status=status.HTTP_404_NOT_FOUND)

    subscriptions = []
    customer = stripe.Customer.search(query=f'email:"{user.email}"')
    if "data" in customer:
        if len(customer["data"]) > 0:
            for _customer in customer["data"]:
                subscription = stripe.Subscription.list(customer=_customer["id"])
                if "data" in subscription:
                    if len(subscription["data"]) > 0:
                        for _subscription in subscription["data"]:
                            if _subscription["status"] == "active":
                                subscriptions.append(
                                    {
                                        "id": _subscription["id"],
                                        "start_date": str(_subscription["start_date"]),
                                        "plan": prices[_subscription["plan"]["id"]],
                                    }
                                )

    return response.Response({"subscriptions": subscriptions}, status.HTTP_200_OK)
