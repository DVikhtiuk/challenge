from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import serializers


class RegistrationSerializer(serializers.ModelSerializer):

    password2 = serializers.CharField(style={"input_type": "password"})

    class Meta:
        model = get_user_model()
        fields = ("first_name", "last_name", "email", "password", "password2")
        extra_kwargs = {
            "password": {"write_only": True},
            "password2": {"write_only": True},
        }

    def save(self):
        user = get_user_model()(
            email=self.validated_data["email"],
            first_name=self.validated_data["first_name"],
            last_name=self.validated_data["last_name"],
        )

        password = self.validated_data["password"]
        password2 = self.validated_data["password2"]

        if password != password2:
            raise serializers.ValidationError({"password": "Passwords do not match!"})

        user.set_password(password)
        user.save()

        return user


class RegistrationSuccessSerializer(serializers.Serializer):
    detail = serializers.CharField(default="Registered Successfully!")


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={"input_type": "password"}, write_only=True)


class LoginSerializerDTO(serializers.Serializer):
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()


class ErrorResponseLogInFailedSerializer(serializers.Serializer):
    err_detail = serializers.CharField(default="Email or Password is incorrect!")


class LogoutSerializer(serializers.Serializer):
    message = serializers.CharField(default="Logged out successfully!")


class ErrorResponseSerializerAlreadyExists(serializers.Serializer):
    err_detail = serializers.CharField(default="User already exists")


class ErrorResponseSerializerInvalidToken(serializers.Serializer):
    err_detail = serializers.CharField(default="Token is invalid!")


class ErrorResponseSerializerNotFound(serializers.Serializer):
    err_detail = serializers.CharField(default="User not found!")


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ("id", "email", "is_staff", "first_name", "last_name")


class SubscriptionDetailSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    start_date = serializers.DateField()
    plan = serializers.CharField()


class SubscriptionsSerializer(serializers.Serializer):
    subscriptions = serializers.ListField(child=SubscriptionDetailSerializer())
