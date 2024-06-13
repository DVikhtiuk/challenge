from django.urls import path

from transaction.views import listSubscriptions, paySubscription

app_name = "transaction"

urlpatterns = [path("pay", paySubscription), path("list", listSubscriptions)]
