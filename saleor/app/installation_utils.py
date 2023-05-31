import requests
from django.conf import settings
from django.contrib.sites.models import Site
from django.urls import reverse
from requests import HTTPError, Response

from ..app.headers import AppHeaders, DeprecatedAppHeaders
from ..core.utils import build_absolute_uri
from ..permission.enums import get_permission_names
from ..plugins.manager import PluginsManager
from ..webhook.models import Webhook, WebhookEvent
from .manifest_schema import ManifestStrict
from .models import App, AppExtension, AppInstallation
from .types import AppType

REQUEST_TIMEOUT = 25


class AppInstallationError(HTTPError):
    pass


def validate_app_install_response(response: Response):
    try:
        response.raise_for_status()
    except HTTPError as err:
        try:
            error_msg = str(response.json()["error"]["message"])
        except Exception:
            raise err
        raise AppInstallationError(error_msg, response=response)


def send_app_token(target_url: str, token: str):
    domain = Site.objects.get_current().domain
    headers = {
        "Content-Type": "application/json",
        # X- headers will be deprecated in Saleor 4.0, proper headers are without X-
        DeprecatedAppHeaders.DOMAIN: domain,
        AppHeaders.DOMAIN: domain,
        AppHeaders.API_URL: build_absolute_uri(reverse("api"), domain),
    }
    json_data = {"auth_token": token}
    response = requests.post(
        target_url,
        json=json_data,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    validate_app_install_response(response)


def install_app(app_installation: AppInstallation, activate: bool = False):
    response = requests.get(
        app_installation.manifest_url, timeout=REQUEST_TIMEOUT, allow_redirects=False
    )
    response.raise_for_status()
    assigned_permissions = app_installation.permissions.all()
    manifest_data = response.json()

    manifest_data["permissions"] = get_permission_names(assigned_permissions)

    manifest = ManifestStrict.parse_obj(manifest_data)

    app = App.objects.create(
        name=app_installation.app_name,
        is_active=activate,
        identifier=manifest.id,
        about_app=manifest.about,
        data_privacy=manifest.data_privacy,
        data_privacy_url=manifest.data_privacy_url,
        homepage_url=manifest.homepage_url,
        support_url=manifest.support_url,
        configuration_url=manifest.configuration_url,
        app_url=manifest.app_url,
        version=manifest.version,
        manifest_url=app_installation.manifest_url,
        type=AppType.THIRDPARTY,
        audience=manifest.audience,
        is_installed=False,
        author=manifest.author,
    )

    app.permissions.set(app_installation.permissions.all())
    for extension_data in manifest.extensions:
        extension = AppExtension.objects.create(
            app=app,
            label=extension_data.label,
            url=extension_data.url,
            mount=extension_data.mount.name,
            target=extension_data.target.name,
        )
        extension.permissions.set(extension_data.permissions)

    webhooks = Webhook.objects.bulk_create(
        Webhook(
            app=app,
            name=webhook.name,
            is_active=webhook.is_active,
            target_url=webhook.target_url,
            subscription_query=webhook.query.query,
            custom_headers=webhook.custom_headers,
        )
        for webhook in manifest.webhooks
    )

    webhook_events = []
    for db_webhook, manifest_webhook in zip(webhooks, manifest.webhooks):
        for event_type in manifest_webhook.events:
            webhook_events.append(
                WebhookEvent(webhook=db_webhook, event_type=event_type)
            )
    WebhookEvent.objects.bulk_create(webhook_events)

    _, token = app.tokens.create(name="Default token")  # type: ignore[call-arg] # calling create on a related manager # noqa: E501

    try:
        send_app_token(target_url=manifest.token_target_url, token=token)
    except requests.RequestException as e:
        app.delete()
        raise e
    PluginsManager(plugins=settings.PLUGINS).app_installed(app)
    return app, token
