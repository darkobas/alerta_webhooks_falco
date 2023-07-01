import datetime
from typing import Any, Dict

from flask import current_app
from werkzeug.datastructures import ImmutableMultiDict, MultiDict

from alerta.app import alarm_model
from alerta.exceptions import ApiError, RejectException
from alerta.models.alert import Alert
from alerta.webhooks import WebhookBase
from alerta.utils.api import process_alert

JSON = Dict[str, Any]

class FalcoWebhook(WebhookBase):
    """
    Falco webhook receiver
    """

    def incoming(self, path, query_string, payload):

      # get values from request params
      environment = query_string.get('environment', current_app.config['DEFAULT_ENVIRONMENT'])
      group = query_string.get('group', 'Security')
      customer = query_string.get('customer', None)
      origin = query_string.get('origin', 'Cloud')

      # validate timeout value
      try:
        timeout = int(query_string.get('timeout', 86400))
      except ValueError:
        raise ApiError("Invalid timeout value")

      # ensure required payload fields are present
      required_fields = ['alert', 'id', 'status']
      for field in required_fields:
        if field not in payload:
          raise ApiError(f"Missing required field in payload: {field}")

      # Extract the hostname
      hostname = payload['alert']['rawData'].get('hostname', '')

      # get service from request params and add hostname
      service = payload['alert'].get('service', ['Falco'])
      if hostname:
        service.append(hostname)

      return Alert(
          resource=payload['alert'].get('resource', ''),
          event=payload['alert'].get('event', ''),
          environment=environment,
          severity=payload['alert'].get('severity', 'indeterminate').lower(),
          service=service,  # updated service field
          group=group,
          value=payload['alert'].get('value', ''),
          text=payload['alert'].get('text', ''),
          tags=payload['alert'].get('tags', []),  # get tags from the payload
          customer=customer,
          origin=origin,
          event_type='falcoAlert',
          timeout=timeout,
          repeat=payload['alert'].get('repeat', False),
          raw_data=payload
      )
