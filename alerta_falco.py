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
      service = query_string.get('service', 'Falco').split(',')
      group = query_string.get('group', 'Security')
      customer = query_string.get('customer', None)
      origin = query_string.get('origin', 'Cloud')
      timeout = query_string.get('timeout', 86400)
  
      # get metric labels (evalMatches tags)
      tags = payload['tags'] or {}
      severity = payload['priority'].lower()
  
      return Alert(
          resource=payload['source'],
          event=payload['rule'],
          environment=environment,
          severity=severity,
          service=service,
          group=group,
          value=payload['output_fields'],
          text=payload['rule'],
          tags=list(),
          customer=customer,
          origin=origin,
          event_type='falcoAlert',
          timeout=timeout,
          raw_data=payload
      )

