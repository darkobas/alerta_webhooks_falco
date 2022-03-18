Falco incomming alert Webhook
==============

Installation
------------

Clone the GitHub repo and run:

    $ python setup.py install

Or, to install remotely from GitHub run:

    $ pip install git+https://github.com/darkobas/alerta_webhooks_falco

Note: If Alerta is installed in a python virtual environment then plugins
need to be installed into the same environment for Alerta to dynamically
discover them.

Configuration of Falco
-------------

edit falco.yml
````
program_output:
  enabled: true
  keep_alive: false
  program: 'curl -s -H "Content-Type: application/json" -H "Authorization: Key xxxxxxxxxxxxxx" --data-binary @- -XPOST "https://alerta.example.com/api/webhooks/falco?environment=Production&service=Falco"'
````
````
json_output: true
````

References
----------

  * Falco Documentation: https://falco.org/docs/configuration/

License
-------

Copyright (c) 2022 Marko Man. Available under the MIT License.
