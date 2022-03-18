
from setuptools import setup, find_packages

version = '1.0.0'

setup(
    name="alerta-falco",
    version=version,
    description='Alerta plugin for Falco',
    url='https://github.com/alerta/alerta-contrib',
    license='MIT',
    author='Marko Man',
    author_email='darkobas@gmail.com',
    packages=find_packages(),
    py_modules=['alerta_falco'],
    install_requires=[
        'requests',
        'alerta-server>=4.10.1'
    ],
    include_package_data=True,
    zip_safe=True,
    entry_points={
        'alerta.webhooks': [
            'falco = alerta_falco:FalcoWebhook'
        ]
    }
)
