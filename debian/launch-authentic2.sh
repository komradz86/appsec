#!/bin/bash

if [ -f /etc/default/authentic2 ]; then
    . /etc/default/authentic2
fi

if [ -f /etc/authentic2/db.conf ]; then
    . /etc/authentic2/db.conf
fi

if [ -f /etc/authentic2/authentic.conf ]; then
    . /etc/authentic2/authentic.conf
fi

exec /usr/bin/uwsgi "$@"
